//! MPP middleware — payment trigger detection and request processing
//!
//! Reuses the same protocol-specific trigger logic as x402 (MCP tool names,
//! A2A method filters) but with MPP-specific challenge/credential handling.

use axum::response::Response;

use super::types::MppConfig;
use super::verification::{create_mpp_receipt, verify_mpp_credential};
use crate::config::types::ChannelProtocol;

/// Check if payment is required for this request based on protocol-specific triggers.
///
/// The trigger logic is identical to x402: MCP checks tool names, A2A checks
/// method filters, other protocols require payment for all requests.
/// Check if payment is required for this request based on protocol-specific triggers.
///
/// `mcp_context` may be supplied by callers that have already parsed the
/// JSON-RPC envelope. When `Some`, the MCP branch reads method + tool
/// name from it directly instead of re-parsing `body_bytes`.
///
/// The trigger logic is identical to x402: MCP checks tool names, A2A checks
/// method filters, other protocols require payment for all requests.
pub fn should_require_payment(
    config: &MppConfig,
    protocol: &ChannelProtocol,
    body_bytes: &[u8],
    mcp_context: Option<&crate::surface_context::McpContext>,
) -> bool {
    if !config.enabled {
        return false;
    }

    match protocol {
        ChannelProtocol::Mcp => crate::x402::middleware::mcp_requires_payment(
            config
                .mcp_payment_triggers
                .as_ref(),
            body_bytes,
            mcp_context,
            "mpp",
        ),
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => {
            let Some(ref filters) = config.a2a_method_filters else {
                return false;
            };
            if filters.is_empty() {
                return false;
            }

            // As for x402: no body (a GET) is not charged; a body the filters cannot
            // be matched against is charged rather than let through free.
            if body_bytes.is_empty() {
                return false;
            }
            let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
                return true;
            };
            let Some(method) = json
                .get("method")
                .and_then(|m| m.as_str())
            else {
                return true;
            };

            let normalized = crate::x402::middleware::normalize_a2a_method(method);

            for filter in filters {
                let filter_normalized = crate::x402::middleware::normalize_a2a_method(&filter.method);
                if filter_normalized != normalized {
                    continue;
                }
                if filter
                    .message_patterns
                    .is_empty()
                {
                    return true;
                }

                let content = if normalized == "message/send" || normalized == "message/stream" {
                    crate::x402::middleware::extract_a2a_message_text(&json)
                } else {
                    return true;
                };

                let Some(content) = content else {
                    return true;
                };

                for pattern in &filter.message_patterns {
                    let escaped = regex::escape(pattern);
                    if let Ok(re) = regex::Regex::new(&escaped)
                        && re.is_match(&content)
                    {
                        return true;
                    }
                }
                return false;
            }
            false
        }
        _ => true,
    }
}

/// Fire MPP challenge-issued side effects without building a 402 response.
///
/// Used when a combined x402+MPP 402 is built externally and we still need
/// to record the challenge issuance and fire integration events.
pub fn fire_challenge_issued_events(
    channel_id: &str,
    channel_name: &str,
    resource_url: &str,
    transaction_store: Option<std::sync::Arc<super::transaction_store::MppTransactionStore>>,
) {
    if let Some(store) = transaction_store {
        let ch_id = channel_id.to_string();
        let ch_name = channel_name.to_string();
        let r_url = resource_url.to_string();
        let trace_id = crate::observability::policy_audit::current_span_trace_id();
        tokio::spawn(async move {
            let _ = store
                .record_challenge_issued(&ch_id, &ch_name, &r_url, trace_id)
                .await;
        });
    }

    let ch_id = channel_id.to_string();
    let ch_name = channel_name.to_string();
    let r_url = resource_url.to_string();
    tokio::spawn(async move {
        crate::integrations::mpp_integration_triggers::trigger_mpp_challenge_issued(&ch_id, &ch_name, &r_url).await;
    });
}

/// Process an MPP payment for a request.
///
/// # Returns
/// - `Ok(Some(receipt_header))` — payment verified, include `Payment-Receipt` header
/// - `Ok(None)` — payment not required (config disabled)
/// - `Err(Response)` — 402 challenge or verification failure response
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn process_payment(
    credential: Option<super::types::MppCredential>,
    config: &MppConfig,
    channel_name: &str,
    channel_id: &str,
    resource_url: &str,
    transaction_store: Option<std::sync::Arc<super::transaction_store::MppTransactionStore>>,
    secrets_store: &Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
) -> Result<Option<String>, Response> {
    if !config.enabled {
        return Ok(None);
    }

    // Capture the request trace id up-front, before any `tokio::spawn` — the
    // task-local / span context does not cross the spawn boundary, so each
    // spawned transaction-store write receives an owned clone.
    let trace_id = crate::observability::policy_audit::current_span_trace_id();

    let resolved_config = match super::secrets::resolve_config_secrets(config, secrets_store).await {
        Ok(resolved) => resolved,
        Err(e) => {
            tracing::error!(channel = channel_name, error = %e, "[mpp] Failed to resolve config secrets");
            return Err(super::errors::secret_resolution_error_response());
        }
    };
    let config = &resolved_config;

    match credential {
        Some(cred) => {
            let method_str = cred
                .challenge
                .method
                .to_string();
            let payer = cred.source.clone();
            tracing::info!(
                channel = channel_name,
                method = %method_str,
                "[mpp] Verifying payment credential"
            );

            // Step 1: Synchronous checks (HMAC binding, expiry, method, non-empty payload)
            match verify_mpp_credential(&cred, config) {
                Ok(()) => {
                    // Step 2: Async payment-method-specific proof verification
                    match super::verification::verify_payment_proof(&cred, config).await {
                        Ok(proof) => {
                            // Step 3: Reject a replay of an already-consumed settlement
                            // (Stripe PaymentIntent id, on-chain tx hash, signature nonce).
                            if let Some(ref key) = proof.single_use_key
                                && super::nonce_guard::global_mpp_nonce_guard()
                                    .check_and_record(key, super::nonce_guard::replay_ttl(&cred))
                                    == super::nonce_guard::ReplayCheck::Replay
                            {
                                let err_msg = "Payment settlement already consumed (replay detected)".to_string();
                                tracing::warn!(
                                    channel = channel_name,
                                    method = %method_str,
                                    "[mpp] Rejected replayed payment settlement"
                                );

                                if let Some(ref store) = transaction_store {
                                    let store = store.clone();
                                    let ch_id = channel_id.to_string();
                                    let ch_name = channel_name.to_string();
                                    let r_url = resource_url.to_string();
                                    let m = method_str.clone();
                                    let err_clone = err_msg.clone();
                                    let payer_clone = payer.clone();
                                    let trace_id = trace_id.clone();
                                    tokio::spawn(async move {
                                        let _ = store
                                            .record_failed(
                                                &ch_id,
                                                &ch_name,
                                                &r_url,
                                                &m,
                                                &err_clone,
                                                payer_clone.as_deref(),
                                                trace_id,
                                            )
                                            .await;
                                    });
                                }

                                let ch_id = channel_id.to_string();
                                let ch_name = channel_name.to_string();
                                let m = method_str.clone();
                                let r_url = resource_url.to_string();
                                let err_clone = err_msg.clone();
                                tokio::spawn(async move {
                                    crate::integrations::mpp_integration_triggers::trigger_mpp_verification_failed(
                                        &ch_id, &ch_name, &m, &r_url, &err_clone,
                                    )
                                    .await;
                                });

                                return Err(super::create_mpp_verification_failed_response(
                                    config,
                                    resource_url,
                                    &err_msg,
                                ));
                            }

                            let reference = proof.reference;
                            tracing::info!(
                                channel = channel_name,
                                channel_id = channel_id,
                                method = %method_str,
                                reference = %reference,
                                "[mpp] Payment verified successfully"
                            );

                            // Record in transaction store
                            if let Some(ref store) = transaction_store {
                                // Find amount/currency from config for this method
                                let method_config = config
                                    .payment_methods
                                    .iter()
                                    .find(|m| m.method == method_str);
                                let amount = method_config.map(|m| m.amount.as_str());
                                let currency = method_config.map(|m| m.currency.as_str());

                                let store = store.clone();
                                let ch_id = channel_id.to_string();
                                let ch_name = channel_name.to_string();
                                let r_url = resource_url.to_string();
                                let m = method_str.clone();
                                let ref_clone = reference.clone();
                                let payer_clone = payer.clone();
                                let amt = amount.map(|s| s.to_string());
                                let cur = currency.map(|s| s.to_string());
                                let trace_id = trace_id.clone();
                                tokio::spawn(async move {
                                    let _ = store
                                        .record_verified(
                                            &ch_id,
                                            &ch_name,
                                            &r_url,
                                            &m,
                                            &ref_clone,
                                            payer_clone.as_deref(),
                                            amt.as_deref(),
                                            cur.as_deref(),
                                            trace_id,
                                        )
                                        .await;
                                });
                            }

                            // Fire integration event for successful payment
                            let ch_id = channel_id.to_string();
                            let ch_name = channel_name.to_string();
                            let m = method_str.clone();
                            let r_url = resource_url.to_string();
                            let ref_clone = reference.clone();
                            tokio::spawn(async move {
                                crate::integrations::mpp_integration_triggers::trigger_mpp_payment_verified(
                                    &ch_id, &ch_name, &m, &r_url, &ref_clone,
                                )
                                .await;
                            });

                            match create_mpp_receipt(&cred.challenge.method, &reference) {
                                Ok(receipt_header) => Ok(Some(receipt_header)),
                                Err(e) => {
                                    tracing::warn!(
                                        channel = channel_name,
                                        error = %e,
                                        "[mpp] Failed to create receipt"
                                    );
                                    Ok(None)
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                channel = channel_name,
                                error = %e,
                                "[mpp] Payment proof verification failed"
                            );

                            // Record failure in transaction store
                            if let Some(ref store) = transaction_store {
                                let store = store.clone();
                                let ch_id = channel_id.to_string();
                                let ch_name = channel_name.to_string();
                                let r_url = resource_url.to_string();
                                let m = method_str.clone();
                                let err_msg = e.clone();
                                let payer_clone = payer.clone();
                                let trace_id = trace_id.clone();
                                tokio::spawn(async move {
                                    let _ = store
                                        .record_failed(
                                            &ch_id,
                                            &ch_name,
                                            &r_url,
                                            &m,
                                            &err_msg,
                                            payer_clone.as_deref(),
                                            trace_id,
                                        )
                                        .await;
                                });
                            }

                            // Fire integration event for verification failure
                            let ch_id = channel_id.to_string();
                            let ch_name = channel_name.to_string();
                            let m = method_str.clone();
                            let r_url = resource_url.to_string();
                            let err_msg = e.clone();
                            tokio::spawn(async move {
                                crate::integrations::mpp_integration_triggers::trigger_mpp_verification_failed(
                                    &ch_id, &ch_name, &m, &r_url, &err_msg,
                                )
                                .await;
                            });

                            Err(super::create_mpp_verification_failed_response(config, resource_url, &e))
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        channel = channel_name,
                        error = %e,
                        "[mpp] Payment verification failed"
                    );

                    // Record failure in transaction store
                    if let Some(ref store) = transaction_store {
                        let store = store.clone();
                        let ch_id = channel_id.to_string();
                        let ch_name = channel_name.to_string();
                        let r_url = resource_url.to_string();
                        let m = method_str.clone();
                        let err_msg = e.clone();
                        let payer_clone = payer.clone();
                        let trace_id = trace_id.clone();
                        tokio::spawn(async move {
                            let _ = store
                                .record_failed(&ch_id, &ch_name, &r_url, &m, &err_msg, payer_clone.as_deref(), trace_id)
                                .await;
                        });
                    }

                    // Fire integration event for credential validation failure
                    let ch_id = channel_id.to_string();
                    let ch_name = channel_name.to_string();
                    let m = method_str.clone();
                    let r_url = resource_url.to_string();
                    let err_msg = e.clone();
                    tokio::spawn(async move {
                        crate::integrations::mpp_integration_triggers::trigger_mpp_verification_failed(
                            &ch_id, &ch_name, &m, &r_url, &err_msg,
                        )
                        .await;
                    });

                    Err(super::create_mpp_verification_failed_response(config, resource_url, &e))
                }
            }
        }
        None => {
            tracing::info!(channel = channel_name, "[mpp] No payment credential — returning 402 challenge");

            // Record challenge in transaction store
            if let Some(ref store) = transaction_store {
                let store = store.clone();
                let ch_id = channel_id.to_string();
                let ch_name = channel_name.to_string();
                let r_url = resource_url.to_string();
                let trace_id = trace_id.clone();
                tokio::spawn(async move {
                    let _ = store
                        .record_challenge_issued(&ch_id, &ch_name, &r_url, trace_id)
                        .await;
                });
            }

            // Fire integration event for challenge issuance
            let ch_id = channel_id.to_string();
            let ch_name = channel_name.to_string();
            let r_url = resource_url.to_string();
            tokio::spawn(async move {
                crate::integrations::mpp_integration_triggers::trigger_mpp_challenge_issued(&ch_id, &ch_name, &r_url)
                    .await;
            });

            Err(super::create_mpp_402_response(config, resource_url))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::types::*;

    fn test_config() -> MppConfig {
        MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"test-secret-32-bytes-long!!!!!!!",
            ),
            stripe_secret_key: None,
            payment_methods: vec![MppPaymentMethod {
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "0xrecipient".to_string(),
                amount: "1.00".to_string(),
                network: None,
            }],
            challenge_ttl_seconds: 300,
            mcp_payment_triggers: Some(crate::config::types::McpPaymentTriggers::Match {
                patterns: vec!["^expensive_tool$".to_string()],
            }),
            a2a_method_filters: None,
            verification_timeout_ms: 10000,
            crypto_verification_mode: MppVerificationMode::default(),
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
        }
    }

    #[test]
    fn test_should_require_payment_disabled() {
        let mut config = test_config();
        config.enabled = false;
        assert!(!should_require_payment(&config, &ChannelProtocol::Mcp, b"{}", None));
    }

    #[test]
    fn test_should_require_payment_mcp_matching_tool() {
        let config = test_config();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "expensive_tool", "arguments": {}}
        });
        assert!(should_require_payment(
            &config,
            &ChannelProtocol::Mcp,
            serde_json::to_vec(&body)
                .unwrap()
                .as_slice(),
            None,
        ));
    }

    #[test]
    fn test_should_require_payment_mcp_non_matching_tool() {
        let config = test_config();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "free_tool", "arguments": {}}
        });
        assert!(!should_require_payment(
            &config,
            &ChannelProtocol::Mcp,
            serde_json::to_vec(&body)
                .unwrap()
                .as_slice(),
            None,
        ));
    }

    #[test]
    fn test_should_require_payment_mcp_tools_list() {
        let config = test_config();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {}
        });
        assert!(!should_require_payment(
            &config,
            &ChannelProtocol::Mcp,
            serde_json::to_vec(&body)
                .unwrap()
                .as_slice(),
            None,
        ));
    }

    #[test]
    fn test_should_require_payment_other_protocol() {
        let config = test_config();
        assert!(should_require_payment(&config, &ChannelProtocol::DIDComm, b"anything", None));
    }

    #[tokio::test]
    async fn test_process_payment_disabled() {
        let mut config = test_config();
        config.enabled = false;
        let result = process_payment(None, &config, "test", "test-id", "/api/resource", None, &None).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_process_payment_no_credential_returns_402() {
        let config = test_config();
        let result = process_payment(None, &config, "test", "test-id", "/api/resource", None, &None).await;
        assert!(result.is_err());
        let response = result.unwrap_err();
        assert_eq!(response.status(), axum::http::StatusCode::PAYMENT_REQUIRED);
    }

    /// As for x402: with A2A method filters configured, a body the filters cannot
    /// be matched against is charged; a request without a body is not.
    #[test]
    fn a2a_method_filters_charge_a_body_without_a_string_method() {
        let mut config = test_config();
        config.a2a_method_filters = Some(vec![crate::config::types::A2AMethodFilter {
            method: "CancelTask".to_string(),
            message_patterns: vec![],
        }]);
        let requires = |body: &[u8]| should_require_payment(&config, &ChannelProtocol::A2a, body, None);

        assert!(requires(br#"[{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t"}}]"#), "a batch");
        assert!(requires(br#"{"jsonrpc":"2.0","id":1,"method":7}"#), "a non-string method");
        assert!(requires(b"not json"), "a body that is not JSON");
        assert!(!requires(b""), "no body");
        assert!(requires(br#"{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t"}}"#));
        assert!(!requires(br#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t"}}"#));
    }
}
