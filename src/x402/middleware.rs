//! x402 middleware for payment processing

use axum::response::Response;
use std::sync::Arc;

use super::{PaymentPayload, PaymentRequired, create_payment_response, settle_payment, verify_payment};
use crate::config::types::{
    ChannelProtocol, McpPaymentTriggers, X402Config, X402PaymentRequirement, X402SettlementMode,
};
use crate::{channel_info, channel_warn};

/// Fallback bound applied to Immediate-mode settlement when
/// `X402Config.settlement_timeout_ms` is not configured.
const IMMEDIATE_SETTLEMENT_TIMEOUT_MS: u64 = 60_000;

/// Emit a `ChallengeIssued` payment audit event for a locally-enforced x402
/// 402 (no credential presented, so no transaction exists yet). Mirrors
/// MPP's `fire_challenge_issued_events`: captures the ambient request trace id
/// synchronously (works on both the HTTP and fabric paths, no signature
/// threading needed) and uses it as the event's `transaction_id` since there is
/// no persisted correlation id at challenge time.
fn emit_challenge_issued_audit(
    channel_name: &str,
    channel_id: &str,
) {
    use crate::delegation_vault::audit::{PaymentEventDetails, PaymentRail, PaymentStage, record_payment_event};
    let trace_id = crate::observability::policy_audit::current_span_trace_id();
    record_payment_event(
        PaymentEventDetails {
            rail: PaymentRail::X402,
            stage: PaymentStage::ChallengeIssued,
            transaction_id: trace_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            amount: None,
            currency: None,
            method: None,
            payer: None,
            error: None,
            delegated: false,
            payment_gateway_id: None,
            payment_surface_id: None,
            remote_status: None,
        },
        Some(channel_id),
        Some(channel_name),
        trace_id.as_deref(),
        false,
        None,
    );
}

/// Shared MCP payment-trigger evaluation used by both x402 and MPP
/// middlewares.
///
/// Uses the regex-based [`McpPaymentTriggers`] modes. When `triggers`
/// is `None`, no `tools/call` request is charged on this channel.
///
/// `mcp_context` lets callers avoid re-parsing the JSON-RPC body when
/// they have already done so. When absent, `body_bytes` is parsed.
/// `tag` is a short label for log lines (e.g. "x402", "mpp").
pub(crate) fn mcp_requires_payment(
    triggers: Option<&McpPaymentTriggers>,
    body_bytes: &[u8],
    mcp_context: Option<&crate::surface_context::McpContext>,
    tag: &str,
) -> bool {
    use tracing::info;

    let Some(triggers) = triggers else {
        info!("[{tag}] MCP payment NOT required: mcp_payment_triggers not configured");
        return false;
    };

    // Extract method + tool name from pre-parsed context or by parsing body.
    let (method, tool_name) = if let Some(ctx) = mcp_context {
        (ctx.method.clone(), ctx.tool_name.clone())
    } else {
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
            info!("[{tag}] MCP payment check: failed to parse body");
            return false;
        };
        let method = json
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let name = json
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .map(String::from);
        (method, name)
    };

    if method != "tools/call" {
        info!("[{tag}] MCP method '{method}' is not tools/call → no payment");
        return false;
    }
    let Some(name) = tool_name else {
        info!("[{tag}] MCP tools/call without tool name → no payment");
        return false;
    };

    let requires = triggers.requires_payment(&name);
    info!("[{tag}] MCP tool '{name}' triggers={triggers:?} requires_payment={requires}");
    requires
}

/// Check if payment is required for this specific request based on protocol-specific triggers.
///
/// `mcp_context` may be supplied by callers that have already parsed the
/// JSON-RPC envelope (e.g. the inbound proxy handler). When `Some`, the
/// MCP branch reads the method + tool_name from it directly instead of
/// re-parsing `body_bytes`. Pass `None` when no pre-parsed context is
/// available (the function then falls back to parsing `body_bytes`).
pub fn should_require_payment(
    config: &X402Config,
    protocol: &ChannelProtocol,
    body_bytes: &[u8],
    mcp_context: Option<&crate::surface_context::McpContext>,
) -> bool {
    use tracing::info;

    info!("[x402] Payment check: enabled={}, protocol={:?}", config.enabled, protocol);

    if !config.enabled {
        info!("[x402] Payment NOT required: config.enabled=false");
        return false;
    }

    // When payment is delegated to a remote payment gateway (provider != local),
    // local x402 enforcement is skipped — the delegation path forwards the whole
    // request to the payment gateway instead of running the paywall here.
    if config.provider != crate::config::types::X402Provider::Local {
        info!("[x402] Payment delegated to remote gateway; skipping local enforcement");
        return false;
    }

    match protocol {
        ChannelProtocol::Mcp => mcp_requires_payment(
            config
                .mcp_payment_triggers
                .as_ref(),
            body_bytes,
            mcp_context,
            "x402",
        ),
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => {
            // For A2A/AP2 protocols:
            // 1. Check if method filters are configured
            // 2. Parse JSON-RPC request to extract method and message content
            // 3. Match method and optionally message content patterns

            // Use new a2a_method_filters if available, otherwise fall back to legacy a2a_methods
            let method_filters = if let Some(ref filters) = config.a2a_method_filters {
                if filters.is_empty() {
                    info!("[x402] A2A/AP2 payment NOT required: a2a_method_filters is empty");
                    return false;
                }
                Some(filters)
            } else if let Some(ref methods) = config.a2a_methods {
                // Backward compatibility: convert legacy a2a_methods to filters
                if methods.is_empty() {
                    info!("[x402] A2A/AP2 payment NOT required: a2a_methods is empty");
                    return false;
                }
                info!("[x402] Using legacy a2a_methods (consider migrating to a2a_method_filters)");
                // Convert to filters without message patterns
                None // Will handle legacy path below
            } else {
                info!("[x402] A2A/AP2 payment NOT required: no method filtering configured");
                return false;
            };

            // Parse JSON-RPC request
            let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
                // If we can't parse the request and filters are configured,
                // fail open (no payment) since we can't match against any filter
                // This allows non-JSON-RPC requests (like GET requests) to pass through
                info!("[x402] A2A/AP2 payment NOT required: failed to parse body as JSON (cannot match filters)");
                return false;
            };

            let Some(method) = json
                .get("method")
                .and_then(|m| m.as_str())
            else {
                // No method field - this is not a JSON-RPC request
                info!("[x402] A2A/AP2 payment NOT required: no method field in request (cannot match filters)");
                return false;
            };

            info!("[x402] A2A/AP2 JSON-RPC method: {}", method);

            // Normalize method name to support both JSON-RPC and gRPC variants
            // JSON-RPC: message/send, message/stream, tasks/cancel
            // gRPC: SendMessage, SendStreamingMessage, CancelTask
            let normalized_method = normalize_a2a_method(method);
            info!("[x402] A2A/AP2 normalized method: {}", normalized_method);

            // Handle new method filters
            if let Some(filters) = method_filters {
                for filter in filters {
                    let filter_normalized = normalize_a2a_method(&filter.method);
                    if filter_normalized != normalized_method {
                        continue; // Method doesn't match
                    }

                    // Method matches - now check message patterns if any
                    if filter
                        .message_patterns
                        .is_empty()
                    {
                        // No patterns means match all requests for this method
                        info!("[x402] A2A/AP2 payment required: method '{}' matches (no message patterns)", method);
                        return true;
                    }

                    // Check if this method has message content to match against
                    let message_content =
                        if normalized_method == "message/send" || normalized_method == "message/stream" {
                            // Extract message text from params.message.parts[].text
                            let content = extract_a2a_message_text(&json);
                            if let Some(ref text) = content {
                                info!(
                                    "[x402] A2A/AP2 extracted message content for method '{}' (length: {} chars): '{}'",
                                    method,
                                    text.len(),
                                    truncate_at_char_boundary(text, 200)
                                );
                            } else {
                                info!("[x402] A2A/AP2 failed to extract message content for method '{}'", method);
                            }
                            content
                        } else {
                            // Other methods don't have message content to filter on
                            info!(
                                "[x402] A2A/AP2 payment required: method '{}' matches (no message content to filter)",
                                method
                            );
                            return true;
                        };

                    let Some(content) = message_content else {
                        // No message content found, require payment to be safe
                        info!(
                            "[x402] A2A/AP2 payment required: method '{}' matches but no message content found",
                            method
                        );
                        return true;
                    };

                    // Check if message content matches any pattern
                    for pattern in &filter.message_patterns {
                        info!(
                            "[x402] A2A/AP2 checking pattern '{}' against message content (first 200 chars): '{}'",
                            pattern,
                            truncate_at_char_boundary(&content, 200)
                        );
                        // Escape pattern to treat it as literal text match
                        let escaped_pattern = regex::escape(pattern);
                        match regex::Regex::new(&escaped_pattern) {
                            Ok(re) => {
                                if re.is_match(&content) {
                                    info!(
                                        "[x402] A2A/AP2 payment required: method '{}' and message matches pattern '{}'\nMessage: {}",
                                        method, pattern, content
                                    );
                                    return true;
                                } else {
                                    info!("[x402] A2A/AP2 pattern '{}' did NOT match message content", pattern);
                                }
                            }
                            Err(e) => {
                                info!(
                                    "[x402] A2A/AP2 invalid regex pattern '{}': {} (treating as non-match)",
                                    pattern, e
                                );
                            }
                        }
                    }

                    info!(
                        "[x402] A2A/AP2 payment NOT required: method '{}' matches but message doesn't match any pattern",
                        method
                    );
                    return false; // Method matches but message doesn't match any pattern
                }

                // No filter matched
                info!("[x402] A2A/AP2 payment NOT required: method '{}' not in configured filters", method);
                return false;
            }

            // Handle legacy a2a_methods
            if let Some(ref methods) = config.a2a_methods {
                let requires_payment = methods
                    .iter()
                    .any(|m| normalize_a2a_method(m) == normalized_method);
                info!(
                    "[x402] A2A/AP2 payment required={}: method '{}' (legacy mode, configured methods: {:?})",
                    requires_payment, method, methods
                );
                return requires_payment;
            }

            // Should not reach here
            false
        }
        _ => {
            // For other protocols, require payment for all requests
            true
        }
    }
}

/// Process x402 payment for a request
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn process_payment(
    payment_signature: Option<String>,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    x402_headers: &crate::config::types::X402Headers,
    resource_url: &str,
    listener_manager: Option<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>,
    transaction_store: Option<Arc<crate::x402::TransactionStore>>,
) -> Result<Option<String>, Response> {
    if !config.enabled {
        // Payments not required for this channel
        return Ok(None);
    }

    match payment_signature {
        Some(sig) => {
            // Verify the payment
            match verify_payment(
                &sig,
                config,
                channel_name,
                channel_id,
                resource_url,
                listener_manager,
                transaction_store.clone(),
                None,
            )
            .await
            {
                Ok((payload, correlation_id)) => {
                    channel_info!(
                        channel_id,
                        "Payment verified successfully correlation_id={} network={} amount={}",
                        correlation_id,
                        payload.network(),
                        payload.amount()
                    );

                    // Settlement gating is driven by X402SettlementMode — see
                    // [`dispatch_settlement`] for per-mode semantics.
                    let settled = dispatch_settlement(
                        &payload,
                        config,
                        channel_name,
                        channel_id,
                        transaction_store,
                        &correlation_id,
                    )
                    .await?;

                    // Create payment response header
                    match create_payment_response(&payload, true, settled) {
                        Ok(response_header) => Ok(Some(response_header)),
                        Err(e) => {
                            tracing::warn!(
                                channel = channel_name,
                                error = %e,
                                "Failed to create payment response"
                            );
                            Ok(None)
                        }
                    }
                }
                Err(e) => {
                    // Payment verification failed
                    Err(super::create_invalid_payment_response(&e))
                }
            }
        }
        None => {
            let payment_required = PaymentRequired {
                x402_version: 2,
                error: Some("Payment required".to_string()),
                resource: super::ResourceInfo {
                    url: resource_url.to_string(),
                    description: "Access to this resource requires payment".to_string(),
                    mime_type: "application/json".to_string(),
                },
                accepts: issued_payment_requirements(config).await,
                extensions: None,
            };

            emit_challenge_issued_audit(channel_name, channel_id);

            Err(super::create_402_response(payment_required, &x402_headers.payment_required))
        }
    }
}

/// Lowercase the asset and recipient of an EVM (`eip155:*`) requirement; EVM hex addresses are
/// case-insensitive, while Solana base58 addresses are case-sensitive and kept as configured.
pub(crate) fn normalize_requirement_addresses(requirement: &mut X402PaymentRequirement) {
    if requirement
        .network
        .starts_with("eip155:")
    {
        requirement.asset = requirement
            .asset
            .to_lowercase();
        requirement.pay_to = requirement
            .pay_to
            .to_lowercase();
    }
}

/// The surface's payment requirements as the 402 challenge issues them: EVM addresses
/// lowercased, Solana requirements given the facilitator `feePayer`, and token `decimals` and
/// `symbol` added from the x402.json token metadata.
pub(crate) async fn issued_payment_requirements(config: &X402Config) -> Vec<X402PaymentRequirement> {
    // Get global config to access facilitator addresses
    let global_config = super::config_cache::get_or_load_x402_config()
        .await
        .ok();

    // Get cached x402 metadata for token decimals and symbols
    // This is loaded at startup from x402.json
    let x402_json_config = super::config_cache::get_x402_metadata().await;

    config
        .payment_requirements
        .iter()
        .map(|req| {
            let mut normalized = req.clone();
            normalize_requirement_addresses(&mut normalized);

            // For Solana networks, add feePayer to extra field
            if normalized
                .network
                .starts_with("solana:")
                && let Some(ref global) = global_config
                && let Some(ref keys) = global.facilitator_private_keys
                && let Some(key_info) = keys.get(&normalized.network)
            {
                // Add feePayer to extra field
                let mut extra = normalized
                    .extra
                    .clone()
                    .unwrap_or_else(|| serde_json::json!({}));
                if let Some(extra_obj) = extra.as_object_mut() {
                    extra_obj.insert("feePayer".to_string(), serde_json::json!(key_info.address));
                    normalized.extra = Some(extra);
                }
            }

            // Add decimals and symbol from x402.json token configuration
            if let Some(ref x402_config) = x402_json_config {
                // Find matching network
                for x402_network in &x402_config.networks {
                    if x402_network.id == normalized.network {
                        tracing::debug!(
                            "[x402] Found matching network: {} with {} tokens",
                            x402_network.id,
                            x402_network.x402_tokens.len()
                        );
                        // Find matching token
                        for token in &x402_network.x402_tokens {
                            // Case-insensitive comparison for EVM addresses, case-sensitive for Solana
                            let addresses_match = if normalized
                                .network
                                .starts_with("eip155:")
                            {
                                token
                                    .contract_address
                                    .to_lowercase()
                                    == normalized
                                        .asset
                                        .to_lowercase()
                            } else {
                                token.contract_address == normalized.asset
                            };

                            if addresses_match {
                                tracing::info!(
                                    "[x402] Matched token {} ({}) for asset {} on network {}",
                                    token.symbol,
                                    token.contract_address,
                                    normalized.asset,
                                    normalized.network
                                );
                                let mut extra = normalized
                                    .extra
                                    .clone()
                                    .unwrap_or_else(|| serde_json::json!({}));
                                if let Some(extra_obj) = extra.as_object_mut() {
                                    extra_obj.insert("decimals".to_string(), serde_json::json!(token.decimals));
                                    extra_obj.insert("symbol".to_string(), serde_json::json!(token.symbol));
                                    normalized.extra = Some(extra);
                                    tracing::info!(
                                        "[x402] Enriched payment requirement with symbol={}, decimals={}",
                                        token.symbol,
                                        token.decimals
                                    );
                                }
                                break;
                            } else {
                                tracing::debug!(
                                    "[x402] Token {} ({}) did not match asset {}",
                                    token.symbol,
                                    token.contract_address,
                                    normalized.asset
                                );
                            }
                        }
                        break;
                    }
                }
            }

            normalized
        })
        .collect()
}

/// Run the post-verification settlement step according to
/// `config.settlement_mode`:
///
/// - `Immediate` awaits `settle_payment` inline, bounded by
///   `settlement_timeout_ms` (default [`IMMEDIATE_SETTLEMENT_TIMEOUT_MS`]).
///   Any settlement error or timeout becomes an `Err(Response)` so the
///   caller never grants on an unsettled payment.
/// - `Deferred` spawns settlement in the background and returns `Ok(false)`
///   immediately, preserving grant-before-settle latency.
/// - `None` is a no-op (verification-only mode).
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
async fn dispatch_settlement(
    payload: &PaymentPayload,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    transaction_store: Option<Arc<crate::x402::TransactionStore>>,
    correlation_id: &str,
) -> Result<bool, Response> {
    match config.settlement_mode {
        X402SettlementMode::Immediate => {
            let timeout_ms = config
                .settlement_timeout_ms
                .unwrap_or(IMMEDIATE_SETTLEMENT_TIMEOUT_MS);
            let settle_future = settle_payment(
                payload,
                config,
                channel_name,
                channel_id,
                transaction_store.as_ref(),
                None, // confirmations captured during verification
                Some(correlation_id.to_string()),
            );

            match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), settle_future).await {
                Ok(Ok(())) => Ok(true),
                Ok(Err(e)) => {
                    channel_warn!(
                        channel_id,
                        "Immediate settlement failed correlation_id={} error={}",
                        correlation_id,
                        e
                    );
                    Err(super::create_invalid_payment_response(&format!("Payment settlement failed: {e}")))
                }
                Err(_) => {
                    channel_warn!(
                        channel_id,
                        "Immediate settlement timed out after {}ms correlation_id={}",
                        timeout_ms,
                        correlation_id
                    );
                    Err(super::create_invalid_payment_response(&format!(
                        "Payment settlement timed out after {timeout_ms}ms"
                    )))
                }
            }
        }
        X402SettlementMode::Deferred => {
            let config_clone = config.clone();
            let channel_name_clone = channel_name.to_string();
            let channel_id_clone = channel_id.to_string();
            let payload_clone = payload.clone();
            let correlation_id_clone = correlation_id.to_string();
            tokio::spawn(async move {
                if let Err(e) = settle_payment(
                    &payload_clone,
                    &config_clone,
                    &channel_name_clone,
                    &channel_id_clone,
                    transaction_store.as_ref(),
                    None,
                    Some(correlation_id_clone),
                )
                .await
                {
                    channel_warn!(&channel_id_clone, "Deferred settlement failed error={}", e);
                }
            });
            Ok(false)
        }
        X402SettlementMode::None => Ok(false),
    }
}

/// Normalize A2A method names to support both JSON-RPC and gRPC variants
/// JSON-RPC: message/send, message/stream, tasks/cancel
/// gRPC: SendMessage, SendStreamingMessage, CancelTask
pub fn normalize_a2a_method(method: &str) -> String {
    // Delegate to the shared A2A method table so this covers the full v1.0 method
    // set (tasks/list, the push-notification-config methods, extended card, …) and
    // stays in sync with method recognition elsewhere. The canonical form is the
    // v0.3 slash-form. This is internal gating only; it does not change the method
    // exposed to policy, which stays exactly as the caller sent it.
    crate::a2a::canonical_method(method).to_string()
}

/// Longest prefix of `text` that is at most `max_bytes` long and ends on a char boundary.
fn truncate_at_char_boundary(
    text: &str,
    max_bytes: usize,
) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let end = (0..=max_bytes)
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0);
    &text[..end]
}

/// Extract message text content from A2A SendMessage/SendStreamingMessage request
/// Returns combined text from all message parts
pub fn extract_a2a_message_text(json: &serde_json::Value) -> Option<String> {
    // A2A request structure:
    // {
    //   "method": "SendMessage",
    //   "params": {
    //     "message": {
    //       "role": "ROLE_USER",
    //       "parts": [
    //         {"text": "some content"},
    //         {"url": "..."},
    //         ...
    //       ]
    //     }
    //   }
    // }

    let params = json.get("params")?;
    let message = params.get("message")?;
    let parts = message
        .get("parts")?
        .as_array()?;

    let mut text_parts = Vec::new();
    for part in parts {
        if let Some(text) = part
            .get("text")
            .and_then(|t| t.as_str())
        {
            text_parts.push(text);
        }
    }

    if text_parts.is_empty() {
        None
    } else {
        Some(text_parts.join(" "))
    }
}

#[cfg(test)]
mod settlement_gating_tests {
    use super::*;
    use crate::config::types::{X402Headers, X402SettlementMode, X402VerificationMode};
    use crate::x402::{PaymentResponse, TransactionStore, config_cache};
    use base64::Engine;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn configured_requirement() -> X402PaymentRequirement {
        X402PaymentRequirement {
            scheme: "exact".to_string(),
            network: "eip155:1".to_string(),
            amount: "1000".to_string(),
            asset: "0x123".to_string(),
            recipient_id: String::new(),
            pay_to: "0x456".to_string(),
            max_timeout_seconds: 300,
            extra: None,
        }
    }

    fn payment_header(nonce_suffix: &str) -> String {
        payment_header_paying("0x456", nonce_suffix)
    }

    fn payment_header_paying(
        pay_to: &str,
        nonce_suffix: &str,
    ) -> String {
        let payload_json = format!(
            r#"{{
                "x402Version": 2,
                "resource": {{"url": "/test", "description": "test", "mimeType": "application/json"}},
                "accepted": {{
                    "scheme": "exact",
                    "network": "eip155:1",
                    "amount": "1000",
                    "asset": "0x123",
                    "payTo": "{pay_to}",
                    "maxTimeoutSeconds": 300
                }},
                "payload": {{
                    "authorization": {{
                        "from": "0xabc",
                        "to": "{pay_to}",
                        "value": "1000",
                        "validAfter": "0",
                        "validBefore": "999999999",
                        "nonce": "0x{nonce_suffix}"
                    }},
                    "signature": "0xsig"
                }}
            }}"#
        );

        base64::engine::general_purpose::STANDARD.encode(payload_json.as_bytes())
    }

    fn decode_payment_response(header: &str) -> PaymentResponse {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header)
            .expect("PAYMENT-RESPONSE must be base64 encoded");
        serde_json::from_slice(&decoded).expect("PAYMENT-RESPONSE must decode to JSON")
    }

    fn assert_payment_response(
        header: &str,
        verified: bool,
        settled: bool,
    ) {
        let response = decode_payment_response(header);

        assert_eq!(response.verified, verified, "unexpected verified flag");
        assert_eq!(response.settled, settled, "unexpected settled flag");
    }

    #[tokio::test]
    async fn immediate_mode_rejects_grant_when_settlement_fails() {
        config_cache::clear_x402_config_cache().await;

        let tmp = tempdir().unwrap();
        let store = Arc::new(
            TransactionStore::new(tmp.path().to_path_buf())
                .await
                .unwrap(),
        );
        let config = X402Config {
            verification_mode: X402VerificationMode::Mock,
            settlement_mode: X402SettlementMode::Immediate,
            facilitator_private_keys: None,
            payment_requirements: vec![configured_requirement()],
            ..Default::default()
        };
        let headers = X402Headers::default();

        let result = process_payment(
            Some(payment_header("aa")),
            &config,
            "Test Channel",
            "channel-immediate-fail",
            &headers,
            "/test",
            None,
            Some(store),
        )
        .await;

        assert!(
            result.is_err(),
            "expected Err(Response) when immediate settlement fails, got Ok({:?})",
            result.ok().flatten()
        );
    }

    #[tokio::test]
    async fn deferred_mode_grants_synchronously_after_verification() {
        let tmp = tempdir().unwrap();
        let store = Arc::new(
            TransactionStore::new(tmp.path().to_path_buf())
                .await
                .unwrap(),
        );
        let config = X402Config {
            verification_mode: X402VerificationMode::Mock,
            settlement_mode: X402SettlementMode::Deferred,
            payment_requirements: vec![configured_requirement()],
            ..Default::default()
        };
        let headers = X402Headers::default();

        let result = process_payment(
            Some(payment_header("bb")),
            &config,
            "Test Channel",
            "channel-deferred",
            &headers,
            "/test",
            None,
            Some(store),
        )
        .await;

        let header = result
            .expect("deferred mode must grant after verification")
            .expect("expected PAYMENT-RESPONSE header in deferred mode");
        assert_payment_response(&header, true, false);
    }

    #[tokio::test]
    async fn none_mode_grants_without_attempting_settlement() {
        let tmp = tempdir().unwrap();
        let store = Arc::new(
            TransactionStore::new(tmp.path().to_path_buf())
                .await
                .unwrap(),
        );
        let config = X402Config {
            verification_mode: X402VerificationMode::Mock,
            settlement_mode: X402SettlementMode::None,
            payment_requirements: vec![configured_requirement()],
            ..Default::default()
        };
        let headers = X402Headers::default();

        let result = process_payment(
            Some(payment_header("cc")),
            &config,
            "Test Channel",
            "channel-none",
            &headers,
            "/test",
            None,
            Some(store),
        )
        .await;

        let header = result
            .expect("none mode must grant after verification")
            .expect("expected PAYMENT-RESPONSE header in none mode");
        assert_payment_response(&header, true, false);
    }

    #[tokio::test]
    async fn rejects_payment_to_a_recipient_the_surface_did_not_issue() {
        let tmp = tempdir().unwrap();
        let store = Arc::new(
            TransactionStore::new(tmp.path().to_path_buf())
                .await
                .unwrap(),
        );
        let config = X402Config {
            verification_mode: X402VerificationMode::Mock,
            settlement_mode: X402SettlementMode::Deferred,
            payment_requirements: vec![configured_requirement()],
            ..Default::default()
        };

        let result = process_payment(
            Some(payment_header_paying("0xbad", "dd")),
            &config,
            "Test Channel",
            "channel-self-payment",
            &X402Headers::default(),
            "/test",
            None,
            Some(Arc::clone(&store)),
        )
        .await;

        let response = result.expect_err("self-payment must not be granted");
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "error": "invalid_payment",
                "message": "Payment does not match any payment requirement issued for this resource"
            })
        );
        let transactions = store.list_all().await;
        assert_eq!(transactions.len(), 1);
        assert!(
            transactions[0]
                .settlement
                .is_none(),
            "settlement must not start"
        );
    }
}

#[cfg(test)]
mod a2a_method_gating_tests {
    use super::*;
    use crate::config::types::A2AMethodFilter;

    fn legacy_config(methods: &[&str]) -> X402Config {
        X402Config {
            a2a_methods: Some(
                methods
                    .iter()
                    .map(|m| m.to_string())
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn a2a_body(method: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {"message": {"role": "user", "parts": [{"text": "hello"}]}}
        }))
        .unwrap()
    }

    fn requires(
        config: &X402Config,
        method: &str,
    ) -> bool {
        should_require_payment(config, &ChannelProtocol::A2a, &a2a_body(method), None)
    }

    #[test]
    fn legacy_slash_form_config_charges_pascal_case_caller() {
        assert!(requires(&legacy_config(&["message/send"]), "SendMessage"));
    }

    #[test]
    fn legacy_pascal_case_config_charges_slash_form_caller() {
        assert!(requires(&legacy_config(&["SendMessage"]), "message/send"));
    }

    #[test]
    fn legacy_config_still_charges_identical_spelling() {
        assert!(requires(&legacy_config(&["message/send"]), "message/send"));
        assert!(requires(&legacy_config(&["SendMessage"]), "SendMessage"));
    }

    #[test]
    fn legacy_config_does_not_charge_unlisted_method_in_either_spelling() {
        let config = legacy_config(&["message/send"]);
        assert!(!requires(&config, "tasks/get"));
        assert!(!requires(&config, "GetTask"));
    }

    #[test]
    fn legacy_config_matches_unknown_method_verbatim_only() {
        assert_eq!(normalize_a2a_method("custom/charge"), "custom/charge");
        let config = legacy_config(&["custom/charge"]);
        assert!(requires(&config, "custom/charge"));
        assert!(!requires(&config, "custom/Charge"));
        assert!(!requires(&config, "message/send"));
    }

    #[test]
    fn truncate_at_char_boundary_backs_off_inside_multibyte_char() {
        let text = format!("a{}", "é".repeat(150));
        assert!(!text.is_char_boundary(200));
        let truncated = truncate_at_char_boundary(&text, 200);
        assert_eq!(truncated.len(), 199);
        assert_eq!(truncated, format!("a{}", "é".repeat(99)));
    }

    #[test]
    fn truncate_at_char_boundary_returns_short_text_unchanged() {
        assert_eq!(truncate_at_char_boundary("héllo", 200), "héllo");
        assert_eq!(truncate_at_char_boundary("", 200), "");
    }

    #[test]
    fn message_pattern_filter_handles_multibyte_message_longer_than_log_limit() {
        let config = X402Config {
            a2a_method_filters: Some(vec![A2AMethodFilter {
                method: "SendMessage".to_string(),
                message_patterns: vec!["premium".to_string()],
            }]),
            ..Default::default()
        };
        let text = format!("a{} premium", "é".repeat(150));
        let body = |text: &str| {
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {"message": {"role": "user", "parts": [{"text": text}]}}
            }))
            .unwrap()
        };
        assert!(should_require_payment(&config, &ChannelProtocol::A2a, &body(&text), None));
        let free = format!("a{}", "é".repeat(150));
        assert!(!should_require_payment(&config, &ChannelProtocol::A2a, &body(&free), None));
    }
}
