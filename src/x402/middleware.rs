//! Which requests a payment policy charges (MCP tool triggers and A2A method
//! filters), and the x402 payment requirements a surface issued.

use crate::config::types::{McpPaymentTriggers, X402Config, X402PaymentRequirement};

/// The `method` of a parsed JSON-RPC request, or an empty string.
pub(crate) fn json_rpc_method(json: &serde_json::Value) -> String {
    json.get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string()
}

/// The `params.name` of a parsed JSON-RPC request.
pub(crate) fn json_rpc_tool_name(json: &serde_json::Value) -> Option<String> {
    json.get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
}

/// Whether the MCP request `method` (with the tool it names) is charged under
/// `triggers`.
pub(crate) fn mcp_tool_requires_payment(
    triggers: Option<&McpPaymentTriggers>,
    method: &str,
    tool_name: Option<&str>,
    tag: &str,
) -> bool {
    use tracing::info;

    let Some(triggers) = triggers else {
        info!("[{tag}] MCP payment NOT required: mcp_payment_triggers not configured");
        return false;
    };
    if method != "tools/call" {
        info!("[{tag}] MCP method {:?} is not tools/call → no payment", crate::a2a::clip_for_log(method));
        return false;
    }
    let Some(name) = tool_name else {
        info!("[{tag}] MCP tools/call without tool name → no payment");
        return false;
    };

    let requires = triggers.requires_payment(name);
    info!("[{tag}] MCP tool {:?} triggers={triggers:?} requires_payment={requires}", crate::a2a::clip_for_log(name));
    requires
}

/// Whether an A2A/AP2 request is charged under `filters` (`parsed` is `None`
/// when the body is not JSON). With no filter, nothing is charged; a body the
/// filters cannot be matched against is charged.
pub(crate) fn a2a_requires_payment_parsed(
    filters: &[crate::config::types::A2AMethodFilter],
    body_is_empty: bool,
    parsed: Option<&serde_json::Value>,
    tag: &str,
) -> bool {
    use tracing::info;

    if filters.is_empty() {
        info!("[{tag}] A2A/AP2 payment NOT required: no method filters configured");
        return false;
    }

    let (json, method) = match (body_is_empty, parsed) {
        (true, _) => {
            info!("[{tag}] A2A/AP2 payment NOT required: empty body (no method to match filters)");
            return false;
        }
        (false, None) => {
            info!("[{tag}] A2A/AP2 payment required: body is not JSON, so method filters cannot be matched");
            return true;
        }
        (false, Some(json)) => match json
            .get("method")
            .and_then(|method| method.as_str())
        {
            Some(method) => (json, method),
            None => {
                info!("[{tag}] A2A/AP2 payment required: no string method, so method filters cannot be matched");
                return true;
            }
        },
    };
    let logged_method = crate::a2a::clip_for_log(method);

    info!("[{tag}] A2A/AP2 JSON-RPC method: {:?}", logged_method);

    // Normalize method name to support both JSON-RPC and gRPC variants
    // JSON-RPC: message/send, message/stream, tasks/cancel
    // gRPC: SendMessage, SendStreamingMessage, CancelTask
    let normalized_method = normalize_a2a_method(method);
    info!("[{tag}] A2A/AP2 normalized method: {:?}", crate::a2a::clip_for_log(&normalized_method));

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
            info!("[{tag}] A2A/AP2 payment required: method {:?} matches (no message patterns)", logged_method);
            return true;
        }

        // Check if this method has message content to match against
        let message_content = if normalized_method == "message/send" || normalized_method == "message/stream" {
            // Extract message text from params.message.parts[].text
            let content = extract_a2a_message_text(json);
            if let Some(ref text) = content {
                info!(
                    "[{tag}] A2A/AP2 extracted message content for method {:?} (length: {} chars)",
                    logged_method,
                    text.len()
                );
            } else {
                info!("[{tag}] A2A/AP2 failed to extract message content for method {:?}", logged_method);
            }
            content
        } else {
            // Other methods don't have message content to filter on
            info!(
                "[{tag}] A2A/AP2 payment required: method {:?} matches (no message content to filter)",
                logged_method
            );
            return true;
        };

        let Some(content) = message_content else {
            // No message content found, require payment to be safe
            info!("[{tag}] A2A/AP2 payment required: method {:?} matches but no message content found", logged_method);
            return true;
        };

        // Check if message content matches any pattern
        for pattern in &filter.message_patterns {
            info!("[{tag}] A2A/AP2 checking pattern '{}' against message content", pattern);
            // A pattern is literal text the message must contain.
            if content.contains(pattern.as_str()) {
                info!(
                    "[{tag}] A2A/AP2 payment required: method {:?} and message matches pattern '{}'",
                    logged_method, pattern
                );
                return true;
            }
            info!("[{tag}] A2A/AP2 pattern '{}' did NOT match message content", pattern);
        }

        info!(
            "[{tag}] A2A/AP2 payment NOT required: method {:?} matches but message doesn't match any pattern",
            logged_method
        );
        return false; // Method matches but message doesn't match any pattern
    }

    info!("[{tag}] A2A/AP2 payment NOT required: method {:?} not in configured filters", logged_method);
    false
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
mod a2a_method_gating_tests {
    use super::*;
    use crate::config::types::A2AMethodFilter;

    fn charged(
        filters: &[A2AMethodFilter],
        body: &[u8],
    ) -> bool {
        a2a_requires_payment_parsed(
            filters,
            body.is_empty(),
            serde_json::from_slice(body)
                .ok()
                .as_ref(),
            "test",
        )
    }

    fn filter(
        method: &str,
        patterns: &[&str],
    ) -> A2AMethodFilter {
        A2AMethodFilter {
            method: method.to_string(),
            message_patterns: patterns
                .iter()
                .map(|pattern| pattern.to_string())
                .collect(),
        }
    }

    fn message(
        method: &str,
        text: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {"message": {"role": "user", "parts": [{"text": text}]}}
        }))
        .unwrap()
    }

    #[test]
    fn a_filter_charges_its_method_in_either_spelling() {
        assert!(charged(&[filter("message/send", &[])], &message("SendMessage", "hello")));
        assert!(charged(&[filter("SendMessage", &[])], &message("message/send", "hello")));
        assert!(!charged(&[filter("message/send", &[])], &message("tasks/get", "hello")));
        assert!(!charged(&[], &message("message/send", "hello")), "no filter charges nothing");
    }

    #[test]
    fn an_unknown_method_matches_verbatim_only() {
        assert_eq!(normalize_a2a_method("custom/charge"), "custom/charge");
        assert!(charged(&[filter("custom/charge", &[])], &message("custom/charge", "hello")));
        assert!(!charged(&[filter("custom/charge", &[])], &message("custom/Charge", "hello")));
    }

    #[test]
    fn message_pattern_filter_handles_multibyte_message_longer_than_log_limit() {
        let filters = [filter("SendMessage", &["premium"])];
        let text = format!("a{} premium", "é".repeat(150));
        assert!(charged(&filters, &message("message/send", &text)));
        let free = format!("a{}", "é".repeat(150));
        assert!(!charged(&filters, &message("message/send", &free)));
    }

    /// A body the filters cannot be matched against is charged instead of let
    /// through free; a request without a body is still not charged.
    #[test]
    fn a2a_method_filters_charge_a_body_without_a_string_method() {
        let filters = [filter("CancelTask", &[])];
        let requires = |body: &[u8]| charged(&filters, body);

        assert!(requires(br#"[{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t"}}]"#), "a batch");
        assert!(requires(br#"{"jsonrpc":"2.0","id":1,"method":7}"#), "a non-string method");
        assert!(requires(b"not json"), "a body that is not JSON");
        assert!(!requires(b""), "no body");
        assert!(requires(br#"{"jsonrpc":"2.0","id":1,"method":"tasks/cancel","params":{"id":"t"}}"#));
        assert!(!requires(br#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t"}}"#));
    }
}
