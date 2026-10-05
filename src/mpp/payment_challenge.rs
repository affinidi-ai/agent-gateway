//! MPP payment-challenge parsing and signing (core primitives).
//!
//! These primitives parse `WWW-Authenticate: Payment` challenges and sign an
//! MPP payment proof from a wallet binding. They are consumed by the core
//! gateway-to-gateway (`fabric://`) auto-pay path (`crate::mpp::auto_pay`) and
//! are independent of any LLM-surface proxy.

use anyhow::{Context, Result};
use tracing::debug;

use crate::mpp::challenge::base64url_decode_nopad;
use crate::x402::proxy_config::WalletBinding;

/// A single parsed MPP challenge from a `WWW-Authenticate: Payment` header.
#[derive(Debug, Clone)]
pub struct ParsedChallenge {
    pub id: String,
    pub realm: String,
    pub method: String,
    pub intent: String,
    pub request: String,
    pub expires: Option<String>,
    pub digest: Option<String>,
    pub description: Option<String>,
    pub opaque: Option<String>,
}

/// Parse all `WWW-Authenticate: Payment` challenges from a response header map.
///
/// Per the spec, each header value has auth-param syntax:
/// `Payment id="...", realm="...", method="...", intent="...", request="..."`
///
/// Multiple challenges may appear as separate headers or comma-separated in one.
pub fn parse_www_authenticate_headers(headers: &reqwest::header::HeaderMap) -> Vec<ParsedChallenge> {
    let mut challenges = Vec::new();

    for value in headers.get_all("www-authenticate") {
        let Ok(s) = value.to_str() else {
            continue;
        };

        // Each "Payment ..." segment is one challenge.
        // They can be comma-separated at the top level but each starts with "Payment".
        // Split on "Payment " boundaries.
        for segment in split_payment_challenges(s) {
            if let Some(parsed) = parse_single_challenge(&segment) {
                challenges.push(parsed);
            }
        }
    }

    challenges
}

/// Split a header value into individual "Payment ..." segments.
fn split_payment_challenges(header_value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();

    // Split on "Payment " boundaries (case-sensitive per HTTP auth scheme rules).
    // Be careful not to split inside quoted strings.
    let chars = header_value
        .chars()
        .peekable();
    let mut in_quotes = false;

    for ch in chars {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
        } else if !in_quotes && current.is_empty() && ch == 'P' {
            // Check if this starts "Payment "
            current.push(ch);
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    // Each segment should start with "Payment" — filter
    segments
        .into_iter()
        .filter(|s| s.starts_with("Payment"))
        .collect()
}

/// Parse a single `Payment id="...", realm="...", ...` challenge string.
fn parse_single_challenge(segment: &str) -> Option<ParsedChallenge> {
    // Strip "Payment " prefix
    let params_str = segment.strip_prefix("Payment ")?;

    let params = parse_auth_params(params_str);

    let id = params.get("id")?.clone();
    let realm = params.get("realm")?.clone();
    let method = params.get("method")?.clone();
    let intent = params.get("intent")?.clone();
    let request = params.get("request")?.clone();

    Some(ParsedChallenge {
        id,
        realm,
        method,
        intent,
        request,
        expires: params.get("expires").cloned(),
        digest: params.get("digest").cloned(),
        description: params
            .get("description")
            .cloned(),
        opaque: params.get("opaque").cloned(),
    })
}

/// Parse auth-param pairs: `key="value", key2="value2"`
fn parse_auth_params(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut remaining = s.trim();

    while !remaining.is_empty() {
        // Skip leading commas and whitespace
        remaining = remaining.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if remaining.is_empty() {
            break;
        }

        // Find key
        let eq_pos = match remaining.find('=') {
            Some(p) => p,
            None => break,
        };
        let key = remaining[..eq_pos]
            .trim()
            .to_lowercase();
        remaining = &remaining[eq_pos + 1..];

        // Parse value (may be quoted or token)
        remaining = remaining.trim_start();
        if remaining.starts_with('"') {
            // Quoted string — find closing quote (handling escaped quotes)
            remaining = &remaining[1..]; // skip opening quote
            let mut value = String::new();
            let mut chars = remaining.chars();
            loop {
                match chars.next() {
                    Some('\\') => {
                        // Escaped character
                        if let Some(c) = chars.next() {
                            value.push(c);
                        }
                    }
                    Some('"') => break,
                    Some(c) => value.push(c),
                    None => break,
                }
            }
            remaining = chars.as_str();
            map.insert(key, value);
        } else {
            // Unquoted token — ends at comma or whitespace
            let end = remaining
                .find(|c: char| c == ',' || c.is_whitespace())
                .unwrap_or(remaining.len());
            let value = remaining[..end].to_string();
            remaining = &remaining[end..];
            map.insert(key, value);
        }
    }

    map
}

/// Decode a challenge's `request` parameter from base64url to JSON.
fn decode_challenge_request(request_b64url: &str) -> Result<serde_json::Value> {
    let bytes = base64url_decode_nopad(request_b64url).context("Invalid base64url in challenge request")?;
    serde_json::from_slice(&bytes).context("Invalid JSON in challenge request")
}

/// Sign an MPP payment proof using a wallet binding.
///
/// Uses the same signing infrastructure as x402 (EVM EIP-3009, etc.) but
/// wraps the result in an MPP-compatible JSON payload.
pub async fn sign_mpp_payment(
    private_key: &str,
    binding: &WalletBinding,
    challenge: &ParsedChallenge,
) -> Result<serde_json::Value> {
    use crate::x402::proxy_signer::PaymentSigner;

    let request_data = decode_challenge_request(&challenge.request)?;

    // Build a minimal x402-style PaymentRequired so we can reuse PaymentSigner
    // The PaymentSigner needs network, asset, amount, pay_to, scheme
    let network = request_data
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or(&binding.network);
    let currency = request_data
        .get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let amount = request_data
        .get("amount")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let recipient = request_data
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // For crypto payment methods, use the x402 signer infrastructure.
    // For methods like "card" or "stripe", we'd use a different flow.
    match challenge.method.as_str() {
        "tempo" | "crypto" | "evm" => {
            let signer = PaymentSigner::new(private_key.to_string(), binding.clone());

            // Build a minimal accept entry for the signer
            let accept = crate::config::types::X402PaymentRequirement {
                scheme: "exact".to_string(),
                network: network.to_string(),
                asset: currency.to_string(),
                amount: amount.to_string(),
                recipient_id: String::new(),
                pay_to: recipient.to_string(),
                max_timeout_seconds: 3600,
                extra: request_data
                    .get("extra")
                    .cloned(),
            };

            let payment_required = crate::x402::PaymentRequired {
                x402_version: 2,
                error: None,
                accepts: vec![accept],
                resource: crate::x402::ResourceInfo {
                    url: String::new(),
                    description: String::new(),
                    mime_type: String::new(),
                },
                extensions: None,
            };

            let payload = signer
                .sign_payment(&payment_required)
                .await
                .context("Failed to sign crypto payment")?;

            // Extract just the signing payload (not the x402 wrapper)
            Ok(serde_json::json!({
                "type": "crypto",
                "network": network,
                "from": binding.address,
                "to": recipient,
                "amount": amount,
                "currency": currency,
                "proof": payload.payload,
            }))
        }
        _ => {
            // Card/Stripe methods are handled by the caller (they don't use
            // sign_mpp_payment). Other unknown methods get a timestamped
            // reference.
            debug!("[mpp] Payment method '{}' — generic payload", challenge.method);
            Ok(serde_json::json!({
                "type": challenge.method,
                "reference": format!("mpp-{}", chrono::Utc::now().timestamp()),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_payment_challenge_with_all_params() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "www-authenticate",
            r#"Payment id="ch-1", realm="mpp", method="tempo", intent="pay", request="eyJhIjoxfQ", expires="later", digest="d1""#
                .parse()
                .unwrap(),
        );

        let challenges = parse_www_authenticate_headers(&headers);

        assert_eq!(challenges.len(), 1);
        let c = &challenges[0];
        assert_eq!(c.id, "ch-1");
        assert_eq!(c.realm, "mpp");
        assert_eq!(c.method, "tempo");
        assert_eq!(c.intent, "pay");
        assert_eq!(c.request, "eyJhIjoxfQ");
        assert_eq!(c.expires.as_deref(), Some("later"));
        assert_eq!(c.digest.as_deref(), Some("d1"));
        assert_eq!(c.description, None);
        assert_eq!(c.opaque, None);
    }

    #[test]
    fn skips_segment_missing_required_params() {
        let mut headers = reqwest::header::HeaderMap::new();
        // Missing `request` — must be dropped, not panic.
        headers.insert(
            "www-authenticate",
            r#"Payment id="ch-2", realm="mpp", method="tempo", intent="pay""#
                .parse()
                .unwrap(),
        );

        let challenges = parse_www_authenticate_headers(&headers);
        assert!(challenges.is_empty());
    }

    #[test]
    fn parses_auth_params_into_lowercased_keys() {
        let params = parse_auth_params(r#"Id="x", Realm="r", Token=abc"#);
        assert_eq!(
            params
                .get("id")
                .map(String::as_str),
            Some("x")
        );
        assert_eq!(
            params
                .get("realm")
                .map(String::as_str),
            Some("r")
        );
        assert_eq!(
            params
                .get("token")
                .map(String::as_str),
            Some("abc")
        );
    }

    #[tokio::test]
    async fn sign_mpp_payment_returns_generic_payload_for_unknown_method() {
        // A base64url-encoded `{}` request body.
        let challenge = ParsedChallenge {
            id: "ch".into(),
            realm: "mpp".into(),
            method: "card".into(),
            intent: "pay".into(),
            request: "e30".into(),
            expires: None,
            digest: None,
            description: None,
            opaque: None,
        };
        let binding = WalletBinding {
            network: "base-sepolia".into(),
            address: "0xabc".into(),
            private_key: "0xdead".into(),
            symbols: vec![],
        };

        let out = sign_mpp_payment("0xdead", &binding, &challenge)
            .await
            .expect("generic payload");
        assert_eq!(
            out.get("type")
                .and_then(|v| v.as_str()),
            Some("card")
        );
        assert!(
            out.get("reference")
                .and_then(|v| v.as_str())
                .is_some_and(|r| r.starts_with("mpp-"))
        );
    }
}
