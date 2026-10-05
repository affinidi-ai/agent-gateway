//! Model B payment delegation: hand the whole payment interaction to a remote
//! payment gateway over the `fabric://` protocol.
//!
//! When a surface's x402 policy sets `provider = agent_pay`, this gateway does
//! **not** run the x402 challenge / verify / settle locally. Instead every
//! inbound request is relayed to the remote payment surface
//! `fabric://{payment_gateway_id}/{payment_surface_id}`; that surface owns the
//! wallet, price, verification and immediate settlement. The delegated surface
//! may enforce either x402 or MPP (`X402Config::delegated_rail` names which,
//! for config/audit clarity only — the relay below is protocol-agnostic and
//! works for either). Its response drives the decision:
//!
//! * `2xx` — payment authorised (or the request is free) → proceed to this
//!   surface's own upstream, carrying any settlement receipt headers (every
//!   value of an allow-listed header is kept, e.g. multiple `Payment-Receipt`).
//! * `402` — payment required → relay the challenge to the caller, copying only
//!   the allow-listed challenge headers (every value kept — MPP issues one
//!   `WWW-Authenticate` per payment method).
//! * anything else / transport failure / timeout → deny (fail-closed).
//!
//! This module is intentionally free of transport concerns so the mapping is
//! unit-testable without a live fabric connection. The proxy handler performs
//! the actual `forward_via_fabric` call and feeds the raw response primitives
//! into [`map_delegation_response`].

use std::collections::HashMap;

use crate::config::types::X402Config;
use crate::mpp::challenge::format_www_authenticate;
use crate::mpp::types::MppChallenge;

/// Response headers copied from the payment gateway's success response onto the
/// caller-facing response (case-insensitive match). `payment-receipt` is MPP's
/// receipt header (`draft-httpauth-payment-00`); `x-payment-receipt` is kept for
/// any legacy delegate that used the non-standard prefix. `cache-control` is
/// relayed so a receipt marked `private` isn't cached by a shared cache.
const RECEIPT_HEADER_ALLOWLIST: &[&str] =
    &["x-payment-response", "x-settlement-tx", "x-payment-receipt", "payment-receipt", "cache-control"];

/// Challenge (402) headers relayed from the delegate payment gateway to the
/// caller (case-insensitive match). Everything else is dropped so the delegate
/// gateway's internals never leak to the caller — cookies, `authorization`,
/// internal fabric routing / credential-delegation tokens (e.g.
/// `x-transit-token`, `x-delegation-token`), tracing / correlation
/// (`traceparent`, `x-request-id`), infrastructure fingerprints (`server`,
/// `via`), and hop-by-hop headers. `content-length` is intentionally excluded
/// because the relayed body is re-framed by the response builder. `cache-control`
/// is relayed so MPP's `no-store` on a payment challenge/nonce survives the relay.
const CHALLENGE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "payment-required",
    "x-payment-required",
    "x-payment-response",
    "www-authenticate",
    "retry-after",
    "cache-control",
];

/// Decision produced by delegating payment to a remote gateway.
#[derive(Debug, Clone, PartialEq)]
pub enum PaymentDelegationDecision {
    /// Payment authorised (or free) — continue to this surface's own upstream.
    Proceed { receipt_headers: HashMap<String, Vec<String>> },
    /// Payment required — relay this challenge to the caller with only the
    /// allow-listed challenge headers.
    Challenge { status: u16, headers: HashMap<String, Vec<String>>, body: Vec<u8> },
    /// Fail-closed: the payment gateway denied, errored, or was unreachable.
    Deny { status: u16, message: String },
}

impl PaymentDelegationDecision {
    /// Convenience constructor for a fail-closed denial.
    pub fn deny(
        status: u16,
        message: impl Into<String>,
    ) -> Self {
        PaymentDelegationDecision::Deny {
            status,
            message: message.into(),
        }
    }
}

/// Map a payment gateway's fabric response (status / headers / body) to a
/// delegation decision. Pure — no transport, so it can be unit-tested directly.
pub fn map_delegation_response(
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
) -> PaymentDelegationDecision {
    match status {
        200..=299 => PaymentDelegationDecision::Proceed {
            receipt_headers: extract_receipt_headers(&headers),
        },
        402 => {
            let mut challenge_headers = extract_challenge_headers(&headers);
            // The delegate's MCP JSON-RPC transport binding (draft-payment-transport-mcp-00
            // §10) carries the challenge in the response body, not a header — synthesize
            // the standard `WWW-Authenticate: Payment` header from it so every caller sees
            // one consistent challenge shape regardless of how payment was enforced.
            if !has_www_authenticate(&challenge_headers)
                && let Some(synthesized) = synthesize_www_authenticate_from_mcp_body(&body)
            {
                challenge_headers.insert("WWW-Authenticate".to_string(), synthesized);
            }
            PaymentDelegationDecision::Challenge {
                status,
                headers: challenge_headers,
                body,
            }
        }
        other => PaymentDelegationDecision::deny(502, format!("payment gateway returned unexpected status {other}")),
    }
}

/// Copy the allow-listed receipt / settlement headers (case-insensitive on the
/// key, original casing preserved on the copied entry, every value kept).
pub fn extract_receipt_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<String, Vec<String>> {
    filter_by_allowlist(headers, RECEIPT_HEADER_ALLOWLIST)
}

/// Copy the allow-listed challenge headers (case-insensitive on the key,
/// original casing preserved on the copied entry, every value kept — e.g. MPP's
/// one `WWW-Authenticate` per payment method). See [`CHALLENGE_HEADER_ALLOWLIST`]
/// for what is dropped.
pub fn extract_challenge_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<String, Vec<String>> {
    filter_by_allowlist(headers, CHALLENGE_HEADER_ALLOWLIST)
}

/// Case-insensitive check for an already-present `WWW-Authenticate` entry.
fn has_www_authenticate(headers: &HashMap<String, Vec<String>>) -> bool {
    headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("www-authenticate"))
}

/// Synthesize `WWW-Authenticate: Payment ...` header values from a delegate's
/// MCP JSON-RPC `-32042`/`-32043` challenge body (`error.data.challenges`,
/// draft-payment-transport-mcp-00 §10) — the delegate's MCP transport carries
/// no header at all, so a caller expecting the standard HTTP challenge shape
/// (every non-delegated MPP path, MCP or not) would otherwise see nothing.
/// Returns `None` when the body isn't that shape (a malformed/non-JSON body,
/// or a body with no challenges, is left for the generic-error fallback).
fn synthesize_www_authenticate_from_mcp_body(body: &[u8]) -> Option<Vec<String>> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let challenges = json
        .get("error")?
        .get("data")?
        .get("challenges")?
        .as_array()?;
    let headers: Vec<String> = challenges
        .iter()
        .filter_map(|c| serde_json::from_value::<MppChallenge>(c.clone()).ok())
        .map(|c| format_www_authenticate(&c))
        .collect();
    (!headers.is_empty()).then_some(headers)
}

/// Case-insensitive allow-list filter: keep only headers whose lower-cased key
/// is in `allowlist`, preserving the original key casing and every value.
fn filter_by_allowlist(
    headers: &HashMap<String, Vec<String>>,
    allowlist: &[&str],
) -> HashMap<String, Vec<String>> {
    headers
        .iter()
        .filter(|(k, _)| {
            allowlist.contains(
                &k.to_ascii_lowercase()
                    .as_str(),
            )
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Validate the delegation config and build the `fabric://{gw}/{channel}`
/// target, or return a human-readable reason when it is misconfigured.
pub fn delegation_target(cfg: &X402Config) -> Result<String, String> {
    let gw = cfg
        .payment_gateway_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ch = cfg
        .payment_surface_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (gw, ch) {
        (Some(gw), Some(ch)) => Ok(format!("fabric://{gw}/{ch}")),
        _ => Err("payment delegation misconfigured: payment_gateway_id / payment_surface_id missing".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::X402Provider;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
            .collect()
    }

    fn multi_headers(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, values)| {
                (
                    k.to_string(),
                    values
                        .iter()
                        .map(|v| v.to_string())
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn maps_200_to_proceed_with_only_receipt_headers() {
        let d =
            map_delegation_response(200, headers(&[("X-Payment-Response", "abc"), ("X-Other", "y")]), b"{}".to_vec());
        match d {
            PaymentDelegationDecision::Proceed { receipt_headers } => {
                assert_eq!(receipt_headers.len(), 1);
                assert_eq!(
                    receipt_headers
                        .get("X-Payment-Response")
                        .map(Vec::as_slice),
                    Some(["abc".to_string()].as_slice())
                );
            }
            other => panic!("expected Proceed, got {other:?}"),
        }
    }

    #[test]
    fn maps_200_to_proceed_preserves_multiple_payment_receipt_values() {
        let d = map_delegation_response(
            200,
            multi_headers(&[("Payment-Receipt", &["receipt-a", "receipt-b"])]),
            b"{}".to_vec(),
        );
        match d {
            PaymentDelegationDecision::Proceed { receipt_headers } => {
                assert_eq!(
                    receipt_headers.get("Payment-Receipt"),
                    Some(&vec!["receipt-a".to_string(), "receipt-b".to_string()])
                );
            }
            other => panic!("expected Proceed, got {other:?}"),
        }
    }

    #[test]
    fn maps_402_to_challenge_with_allowlisted_headers() {
        let d = map_delegation_response(
            402,
            headers(&[
                ("WWW-Authenticate", "x402"),
                ("Content-Type", "application/json"),
                ("PAYMENT-REQUIRED", "eyJhY2NlcHRzIjpbXX0="),
                ("Set-Cookie", "sid=secret"),
                ("Authorization", "Bearer internal"),
                ("X-Transit-Token", "transit-secret"),
                ("X-Delegation-Token", "cred-secret"),
                ("Traceparent", "00-abc-def-01"),
            ]),
            b"{\"accepts\":[]}".to_vec(),
        );
        match d {
            PaymentDelegationDecision::Challenge { status, headers, body } => {
                assert_eq!(status, 402);
                assert_eq!(body, b"{\"accepts\":[]}");
                // Allow-listed payment headers pass through.
                assert_eq!(
                    headers
                        .get("WWW-Authenticate")
                        .map(Vec::as_slice),
                    Some(["x402".to_string()].as_slice())
                );
                assert_eq!(
                    headers
                        .get("Content-Type")
                        .map(Vec::as_slice),
                    Some(["application/json".to_string()].as_slice())
                );
                assert_eq!(
                    headers
                        .get("PAYMENT-REQUIRED")
                        .map(Vec::as_slice),
                    Some(["eyJhY2NlcHRzIjpbXX0=".to_string()].as_slice())
                );
                // Sensitive / internal headers are stripped.
                assert!(!headers.contains_key("Set-Cookie"));
                assert!(!headers.contains_key("Authorization"));
                assert!(!headers.contains_key("X-Transit-Token"));
                assert!(!headers.contains_key("X-Delegation-Token"));
                assert!(!headers.contains_key("Traceparent"));
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn maps_402_to_challenge_preserves_multiple_www_authenticate_values() {
        let d = map_delegation_response(
            402,
            multi_headers(&[
                ("WWW-Authenticate", &["Payment method=tempo", "Payment method=card"]),
                ("Content-Type", &["application/problem+json"]),
            ]),
            b"{\"challengeId\":\"c1\"}".to_vec(),
        );
        match d {
            PaymentDelegationDecision::Challenge { headers, .. } => {
                assert_eq!(
                    headers.get("WWW-Authenticate"),
                    Some(&vec!["Payment method=tempo".to_string(), "Payment method=card".to_string()])
                );
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn maps_200_to_proceed_relays_cache_control_receipt_header() {
        let d = map_delegation_response(
            200,
            headers(&[("Payment-Receipt", "r1"), ("Cache-Control", "private")]),
            b"{}".to_vec(),
        );
        match d {
            PaymentDelegationDecision::Proceed { receipt_headers } => {
                assert_eq!(
                    receipt_headers
                        .get("Cache-Control")
                        .map(Vec::as_slice),
                    Some(["private".to_string()].as_slice())
                );
            }
            other => panic!("expected Proceed, got {other:?}"),
        }
    }

    #[test]
    fn maps_402_to_challenge_relays_cache_control_header() {
        let d = map_delegation_response(
            402,
            headers(&[("WWW-Authenticate", "Payment"), ("Cache-Control", "no-store")]),
            b"{}".to_vec(),
        );
        match d {
            PaymentDelegationDecision::Challenge { headers, .. } => {
                assert_eq!(
                    headers
                        .get("Cache-Control")
                        .map(Vec::as_slice),
                    Some(["no-store".to_string()].as_slice())
                );
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn maps_402_to_challenge_synthesizes_www_authenticate_from_mcp_json_rpc_body() {
        // The delegate's MCP transport binding (draft-payment-transport-mcp-00)
        // carries no WWW-Authenticate header at all — only a JSON-RPC -32042 body.
        let body = br#"{
            "jsonrpc":"2.0","id":3,
            "error":{"code":-32042,"message":"Payment Required","data":{"httpStatus":402,
                "challenges":[
                    {"id":"chal-1","realm":"agentpay-mpp-local","method":"tempo","intent":"charge","request":"eyJhIjoxfQ","expires":"2026-09-03T14:04:00Z","opaque":"op-1"},
                    {"id":"chal-2","realm":"agentpay-mpp-local","method":"card","intent":"charge","request":"eyJiIjoyfQ","expires":"2026-09-03T14:04:00Z","opaque":"op-2"}
                ]}}}"#.to_vec();
        let d = map_delegation_response(402, headers(&[("Cache-Control", "no-store")]), body);
        match d {
            PaymentDelegationDecision::Challenge { headers, .. } => {
                let www = headers
                    .get("WWW-Authenticate")
                    .expect("synthesized WWW-Authenticate header");
                assert_eq!(www.len(), 2);
                assert!(www[0].contains("method=\"tempo\""));
                assert!(www[1].contains("method=\"card\""));
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn maps_402_to_challenge_does_not_override_existing_www_authenticate() {
        let body = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32042,"data":{"challenges":[
            {"id":"chal-1","realm":"r","method":"tempo","intent":"charge","request":"eyJhIjoxfQ"}
        ]}}}"#
            .to_vec();
        let d = map_delegation_response(402, headers(&[("WWW-Authenticate", "Payment id=\"header-one\"")]), body);
        match d {
            PaymentDelegationDecision::Challenge { headers, .. } => {
                let www = headers
                    .get("WWW-Authenticate")
                    .expect("header preserved");
                assert_eq!(www, &vec!["Payment id=\"header-one\"".to_string()]);
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn maps_402_to_challenge_leaves_non_mcp_body_unsynthesized() {
        let d = map_delegation_response(
            402,
            headers(&[("Content-Type", "application/json")]),
            b"{\"accepts\":[]}".to_vec(),
        );
        match d {
            PaymentDelegationDecision::Challenge { headers, .. } => {
                assert!(!headers.contains_key("WWW-Authenticate"));
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn maps_500_to_fail_closed_502() {
        let d = map_delegation_response(500, HashMap::new(), b"boom".to_vec());
        assert!(matches!(d, PaymentDelegationDecision::Deny { status: 502, .. }));
    }

    #[test]
    fn maps_403_to_fail_closed_502() {
        let d = map_delegation_response(403, HashMap::new(), Vec::new());
        assert!(matches!(d, PaymentDelegationDecision::Deny { status: 502, .. }));
    }

    #[test]
    fn missing_delegation_config_is_rejected() {
        let cfg = X402Config {
            provider: X402Provider::AgentPay,
            ..Default::default()
        };
        assert!(delegation_target(&cfg).is_err());
    }

    #[test]
    fn blank_surface_is_rejected() {
        let cfg = X402Config {
            provider: X402Provider::AgentPay,
            payment_gateway_id: Some("gw-1".into()),
            payment_surface_id: Some("   ".into()),
            ..Default::default()
        };
        assert!(delegation_target(&cfg).is_err());
    }

    #[test]
    fn valid_delegation_config_builds_fabric_target() {
        let cfg = X402Config {
            provider: X402Provider::AgentPay,
            payment_gateway_id: Some("gw-1".into()),
            payment_surface_id: Some("pay-ch".into()),
            ..Default::default()
        };
        assert_eq!(delegation_target(&cfg).unwrap(), "fabric://gw-1/pay-ch");
    }

    #[test]
    fn local_provider_omitted_from_serialized_config() {
        let v = serde_json::to_value(X402Config::default()).unwrap();
        assert!(v.get("provider").is_none(), "Local provider must be omitted for byte-compat");
        assert!(
            v.get("payment_gateway_id")
                .is_none()
        );
        assert!(
            v.get("payment_surface_id")
                .is_none()
        );
    }

    #[test]
    fn agent_pay_provider_round_trips() {
        let cfg = X402Config {
            provider: X402Provider::AgentPay,
            payment_gateway_id: Some("gw-1".into()),
            payment_surface_id: Some("pay-ch".into()),
            ..Default::default()
        };
        let v = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            v.get("provider")
                .and_then(|p| p.as_str()),
            Some("agent_pay")
        );
        let back: X402Config = serde_json::from_value(v).unwrap();
        assert_eq!(back.provider, X402Provider::AgentPay);
        assert_eq!(
            back.payment_gateway_id
                .as_deref(),
            Some("gw-1")
        );
        assert_eq!(
            back.payment_surface_id
                .as_deref(),
            Some("pay-ch")
        );
    }

    #[test]
    fn x402_delegated_rail_omitted_from_serialized_config() {
        let v = serde_json::to_value(X402Config::default()).unwrap();
        assert!(
            v.get("delegated_rail")
                .is_none(),
            "X402 rail (default) must be omitted for byte-compat"
        );
    }

    #[test]
    fn mpp_delegated_rail_round_trips() {
        let cfg = X402Config {
            provider: X402Provider::AgentPay,
            payment_gateway_id: Some("gw-1".into()),
            payment_surface_id: Some("pay-ch".into()),
            delegated_rail: crate::config::types::DelegatedPaymentRail::Mpp,
            ..Default::default()
        };
        let v = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            v.get("delegated_rail")
                .and_then(|p| p.as_str()),
            Some("mpp")
        );
        let back: X402Config = serde_json::from_value(v).unwrap();
        assert_eq!(back.delegated_rail, crate::config::types::DelegatedPaymentRail::Mpp);
    }
}
