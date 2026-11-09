//! Payment delegation: classify the answer of a remote agent-pay payment gate.
//!
//! A surface with an `agent_pay` payment policy asks a payment surface on a
//! connected agent-pay gateway, over the `fabric://` protocol, to take the
//! payment for a chargeable request. The gate's `forward-response` drives the
//! decision ([`map_delegation_response`]):
//!
//! * `2xx` — paid: proceed to this surface's own upstream with the allow-listed
//!   receipt headers.
//! * `402` — a challenge, or a refused MPP credential (a problem type such as
//!   `verification-failed` or `malformed-credential`; `payment-expired` is a
//!   fresh challenge).
//! * `400 invalid_payment` — a refused x402 credential.
//! * `202 held_for_oversight` — held for human review, with its `case_id`.
//! * `403` — `rejected_by_oversight` or `delegated_mandate_denied` is a refused
//!   payment; any other `403` is this gateway not being admitted, which is
//!   unavailable, fail closed.
//! * `409` — `idempotency_key_in_use` is a payment still in progress, to be
//!   retried; any other `409` is an idempotency conflict, rejected.
//! * `410` — an MPP session that is gone, rejected.
//! * `429` — rate limited, with `retry-after`.
//! * `503` and any other `5xx` — unconfirmed: the answer does not say whether
//!   the payment was taken (the gate treats it as unavailable when the request
//!   carried no credential, so nothing could have been taken).
//! * anything else — unavailable, fail closed.
//!
//! This module is free of transport concerns so the mapping is unit-testable
//! without a live fabric connection.

use std::collections::HashMap;

use crate::mpp::challenge::format_www_authenticate;
use crate::mpp::types::MppChallenge;

/// Response headers kept from the payment gate's success response
/// (case-insensitive match, every value kept). `payment-receipt` carries the
/// x402 `PAYMENT-RESPONSE` value or the MPP receipt.
const RECEIPT_HEADER_ALLOWLIST: &[&str] = &[
    "x-payment-response",
    "x-settlement-tx",
    "x-payment-receipt",
    "payment-receipt",
    "payment-receipt-vc-fingerprint",
    "cache-control",
    "payment-authorization",
    "payment-capture-deadline",
];

/// The `https://paymentauth.org/problems/<slug>` types agent-pay answers a
/// presented MPP credential with when it refuses it. Any other `402`, such as
/// `payment-expired`, is a fresh challenge.
const REFUSED_CREDENTIAL_PROBLEMS: &[&str] = &[
    "verification-failed",
    "payment-action-required",
    "malformed-credential",
    "invalid-challenge",
    "invalid-payload",
    "session/invalid-signature",
    "session/signer-mismatch",
    "session/amount-exceeds-deposit",
    "session/delta-too-small",
    "session/insufficient-balance",
];

/// The `409` reason of a request whose idempotency key agent-pay is still
/// working on.
const IDEMPOTENCY_KEY_IN_USE: &str = "idempotency_key_in_use";
/// The `503` reason of an agent-pay that refused to start the request.
const IDEMPOTENCY_STORE_FULL: &str = "idempotency_store_full";
/// Seconds a caller is told to wait when agent-pay sends no `retry-after`.
const IN_PROGRESS_RETRY_AFTER_SECS: u64 = 1;

/// The `403` reasons that refuse the payment itself; every other `403` refuses
/// this gateway's request (exposure, authentication, policy).
const PAYMENT_REFUSALS: &[&str] = &["rejected_by_oversight", "delegated_mandate_denied"];

/// Challenge headers relayed from the payment gate to the caller
/// (case-insensitive match). Everything else is dropped so the gate's internals
/// never leak to the caller — cookies, `authorization`, internal fabric routing
/// and credential-delegation tokens, tracing and correlation headers,
/// infrastructure fingerprints and hop-by-hop headers. `content-length` is
/// excluded because the relayed body is re-framed.
const CHALLENGE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "payment-required",
    "x-payment-required",
    "x-payment-response",
    "www-authenticate",
    "retry-after",
    "cache-control",
];

/// Decision produced by delegating payment to a remote payment gate.
#[derive(Debug, Clone, PartialEq)]
pub enum PaymentDelegationDecision {
    /// Paid — continue to this surface's own upstream.
    Proceed { receipt_headers: HashMap<String, Vec<String>> },
    /// Payment required — relay this challenge with the allow-listed headers.
    Challenge { status: u16, headers: HashMap<String, Vec<String>>, body: Vec<u8> },
    /// The presented credential was refused; any fresh challenge headers are kept.
    VerificationFailed { headers: HashMap<String, Vec<String>>, body: Vec<u8>, reason: String, detail: Option<String> },
    /// Held for human review.
    Held { case_id: String, reason: Option<String> },
    /// Rejected by a reviewer or a delegated mandate, an idempotency conflict,
    /// or a payment session that is gone.
    Rejected { status: u16, reason: String },
    /// The payment gate throttled this gateway.
    RateLimited { retry_after: Option<String> },
    /// Agent-pay is still working on a request with this idempotency key.
    InProgress { retry_after: Option<String> },
    /// The payment gate's answer does not say whether the payment was taken: it
    /// did not answer in time, its answer was unusable, or it failed after
    /// receiving a credential. Retrying the same request with the same
    /// credential is safe.
    Unconfirmed { status: u16, message: String },
    /// Fail-closed: the gate was unreachable, timed out, or failed, and nothing
    /// was taken.
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

    pub fn unconfirmed(
        status: u16,
        message: impl Into<String>,
    ) -> Self {
        PaymentDelegationDecision::Unconfirmed {
            status,
            message: message.into(),
        }
    }

    /// The decision for a request that carried no credential, where nothing
    /// could have been taken: an unconfirmed answer is plain unavailability.
    pub fn without_credential(self) -> Self {
        match self {
            PaymentDelegationDecision::Unconfirmed { status, message } => {
                PaymentDelegationDecision::Deny { status, message }
            }
            other => other,
        }
    }
}

/// Map a payment gate's fabric response (status / headers / body) to a
/// delegation decision. Pure — no transport, so it can be unit-tested directly.
pub fn map_delegation_response(
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
) -> PaymentDelegationDecision {
    let json = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let field = |name: &str| {
        json.as_ref()
            .and_then(|json| json.get(name))
            .and_then(serde_json::Value::as_str)
    };
    match status {
        200..=299 if status != 202 => PaymentDelegationDecision::Proceed {
            receipt_headers: extract_receipt_headers(&headers),
        },
        202 => match (field("status"), field("case_id").filter(|id| is_token(id))) {
            (Some("held_for_oversight"), Some(case_id)) => PaymentDelegationDecision::Held {
                case_id: case_id.to_string(),
                reason: field("reason").map(|reason| crate::a2a::clip_for_log(reason).into_owned()),
            },
            _ => PaymentDelegationDecision::unconfirmed(502, "payment gateway returned an unrecognised 202"),
        },
        402 => match field("type")
            .map(problem_slug)
            .filter(|slug| REFUSED_CREDENTIAL_PROBLEMS.contains(slug))
        {
            Some(slug) => PaymentDelegationDecision::VerificationFailed {
                headers: extract_challenge_headers(&headers),
                detail: field("detail").map(|detail| crate::a2a::clip_for_log(detail).into_owned()),
                reason: slug.replace(['-', '/'], "_"),
                body,
            },
            None => {
                let mut challenge_headers = extract_challenge_headers(&headers);
                // A challenge carried only in an MCP JSON-RPC body
                // (draft-payment-transport-mcp-00 §10) also gets the standard
                // `WWW-Authenticate: Payment` header.
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
        },
        400 if field("error") == Some("invalid_payment") => PaymentDelegationDecision::VerificationFailed {
            headers: extract_challenge_headers(&headers),
            detail: field("detail")
                .or(field("message"))
                .map(|detail| crate::a2a::clip_for_log(detail).into_owned()),
            reason: "invalid_payment".to_string(),
            body,
        },
        403 => match ["error", "status"]
            .into_iter()
            .filter_map(field)
            .find(|reason| PAYMENT_REFUSALS.contains(reason))
        {
            Some(reason) => PaymentDelegationDecision::Rejected {
                status,
                reason: reason.to_string(),
            },
            None => {
                tracing::warn!(
                    reason = %crate::a2a::clip_for_log(field("error").unwrap_or_default()),
                    "The payment gateway refused this gateway's request"
                );
                PaymentDelegationDecision::deny(502, "payment gateway refused the request")
            }
        },
        409 => {
            let reason = field("error")
                .or(field("status"))
                .filter(|reason| is_token(reason))
                .unwrap_or("idempotency_key_conflict");
            if reason == IDEMPOTENCY_KEY_IN_USE {
                PaymentDelegationDecision::InProgress {
                    retry_after: Some(
                        retry_after(&headers).unwrap_or_else(|| IN_PROGRESS_RETRY_AFTER_SECS.to_string()),
                    ),
                }
            } else {
                PaymentDelegationDecision::Rejected {
                    status,
                    reason: reason.to_string(),
                }
            }
        }
        410 => PaymentDelegationDecision::Rejected {
            status,
            reason: "payment_session_gone".to_string(),
        },
        429 => PaymentDelegationDecision::RateLimited {
            retry_after: retry_after(&headers),
        },
        404 => PaymentDelegationDecision::deny(502, "payment surface not found on the payment gateway"),
        503 if field("error") == Some(IDEMPOTENCY_STORE_FULL) => {
            PaymentDelegationDecision::deny(503, "payment gateway unavailable")
        }
        503 => PaymentDelegationDecision::unconfirmed(503, "payment gateway unavailable"),
        500..=599 => {
            PaymentDelegationDecision::unconfirmed(502, format!("payment gateway returned unexpected status {status}"))
        }
        other => PaymentDelegationDecision::deny(502, format!("payment gateway returned unexpected status {other}")),
    }
}

/// The slug of a `https://paymentauth.org/problems/<slug>` problem type.
fn problem_slug(kind: &str) -> &str {
    kind.rsplit_once("/problems/")
        .map_or(kind, |(_, slug)| slug)
}

/// A short machine-readable code: what agent-pay uses for error codes and case ids.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

/// The first `retry-after` value when it is a whole number of seconds.
pub fn retry_after(headers: &HashMap<String, Vec<String>>) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, values)| values.first())
        .map(|value| value.trim())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 10
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
        })
        .map(str::to_string)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{X402Config, X402Provider};

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
    fn a_5xx_answer_does_not_say_whether_the_payment_was_taken() {
        assert_eq!(
            map_delegation_response(500, HashMap::new(), b"boom".to_vec()),
            PaymentDelegationDecision::unconfirmed(502, "payment gateway returned unexpected status 500")
        );
        assert_eq!(
            map_delegation_response(504, HashMap::new(), Vec::new()),
            PaymentDelegationDecision::unconfirmed(502, "payment gateway returned unexpected status 504")
        );
        assert_eq!(
            map_delegation_response(418, HashMap::new(), Vec::new()),
            PaymentDelegationDecision::deny(502, "payment gateway returned unexpected status 418"),
            "a 4xx refused the request before taking anything"
        );
    }

    #[test]
    fn an_unconfirmed_decision_is_plain_unavailability_without_a_credential() {
        assert_eq!(
            PaymentDelegationDecision::unconfirmed(503, "down").without_credential(),
            PaymentDelegationDecision::deny(503, "down")
        );
        assert_eq!(
            PaymentDelegationDecision::deny(503, "down").without_credential(),
            PaymentDelegationDecision::deny(503, "down")
        );
        assert_eq!(
            PaymentDelegationDecision::RateLimited { retry_after: None }.without_credential(),
            PaymentDelegationDecision::RateLimited { retry_after: None }
        );
    }

    #[test]
    fn a_key_in_use_is_a_payment_in_progress_to_retry_and_a_conflict_is_a_rejection() {
        assert_eq!(
            map_delegation_response(409, HashMap::new(), br#"{"error":"idempotency_key_in_use"}"#.to_vec()),
            PaymentDelegationDecision::InProgress {
                retry_after: Some("1".to_string())
            }
        );
        assert_eq!(
            map_delegation_response(
                409,
                headers(&[("Retry-After", "3")]),
                br#"{"status":"idempotency_key_in_use"}"#.to_vec()
            ),
            PaymentDelegationDecision::InProgress {
                retry_after: Some("3".to_string())
            }
        );
        assert_eq!(
            map_delegation_response(409, HashMap::new(), br#"{"error":"idempotency_key_conflict"}"#.to_vec()),
            PaymentDelegationDecision::Rejected {
                status: 409,
                reason: "idempotency_key_conflict".to_string()
            }
        );
    }

    #[test]
    fn a_503_is_unconfirmed_unless_agent_pay_refused_to_start_the_request() {
        assert_eq!(
            map_delegation_response(503, HashMap::new(), br#"{"error":"payment_unavailable"}"#.to_vec()),
            PaymentDelegationDecision::unconfirmed(503, "payment gateway unavailable")
        );
        assert_eq!(
            map_delegation_response(503, HashMap::new(), br#"{"error":"idempotency_store_full"}"#.to_vec()),
            PaymentDelegationDecision::deny(503, "payment gateway unavailable")
        );
        assert_eq!(
            map_delegation_response(202, HashMap::new(), br#"{"status":"queued"}"#.to_vec()),
            PaymentDelegationDecision::unconfirmed(502, "payment gateway returned an unrecognised 202")
        );
    }

    #[test]
    fn maps_a_refused_payment_and_an_idempotency_conflict_to_rejected_with_the_gate_reason() {
        for (status, body, reason) in [
            (403, br#"{"status":"rejected_by_oversight","case_id":"c1"}"#.to_vec(), "rejected_by_oversight"),
            (403, br#"{"error":"rejected_by_oversight"}"#.to_vec(), "rejected_by_oversight"),
            (
                403,
                br#"{"error":"delegated_mandate_denied","reason":"over budget"}"#.to_vec(),
                "delegated_mandate_denied",
            ),
            (409, br#"{"error":"idempotency_key_conflict"}"#.to_vec(), "idempotency_key_conflict"),
            (409, Vec::new(), "idempotency_key_conflict"),
            (
                410,
                br#"{"type":"https://paymentauth.org/problems/session/channel-finalized"}"#.to_vec(),
                "payment_session_gone",
            ),
            (410, Vec::new(), "payment_session_gone"),
        ] {
            assert_eq!(
                map_delegation_response(status, HashMap::new(), body),
                PaymentDelegationDecision::Rejected {
                    status,
                    reason: reason.to_string()
                }
            );
        }
    }

    #[test]
    fn a_403_that_does_not_refuse_the_payment_is_unavailable_not_rejected() {
        for body in [
            br#"{"error":"Channel not exposed on this connection point","status":403}"#.to_vec(),
            br#"{"error":"Connection-point access disabled for this surface","status":403}"#.to_vec(),
            br#"{"error":"Gateway not authorized for this surface","reason":"gateway_not_authorized"}"#.to_vec(),
            br#"{"error":"Source authentication failed","status":403}"#.to_vec(),
            br#"{"error":"policy_denied"}"#.to_vec(),
            br#"{"error":"not a <token>"}"#.to_vec(),
            Vec::new(),
        ] {
            assert_eq!(
                map_delegation_response(403, headers(&[("Set-Cookie", "x")]), body.clone()),
                PaymentDelegationDecision::deny(502, "payment gateway refused the request"),
                "{}",
                String::from_utf8_lossy(&body)
            );
        }
    }

    #[test]
    fn a_refused_mpp_credential_is_a_verification_failure_with_its_fresh_challenge() {
        for (slug, reason) in [
            ("verification-failed", "verification_failed"),
            ("malformed-credential", "malformed_credential"),
            ("invalid-challenge", "invalid_challenge"),
            ("invalid-payload", "invalid_payload"),
            ("payment-action-required", "payment_action_required"),
            ("session/invalid-signature", "session_invalid_signature"),
            ("session/insufficient-balance", "session_insufficient_balance"),
        ] {
            let body = format!(r#"{{"type":"https://paymentauth.org/problems/{slug}","detail":"why"}}"#);
            let decision = map_delegation_response(
                402,
                headers(&[("www-authenticate", "Payment id=\"fresh\""), ("set-cookie", "x")]),
                body.clone().into_bytes(),
            );
            assert_eq!(
                decision,
                PaymentDelegationDecision::VerificationFailed {
                    headers: headers(&[("www-authenticate", "Payment id=\"fresh\"")]),
                    body: body.into_bytes(),
                    reason: reason.to_string(),
                    detail: Some("why".to_string()),
                },
                "{slug}"
            );
        }
    }

    #[test]
    fn an_expired_or_unknown_problem_on_a_402_is_a_fresh_challenge() {
        for slug in ["payment-expired", "some-new-problem", "session/channel-not-found-ish"] {
            let decision = map_delegation_response(
                402,
                headers(&[("www-authenticate", "Payment id=\"fresh\"")]),
                format!(r#"{{"type":"https://paymentauth.org/problems/{slug}","detail":"expired"}}"#).into_bytes(),
            );
            assert!(
                matches!(decision, PaymentDelegationDecision::Challenge { status: 402, .. }),
                "{slug}: {decision:?}"
            );
        }
    }

    #[test]
    fn maps_202_held_only_with_a_case_id() {
        assert_eq!(
            map_delegation_response(
                202,
                HashMap::new(),
                br#"{"status":"held_for_oversight","case_id":"case-1","reason":"over limit"}"#.to_vec()
            ),
            PaymentDelegationDecision::Held {
                case_id: "case-1".to_string(),
                reason: Some("over limit".to_string())
            }
        );
        for body in [br#"{"status":"held_for_oversight"}"#.to_vec(), br#"{"case_id":"case-1"}"#.to_vec(), Vec::new()] {
            assert!(matches!(
                map_delegation_response(202, HashMap::new(), body),
                PaymentDelegationDecision::Unconfirmed { status: 502, .. }
            ));
        }
    }

    #[test]
    fn maps_refused_credentials_to_verification_failed() {
        let d = map_delegation_response(
            402,
            headers(&[("www-authenticate", "Payment id=\"fresh\""), ("set-cookie", "x")]),
            br#"{"type":"https://paymentauth.org/problems/verification-failed","detail":"bad proof"}"#.to_vec(),
        );
        let PaymentDelegationDecision::VerificationFailed { headers, reason, detail, .. } = d else {
            panic!("expected VerificationFailed, got {d:?}")
        };
        assert_eq!(reason, "verification_failed");
        assert_eq!(detail.as_deref(), Some("bad proof"));
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("www-authenticate"));
        let d = map_delegation_response(400, HashMap::new(), br#"{"error":"invalid_payment"}"#.to_vec());
        assert!(
            matches!(d, PaymentDelegationDecision::VerificationFailed { ref reason, .. } if reason == "invalid_payment")
        );
        assert!(matches!(
            map_delegation_response(400, HashMap::new(), br#"{"error":"bad_request"}"#.to_vec()),
            PaymentDelegationDecision::Deny { status: 502, .. }
        ));
    }

    #[test]
    fn maps_429_503_and_404() {
        assert_eq!(
            map_delegation_response(429, headers(&[("Retry-After", "7")]), Vec::new()),
            PaymentDelegationDecision::RateLimited {
                retry_after: Some("7".to_string())
            }
        );
        assert_eq!(
            map_delegation_response(429, headers(&[("retry-after", "Wed, 21 Oct 2015 07:28:00 GMT")]), Vec::new()),
            PaymentDelegationDecision::RateLimited { retry_after: None }
        );
        assert!(matches!(
            map_delegation_response(503, HashMap::new(), Vec::new()),
            PaymentDelegationDecision::Unconfirmed { status: 503, .. }
        ));
        assert!(matches!(
            map_delegation_response(404, HashMap::new(), Vec::new()),
            PaymentDelegationDecision::Deny { status: 502, .. }
        ));
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
