//! Trace-id propagation and the per-surface trace-id termination (egress
//! firewall) helpers.
//!
//! One `trace_id` correlates a request across every hop (metrics, audit, the
//! "This request" filter, and the injected VPs' `traceId`). Two pure helpers
//! govern how it flows:
//!
//! * [`continue_or_mint_trace_id`] — at a gateway's **inbound**, continue a
//!   trusted upstream trace carried in `X-Gateway-Trace-Id` (only when it parses
//!   as a UUID, so a spoofed value can't inject or poison correlation), else mint
//!   a fresh one.
//! * [`egress_trace_id`] — at a gateway's **egress**, forward the request's own
//!   trace downstream unless the surface opts into termination, in which case a
//!   fresh id crosses the boundary while this gateway keeps the incoming trace for
//!   its own VP + audit.
//!
//! [`TraceId`] reads a received trace id as the trace context requirements
//! shared with Agent Stream and Agent Watch define it. Their test vectors are
//! `tests/fixtures/trace_context/trace-context-vectors.json`.

#![cfg_attr(not(test), expect(dead_code))]

/// Why a received trace header is treated as absent. It names the header only,
/// never any part of its value, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TraceHeaderError {
    #[error("the trace id is not valid")]
    TraceId,
}

/// A trace id in its written form: 32 lowercase hexadecimal digits, not all
/// zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceId(String);

impl TraceId {
    const DIGITS: usize = 32;
    const HYPHENATED_LEN: usize = 36;

    /// Reads a received trace id: 32 hexadecimal digits in any case, or the
    /// hyphenated 8-4-4-4-12 form in any case, normalised to the written
    /// form. Any other shape, and an id of all zeros, is refused.
    pub fn parse(input: &str) -> Result<Self, TraceHeaderError> {
        let bytes = input.as_bytes();
        let hyphenated = match bytes.len() {
            Self::DIGITS => false,
            Self::HYPHENATED_LEN => true,
            _ => return Err(TraceHeaderError::TraceId),
        };
        let mut written = String::with_capacity(Self::DIGITS);
        for (position, byte) in bytes
            .iter()
            .enumerate()
        {
            if hyphenated && matches!(position, 8 | 13 | 18 | 23) {
                if *byte != b'-' {
                    return Err(TraceHeaderError::TraceId);
                }
            } else if byte.is_ascii_hexdigit() {
                written.push(char::from(byte.to_ascii_lowercase()));
            } else {
                return Err(TraceHeaderError::TraceId);
            }
        }
        if is_all_zero(written.as_bytes()) {
            return Err(TraceHeaderError::TraceId);
        }
        Ok(Self(written))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_all_zero(digits: &[u8]) -> bool {
    digits
        .iter()
        .all(|digit| *digit == b'0')
}

/// Continue a trusted upstream trace or mint a fresh one.
///
/// `incoming` is the `X-Gateway-Trace-Id` header (or fabric message `trace_id`)
/// from the previous hop. It is reused **only** when it parses as a UUID — an
/// external caller could set the header, but the UUID check blocks log/field
/// injection and a spoofed value can at worst pollute correlation (never an
/// authorization decision). Any missing or malformed value mints a fresh id, so
/// the external entry hop always starts a new trace.
pub fn continue_or_mint_trace_id(incoming: Option<&str>) -> String {
    incoming
        .and_then(|s| {
            uuid::Uuid::parse_str(s)
                .ok()
                .map(|_| s.to_string())
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Egress-firewall trace id for the onward hop.
///
/// Returns `own` (this request's trace) unchanged unless `terminate` is set, in
/// which case a **fresh** id is minted so the trace never crosses this boundary
/// to the next gateway/agent — while the gateway keeps `own` for its own VP +
/// audit (the `caller → … → here` past stays traceable).
pub fn egress_trace_id(
    terminate: bool,
    own: &str,
) -> String {
    if terminate {
        uuid::Uuid::new_v4().to_string()
    } else {
        own.to_string()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// The cases of `group` in the trace context vectors shared with the
    /// other appliances.
    fn vector_cases(group: &str) -> Vec<Value> {
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/trace_context/trace-context-vectors.json"))
                .unwrap();
        let cases = vectors["groups"][group]["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("no vector group {group}"))
            .clone();
        assert!(
            cases
                .iter()
                .any(|case| case["accepted"] == json!(true))
                && cases
                    .iter()
                    .any(|case| case["accepted"] == json!(false)),
            "{group} has accepting and refusing cases"
        );
        cases
    }

    #[test]
    fn trace_ids_parse_as_the_vectors_say() {
        for case in vector_cases("trace_id") {
            let name = &case["name"];
            let parsed = TraceId::parse(
                case["input"]
                    .as_str()
                    .unwrap(),
            );
            assert_eq!(json!(parsed.is_ok()), case["accepted"], "{name}");
            assert_eq!(
                json!(
                    parsed
                        .as_ref()
                        .ok()
                        .map(TraceId::as_str)
                ),
                case["expected"]["trace_id"],
                "{name}"
            );
        }
    }

    #[test]
    fn continue_reuses_a_valid_uuid() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(continue_or_mint_trace_id(Some(&id)), id);
    }

    #[test]
    fn continue_mints_for_non_uuid() {
        // A non-UUID header value is rejected (injection guard) and a fresh
        // UUID is minted instead of being echoed back.
        let out = continue_or_mint_trace_id(Some("not-a-uuid; DROP TABLE"));
        assert_ne!(out, "not-a-uuid; DROP TABLE");
        assert!(uuid::Uuid::parse_str(&out).is_ok());
    }

    #[test]
    fn continue_mints_for_missing_or_empty() {
        let a = continue_or_mint_trace_id(None);
        let b = continue_or_mint_trace_id(Some(""));
        assert!(uuid::Uuid::parse_str(&a).is_ok());
        assert!(uuid::Uuid::parse_str(&b).is_ok());
        // Two independent mints must differ.
        assert_ne!(a, b);
    }

    #[test]
    fn egress_passes_through_when_not_terminating() {
        let own = uuid::Uuid::new_v4().to_string();
        assert_eq!(egress_trace_id(false, &own), own);
    }

    #[test]
    fn egress_mints_a_fresh_id_when_terminating() {
        let own = uuid::Uuid::new_v4().to_string();
        let out = egress_trace_id(true, &own);
        assert_ne!(out, own, "termination must not forward the incoming trace");
        assert!(uuid::Uuid::parse_str(&out).is_ok());
    }
}
