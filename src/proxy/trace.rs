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
//! [`TraceId`], [`SpanId`] and [`Traceparent`] read a received trace id, span
//! id and `traceparent` header as the trace context requirements shared with
//! Agent Stream and Agent Watch define them. Their test vectors are
//! `tests/fixtures/trace_context/trace-context-vectors.json`. A value that is
//! not valid is refused whole, and its [`TraceHeaderError`] carries no part of
//! it.

#![cfg_attr(not(test), expect(dead_code))]

/// Why a received trace header is treated as absent. It names the header only,
/// never any part of its value, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TraceHeaderError {
    #[error("the trace id is not valid")]
    TraceId,
    #[error("the span id is not valid")]
    SpanId,
    #[error("the traceparent is not valid")]
    Traceparent,
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

/// A span id: 16 lowercase hexadecimal digits, not all zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanId(String);

impl SpanId {
    const DIGITS: usize = 16;

    pub fn parse(input: &str) -> Result<Self, TraceHeaderError> {
        written_id(input.as_bytes(), Self::DIGITS)
            .map(Self)
            .ok_or(TraceHeaderError::SpanId)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The flags of a received `traceparent`. Only the sampled bit is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceFlags(u8);

impl TraceFlags {
    const SAMPLED: u8 = 0x01;

    pub fn is_sampled(self) -> bool {
        self.0 & Self::SAMPLED != 0
    }
}

impl std::fmt::Display for TraceFlags {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(formatter, "{:02x}", self.0)
    }
}

/// A valid received `traceparent` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traceparent {
    pub trace_id: TraceId,
    pub parent_span_id: SpanId,
    pub flags: TraceFlags,
}

impl Traceparent {
    const VERSION_00_LEN: usize = 55;

    /// Reads a received `traceparent` as W3C Trace Context defines it. Version
    /// `00` is the fixed 55 character format. A version from `01` to `fe` is
    /// read up to its flags, which end the header or are followed by a
    /// hyphen; nothing after them is read. Version `ff`, upper-case digits and
    /// an id of all zeros are refused.
    pub fn parse(input: &str) -> Result<Self, TraceHeaderError> {
        Self::read(input.as_bytes()).ok_or(TraceHeaderError::Traceparent)
    }

    fn read(header: &[u8]) -> Option<Self> {
        let version = header.get(..2)?;
        if !is_lowercase_hex(version) || version == b"ff" {
            return None;
        }
        let fixed_format = version == b"00";
        if fixed_format && header.len() != Self::VERSION_00_LEN {
            return None;
        }
        let separated = [2, 35, 52]
            .iter()
            .all(|position| header.get(*position) == Some(&b'-'));
        let ends_after_flags = match header.get(Self::VERSION_00_LEN) {
            None => true,
            Some(next) => !fixed_format && *next == b'-',
        };
        if !separated || !ends_after_flags {
            return None;
        }
        Some(Self {
            trace_id: written_id(header.get(3..35)?, TraceId::DIGITS).map(TraceId)?,
            parent_span_id: written_id(header.get(36..52)?, SpanId::DIGITS).map(SpanId)?,
            flags: hex_byte(header.get(53..55)?).map(TraceFlags)?,
        })
    }
}

fn is_all_zero(digits: &[u8]) -> bool {
    digits
        .iter()
        .all(|digit| *digit == b'0')
}

fn is_lowercase_hex(digits: &[u8]) -> bool {
    digits
        .iter()
        .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
}

/// `digits` as text when they are exactly `len` lowercase hexadecimal digits,
/// not all zero.
fn written_id(
    digits: &[u8],
    len: usize,
) -> Option<String> {
    (digits.len() == len && is_lowercase_hex(digits) && !is_all_zero(digits)).then(|| {
        digits
            .iter()
            .map(|digit| char::from(*digit))
            .collect()
    })
}

/// The value of two lowercase hexadecimal digits.
fn hex_byte(digits: &[u8]) -> Option<u8> {
    if digits.len() != 2 || !is_lowercase_hex(digits) {
        return None;
    }
    let text = std::str::from_utf8(digits).ok()?;
    u8::from_str_radix(text, 16).ok()
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
    fn span_ids_parse_as_the_vectors_say() {
        for case in vector_cases("span_id") {
            let name = &case["name"];
            let parsed = SpanId::parse(
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
                        .map(SpanId::as_str)
                ),
                case["expected"]["span_id"],
                "{name}"
            );
        }
    }

    #[test]
    fn traceparents_parse_as_the_vectors_say() {
        for case in vector_cases("traceparent_parse") {
            let name = &case["name"];
            let parsed = Traceparent::parse(
                case["input"]
                    .as_str()
                    .unwrap(),
            );
            assert_eq!(json!(parsed.is_ok()), case["accepted"], "{name}");
            let read = match &parsed {
                Ok(traceparent) => json!({
                    "trace_id": traceparent.trace_id.as_str(),
                    "parent_span_id": traceparent.parent_span_id.as_str(),
                    "flags": traceparent.flags.to_string(),
                    "sampled": traceparent.flags.is_sampled(),
                }),
                Err(error) => {
                    assert_eq!(*error, TraceHeaderError::Traceparent, "{name}");
                    json!({"trace_id": null, "parent_span_id": null, "flags": null, "sampled": null})
                }
            };
            assert_eq!(read, case["expected"], "{name}");
        }
    }

    #[test]
    fn a_refused_trace_header_is_described_without_its_value() {
        let sent = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01";
        for error in [
            TraceId::parse(sent).unwrap_err(),
            SpanId::parse(sent).unwrap_err(),
            Traceparent::parse(sent).unwrap_err(),
        ] {
            let described = format!("{error} {error:?}");
            assert!(!described.contains("4BF9") && !described.contains("00f0"), "{described}");
        }
    }

    #[test]
    fn no_input_makes_a_trace_header_parser_panic() {
        let valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut inputs: Vec<String> = (0..=valid.len())
            .map(|end| valid[..end].to_string())
            .collect();
        inputs.extend(
            ["é", "\u{0}", "-", "--", "00-", "ｆｆ", "4bf92f3577b34da6a3ce929d0e0e473é", "00f067aa0ba902bé"]
                .map(str::to_string),
        );
        inputs.push("é".repeat(55));
        inputs.push(format!("{valid}é"));
        inputs.push(valid.replace('-', "é"));
        inputs.push("0".repeat(100_000));
        for input in inputs {
            let _ = TraceId::parse(&input);
            let _ = SpanId::parse(&input);
            let _ = Traceparent::parse(&input);
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
