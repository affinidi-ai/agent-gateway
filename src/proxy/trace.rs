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
//! Both mint with [`TraceId::mint`]: 32 lowercase hexadecimal digits, the W3C
//! Trace Context form.
//!
//! [`TraceId`], [`SpanId`] and [`Traceparent`] read a received trace id, span
//! id and `traceparent` header as the trace context requirements shared with
//! Agent Stream and Agent Watch define them. Their test vectors are
//! `tests/fixtures/trace_context/trace-context-vectors.json`. A value that is
//! not valid is refused whole, and its [`TraceHeaderError`] carries no part of
//! it.
//!
//! [`RequestTrace`] is one request's trace context: the trace it continues or
//! starts, this gateway's span, the parent span and where the trace id came
//! from. [`OutgoingTrace`] writes the `traceparent`, the trace id and the
//! `tracestate` a request is sent onward with.

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
        for (position, byte) in bytes.iter().enumerate() {
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

    /// Reads a trace id that must already be in its written form.
    pub fn from_written(input: &str) -> Result<Self, TraceHeaderError> {
        written_id(input.as_bytes(), Self::DIGITS)
            .map(Self)
            .ok_or(TraceHeaderError::TraceId)
    }

    /// A new trace id: a random version 4 UUID written without hyphens, so it
    /// is never all zero and still reads as a UUID.
    pub fn mint() -> Self {
        Self(
            uuid::Uuid::new_v4()
                .simple()
                .to_string(),
        )
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

/// Where a request's trace id came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceSource {
    /// A verified transit token.
    TransitToken,
    /// `traceparent` or `X-Gateway-Trace-Id`.
    Header,
    /// This gateway started the trace.
    Minted,
}

impl TraceSource {
    pub const ALL: [Self; 3] = [Self::TransitToken, Self::Header, Self::Minted];

    /// The value written in a record's `trace_source`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransitToken => "transit_token",
            Self::Header => "header",
            Self::Minted => "minted",
        }
    }
}

/// A valid `traceparent` and a valid `X-Gateway-Trace-Id` that arrived
/// together and name different traces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceDisagreement {
    pub traceparent_trace_id: TraceId,
    pub x_gateway_trace_id: TraceId,
}

/// Whether this gateway exports the request's span, which decides the sampled
/// flag it sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanExport {
    Off,
    On { sampled: bool },
}

/// One request's trace context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTrace {
    pub trace_id: TraceId,
    /// This gateway's span for the request.
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub trace_source: TraceSource,
    /// The flags of the `traceparent` whose trace the request continues.
    continued_flags: Option<TraceFlags>,
}

impl RequestTrace {
    /// The trace a request continues or starts, from the `traceparent` and
    /// `X-Gateway-Trace-Id` it arrived with and this gateway's span for it.
    ///
    /// A header that is not valid is treated as absent. A `traceparent` alone,
    /// or one naming the same trace as `X-Gateway-Trace-Id`, is continued with
    /// its span as the parent. `X-Gateway-Trace-Id` alone is continued with no
    /// parent. When both are valid and name different traces,
    /// `X-Gateway-Trace-Id` wins with no parent, and the two ids are returned
    /// for the caller to warn about. With neither, a trace id is minted.
    pub fn from_headers(
        traceparent: Option<&str>,
        x_gateway_trace_id: Option<&str>,
        span_id: SpanId,
    ) -> (Self, Option<TraceDisagreement>) {
        let traceparent = traceparent.and_then(|header| valid_header(Traceparent::parse(header)));
        let named = x_gateway_trace_id.and_then(|header| valid_header(TraceId::parse(header)));
        let unparented = |trace_id, trace_source| Self {
            trace_id,
            span_id: span_id.clone(),
            parent_span_id: None,
            trace_source,
            continued_flags: None,
        };
        match (traceparent, named) {
            (Some(traceparent), Some(named)) if traceparent.trace_id != named => {
                let disagreement = TraceDisagreement {
                    traceparent_trace_id: traceparent.trace_id,
                    x_gateway_trace_id: named.clone(),
                };
                (unparented(named, TraceSource::Header), Some(disagreement))
            }
            (Some(traceparent), _) => {
                let continued = Self {
                    trace_id: traceparent.trace_id,
                    span_id,
                    parent_span_id: Some(traceparent.parent_span_id),
                    trace_source: TraceSource::Header,
                    continued_flags: Some(traceparent.flags),
                };
                (continued, None)
            }
            (None, Some(named)) => (unparented(named, TraceSource::Header), None),
            (None, None) => (unparented(TraceId::mint(), TraceSource::Minted), None),
        }
    }

    /// The request's own trace, sent onward under this gateway's span.
    pub fn outgoing(&self) -> OutgoingTrace {
        OutgoingTrace {
            trace_id: self.trace_id.clone(),
            span_id: self.span_id.clone(),
            continued_flags: self.continued_flags,
        }
    }

    /// The trace `fresh`, sent onward in place of the request's own under this
    /// gateway's span. It continues no `traceparent`.
    pub fn terminated(
        &self,
        fresh: TraceId,
    ) -> OutgoingTrace {
        OutgoingTrace {
            trace_id: fresh,
            span_id: self.span_id.clone(),
            continued_flags: None,
        }
    }
}

/// The trace context a request is sent onward with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingTrace {
    trace_id: TraceId,
    span_id: SpanId,
    continued_flags: Option<TraceFlags>,
}

impl OutgoingTrace {
    /// The trace id sent in `X-Gateway-Trace-Id` and in the transit token.
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// The `traceparent` to send: version `00`, the trace id, this gateway's
    /// span and the sampled flag alone. The flag is the sampler's decision
    /// when the span is exported, else the sampled bit of the continued
    /// `traceparent`, else unset.
    pub fn traceparent(
        &self,
        export: SpanExport,
    ) -> String {
        let sampled = match export {
            SpanExport::On { sampled } => sampled,
            SpanExport::Off => self
                .continued_flags
                .is_some_and(TraceFlags::is_sampled),
        };
        format!("00-{}-{}-{:02x}", self.trace_id.as_str(), self.span_id.as_str(), u8::from(sampled))
    }

    /// The `tracestate` to send: the received one, unchanged, only when the
    /// trace of a received `traceparent` is continued.
    pub fn tracestate<T>(
        &self,
        received: Option<T>,
    ) -> Option<T> {
        received.filter(|_| self.continued_flags.is_some())
    }
}

/// `parsed` when it is valid. A header that is not is treated as absent, and
/// the log line carries no part of it.
fn valid_header<T>(parsed: Result<T, TraceHeaderError>) -> Option<T> {
    parsed
        .inspect_err(|error| tracing::debug!(%error, "Ignoring a trace header that is not valid"))
        .ok()
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
        .unwrap_or_else(|| TraceId::mint().0)
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
        TraceId::mint().0
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
        for error in
            [TraceId::parse(sent).unwrap_err(), SpanId::parse(sent).unwrap_err(), Traceparent::parse(sent).unwrap_err()]
        {
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
            let _ = RequestTrace::from_headers(Some(&input), Some(&input), own_span());
        }
    }

    fn own_span() -> SpanId {
        SpanId::parse("53995c3f42cd8ad8").unwrap()
    }

    fn flags(value: &Value) -> Option<TraceFlags> {
        value
            .as_str()
            .map(|digits| TraceFlags(hex_byte(digits.as_bytes()).unwrap()))
    }

    fn export(input: &Value) -> SpanExport {
        if input["exports_spans"] == json!(true) {
            SpanExport::On {
                sampled: input["span_sampled"] == json!(true),
            }
        } else {
            SpanExport::Off
        }
    }

    /// The flags field of a composed `traceparent`.
    fn sent_flags(traceparent: &str) -> Option<&str> {
        traceparent.get(53..)
    }

    #[test]
    fn outgoing_traceparent_names_the_span_and_flags() {
        for case in vector_cases("traceparent_compose") {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            let trace_id = TraceId::from_written(
                input["trace_id"]
                    .as_str()
                    .unwrap(),
            );
            let span_id = SpanId::parse(
                input["span_id"]
                    .as_str()
                    .unwrap(),
            );
            let composed = trace_id
                .ok()
                .zip(span_id.ok())
                .map(|(trace_id, span_id)| {
                    OutgoingTrace {
                        trace_id,
                        span_id,
                        continued_flags: flags(&input["continued_flags"]),
                    }
                    .traceparent(export(input))
                });
            assert_eq!(json!(composed.is_some()), case["accepted"], "{name}");
            assert_eq!(json!(composed), expected["traceparent"], "{name}");
            assert_eq!(
                json!(
                    composed
                        .as_deref()
                        .and_then(sent_flags)
                ),
                expected["flags"],
                "{name}"
            );
        }
    }

    #[test]
    fn tracestate_is_kept_only_when_a_traceparent_is_continued() {
        for case in vector_cases("tracestate_and_flags") {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            let continued_flags = flags(&input["continued_flags"]);
            assert_eq!(json!(continued_flags.is_some()), input["continued"], "{name}");
            assert_eq!(input["continued"], case["accepted"], "{name}");
            let outgoing = OutgoingTrace {
                trace_id: TraceId::mint(),
                span_id: own_span(),
                continued_flags,
            };
            assert_eq!(json!(outgoing.tracestate(input["tracestate"].as_str())), expected["tracestate"], "{name}");
            assert_eq!(json!(sent_flags(&outgoing.traceparent(export(input)))), expected["flags"], "{name}");
        }
    }

    #[test]
    fn incoming_trace_headers_resolve_as_the_vectors_say() {
        for case in vector_cases("incoming_headers") {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            let (trace, disagreement) = RequestTrace::from_headers(
                input["traceparent"].as_str(),
                input["x_gateway_trace_id"].as_str(),
                own_span(),
            );
            assert_eq!(json!(trace.trace_source.as_str()), expected["trace_source"], "{name}");
            assert_eq!(json!(trace.trace_source != TraceSource::Minted), case["accepted"], "{name}");
            if trace.trace_source == TraceSource::Minted {
                assert_eq!(expected["trace_id"], Value::Null, "{name}");
                assert_eq!(TraceId::from_written(trace.trace_id.as_str()).as_ref(), Ok(&trace.trace_id), "{name}");
            } else {
                assert_eq!(json!(trace.trace_id.as_str()), expected["trace_id"], "{name}");
            }
            assert_eq!(trace.span_id, own_span(), "{name}");
            assert_eq!(
                json!(
                    trace
                        .parent_span_id
                        .as_ref()
                        .map(SpanId::as_str)
                ),
                expected["parent_span_id"],
                "{name}"
            );
            assert_eq!(
                json!(
                    trace
                        .continued_flags
                        .map(|flags| flags.to_string())
                ),
                expected["continued_flags"],
                "{name}"
            );
            assert_eq!(
                json!(
                    trace
                        .outgoing()
                        .tracestate(input["tracestate"].as_str())
                ),
                expected["tracestate"],
                "{name}"
            );
            let warning = disagreement.map(|disagreement| {
                json!({
                    "traceparent_trace_id": disagreement.traceparent_trace_id.as_str(),
                    "x_gateway_trace_id": disagreement.x_gateway_trace_id.as_str(),
                })
            });
            assert_eq!(json!(warning), expected["warning"], "{name}");
        }
    }

    #[test]
    fn a_terminated_trace_is_sent_onward_as_the_vectors_say() {
        for case in vector_cases("trace_termination") {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            let request = RequestTrace {
                trace_id: TraceId::from_written(
                    input["trace_id"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                span_id: SpanId::parse(
                    input["span_id"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                parent_span_id: None,
                trace_source: TraceSource::Header,
                continued_flags: flags(&input["continued_flags"]),
            };
            let fresh = input["fresh_trace_id"]
                .as_str()
                .map(|fresh| TraceId::from_written(fresh).unwrap());
            assert_eq!(json!(fresh.is_some()), input["terminate_trace_id"], "{name}");
            assert_eq!(input["terminate_trace_id"], case["accepted"], "{name}");
            let outgoing = match fresh {
                Some(fresh) => request.terminated(fresh),
                None => request.outgoing(),
            };

            assert_eq!(json!(request.trace_id.as_str()), expected["own_records_trace_id"], "{name}");
            assert_eq!(json!(outgoing.traceparent(export(input))), expected["traceparent"], "{name}");
            assert_eq!(json!(outgoing.tracestate(input["tracestate"].as_str())), expected["tracestate"], "{name}");
            let sent = json!(outgoing.trace_id().as_str());
            assert_eq!(sent, expected["x_gateway_trace_id"], "{name}");
            assert_eq!(sent, expected["transit_token_trace_id"], "{name}");
            let terminated = &expected["trace_terminated"];
            assert_eq!(json!(!terminated.is_null()), case["accepted"], "{name}");
            if !terminated.is_null() {
                assert_eq!(json!(request.trace_id.as_str()), terminated["trace_id"], "{name}");
                assert_eq!(sent, terminated["downstream_trace_id"], "{name}");
            }
        }
    }

    #[test]
    fn trace_sources_are_written_as_the_vectors_say() {
        for case in vector_cases("trace_source") {
            let input = &case["input"];
            if input["appliance"] != json!("agent_gateway") {
                continue;
            }
            let written = TraceSource::ALL
                .iter()
                .any(|source| json!(source.as_str()) == input["trace_source"]);
            assert_eq!(json!(written), case["accepted"], "{}", case["name"]);
        }
    }

    #[test]
    fn every_vector_group_is_run_here_or_belongs_to_another_rule() {
        let run_here = [
            "trace_id",
            "span_id",
            "traceparent_parse",
            "traceparent_compose",
            "incoming_headers",
            "tracestate_and_flags",
            "trace_termination",
            "trace_source",
        ];
        let not_this_modules_rule =
            ["mcp_meta", "transit_point", "link", "caller_identity_verified", "caller_key", "request_forwarded"];
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/trace_context/trace-context-vectors.json"))
                .unwrap();
        let mut groups: Vec<&str> = vectors["groups"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        groups.sort_unstable();
        let mut known: Vec<&str> = run_here
            .into_iter()
            .chain(not_this_modules_rule)
            .collect();
        known.sort_unstable();
        assert_eq!(groups, known);
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
        assert!(TraceId::from_written(&out).is_ok(), "{out}");
    }

    #[test]
    fn continue_mints_for_missing_or_empty() {
        let a = continue_or_mint_trace_id(None);
        let b = continue_or_mint_trace_id(Some(""));
        assert!(TraceId::from_written(&a).is_ok(), "{a}");
        assert!(TraceId::from_written(&b).is_ok(), "{b}");
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
        assert!(TraceId::from_written(&out).is_ok(), "{out}");
    }

    #[test]
    fn a_minted_trace_id_is_32_lowercase_hex_and_never_zero() {
        let minted: Vec<TraceId> = (0..1000)
            .map(|_| TraceId::mint())
            .collect();
        for id in &minted {
            assert_eq!(TraceId::from_written(id.as_str()).as_ref(), Ok(id));
            assert_eq!(TraceId::parse(id.as_str()).as_ref(), Ok(id));
        }
        let distinct: std::collections::HashSet<&str> = minted
            .iter()
            .map(TraceId::as_str)
            .collect();
        assert_eq!(distinct.len(), minted.len());
    }

    #[test]
    fn only_the_written_form_is_a_written_trace_id() {
        assert!(TraceId::from_written("4bf92f3577b34da6a3ce929d0e0e4736").is_ok());
        for other in [
            "4BF92F3577B34DA6A3CE929D0E0E4736",
            "4bf92f35-77b3-4da6-a3ce-929d0e0e4736",
            "00000000000000000000000000000000",
            "4bf92f3577b34da6a3ce929d0e0e473",
            "",
        ] {
            assert_eq!(TraceId::from_written(other), Err(TraceHeaderError::TraceId), "{other}");
        }
    }
}
