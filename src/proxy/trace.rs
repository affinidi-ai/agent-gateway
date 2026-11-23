//! Trace-id propagation and the per-surface trace-id termination (egress
//! firewall) helpers.
//!
//! One `trace_id` correlates a request across every hop (metrics, audit, the
//! "This request" filter, and the injected VPs' `traceId`). An Access Point
//! reads the trace its caller names with [`RequestTrace::from_request_headers`].
//! [`egress_trace_id`], at a gateway's **egress**, forwards the request's own
//! trace downstream unless the surface opts into termination, in which case a
//! fresh id crosses the boundary while this gateway keeps the incoming trace for
//! its own VP + audit. A trace id is minted with [`TraceId::mint`]: 32 lowercase
//! hexadecimal digits, the W3C Trace Context form.
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
    /// Where the hyphenated form puts its hyphens: 8-4-4-4-12.
    const HYPHENS: [usize; 4] = [8, 13, 18, 23];

    /// Reads a received trace id: 32 hexadecimal digits in any case, or the
    /// hyphenated 8-4-4-4-12 form in any case, normalised to the written
    /// form. Any other shape, and an id of all zeros, is refused.
    pub fn parse(input: &str) -> Result<Self, TraceHeaderError> {
        let bytes = input
            .to_ascii_lowercase()
            .into_bytes();
        let digits = match bytes.len() {
            Self::DIGITS => bytes,
            Self::HYPHENATED_LEN
                if Self::HYPHENS
                    .iter()
                    .all(|position| bytes[*position] == b'-') =>
            {
                bytes
                    .iter()
                    .enumerate()
                    .filter(|(position, _)| !Self::HYPHENS.contains(position))
                    .map(|(_, digit)| *digit)
                    .collect()
            }
            _ => return Err(TraceHeaderError::TraceId),
        };
        written_id(&digits, Self::DIGITS)
            .map(Self)
            .ok_or(TraceHeaderError::TraceId)
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

    /// A new span id: 8 random bytes, never all zero.
    pub fn mint() -> Self {
        loop {
            let bytes = rand::random::<[u8; 8]>();
            if bytes != [0u8; 8] {
                return Self(hex::encode(bytes));
            }
        }
    }

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
    /// The trace a request continues or starts, from every value of the
    /// `traceparent` and `X-Gateway-Trace-Id` headers it arrived with and this
    /// gateway's span for it.
    ///
    /// A header that is not valid, or that arrived more than once, is treated
    /// as absent. A `traceparent` alone,
    /// or one naming the same trace as `X-Gateway-Trace-Id`, is continued with
    /// its span as the parent. `X-Gateway-Trace-Id` alone is continued with no
    /// parent. When both are valid and name different traces,
    /// `X-Gateway-Trace-Id` wins with no parent, and the two ids are returned
    /// for the caller to warn about. With neither, a trace id is minted.
    pub fn from_headers(
        traceparent: &[&str],
        x_gateway_trace_id: &[&str],
        span_id: SpanId,
    ) -> (Self, Option<TraceDisagreement>) {
        let traceparent = single(traceparent).and_then(|header| valid_header(Traceparent::parse(header)));
        let named = single(x_gateway_trace_id).and_then(|header| valid_header(TraceId::parse(header)));
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

    /// The trace of a request to a Transit Point, under this gateway's span
    /// `span_id`. The trace id of the transit token the Transit Point
    /// verified, `token_trace_id`, is continued first: the `traceparent`'s
    /// span is its parent only when it names that trace, and any other trace
    /// header is ignored without a warning. Without a verified token, or with
    /// one whose trace id is not valid, the headers are read as
    /// [`Self::from_headers`] reads them.
    pub fn at_transit_point(
        token_trace_id: Option<&str>,
        traceparent: &[&str],
        x_gateway_trace_id: &[&str],
        span_id: SpanId,
    ) -> (Self, Option<TraceDisagreement>) {
        let Some(trace_id) = token_trace_id.and_then(|trace_id| valid_header(TraceId::parse(trace_id))) else {
            return Self::from_headers(traceparent, x_gateway_trace_id, span_id);
        };
        let parent = single(traceparent)
            .and_then(|header| valid_header(Traceparent::parse(header)))
            .filter(|traceparent| traceparent.trace_id == trace_id);
        let continued = Self {
            trace_id,
            span_id,
            parent_span_id: parent
                .as_ref()
                .map(|traceparent| {
                    traceparent
                        .parent_span_id
                        .clone()
                }),
            trace_source: TraceSource::TransitToken,
            continued_flags: parent.map(|traceparent| traceparent.flags),
        };
        (continued, None)
    }

    /// The trace of a Transit Point request that arrived with `headers`,
    /// under this gateway's span `span_id`: [`Self::at_transit_point`] over
    /// the trace id of the transit token it verified, `token_trace_id`, and
    /// every field of the trace headers, as [`Self::from_request_headers`]
    /// reads them.
    pub fn from_transit_point_request(
        token_trace_id: Option<&str>,
        headers: &axum::http::HeaderMap,
        span_id: SpanId,
    ) -> Self {
        warned(Self::at_transit_point(
            token_trace_id,
            &header_fields(headers, "traceparent"),
            &header_fields(headers, "x-gateway-trace-id"),
            span_id,
        ))
    }

    /// The trace of a request that arrived with `headers`, under this
    /// gateway's span `span_id`: [`Self::from_headers`] over every field of
    /// `traceparent` and `X-Gateway-Trace-Id`. A field whose value is not
    /// text counts and is not valid. When the two name different traces, a
    /// warning names both validated trace ids.
    pub fn from_request_headers(
        headers: &axum::http::HeaderMap,
        span_id: SpanId,
    ) -> Self {
        warned(Self::from_headers(
            &header_fields(headers, "traceparent"),
            &header_fields(headers, "x-gateway-trace-id"),
            span_id,
        ))
    }

    /// The request's own trace, sent onward under this gateway's span.
    pub fn outgoing(&self) -> OutgoingTrace {
        OutgoingTrace {
            trace_id: self.trace_id.clone(),
            span_id: self.span_id.clone(),
            continued_flags: self.continued_flags,
        }
    }

    /// The trace the request is sent onward with: its own, or a freshly minted
    /// one when the surface terminates trace ids.
    pub fn onward(
        &self,
        terminate: bool,
    ) -> OutgoingTrace {
        if terminate {
            self.terminated(TraceId::mint())
        } else {
            self.outgoing()
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

    /// The trace headers to send onward, each once: `traceparent`,
    /// `X-Gateway-Trace-Id`, and the `received` `tracestate` when
    /// [`Self::tracestate`] keeps it.
    pub fn headers(
        &self,
        export: SpanExport,
        received_tracestate: Option<&str>,
    ) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("traceparent", self.traceparent(export)),
            (
                X_GATEWAY_TRACE_ID,
                self.trace_id
                    .as_str()
                    .to_string(),
            ),
        ];
        if let Some(tracestate) = self.tracestate(received_tracestate) {
            headers.push(("tracestate", tracestate.to_string()));
        }
        headers
    }

    /// The trace headers a request that arrived with `received` headers is
    /// sent with toward a target of `class`, each once: [`Self::headers`]
    /// toward a Fabric target, the trace id in `X-Gateway-Trace-Id` alone
    /// toward a Target bound by external consent, and none toward a third
    /// party.
    pub fn headers_toward(
        &self,
        class: TargetClass,
        export: SpanExport,
        received: &axum::http::HeaderMap,
    ) -> Vec<(&'static str, String)> {
        match class {
            TargetClass::Fabric => self.headers(export, received_tracestate(received).as_deref()),
            TargetClass::ExternalConsent => vec![(
                X_GATEWAY_TRACE_ID,
                self.trace_id
                    .as_str()
                    .to_string(),
            )],
            TargetClass::ThirdParty => Vec::new(),
        }
    }

    /// The trace headers a Fabric message carries: those toward a Fabric
    /// target but `X-Gateway-Trace-Id`. The message names the trace id itself,
    /// and the receiving gateway writes `X-Gateway-Trace-Id` from it, so its
    /// Managed Agent receives that header once.
    pub fn fabric_message_headers(
        &self,
        export: SpanExport,
        received: &axum::http::HeaderMap,
    ) -> Vec<(&'static str, String)> {
        self.headers_toward(TargetClass::Fabric, export, received)
            .into_iter()
            .filter(|(name, _)| *name != X_GATEWAY_TRACE_ID)
            .collect()
    }

    /// The trace headers a Transit Point sends its target at `endpoint`: a
    /// `fabric://` target is reached by a Fabric message
    /// ([`Self::fabric_message_headers`]), every other target is a third party
    /// ([`Self::headers_toward`]).
    pub fn transit_headers(
        &self,
        endpoint: &str,
        export: SpanExport,
        received: &axum::http::HeaderMap,
    ) -> Vec<(&'static str, String)> {
        match TargetClass::of_transit_target(endpoint) {
            TargetClass::Fabric => self.fabric_message_headers(export, received),
            class => self.headers_toward(class, export, received),
        }
    }
}

/// The header that names a request's trace id.
const X_GATEWAY_TRACE_ID: &str = "x-gateway-trace-id";

/// The class of the target a request is sent to, by the route it takes, which
/// decides the trace it is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    /// A target over the Fabric, and an Access Point's Managed Agent: the trace
    /// is continued.
    Fabric,
    /// Every other target: it is sent no trace.
    ThirdParty,
    /// An Access Point's Target bound by external consent: it is sent the trace
    /// id in `X-Gateway-Trace-Id` alone.
    ExternalConsent,
}

impl TargetClass {
    /// The class of a Transit Point's target at `endpoint`.
    pub fn of_transit_target(endpoint: &str) -> Self {
        if endpoint.starts_with("fabric://") {
            Self::Fabric
        } else {
            Self::ThirdParty
        }
    }
}

/// The `tracestate` a request arrived with, its fields joined in the order
/// received.
fn received_tracestate(headers: &axum::http::HeaderMap) -> Option<String> {
    let fields: Vec<&str> = headers
        .get_all("tracestate")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    (!fields.is_empty()).then(|| fields.join(","))
}

/// `params._meta` of an MCP request as it is sent to a target of `class`.
/// Toward a Fabric target a `traceparent` it carries is replaced by the one
/// sent in the header, `sent_traceparent`, and none is added; toward a third
/// party `traceparent` and `tracestate` are removed; toward a Target bound by
/// external consent nothing changes. Every other key stays as it is.
pub fn mcp_meta_toward(
    class: TargetClass,
    meta: &mut serde_json::Map<String, serde_json::Value>,
    sent_traceparent: Option<&str>,
) {
    match class {
        TargetClass::Fabric => {
            if let (Some(carried), Some(sent)) = (meta.get_mut("traceparent"), sent_traceparent) {
                *carried = serde_json::Value::from(sent);
            }
        }
        TargetClass::ThirdParty => {
            meta.remove("traceparent");
            meta.remove("tracestate");
        }
        TargetClass::ExternalConsent => {}
    }
}

/// An MCP request `body` as it is sent to a target of `class`, by
/// [`mcp_meta_toward`]; `None` when it is sent as it is: not a JSON object,
/// without `params._meta`, or with nothing to change there.
pub fn mcp_body_toward(
    class: TargetClass,
    body: &[u8],
    sent_traceparent: Option<&str>,
) -> Option<Vec<u8>> {
    let mut request: serde_json::Value = serde_json::from_slice(body).ok()?;
    let meta = request
        .get_mut("params")?
        .get_mut("_meta")?
        .as_object_mut()?;
    let received = meta.clone();
    mcp_meta_toward(class, meta, sent_traceparent);
    if *meta == received {
        return None;
    }
    serde_json::to_vec(&request).ok()
}

/// The trace a payment call goes out under.
#[derive(Debug, Clone, Copy)]
pub enum PaymentTrace<'a> {
    /// An Access Point request's onward trace.
    Onward(&'a OutgoingTrace),
    /// The trace id a Fabric receive was sent, in whatever form it arrived.
    Received(&'a str),
}

impl PaymentTrace<'_> {
    /// The trace id the payment call names.
    pub fn trace_id(&self) -> &str {
        match self {
            Self::Onward(trace) => trace.trace_id().as_str(),
            Self::Received(trace_id) => trace_id,
        }
    }
}

/// The trace of a request that named `trace_id` in `X-Gateway-Trace-Id`, under
/// a fresh span, for tests that need a request's trace.
#[cfg(test)]
pub(crate) fn request_trace_for(trace_id: &str) -> RequestTrace {
    RequestTrace::from_headers(&[], &[trace_id], SpanId::mint()).0
}

/// Whether `name` is a trace header this gateway writes itself, so a caller's
/// copy of it is never passed on.
pub fn is_trace_header(name: &str) -> bool {
    ["traceparent", "tracestate", "x-gateway-trace-id"]
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
}

/// `resolved`'s trace, with a warning naming both validated trace ids when the
/// trace headers named different traces.
fn warned((trace, disagreement): (RequestTrace, Option<TraceDisagreement>)) -> RequestTrace {
    if let Some(disagreement) = disagreement {
        tracing::warn!(
            traceparent_trace_id = disagreement
                .traceparent_trace_id
                .as_str(),
            x_gateway_trace_id = disagreement
                .x_gateway_trace_id
                .as_str(),
            "traceparent and X-Gateway-Trace-Id name different traces; X-Gateway-Trace-Id is continued"
        );
    }
    trace
}

/// Every field of header `name`, in the order received. A value that is not
/// text is read as empty, so it still counts and is not valid.
fn header_fields<'a>(
    headers: &'a axum::http::HeaderMap,
    name: &str,
) -> Vec<&'a str> {
    headers
        .get_all(name)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap_or_default()
        })
        .collect()
}

/// The value of a header that arrived exactly once. A header that arrived more
/// than once is treated as absent: none of its values is used.
fn single<'a>(values: &[&'a str]) -> Option<&'a str> {
    match values {
        [value] => Some(value),
        [] => None,
        _ => {
            tracing::debug!(fields = values.len(), "Ignoring a trace header that arrived more than once");
            None
        }
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

/// The trace context vectors shared with the other appliances.
#[cfg(test)]
fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/trace_context/trace-context-vectors.json")).unwrap()
}

/// The cases of `group` in the trace context vectors shared with the other
/// appliances. Every group has accepting and refusing cases.
#[cfg(test)]
pub(crate) fn vector_cases(group: &str) -> Vec<serde_json::Value> {
    use serde_json::json;
    let cases = vectors()["groups"][group]["cases"]
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

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
            let _ = RequestTrace::from_headers(&[&input], &[&input], own_span());
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

    /// The target class a vector names, a Fabric target when it names none.
    fn class_of(input: &Value) -> TargetClass {
        match input["target_class"].as_str() {
            None | Some("fabric") => TargetClass::Fabric,
            Some("third_party") => TargetClass::ThirdParty,
            Some("external_consent") => TargetClass::ExternalConsent,
            Some(other) => panic!("no target class {other}"),
        }
    }

    /// The `tracestate` a vector's request arrived with, as its headers.
    fn received_headers(input: &Value) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        for tracestate in header_values(&input["tracestate"]) {
            headers.append("tracestate", tracestate.parse().unwrap());
        }
        headers
    }

    /// What `headers` send, as the vectors' `expected.sent` names it.
    fn sent(headers: &[(&'static str, String)]) -> Value {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(sent, _)| *sent == name)
                .map(|(_, value)| value.as_str())
        };
        json!({
            "traceparent_trace_id": header("traceparent").and_then(|traceparent| traceparent.get(3..35)),
            "tracestate": header("tracestate"),
            "x_gateway_trace_id": header("x-gateway-trace-id"),
        })
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
            let headers = trace_id
                .ok()
                .zip(span_id.ok())
                .map(|(trace_id, span_id)| {
                    OutgoingTrace {
                        trace_id,
                        span_id,
                        continued_flags: flags(&input["continued_flags"]),
                    }
                    .headers_toward(class_of(input), export(input), &received_headers(input))
                })
                .unwrap_or_default();
            if !expected["sent"].is_null() {
                assert_eq!(sent(&headers), expected["sent"], "{name}");
            }
            let composed = headers
                .into_iter()
                .find(|(header, _)| *header == "traceparent")
                .map(|(_, traceparent)| traceparent);
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

    /// The outgoing trace of a `tracestate_and_flags` case.
    fn outgoing_of(case: &Value) -> OutgoingTrace {
        let input = &case["input"];
        let continued_flags = flags(&input["continued_flags"]);
        assert_eq!(json!(continued_flags.is_some()), input["continued"], "{}", case["name"]);
        assert_eq!(input["continued"], case["accepted"], "{}", case["name"]);
        OutgoingTrace {
            trace_id: TraceId::mint(),
            span_id: own_span(),
            continued_flags,
        }
    }

    #[test]
    fn tracestate_is_kept_only_when_a_traceparent_is_continued() {
        for case in vector_cases("tracestate_and_flags") {
            let sent = outgoing_of(&case).tracestate(case["input"]["tracestate"].as_str());
            assert_eq!(json!(sent), case["expected"]["tracestate"], "{}", case["name"]);
        }
    }

    #[test]
    fn sent_flags_follow_the_sampler_or_the_continued_traceparent() {
        for case in vector_cases("tracestate_and_flags") {
            let sent = outgoing_of(&case).traceparent(export(&case["input"]));
            assert_eq!(json!(sent_flags(&sent)), case["expected"]["flags"], "{}", case["name"]);
        }
    }

    /// Every value of a header in a vector: none for `null`, one for a
    /// string, and each field in order for an array.
    fn header_values(value: &Value) -> Vec<&str> {
        match value {
            Value::Null => Vec::new(),
            Value::Array(fields) => fields
                .iter()
                .map(|field| field.as_str().unwrap())
                .collect(),
            field => vec![field.as_str().unwrap()],
        }
    }

    #[test]
    fn incoming_trace_headers_resolve_as_the_vectors_say() {
        for case in vector_cases("incoming_headers") {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            let (trace, disagreement) = RequestTrace::from_headers(
                &header_values(&input["traceparent"]),
                &header_values(&input["x_gateway_trace_id"]),
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

    /// The `transit_point` cases the Transit Point refuses before any trace is
    /// resolved. Run by the Transit Point's own tests, which send it requests.
    const REFUSED_AT_THE_TRANSIT_POINT: [&str; 2] =
        ["transit_required_token_unverified_refused", "transit_required_token_absent_refused"];

    #[test]
    fn transit_point_traces_resolve_as_the_vectors_say() {
        let mut refused = Vec::new();
        for case in vector_cases("transit_point") {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            if expected["refused"] == json!(true) {
                assert_eq!(input["requires_token"], json!(true), "{name}");
                assert_ne!(input["transit_token"]["verified"], json!(true), "{name}");
                refused.push(
                    name.as_str()
                        .unwrap()
                        .to_string(),
                );
                continue;
            }
            let token = &input["transit_token"];
            let verified_token_trace_id = (token["verified"] == json!(true)).then(|| {
                token["trace_id"]
                    .as_str()
                    .unwrap()
            });
            assert_eq!(json!(verified_token_trace_id.is_some()), case["accepted"], "{name}");
            let (trace, disagreement) = RequestTrace::at_transit_point(
                verified_token_trace_id,
                &header_values(&input["traceparent"]),
                &header_values(&input["x_gateway_trace_id"]),
                own_span(),
            );
            assert_eq!(json!(trace.trace_source.as_str()), expected["trace_source"], "{name}");
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
            assert_eq!(disagreement, None, "{name}");
            assert_eq!(expected["warning"], Value::Null, "{name}");
            let outgoing = trace.outgoing();
            let sent = match class_of(input) {
                TargetClass::Fabric => {
                    let carried = outgoing.transit_headers(
                        "fabric://peer-gateway/peer-surface",
                        SpanExport::Off,
                        &received_headers(input),
                    );
                    let mut sent = sent(&carried);
                    assert_eq!(sent["x_gateway_trace_id"], Value::Null, "{name}: the message carries no header");
                    sent["x_gateway_trace_id"] = json!(outgoing.trace_id().as_str());
                    sent
                }
                _ => sent(&outgoing.transit_headers(
                    "https://tools.example/mcp",
                    SpanExport::Off,
                    &received_headers(input),
                )),
            };
            assert_eq!(sent, expected["sent"], "{name}");
        }
        assert_eq!(refused, REFUSED_AT_THE_TRANSIT_POINT);
    }

    #[test]
    fn mcp_metadata_is_sent_as_the_vectors_say() {
        for case in vector_cases("mcp_meta") {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            let mut meta = input["body_other"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            for (field, key) in [("body_traceparent", "traceparent"), ("body_tracestate", "tracestate")] {
                if let Some(value) = input[field].as_str() {
                    meta.insert(key.to_string(), json!(value));
                }
            }
            let received = meta.clone();
            mcp_meta_toward(class_of(input), &mut meta, input["sent_traceparent"].as_str());
            assert_eq!(json!(meta.get("traceparent")), expected["body_traceparent"], "{name}");
            if let Some(tracestate) = expected.get("body_tracestate") {
                assert_eq!(json!(meta.get("tracestate")), *tracestate, "{name}");
            }
            if let Some(other) = expected.get("body_other") {
                let mut kept = meta.clone();
                kept.remove("traceparent");
                kept.remove("tracestate");
                assert_eq!(json!(kept), *other, "{name}");
            }
            let replaced = meta
                .get("traceparent")
                .is_some()
                && meta.get("traceparent") != received.get("traceparent");
            assert_eq!(json!(replaced), case["accepted"], "{name}");
        }
    }

    #[test]
    fn an_mcp_body_is_rewritten_only_when_its_metadata_changes() {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo",
            "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "tracestate": "rojo=00f067aa0ba902b7", "progressToken": "t-1"}}});
        let sent: Value = serde_json::from_slice(
            &mcp_body_toward(TargetClass::ThirdParty, body.to_string().as_bytes(), None).unwrap(),
        )
        .unwrap();
        assert_eq!(sent["params"]["_meta"], json!({"progressToken": "t-1"}));
        assert_eq!(sent["params"]["name"], "echo");
        for unchanged in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"_meta": {"progressToken": "t-1"}}}),
        ] {
            assert_eq!(
                mcp_body_toward(
                    TargetClass::ThirdParty,
                    unchanged
                        .to_string()
                        .as_bytes(),
                    None
                ),
                None
            );
        }
        assert_eq!(mcp_body_toward(TargetClass::ThirdParty, b"not json", None), None);
        assert_eq!(mcp_body_toward(TargetClass::ExternalConsent, body.to_string().as_bytes(), None), None);
    }

    fn request_headers(fields: &[(&'static str, &[u8])]) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in fields {
            headers.append(*name, axum::http::HeaderValue::from_bytes(value).unwrap());
        }
        headers
    }

    #[test]
    fn a_request_is_traced_from_every_field_of_its_trace_headers() {
        let traceparent = b"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".as_slice();
        let named = b"4bf92f3577b34da6a3ce929d0e0e4736".as_slice();
        let resolved = |fields: &[(&'static str, &[u8])]| {
            let trace = RequestTrace::from_request_headers(&request_headers(fields), own_span());
            (
                trace
                    .trace_id
                    .as_str()
                    .to_string(),
                trace.trace_source,
            )
        };

        assert_eq!(
            resolved(&[("traceparent", traceparent)]),
            ("0af7651916cd43dd8448eb211c80319c".to_string(), TraceSource::Header)
        );
        assert_eq!(resolved(&[("traceparent", traceparent), ("TraceParent", traceparent)]).1, TraceSource::Minted);
        assert_eq!(
            resolved(&[("traceparent", traceparent), ("x-gateway-trace-id", named), ("x-gateway-trace-id", b"\xff")]),
            ("0af7651916cd43dd8448eb211c80319c".to_string(), TraceSource::Header),
            "a field that is not text still makes X-Gateway-Trace-Id repeated"
        );
        assert_eq!(
            resolved(&[("traceparent", traceparent), ("X-Gateway-Trace-Id", named)]),
            ("4bf92f3577b34da6a3ce929d0e0e4736".to_string(), TraceSource::Header)
        );
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

    /// Where each vector group is run, or why Gateway does not run it.
    const VECTOR_GROUPS: [(&str, &str); 15] = [
        ("trace_id", "run here"),
        ("span_id", "run here"),
        ("traceparent_parse", "run here"),
        ("traceparent_compose", "run here"),
        ("incoming_headers", "run here"),
        ("tracestate_and_flags", "run here"),
        ("trace_termination", "run here"),
        ("trace_source", "run here, the cases of Gateway"),
        ("request_forwarded", "run by the request_forwarded record in audit::request_events"),
        ("transit_point", "run here"),
        ("transit_request_forwarded", "run by the transit_request_forwarded record in audit::request_events"),
        ("mcp_meta", "run here"),
        ("link", "not Gateway's: Agent Watch follows links"),
        ("caller_identity_verified", "not Gateway's: Agent Stream writes it"),
        ("caller_key", "not Gateway's: Agent Watch builds caller keys"),
    ];

    #[test]
    fn every_vector_group_is_run_or_named_and_the_version_is_pinned() {
        let vectors = vectors();
        assert_eq!(vectors["version"], 6, "the vectors version this gateway is tested against");
        let groups = vectors["groups"]
            .as_object()
            .unwrap();
        let cases: usize = groups
            .values()
            .map(|group| {
                group["cases"]
                    .as_array()
                    .unwrap()
                    .len()
            })
            .sum();
        assert_eq!(cases, 162, "the case count of vectors version 6");
        let mut named: Vec<&str> = VECTOR_GROUPS
            .iter()
            .map(|(group, _)| *group)
            .collect();
        named.sort_unstable();
        let mut present: Vec<&str> = groups
            .keys()
            .map(String::as_str)
            .collect();
        present.sort_unstable();
        assert_eq!(present, named);
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
    fn a_minted_span_id_is_16_lowercase_hex_and_random() {
        let ids: Vec<SpanId> = (0..64)
            .map(|_| SpanId::mint())
            .collect();
        for id in &ids {
            assert_eq!(SpanId::parse(id.as_str()).as_ref(), Ok(id));
        }
        let distinct: std::collections::HashSet<&str> = ids
            .iter()
            .map(SpanId::as_str)
            .collect();
        assert_eq!(distinct.len(), ids.len());
        let thirteenth: std::collections::HashSet<char> = ids
            .iter()
            .filter_map(|id| id.as_str().chars().nth(12))
            .collect();
        assert!(thirteenth.len() > 1, "every character is random, none fixed by a UUID version");
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
