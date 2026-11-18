//! Policy input capture: while a dashboard connection listens to a surface's policy
//! input, each request and response policy evaluation on that surface is sent as a `policy_input_captured`
//! WebSocket update with its input, credentials masked, and its outcome. Only the
//! listening connections receive it; capture stops when the last of them stops listening
//! or closes. Nothing is written to the log or stored.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use chrono::Utc;
use dashmap::DashMap;
use regex::Regex;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::observability::loggable::REDACTED;
use crate::server::WsUpdate;

/// The system feature flag that allows policy input capture. Off unless set to `true`.
pub const FLAG_POLICY_INPUT_CAPTURE: &str = "policy_input_capture";

/// Whether policy input capture is turned on: the [`FLAG_POLICY_INPUT_CAPTURE`] system flag,
/// read on every call so turning it off stops new captures at once. False when settings are
/// unavailable.
pub fn capture_turned_on() -> bool {
    #[cfg(test)]
    return TURNED_ON_IN_THIS_THREAD.with(std::cell::Cell::get);
    #[cfg(not(test))]
    turned_on_in(crate::storage::settings_store::global_settings_store())
}

/// Whether `settings` turn policy input capture on: [`FLAG_POLICY_INPUT_CAPTURE`] explicitly
/// `true`. False without settings.
fn turned_on_in(settings: Option<&crate::storage::settings_store::SettingsStore>) -> bool {
    settings.is_some_and(|settings| settings.flag_enabled(FLAG_POLICY_INPUT_CAPTURE))
}

#[cfg(test)]
thread_local! {
    /// What [`capture_turned_on`] answers on this test thread. Tests share one process-wide
    /// settings store, so each turns capture off on its own thread; [`turned_on_in`] is tested
    /// against settings of its own.
    static TURNED_ON_IN_THIS_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Makes [`capture_turned_on`] answer `turned_on` on this test thread.
#[cfg(test)]
pub(crate) fn set_turned_on_in_this_thread(turned_on: bool) {
    TURNED_ON_IN_THIS_THREAD.with(|cell| cell.set(turned_on));
}

/// A serialized `policy_input_captured` update, or a `policy_input_skipped` update
/// counting the captures dropped because the queue was full, queued for one listen:
/// the surface it belongs to and the id of that listen's [`Listening`].
#[derive(Debug, Clone)]
pub struct QueuedCapture {
    pub surface_id: String,
    pub listen: u64,
    pub update: Arc<str>,
}

/// Where a dashboard connection receives its captures.
pub type CaptureSender = mpsc::Sender<QueuedCapture>;

/// One listen: the id of its [`Listening`], where its captures go, and how many it has
/// missed since it was last told.
struct Listener {
    id: u64,
    captures: CaptureSender,
    skipped: AtomicU64,
}

impl Listener {
    /// Queue `capture`, first telling the listener how many captures it missed. A capture
    /// that finds the queue full is counted as missed instead. The missed count is claimed
    /// whole before it is reported, so concurrent sends never report the same captures twice.
    fn send(
        &self,
        surface_id: &str,
        capture: &Arc<str>,
    ) {
        let queued = |update: Arc<str>| QueuedCapture {
            surface_id: surface_id.to_string(),
            listen: self.id,
            update,
        };
        let skipped = self
            .skipped
            .swap(0, Ordering::AcqRel);
        if skipped > 0 {
            let notice = serde_json::json!({
                "type": "policy_input_skipped",
                "config_id": surface_id,
                "skipped": skipped,
            })
            .to_string();
            if self
                .captures
                .try_send(queued(notice.into()))
                .is_err()
            {
                self.skipped
                    .fetch_add(skipped + 1, Ordering::AcqRel);
                return;
            }
        }
        if self
            .captures
            .try_send(queued(Arc::clone(capture)))
            .is_err()
        {
            self.skipped
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The connections listening to each surface's policy input, by surface id: one entry
/// per listen.
static LISTENERS: LazyLock<DashMap<String, Vec<Listener>>> = LazyLock::new(DashMap::new);

static NEXT_LISTEN_ID: AtomicU64 = AtomicU64::new(0);

/// A dashboard connection listening to one surface's policy input. The surface is
/// captured while at least one exists; dropping it stops listening.
#[derive(Debug)]
pub struct Listening {
    surface_id: String,
    id: u64,
}

/// Start listening to the policy input of `surface_id`, its captures sent to `captures`.
pub fn listen(
    surface_id: &str,
    captures: CaptureSender,
) -> Listening {
    let id = NEXT_LISTEN_ID.fetch_add(1, Ordering::Relaxed);
    LISTENERS
        .entry(surface_id.to_string())
        .or_default()
        .push(Listener {
            id,
            captures,
            skipped: AtomicU64::new(0),
        });
    Listening {
        surface_id: surface_id.to_string(),
        id,
    }
}

impl Listening {
    /// The id the captures queued for this listen carry.
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        if let Some(mut listeners) = LISTENERS.get_mut(&self.surface_id) {
            listeners.retain(|listener| listener.id != self.id);
        }
        LISTENERS.remove_if(&self.surface_id, |_, listeners| listeners.is_empty());
    }
}

/// A policy definition a captured evaluation ran: its id and name, and the version
/// compiled. A legacy inline gateway policy has neither id nor name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapturedPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl CapturedPolicy {
    /// The policy compiled from `definition`.
    pub fn of(definition: &super::policy_definitions::PolicyDefinition) -> Self {
        Self {
            id: Some(definition.id.clone()),
            name: Some(definition.name.clone()),
            version: definition.version,
        }
    }
}

/// A listen to `surface_id` for tests, with the receiver of its captures.
#[cfg(test)]
pub(crate) fn listening(surface_id: &str) -> (Listening, mpsc::Receiver<QueuedCapture>) {
    let (captures, received) = mpsc::channel(64);
    (listen(surface_id, captures), received)
}

/// The updates `received` has been sent so far, as JSON.
#[cfg(test)]
pub(crate) fn received_captures(received: &mut mpsc::Receiver<QueuedCapture>) -> Vec<Value> {
    let mut captures = Vec::new();
    while let Ok(capture) = received.try_recv() {
        captures.push(serde_json::from_str(&capture.update).expect("a capture is JSON"));
    }
    captures
}

pub(crate) fn is_captured(surface_id: &str) -> bool {
    LISTENERS
        .get(surface_id)
        .is_some_and(|listeners| !listeners.is_empty())
}

/// Whether an evaluation of `input` would be captured: a dashboard connection listens to its
/// surface and policy input capture is turned on.
pub(crate) fn is_listened(input: &Value) -> bool {
    surface_of(input).is_some_and(is_captured) && capture_turned_on()
}

/// Whether a listener of `surface_id` has room in its queue for a capture. When none has,
/// each counts the capture as missed, so it is told at its next capture.
fn has_room_for_capture(surface_id: &str) -> bool {
    let Some(listeners) = LISTENERS.get(surface_id) else {
        return false;
    };
    if listeners
        .iter()
        .any(|listener| listener.captures.capacity() > 0)
    {
        return true;
    }
    for listener in listeners.iter() {
        listener
            .skipped
            .fetch_add(1, Ordering::Relaxed);
    }
    false
}

/// The surface a policy input belongs to: `input.channel.config_id` for a request
/// policy, `input.surface.id` for a response policy.
fn surface_of(input: &Value) -> Option<&str> {
    input
        .pointer("/channel/config_id")
        .or_else(|| input.pointer("/surface/id"))
        .and_then(Value::as_str)
}

/// The policy slot `engine` names, in words, and the Transit Point alias it belongs to.
/// Surface engines are keyed `<surface id>`, `inbound:<surface id>`,
/// `inbound:variant:<surface id>:<alias>`, `variant:<surface id>:<alias>`,
/// `outbound:<surface id>` and `transit:<surface id>:<alias>`; response policy engines
/// `response:transit:<surface id>:<alias>` and `response:<policy definition id>`.
fn slot_of(
    plane: &str,
    engine: &str,
    surface_id: &str,
) -> (String, Option<String>) {
    if plane != "surface" {
        return match plane {
            "gateway" => ("gateway".to_string(), None),
            _ => (format!("{plane} {engine}"), None),
        };
    }
    let alias_after = |prefix: &str| {
        engine
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix(surface_id))
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::to_string)
    };
    if let Some(alias) = alias_after("response:transit:") {
        (format!("transit {alias} response"), Some(alias))
    } else if engine.starts_with("response:") {
        ("response".to_string(), None)
    } else if engine == surface_id {
        ("target".to_string(), None)
    } else if engine
        .strip_prefix("inbound:")
        .is_some_and(|rest| rest == surface_id)
    {
        ("inbound".to_string(), None)
    } else if engine
        .strip_prefix("outbound:")
        .is_some_and(|rest| rest == surface_id)
    {
        ("outbound".to_string(), None)
    } else if let Some(alias) = alias_after("inbound:variant:") {
        (format!("inbound variant {alias}"), None)
    } else if let Some(alias) = alias_after("variant:") {
        (format!("target variant {alias}"), None)
    } else if let Some(alias) = alias_after("transit:") {
        (format!("transit {alias}"), Some(alias))
    } else {
        (engine.to_string(), None)
    }
}

/// A policy evaluation being captured, sent with its outcome by [`Capture::finish`].
pub struct Capture {
    surface_id: String,
    plane: String,
    engine: String,
    slot: String,
    transit_point: Option<String>,
    policies: Vec<CapturedPolicy>,
    decided_by: Option<String>,
    input: Value,
}

/// Start capturing the evaluation of `input` by `plane` (`gateway`, `surface` or
/// `appliance`), `engine` naming the evaluated policy slot, when a dashboard connection
/// listens to its surface and policy input capture is turned on. When every listener's queue
/// is full the evaluation is counted as missed and not masked. `policies` lists the policy
/// definitions the slot evaluates; it is called only when the evaluation is captured.
pub fn begin(
    plane: &str,
    engine: &str,
    input: &Value,
    policies: impl FnOnce() -> Vec<CapturedPolicy>,
) -> Option<Capture> {
    let surface_id = surface_of(input)?;
    if !is_captured(surface_id) || !capture_turned_on() || !has_room_for_capture(surface_id) {
        return None;
    }
    let (slot, transit_point) = if plane == "gateway"
        && input
            .pointer("/gateway/direction")
            .and_then(Value::as_str)
            == Some("outbound")
    {
        ("gateway outbound".to_string(), None)
    } else {
        slot_of(plane, engine, surface_id)
    };
    let mut masked = input.clone();
    mask_credentials(&mut masked);
    apply_redaction_rules(&mut masked, &crate::observability::opentelemetry::log_redactor());
    mask_request_path(&mut masked);
    Some(Capture {
        surface_id: surface_id.to_string(),
        plane: plane.to_string(),
        engine: engine.to_string(),
        slot,
        transit_point,
        policies: policies(),
        decided_by: None,
        input: masked,
    })
}

impl Capture {
    /// Name the policy, by id, that decided a set of several: the one that denied.
    pub fn decided_by(
        mut self,
        policy_id: Option<&str>,
    ) -> Self {
        self.decided_by = policy_id.map(str::to_string);
        self
    }

    /// Send the capture with its outcome, `Ok((allow, deny reason))` or the evaluation
    /// error, to the connections listening to its surface, serialized once for all of them.
    pub fn finish(
        self,
        outcome: Result<(bool, Option<&str>), &str>,
    ) {
        let surface_id = self.surface_id.clone();
        let capture: Arc<str> = match serde_json::to_string(&self.into_update(outcome)) {
            Ok(json) => json.into(),
            Err(error) => {
                tracing::error!("Failed to serialize a policy input capture: {}", error);
                return;
            }
        };
        if let Some(listeners) = LISTENERS.get(&surface_id) {
            for listener in listeners.iter() {
                listener.send(&surface_id, &capture);
            }
        }
    }

    fn into_update(
        self,
        outcome: Result<(bool, Option<&str>), &str>,
    ) -> WsUpdate {
        let (decision, reason) = match outcome {
            Ok((true, _)) => ("allow", None),
            Ok((false, reason)) => ("deny", reason.map(mask_outcome_text)),
            Err(error) => ("error", Some(mask_outcome_text(error))),
        };
        WsUpdate::PolicyInputCaptured {
            config_id: self.surface_id,
            timestamp: Utc::now().to_rfc3339(),
            plane: self.plane,
            engine: self.engine,
            slot: self.slot,
            transit_point: self.transit_point,
            policies: self.policies,
            decided_by: self.decided_by,
            input: Box::new(self.input),
            decision: decision.to_string(),
            reason,
            surface_variant: crate::observability::policy_audit::current_request_variant(),
        }
    }
}

/// [`Capture::finish`] for a surface or gateway policy result.
pub fn finish(
    capture: Option<Capture>,
    result: &Result<super::PolicyDecision, String>,
) {
    if let Some(capture) = capture {
        capture.finish(
            result
                .as_ref()
                .map(|decision| (decision.allow, decision.reason.as_deref()))
                .map_err(String::as_str),
        );
    }
}

/// Render `input.http.path` as the request log line does: capability ids shortened and
/// every query value redacted, so a credential passed in the query string (a request
/// received over Fabric carries the caller's full path and query) is not sent.
fn mask_request_path(input: &mut Value) {
    if let Some(Value::String(path)) = input.pointer_mut("/http/path") {
        *path = match path.split_once('?') {
            Some((path, query)) => format!(
                "{}?{}",
                crate::observability::loggable::path(path),
                crate::observability::loggable::query(query)
            ),
            None => crate::observability::loggable::path(path),
        };
    }
}

/// A deny reason or evaluation error with the masking of [`mask_text`] and then the log
/// redaction rules applied, since a policy can build its reason from input text and an
/// engine error can quote it.
fn mask_outcome_text(text: &str) -> String {
    let masked = mask_text(text).unwrap_or_else(|| text.to_string());
    crate::observability::opentelemetry::log_redactor()
        .redact(&masked)
        .into_owned()
}

/// Apply the operator's log redaction rules (`logging.redaction.rules`) to every string
/// in `value`. A string field is also matched as the log line shows it, `"<key>":"<value>"`,
/// so a rule that matches a field name with its value, such as the built-in quoted
/// credential fields rule, masks the whole value.
fn apply_redaction_rules(
    value: &mut Value,
    redactor: &crate::observability::LogRedactor,
) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if matches!(entry, Value::String(text) if field_is_redacted(key, text, redactor)) {
                    *entry = Value::String(REDACTED.to_string());
                } else {
                    apply_redaction_rules(entry, redactor);
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| apply_redaction_rules(item, redactor)),
        Value::String(text) => {
            if let std::borrow::Cow::Owned(redacted) = redactor.redact(text) {
                *text = redacted;
            }
        }
        _ => {}
    }
}

/// Whether a redaction rule that needs the field's name changes its value: the field written
/// as JSON, `"<key>":"<value>"`, redacts differently from the value redacted on its own. A
/// rule that changes only the key doesn't count.
fn field_is_redacted(
    key: &str,
    text: &str,
    redactor: &crate::observability::LogRedactor,
) -> bool {
    let key = format!("{}:", Value::String(key.to_string()));
    let redacted_field = redactor
        .redact(&format!("{key}{}", Value::String(text.to_string())))
        .into_owned();
    let redacted_value = format!(
        "{key}{}",
        Value::String(
            redactor
                .redact(text)
                .into_owned()
        )
    );
    redacted_field != redacted_value && redacted_field.starts_with(&key)
}

/// Replace every credential in `value` with [`REDACTED`]: the value of a key named like a
/// credential, a JWT, and a `Bearer` or `Basic` authorization value.
pub fn mask_credentials(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if crate::observability::log_redact::is_credential_attribute(key) {
                    *entry = Value::String(REDACTED.to_string());
                } else {
                    mask_credentials(entry);
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(mask_credentials),
        Value::String(text) => {
            if let Some(masked) = mask_text(text) {
                *text = masked;
            }
        }
        _ => {}
    }
}

/// A JWT candidate anywhere in a text, with the `~`-separated disclosures and key binding
/// JWT that follow it in an SD-JWT. A header starting with `{` encodes to `ey` or `ew`, and
/// one starting with JSON whitespace (space, tab, newline or carriage return) before the `{`
/// to `IA`, `IC`, `IH`, `CQ`, `CS`, `CX`, `Cg`, `Ci`, `Cn`, `DQ`, `DS` or `DX`. The header
/// takes `=` only as trailing padding, so `CSRF=` in front of a JWT is not part of it. A
/// word joined to the header by `-`, `_` or `.`, as in `session_`, is matched with it, and
/// [`header_start_before_last_dot`] or [`header_start`] finds where in that run the header
/// starts. The payload is the third group.
static EMBEDDED_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b([A-Za-z0-9_.-]*[-_.])?((?:e[wy]|I[ACH]|C[QSXgin]|D[QSX])[A-Za-z0-9_-]+={0,2})\.([A-Za-z0-9_=-]+)\.[A-Za-z0-9_=-]*(?:~[A-Za-z0-9_=.-]*)*",
    )
    .expect("valid JWT pattern")
});

/// The encodings a JWT header can start with; see [`EMBEDDED_JWT`].
static HEADER_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:e[wy]|I[ACH]|C[QSXgin]|D[QSX])").expect("valid JWT header prefix pattern"));

/// The most header starts [`header_start`] decodes for one candidate, which keeps masking
/// linear in the text length.
const MAX_HEADER_STARTS: usize = 8;

/// Where the JWT header starts in `lead`, the run before a candidate's first `.`: at the start
/// of `lead` or just after a `-`, `_` or `.`, where a header encoding begins. Starts are tried
/// from the right, at most [`MAX_HEADER_STARTS`] of them, and the first that decodes to a JSON
/// object is taken. The start only decides how much of `lead` is kept: when none is found and
/// the payload decodes to a JSON object, [`mask_text`] masks the whole of `lead`.
fn header_start(lead: &str) -> Option<usize> {
    let bytes = lead.as_bytes();
    (0..bytes.len())
        .rev()
        .filter(|&start| {
            (start == 0 || matches!(bytes[start - 1], b'-' | b'_' | b'.')) && HEADER_PREFIX.is_match(&lead[start..])
        })
        .take(MAX_HEADER_STARTS)
        .find(|&start| is_jwt_header(&lead[start..]))
}

/// Where a JWT starts in `lead` when its header is a `.`-separated segment before the last,
/// as in `<JWT>.Cisco.com.au` or `<JWT>.<JWT>`, whose candidate starts at the first JWT.
/// Segments are tried from the left with [`header_start`], and one counts only when the
/// segment after it is not empty. The last segment is [`header_start`]'s own case.
fn header_start_before_last_dot(lead: &str) -> Option<usize> {
    let mut segments = lead.split('.').peekable();
    let mut offset = 0;
    while let Some(segment) = segments.next() {
        let next = segments.peek()?;
        if !next.is_empty()
            && let Some(start) = header_start(segment)
        {
            return Some(offset + start);
        }
        offset += segment.len() + 1;
    }
    None
}

/// `Bearer` or `Basic`, whitespace and the token after it, anywhere in a text.
static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(bearer|basic)(\s+)([A-Za-z0-9\-._~+/]+=*)").expect("valid authorization pattern")
});

/// An absolute URL with a query string, anywhere in a text.
static URL_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-z][a-z0-9+.\-]*://[^\s?#"<>]+)\?([^\s#"<>]+)"#).expect("valid URL pattern")
});

/// An absolute URL whose fragment holds `name=value` parameters, as an OAuth redirect's
/// does, anywhere in a text. A plain anchor such as `#top` is not matched.
static URL_FRAGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-z][a-z0-9+.\-]*://[^\s#"<>]+)#([^\s"<>=]*=[^\s"<>]*)"#).expect("valid URL fragment pattern")
});

/// The scheme and userinfo of an absolute URL, anywhere in a text. The userinfo may hold
/// `@` and `'`, so it runs to the last `@` before the host.
static URL_USERINFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/?#"<>]+@"#).expect("valid URL userinfo pattern"));

/// `text` with its credentials masked, or `None` when it holds none. A text that is
/// one JWT or one authorization value becomes [`REDACTED`] whole; inside longer text
/// each URL keeps its fragment and query parameter names with their values redacted and
/// loses its userinfo, then each JWT and authorization token becomes [`REDACTED`].
/// Fragments and queries go first, so a JWT in either cannot end it before the parameters
/// after it.
fn mask_text(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if is_jwt(trimmed) || is_authorization_value(trimmed) {
        return Some(REDACTED.to_string());
    }
    let masked = URL_FRAGMENT
        .replace_all(text, |caps: &regex::Captures<'_>| {
            format!("{}#{}", &caps[1], crate::observability::loggable::query(&caps[2]))
        })
        .into_owned();
    let masked = URL_QUERY
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            format!("{}?{}", &caps[1], crate::observability::loggable::query(&caps[2]))
        })
        .into_owned();
    let masked = URL_USERINFO
        .replace_all(&masked, |caps: &regex::Captures<'_>| format!("{}{REDACTED}@", &caps[1]))
        .into_owned();
    let masked = EMBEDDED_JWT
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            let glue = caps
                .get(1)
                .map_or("", |glue| glue.as_str());
            let lead = format!("{glue}{}", &caps[2]);
            match header_start_before_last_dot(&lead).or_else(|| header_start(&lead)) {
                Some(start) => format!("{}{REDACTED}", &lead[..start]),
                None if is_jwt_header(&caps[3]) => REDACTED.to_string(),
                None => caps[0].to_string(),
            }
        })
        .into_owned();
    let masked = AUTHORIZATION
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            if is_authorization_token(&caps[1], &caps[3]) {
                format!("{}{}{REDACTED}", &caps[1], &caps[2])
            } else {
                caps[0].to_string()
            }
        })
        .into_owned();
    (masked != text).then_some(masked)
}

/// The shortest `Bearer` token taken as a credential when it is only letters. Shorter
/// words ("Bearer arms") are message text.
const MIN_AUTHORIZATION_TOKEN_LEN: usize = 12;

/// The shortest `Bearer` token taken as a credential when it holds a digit or one of
/// `-._~+/=`.
const MIN_MARKED_TOKEN_LEN: usize = 6;

fn is_authorization_value(text: &str) -> bool {
    text.split_once(char::is_whitespace)
        .is_some_and(|(scheme, token)| is_authorization_token(scheme, token.trim()))
}

/// Whether `token` after `scheme` is a credential. A `Basic` token is one when it
/// decodes as base64 to `user:password`, so text such as "Basic authentication" is
/// kept. A `Bearer` token is one at [`MIN_AUTHORIZATION_TOKEN_LEN`] characters, or at
/// [`MIN_MARKED_TOKEN_LEN`] when it holds a digit or a symbol.
fn is_authorization_token(
    scheme: &str,
    token: &str,
) -> bool {
    if token.is_empty()
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
    {
        return false;
    }
    if scheme.eq_ignore_ascii_case("basic") {
        use base64::Engine;
        return base64::engine::general_purpose::STANDARD
            .decode(token)
            .ok()
            .and_then(|decoded| String::from_utf8(decoded).ok())
            .is_some_and(|decoded| decoded.contains(':'));
    }
    scheme.eq_ignore_ascii_case("bearer")
        && (token.len() >= MIN_AUTHORIZATION_TOKEN_LEN
            || (token.len() >= MIN_MARKED_TOKEN_LEN
                && token
                    .bytes()
                    .any(|b| !b.is_ascii_alphabetic())))
}

/// Whether `segment` is base64url of a JSON object, as a JWT header is, whatever
/// whitespace the JSON holds.
fn is_jwt_header(segment: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment.trim_end_matches('='))
        .ok()
        .is_some_and(|decoded| serde_json::from_slice::<serde_json::Map<String, Value>>(&decoded).is_ok())
}

fn is_jwt(text: &str) -> bool {
    let segments: Vec<&str> = text.split('.').collect();
    segments.len() == 3
        && is_jwt_header(segments[0])
        && segments[..2]
            .iter()
            .all(|segment| !segment.is_empty())
        && segments
            .iter()
            .all(|segment| {
                segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbHBoYSJ9.sig";

    #[test]
    fn a_surface_is_captured_while_any_connection_listens() {
        let first = listening("input-capture-listened");
        let second = listening("input-capture-listened");
        assert!(is_captured("input-capture-listened"));

        drop(first);
        assert!(is_captured("input-capture-listened"));

        drop(second);
        assert!(!is_captured("input-capture-listened"));
        assert!(!LISTENERS.contains_key("input-capture-listened"));
        assert!(!is_captured("input-capture-never-listened"));
    }

    #[test]
    fn an_outbound_gateway_evaluation_has_its_own_slot() {
        let _listening = listening("input-capture-gateway-direction");
        let input = |direction: &str| {
            json!({
                "channel": { "config_id": "input-capture-gateway-direction" },
                "gateway": { "direction": direction },
            })
        };

        let outbound = begin("gateway", "gw-1", &input("outbound"), Vec::new).unwrap();
        let inbound = begin("gateway", "gw-1", &input("inbound"), Vec::new).unwrap();
        let surface = begin("surface", "input-capture-gateway-direction", &input("outbound"), Vec::new).unwrap();

        assert_eq!(outbound.slot, "gateway outbound");
        assert_eq!(inbound.slot, "gateway");
        assert_eq!(surface.slot, "target");
    }

    #[test]
    fn a_capture_reaches_only_the_listeners_of_its_surface() {
        let (_first, mut first) = listening("input-capture-delivered");
        let (_second, mut second) = listening("input-capture-delivered");
        let (_other, mut other) = listening("input-capture-other");
        let input = json!({ "channel": { "config_id": "input-capture-delivered" } });

        begin("surface", "input-capture-delivered", &input, Vec::new)
            .unwrap()
            .finish(Ok((true, None)));

        for received in [&mut first, &mut second] {
            let captures = received_captures(received);
            assert_eq!(captures.len(), 1, "{captures:?}");
            assert_eq!(captures[0]["type"], "policy_input_captured");
            assert_eq!(captures[0]["config_id"], "input-capture-delivered");
            assert_eq!(captures[0]["decision"], "allow");
        }
        assert!(received_captures(&mut other).is_empty());
    }

    #[test]
    fn a_capture_is_dropped_for_a_listener_whose_queue_is_full_and_still_reaches_the_others() {
        let (full_queue, mut full) = mpsc::channel(1);
        let _full = listen("input-capture-full", full_queue);
        let (_open, mut open) = listening("input-capture-full");
        let input = json!({ "channel": { "config_id": "input-capture-full" } });

        for _ in 0..3 {
            begin("surface", "input-capture-full", &input, Vec::new)
                .unwrap()
                .finish(Ok((true, None)));
        }

        assert_eq!(received_captures(&mut full).len(), 1);
        assert_eq!(received_captures(&mut open).len(), 3);
    }

    #[test]
    fn an_evaluation_is_not_captured_while_every_listener_queue_is_full() {
        let (queue, mut received) = mpsc::channel(1);
        let _listening = listen("input-capture-no-room", queue);
        let input = json!({ "channel": { "config_id": "input-capture-no-room" } });
        begin("surface", "input-capture-no-room", &input, Vec::new)
            .unwrap()
            .finish(Ok((true, None)));
        let mut listed = false;

        let capture = begin("surface", "input-capture-no-room", &input, || {
            listed = true;
            Vec::new()
        });

        assert!(capture.is_none());
        assert!(!listed);
        assert_eq!(received_captures(&mut received).len(), 1);
        begin("surface", "input-capture-no-room", &input, Vec::new)
            .unwrap()
            .finish(Ok((true, None)));
        let after = received_captures(&mut received);
        assert_eq!(after.len(), 1, "{after:?}");
        assert_eq!(after[0]["type"], "policy_input_skipped");
        assert_eq!(after[0]["skipped"], 1);
    }

    #[test]
    fn an_evaluation_is_listened_only_while_its_surface_is() {
        let input = json!({ "channel": { "config_id": "input-capture-is-listened" } });
        assert!(!is_listened(&input));

        let (_listening, _received) = listening("input-capture-is-listened");

        assert!(is_listened(&input));
        assert!(!is_listened(&json!({ "channel": { "config_id": "input-capture-not-listened" } })));
        set_turned_on_in_this_thread(false);
        assert!(!is_listened(&input));
    }

    #[test]
    fn a_listener_that_missed_captures_is_told_how_many_before_the_next_one() {
        let (queue, mut received) = mpsc::channel(2);
        let _listening = listen("input-capture-skipped", queue);
        let input = json!({ "channel": { "config_id": "input-capture-skipped" } });
        let capture = || {
            if let Some(capture) = begin("surface", "input-capture-skipped", &input, Vec::new) {
                capture.finish(Ok((true, None)));
            }
        };

        for _ in 0..4 {
            capture();
        }
        let first = received_captures(&mut received);
        capture();
        let after = received_captures(&mut received);

        assert_eq!(first.len(), 2, "{first:?}");
        assert!(
            first
                .iter()
                .all(|update| update["type"] == "policy_input_captured")
        );
        assert_eq!(after.len(), 2, "{after:?}");
        assert_eq!(after[0]["type"], "policy_input_skipped");
        assert_eq!(after[0]["config_id"], "input-capture-skipped");
        assert_eq!(after[0]["skipped"], 2);
        assert_eq!(after[1]["type"], "policy_input_captured");
    }

    #[test]
    fn captures_and_skipped_notices_are_queued_with_their_surface_and_the_id_of_their_listen() {
        let (queue, mut received) = mpsc::channel(1);
        let tagged = listen("input-capture-tagged", queue);
        let (other, _other_received) = listening("input-capture-tagged");
        let input = json!({ "channel": { "config_id": "input-capture-tagged" } });
        let capture = || {
            begin("surface", "input-capture-tagged", &input, Vec::new)
                .unwrap()
                .finish(Ok((true, None)))
        };

        capture();
        capture();
        let first = received.try_recv().unwrap();
        capture();
        let notice = received.try_recv().unwrap();

        for (queued, kind) in [(&first, "policy_input_captured"), (&notice, "policy_input_skipped")] {
            assert_eq!(queued.surface_id, "input-capture-tagged");
            assert_eq!(queued.listen, tagged.id());
            let update: Value = serde_json::from_str(&queued.update).unwrap();
            assert_eq!(update["type"], kind);
        }
        assert_ne!(other.id(), tagged.id());
    }

    #[test]
    fn concurrent_captures_report_each_missed_capture_exactly_once() {
        const SENDERS: usize = 8;
        const SENDS: usize = 2_000;
        let (queue, mut received) = mpsc::channel(4);
        let listener = Arc::new(Listener {
            id: 0,
            captures: queue,
            skipped: AtomicU64::new(0),
        });
        let capture: Arc<str> = Arc::from("{\"type\":\"policy_input_captured\"}");
        let sending = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let reader = {
            let sending = Arc::clone(&sending);
            std::thread::spawn(move || {
                let (mut delivered, mut reported) = (0u64, 0u64);
                loop {
                    match received.try_recv() {
                        Ok(update) => {
                            let update: Value = serde_json::from_str(&update.update).unwrap();
                            match update["skipped"].as_u64() {
                                Some(skipped) => reported += skipped,
                                None => delivered += 1,
                            }
                        }
                        Err(_) if !sending.load(Ordering::Acquire) => return (delivered, reported),
                        Err(_) => std::thread::yield_now(),
                    }
                }
            })
        };
        let senders: Vec<_> = (0..SENDERS)
            .map(|_| {
                let listener = Arc::clone(&listener);
                let capture = Arc::clone(&capture);
                std::thread::spawn(move || {
                    for _ in 0..SENDS {
                        listener.send("input-capture-concurrent", &capture);
                    }
                })
            })
            .collect();
        for sender in senders {
            sender.join().unwrap();
        }
        sending.store(false, Ordering::Release);
        let (delivered, reported) = reader.join().unwrap();

        let still_missed = listener
            .skipped
            .load(Ordering::Acquire);
        assert_eq!(delivered + reported + still_missed, (SENDERS * SENDS) as u64);
    }

    #[test]
    fn the_surface_comes_from_the_channel_config_id() {
        let input = json!({ "channel": { "config_id": "alpha", "name": "Alpha" } });

        assert_eq!(surface_of(&input), Some("alpha"));
        assert_eq!(surface_of(&json!({ "http": {} })), None);
    }

    #[test]
    fn a_request_received_over_fabric_is_captured_for_its_surface() {
        let _listening = listening("input-capture-fabric");
        let input = crate::surface_context::PolicyInput::new(
            "POST",
            "/example",
            std::collections::HashMap::new(),
            "inbound",
            Some("did:web:peer.example".to_string()),
            None,
            Some("input-capture-fabric".to_string()),
            "Fabric surface",
        );
        let input = serde_json::to_value(&input).unwrap();

        for (plane, engine, slot) in [
            ("appliance", "gateway", "appliance gateway"),
            ("gateway", "gw-1", "gateway"),
            ("surface", "inbound:input-capture-fabric", "inbound"),
        ] {
            let capture = begin(plane, engine, &input, Vec::new).unwrap_or_else(|| panic!("{plane} is captured"));
            assert_eq!(capture.surface_id, "input-capture-fabric");
            assert_eq!(capture.slot, slot);
        }
    }

    #[test]
    fn a_response_policy_input_names_its_surface_in_surface_id() {
        let input = json!({ "response": { "status_code": 200 }, "surface": { "id": "alpha", "name": "Alpha" } });

        assert_eq!(surface_of(&input), Some("alpha"));
    }

    #[test]
    fn a_response_policy_evaluation_is_captured() {
        let _listening = listening("input-capture-response");
        let input = json!({
            "response": { "status_code": 200, "body": { "result": "done" } },
            "surface": { "id": "input-capture-response" },
        });

        let update = serde_json::to_value(
            begin("surface", "response:pil-allow-message-send", &input, Vec::new)
                .unwrap()
                .into_update(Ok((false, Some("only message/send is allowed")))),
        )
        .unwrap();

        assert_eq!(update["config_id"], "input-capture-response");
        assert_eq!(update["slot"], "response");
        assert_eq!(update["input"]["response"]["body"]["result"], "done");
        assert_eq!(update["decision"], "deny");
    }

    #[test]
    fn a_captured_request_path_keeps_its_parameter_names_but_not_their_values() {
        let _listening = listening("input-capture-query");
        let input = json!({
            "channel": { "config_id": "input-capture-query" },
            "http": { "method": "GET", "path": "/pay/orders?token=secret-token&page=2&flag" },
        });

        let update = update_json(
            begin("surface", "input-capture-query", &input, Vec::new)
                .unwrap()
                .into_update(Ok((true, None))),
        );

        let path = update["input"]["http"]["path"]
            .as_str()
            .unwrap();
        assert_eq!(path, format!("/pay/orders?token={REDACTED}&page={REDACTED}&{REDACTED}"));
        assert!(
            !update
                .to_string()
                .contains("secret-token"),
            "{update}"
        );
    }

    #[test]
    fn a_captured_request_path_without_a_query_is_kept() {
        let _listening = listening("input-capture-plain-path");
        let input = json!({
            "channel": { "config_id": "input-capture-plain-path" },
            "http": { "method": "POST", "path": "/a2a/agent" },
        });

        let update = update_json(
            begin("surface", "input-capture-plain-path", &input, Vec::new)
                .unwrap()
                .into_update(Ok((true, None))),
        );

        assert_eq!(update["input"]["http"]["path"], "/a2a/agent");
    }

    #[test]
    fn credential_named_values_jwts_and_authorization_values_are_masked() {
        let mut input = json!({
            "http": { "headers": { "x-request-id": "r-1", "x-api-key": "k-secret-value" } },
            "source_auth": { "method": "jwt", "token": JWT, "claims": { "sub": "alpha" } },
            "a2a": { "message": { "parts": [{ "text": format!("Bearer {JWT}") }, { "text": JWT }] } },
            "transit": { "caller": { "transit_token": "tt-secret-value" } },
        });

        mask_credentials(&mut input);

        let masked = input.to_string();
        assert!(!masked.contains(JWT), "{masked}");
        assert!(!masked.contains("k-secret-value"), "{masked}");
        assert!(!masked.contains("tt-secret-value"), "{masked}");
        assert_eq!(input["http"]["headers"]["x-api-key"], REDACTED);
        assert_eq!(input["source_auth"]["token"], REDACTED);
        assert_eq!(input["a2a"]["message"]["parts"][0]["text"], REDACTED);
        assert_eq!(input["a2a"]["message"]["parts"][1]["text"], REDACTED);
    }

    #[test]
    fn camel_case_credential_keys_are_masked_and_similar_keys_kept() {
        let mut input = json!({
            "mcp": { "params": { "arguments": {
                "accessToken": "at-secret-value",
                "clientSecret": "cs-secret-value",
                "apiKey": "ak-secret-value",
                "maxTokens": 512,
                "apiKeyId": "key-7",
            } } },
        });

        mask_credentials(&mut input);

        let arguments = &input["mcp"]["params"]["arguments"];
        assert_eq!(arguments["accessToken"], REDACTED);
        assert_eq!(arguments["clientSecret"], REDACTED);
        assert_eq!(arguments["apiKey"], REDACTED);
        assert_eq!(arguments["maxTokens"], 512);
        assert_eq!(arguments["apiKeyId"], "key-7");
    }

    #[test]
    fn a_credential_inside_longer_text_is_masked_and_the_text_around_it_kept() {
        let mut input = json!({
            "a2a": { "parts": [
                { "text": "Authorization: Bearer abc123def456ghi please" },
                { "text": "send basic dXNlcjpwYXNz to it" },
                { "text": format!("the token is {JWT} ok") },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(parts[0]["text"], format!("Authorization: Bearer {REDACTED} please"));
        assert_eq!(parts[1]["text"], format!("send basic {REDACTED} to it"));
        assert_eq!(parts[2]["text"], format!("the token is {REDACTED} ok"));
    }

    #[test]
    fn an_sd_jwt_is_masked_with_its_disclosures_whole_or_inside_text() {
        let sd_jwt = format!("{JWT}~WyJzYWx0IiwiZW1haWwiLCJhQGV4YW1wbGUudGVzdCJd~{JWT}");
        let mut input = json!({
            "source_auth": { "presented": sd_jwt },
            "a2a": { "parts": [{ "text": format!("here is {sd_jwt} for you") }] },
        });

        mask_credentials(&mut input);

        assert_eq!(input["source_auth"]["presented"], REDACTED);
        assert_eq!(input["a2a"]["parts"][0]["text"], format!("here is {REDACTED} for you"));
        assert!(
            !input
                .to_string()
                .contains("WyJzYWx0"),
            "{input}"
        );
    }

    #[test]
    fn a_short_bearer_token_with_a_digit_or_symbol_is_masked_and_a_short_word_kept() {
        let mut input = json!({
            "a2a": { "parts": [
                { "text": "Bearer ab12cd" },
                { "text": "Bearer k-9_x." },
                { "text": "Bearer arms" },
                { "text": "Bearer abcde1" },
                { "text": "Bearer ab1" },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(parts[0]["text"], REDACTED);
        assert_eq!(parts[1]["text"], REDACTED);
        assert_eq!(parts[2]["text"], "Bearer arms");
        assert_eq!(parts[3]["text"], REDACTED);
        assert_eq!(parts[4]["text"], "Bearer ab1");
    }

    #[test]
    fn basic_followed_by_words_is_kept_and_only_a_base64_user_and_password_masked() {
        let mut input = json!({
            "a2a": { "parts": [
                { "text": "Basic authentication" },
                { "text": "Basic understanding of the API" },
                { "text": "Basic YWxpY2U6czNjcmV0" },
                { "text": "Basic YWxpY2VzM2NyZXQ=" },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(parts[0]["text"], "Basic authentication");
        assert_eq!(parts[1]["text"], "Basic understanding of the API");
        assert_eq!(parts[2]["text"], REDACTED);
        assert_eq!(parts[3]["text"], "Basic YWxpY2VzM2NyZXQ=");
    }

    #[test]
    fn a_jwt_in_a_url_query_does_not_shield_the_parameters_after_it() {
        let mut input = json!({
            "mcp": { "arguments": {
                "callback": format!("https://app.example.test/cb?id_token={JWT}&state=s1&code=abc123"),
                "note": format!("open https://app.example.test/cb?token={JWT}&code=abc123 now"),
            } },
        });

        mask_credentials(&mut input);

        let arguments = &input["mcp"]["arguments"];
        assert_eq!(
            arguments["callback"],
            format!("https://app.example.test/cb?id_token={REDACTED}&state={REDACTED}&code={REDACTED}")
        );
        assert_eq!(arguments["note"], format!("open https://app.example.test/cb?token={REDACTED}&code={REDACTED} now"));
        assert!(
            !input
                .to_string()
                .contains("abc123"),
            "{input}"
        );
    }

    #[test]
    fn a_url_anywhere_in_the_input_keeps_its_query_names_and_loses_their_values() {
        let mut input = json!({
            "mcp": { "arguments": {
                "endpoint": "https://api.example.test/v1/items?api_key=k-secret&page=2#top",
                "note": "call back on https://cb.example.test/done?code=abc123 when ready",
                "plain": "https://api.example.test/v1/items",
            } },
        });

        mask_credentials(&mut input);

        let arguments = &input["mcp"]["arguments"];
        assert_eq!(
            arguments["endpoint"],
            format!("https://api.example.test/v1/items?api_key={REDACTED}&page={REDACTED}#top")
        );
        assert_eq!(arguments["note"], format!("call back on https://cb.example.test/done?code={REDACTED} when ready"));
        assert_eq!(arguments["plain"], "https://api.example.test/v1/items");
    }

    #[test]
    fn a_url_anywhere_in_the_input_loses_its_whole_userinfo() {
        let mut input = json!({
            "mcp": { "arguments": {
                "endpoint": "https://user:pw@api.example.test/p",
                "token_as_user": "https://ghp_abc123def456@git.example.test/repo.git",
                "note": "fetch it from ftp://svc:secret@files.example.test/data now",
                "two": "see https://a.example.test/x and https://u:p@b.example.test/y",
                "apostrophe": "https://svc:pa'ss@host.example.test/x",
            } },
        });

        mask_credentials(&mut input);

        let arguments = &input["mcp"]["arguments"];
        assert_eq!(arguments["apostrophe"], format!("https://{REDACTED}@host.example.test/x"));
        assert_eq!(arguments["endpoint"], format!("https://{REDACTED}@api.example.test/p"));
        assert_eq!(arguments["token_as_user"], format!("https://{REDACTED}@git.example.test/repo.git"));
        assert_eq!(arguments["note"], format!("fetch it from ftp://{REDACTED}@files.example.test/data now"));
        assert_eq!(arguments["two"], format!("see https://a.example.test/x and https://{REDACTED}@b.example.test/y"));
    }

    #[test]
    fn a_password_holding_an_at_sign_is_masked_up_to_the_last_at_sign_before_the_path() {
        let mut input = json!({
            "mcp": { "arguments": {
                "path": "https://user:p@ss@host.example.test/x",
                "query": "https://user:p@ss@host.example.test?q=1",
                "fragment": "https://user:p@ss@host.example.test#top",
            } },
        });

        mask_credentials(&mut input);

        let arguments = &input["mcp"]["arguments"];
        assert_eq!(arguments["path"], format!("https://{REDACTED}@host.example.test/x"));
        assert_eq!(arguments["query"], format!("https://{REDACTED}@host.example.test?q={REDACTED}"));
        assert_eq!(arguments["fragment"], format!("https://{REDACTED}@host.example.test#top"));
        assert!(
            !input
                .to_string()
                .contains("ss@"),
            "{input}"
        );
    }

    #[test]
    fn a_url_with_a_jwt_as_its_user_name_in_its_path_and_in_its_query_loses_all_three() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
        let mut input = json!({
            "mcp": { "arguments": {
                "endpoint": format!("https://{jwt}:x@host.example.test/{jwt}?access_token={jwt}&page=2"),
            } },
        });

        mask_credentials(&mut input);

        assert_eq!(
            input["mcp"]["arguments"]["endpoint"],
            format!("https://{REDACTED}@host.example.test/{REDACTED}?access_token={REDACTED}&page={REDACTED}")
        );
    }

    #[test]
    fn a_url_with_userinfo_and_a_query_loses_both() {
        let mut input = json!({
            "mcp": { "arguments": {
                "endpoint": "https://svc:secret@api.example.test/v1/items?api_key=k-secret&page=2",
            } },
        });

        mask_credentials(&mut input);

        assert_eq!(
            input["mcp"]["arguments"]["endpoint"],
            format!("https://{REDACTED}@api.example.test/v1/items?api_key={REDACTED}&page={REDACTED}")
        );
        assert!(
            !input
                .to_string()
                .contains("secret"),
            "{input}"
        );
    }

    #[test]
    fn an_at_sign_outside_url_userinfo_is_kept() {
        let mut input = json!({
            "a2a": { "parts": [
                { "text": "https://host.example.test/users/@alice" },
                { "text": "write to alice@example.test" },
                { "text": "mailto:a@b.test" },
                { "text": "did:web:alice.example.test" },
                { "text": "https://host.example.test#me@x" },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(parts[0]["text"], "https://host.example.test/users/@alice");
        assert_eq!(parts[1]["text"], "write to alice@example.test");
        assert_eq!(parts[2]["text"], "mailto:a@b.test");
        assert_eq!(parts[3]["text"], "did:web:alice.example.test");
        assert_eq!(parts[4]["text"], "https://host.example.test#me@x");
    }

    #[test]
    fn an_authorization_value_is_masked_but_text_that_starts_with_its_scheme_is_kept() {
        let mut input = json!({
            "a2a": { "parts": [
                { "text": "Bearer abc.def-123_xyz" },
                { "text": "basic dXNlcjpwYXNz" },
                { "text": "Bearer\tabcdefghijklmnop" },
                { "text": "Basic plan question" },
                { "text": "Basic plan" },
                { "text": "Bearer arms" },
                { "text": "Bearer abcdefghijklmnop and more words" },
                { "text": "Bearer " },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(parts[0]["text"], REDACTED);
        assert_eq!(parts[1]["text"], REDACTED);
        assert_eq!(parts[2]["text"], REDACTED);
        assert_eq!(parts[3]["text"], "Basic plan question");
        assert_eq!(parts[4]["text"], "Basic plan");
        assert_eq!(parts[5]["text"], "Bearer arms");
        assert_eq!(parts[6]["text"], format!("Bearer {REDACTED} and more words"));
        assert_eq!(parts[7]["text"], "Bearer ");
    }

    #[test]
    fn values_that_are_not_credentials_are_kept() {
        let mut input = json!({
            "http": { "method": "POST", "headers": { "x-request-id": "r-1" } },
            "source_auth": { "method": "jwt", "claims": { "sub": "alpha", "scope": "read" } },
            "mcp": { "method": "tools/call", "tool_name": "lookup", "arguments": { "query": "example.test" } },
            "agent": { "did": "did:web:alpha.example.test" },
        });
        let expected = input.clone();

        mask_credentials(&mut input);

        assert_eq!(input, expected);
    }

    fn update_json(update: WsUpdate) -> Value {
        serde_json::to_value(update).unwrap()
    }

    #[test]
    fn a_captured_input_is_sent_with_its_credentials_masked_and_its_decision() {
        let _listening = listening("input-capture-sent");
        let input = json!({
            "channel": { "config_id": "input-capture-sent" },
            "source_auth": { "method": "jwt", "token": JWT },
            "mcp": { "tool_name": "lookup" },
        });

        let capture = begin("surface", "inbound:input-capture-sent", &input, Vec::new).unwrap();
        let update = update_json(capture.into_update(Ok((false, Some("only message/send is allowed")))));

        assert_eq!(update["type"], "policy_input_captured");
        assert_eq!(update["config_id"], "input-capture-sent");
        assert_eq!(update["plane"], "surface");
        assert_eq!(update["engine"], "inbound:input-capture-sent");
        assert_eq!(update["slot"], "inbound");
        assert_eq!(update["input"]["mcp"]["tool_name"], "lookup");
        assert_eq!(update["input"]["source_auth"]["token"], REDACTED);
        assert_eq!(update["decision"], "deny");
        assert_eq!(update["reason"], "only message/send is allowed");
        assert!(
            update
                .get("transit_point")
                .is_none(),
            "{update}"
        );
    }

    fn policy(
        id: &str,
        name: &str,
    ) -> CapturedPolicy {
        CapturedPolicy {
            id: Some(id.to_string()),
            name: Some(name.to_string()),
            version: Some(3),
        }
    }

    #[test]
    fn a_capture_names_the_policies_its_slot_ran_and_the_one_that_denied() {
        let _listening = listening("input-capture-named");
        let input = json!({ "channel": { "config_id": "input-capture-named" } });

        let update = update_json(
            begin("gateway", "gw-1", &input, || vec![policy("p-1", "Allow partners"), policy("p-2", "Block nights")])
                .unwrap()
                .decided_by(Some("p-2"))
                .into_update(Ok((false, Some("closed at night")))),
        );

        assert_eq!(
            update["policies"],
            json!([
                { "id": "p-1", "name": "Allow partners", "version": 3 },
                { "id": "p-2", "name": "Block nights", "version": 3 },
            ])
        );
        assert_eq!(update["decided_by"], "p-2");
    }

    #[test]
    fn the_policies_are_listed_only_for_a_captured_evaluation() {
        let mut asked = false;
        let unheard = json!({ "channel": { "config_id": "input-capture-unasked" } });

        let capture = begin("surface", "input-capture-unasked", &unheard, || {
            asked = true;
            Vec::new()
        });

        assert!(capture.is_none());
        assert!(!asked);
    }

    #[test]
    fn an_allow_has_no_reason_and_an_error_carries_its_message() {
        let _listening = listening("input-capture-decided");
        let input = json!({ "channel": { "config_id": "input-capture-decided" } });

        let allow = update_json(
            begin("surface", "input-capture-decided", &input, Vec::new)
                .unwrap()
                .into_update(Ok((true, None))),
        );
        let error = update_json(
            begin("surface", "input-capture-decided", &input, Vec::new)
                .unwrap()
                .into_update(Err("no allow rule")),
        );

        assert_eq!(allow["decision"], "allow");
        assert!(allow.get("reason").is_none(), "{allow}");
        assert_eq!(error["decision"], "error");
        assert_eq!(error["reason"], "no allow rule");
    }

    #[test]
    fn a_deny_reason_or_error_holding_a_credential_is_masked() {
        let _listening = listening("input-capture-masked-outcome");
        let input = json!({ "channel": { "config_id": "input-capture-masked-outcome" } });
        let reason = format!("caller sent Bearer {JWT}");
        let error = format!("invalid token {JWT} at https://h.example.test/p?key=k-secret");

        let deny = update_json(
            begin("surface", "input-capture-masked-outcome", &input, Vec::new)
                .unwrap()
                .into_update(Ok((false, Some(reason.as_str())))),
        );
        let failed = update_json(
            begin("surface", "input-capture-masked-outcome", &input, Vec::new)
                .unwrap()
                .into_update(Err(error.as_str())),
        );

        let deny_reason = deny["reason"]
            .as_str()
            .unwrap();
        let failed_reason = failed["reason"]
            .as_str()
            .unwrap();
        assert!(deny_reason.starts_with("caller sent Bearer "), "{deny_reason}");
        assert!(!deny_reason.contains(JWT), "{deny_reason}");
        assert!(failed_reason.starts_with("invalid token "), "{failed_reason}");
        assert!(!failed_reason.contains(JWT), "{failed_reason}");
        assert!(failed_reason.ends_with(&format!(" at https://h.example.test/p?key={REDACTED}")), "{failed_reason}");
    }

    #[test]
    fn a_url_fragment_with_parameters_has_its_values_masked_and_an_anchor_kept() {
        let mut input = json!({
            "a2a": { "parts": [
                { "text": "back to https://app.example.test/cb#access_token=t-secret&state=s1 now" },
                { "text": "see https://app.example.test/p?page=2#id_token=t-secret" },
                { "text": "read https://docs.example.test/guide#top" },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(
            parts[0]["text"],
            format!("back to https://app.example.test/cb#access_token={REDACTED}&state={REDACTED} now")
        );
        assert_eq!(parts[1]["text"], format!("see https://app.example.test/p?page={REDACTED}#id_token={REDACTED}"));
        assert_eq!(parts[2]["text"], "read https://docs.example.test/guide#top");
    }

    #[test]
    fn the_log_redaction_rules_apply_to_captured_input_and_outcome_text() {
        let _listening = listening("input-capture-redaction-rules");
        let input = json!({
            "channel": { "config_id": "input-capture-redaction-rules" },
            "http": { "path": "/a2a/agent?token=t-secret&page=2" },
            "a2a": { "parts": [
                { "text": "fetch https://svc:s3cr3t-pw@host.example.test/path please" },
                { "text": "login with password=hunter2 please" },
                { "text": "contact alice@example.test" },
                { "text": "use agpat_abc123def" },
            ] },
        });

        let update = update_json(
            begin("surface", "input-capture-redaction-rules", &input, Vec::new)
                .unwrap()
                .into_update(Ok((false, Some("alice@example.test is not allowed")))),
        );

        let masked = update.to_string();
        assert!(!masked.contains("hunter2"), "{masked}");
        assert!(!masked.contains("alice@example.test"), "{masked}");
        assert!(!masked.contains("agpat_abc123def"), "{masked}");
        assert!(!masked.contains("s3cr3t"), "{masked}");
        assert!(!masked.contains("t-secret"), "{masked}");
        assert_eq!(
            update["input"]["a2a"]["parts"][0]["text"],
            format!("fetch https://{REDACTED}@host.example.test/path please")
        );
        assert_eq!(update["input"]["http"]["path"], format!("/a2a/agent?token={REDACTED}&page={REDACTED}"));
        assert_eq!(update["reason"], "[REDACTED-EMAIL] is not allowed");
        assert_eq!(update["input"]["channel"]["config_id"], "input-capture-redaction-rules");
    }

    #[test]
    fn a_field_the_log_masks_by_its_name_is_masked_in_the_capture() {
        let _listening = listening("input-capture-field-rules");
        let input = json!({
            "channel": { "config_id": "input-capture-field-rules" },
            "mcp": { "arguments": {
                "clientsecret": "s3cr3t-value",
                "accesstoken": "opaque-value",
                "APIToken": "api-value",
                "note": "kept text",
                "contact": "alice@example.test",
            } },
        });

        let update = update_json(
            begin("surface", "input-capture-field-rules", &input, Vec::new)
                .unwrap()
                .into_update(Ok((true, None))),
        );

        let arguments = &update["input"]["mcp"]["arguments"];
        assert_eq!(arguments["clientsecret"], REDACTED);
        assert_eq!(arguments["accesstoken"], REDACTED);
        assert_eq!(arguments["APIToken"], REDACTED);
        assert_eq!(arguments["note"], "kept text");
        assert_eq!(arguments["contact"], "[REDACTED-EMAIL]");
        assert_eq!(update["input"]["channel"]["config_id"], "input-capture-field-rules");
    }

    #[test]
    fn a_rule_that_changes_only_a_field_name_leaves_its_value() {
        let redactor = crate::observability::opentelemetry::log_redactor();
        assert!(!field_is_redacted("alice@example.test", "kept", &redactor));
        assert!(field_is_redacted("clientsecret", "s3cr3t", &redactor));
        assert!(!field_is_redacted("note", "kept", &redactor));
        assert!(!field_is_redacted("path", "/a2a/agent?token=t-secret", &redactor));
    }

    #[test]
    fn a_url_with_an_apostrophe_still_has_its_query_masked() {
        let mut input = json!({
            "a2a": { "parts": [
                { "text": "use https://svc:pa'ss@host.example.test/path?api_key=k-secret&page=2 now" },
                { "text": "see https://host.example.test/it's?token=t-secret&page=2" },
                { "text": "search https://host.example.test/s?q=it's&token=t-secret" },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(
            parts[0]["text"],
            format!("use https://{REDACTED}@host.example.test/path?api_key={REDACTED}&page={REDACTED} now")
        );
        assert_eq!(parts[1]["text"], format!("see https://host.example.test/it's?token={REDACTED}&page={REDACTED}"));
        assert_eq!(parts[2]["text"], format!("search https://host.example.test/s?q={REDACTED}&token={REDACTED}"));
    }

    #[test]
    fn a_jwt_whose_header_json_holds_whitespace_is_masked_and_similar_words_kept() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let spaced = format!("{}.{}.c2ln", encode(r#"{ "alg": "HS256", "typ": "JWT" }"#), encode(r#"{"sub":"x"}"#));
        let newline = format!("{}.{}.c2ln", encode("{\n  \"alg\": \"HS256\"\n}"), encode(r#"{"sub":"x"}"#));
        assert!(spaced.starts_with("eyAi"), "{spaced}");
        assert!(newline.starts_with("ewo"), "{newline}");
        let mut input = json!({
            "a2a": { "parts": [
                { "text": spaced },
                { "text": format!("the token is {newline} ok") },
                { "text": "see ewe.com.au or eyes.on.it" },
            ] },
        });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(parts[0]["text"], REDACTED);
        assert_eq!(parts[1]["text"], format!("the token is {REDACTED} ok"));
        assert_eq!(parts[2]["text"], "see ewe.com.au or eyes.on.it");
    }

    #[test]
    fn a_jwt_whose_header_json_starts_with_whitespace_is_masked_inside_text() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let payload = encode(r#"{"sub":"x"}"#);
        for lead in [" ", "\t", "\n", "\r", "  ", " \t", "\t ", "\n ", "\r\n", "\t\t", "\n\n", "\r "] {
            let jwt = format!("{}.{payload}.c2ln", encode(&format!(r#"{lead}{{"alg":"HS256"}}"#)));
            let mut input = json!({ "a2a": { "parts": [{ "text": format!("presented {jwt} here") }] } });

            mask_credentials(&mut input);

            assert_eq!(
                input["a2a"]["parts"][0]["text"],
                format!("presented {REDACTED} here"),
                "lead {lead:?}, jwt {jwt}"
            );
        }
    }

    #[test]
    fn a_jwt_after_a_word_and_an_equals_sign_is_masked() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let spaced = format!("{}.{}.c2ln", encode(r#" {"alg":"HS256"}"#), encode(r#"{"sub":"x"}"#));
        assert!(spaced.starts_with("IHsi"), "{spaced}");
        let mut input = json!({ "a2a": { "parts": [
            { "text": format!("CSRF={JWT}") },
            { "text": format!("X-CSRF-Token={JWT}") },
            { "text": format!("DSID={JWT}") },
            { "text": format!("ewe={JWT}") },
            { "text": format!("DSID={spaced}") },
            { "text": "Cisco.com.au CQRS.handler.ts ICE.v2.bak" },
        ] } });

        mask_credentials(&mut input);

        let parts = &input["a2a"]["parts"];
        assert_eq!(parts[0]["text"], format!("CSRF={REDACTED}"));
        assert_eq!(parts[1]["text"], format!("X-CSRF-Token={REDACTED}"));
        assert_eq!(parts[2]["text"], format!("DSID={REDACTED}"));
        assert_eq!(parts[3]["text"], format!("ewe={REDACTED}"));
        assert_eq!(parts[4]["text"], format!("DSID={REDACTED}"));
        assert_eq!(parts[5]["text"], "Cisco.com.au CQRS.handler.ts ICE.v2.bak");
    }

    #[test]
    fn a_jwt_joined_to_the_word_before_it_is_masked() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let spaced = format!("{}.{}.c2ln", encode(r#" {"alg":"HS256"}"#), encode(r#"{"sub":"x"}"#));
        let cases = [
            (format!("Cisco-{JWT}"), format!("Cisco-{REDACTED}")),
            (format!("X-CSRF-Token-{JWT}"), format!("X-CSRF-Token-{REDACTED}")),
            (format!("session_{JWT}"), format!("session_{REDACTED}")),
            (format!("Cisco.{JWT}"), format!("Cisco.{REDACTED}")),
            (format!("eyes-{JWT}"), format!("eyes-{REDACTED}")),
            (format!("Cisco-{spaced}"), format!("Cisco-{REDACTED}")),
            (format!("session_{spaced}"), format!("session_{REDACTED}")),
            (format!("Cisco.{spaced}"), format!("Cisco.{REDACTED}")),
            (
                format!("the cookie session_{JWT}~WyJzIiwibiJd~ expired"),
                format!("the cookie session_{REDACTED} expired"),
            ),
            (format!("the token {JWT}~WyJzIiwibiJd~ expired"), format!("the token {REDACTED} expired")),
            (format!("token {JWT}.Cisco.com.au"), format!("token {REDACTED}")),
            (format!("token {spaced}.Cisco.com.au"), format!("token {REDACTED}")),
            (format!("Cisco.{spaced}.Cisco.com.au"), format!("Cisco.{REDACTED}")),
            (format!("session_{spaced}.Cisco.com.au"), format!("session_{REDACTED}")),
            (format!("{JWT}.{JWT}"), REDACTED.to_string()),
            (format!("{spaced}.{spaced} expired"), format!("{REDACTED} expired")),
        ];
        for (text, expected) in cases {
            let (value, _) = masked(&text);

            assert_eq!(value, Value::String(expected), "{text}");
        }
    }

    #[test]
    fn every_jwt_header_shape_is_masked_after_every_prefix_in_every_place() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let payload = encode(r#"{"sub":"matrix"}"#);
        let signature = "c2lnbmF0dXJlLW1hdHJpeA";
        let headers = [
            encode(r#"{"alg":"HS256"}"#),
            encode(r#"{"kid":"? "}"#),
            encode(r#"{"kid":"> "}"#),
            encode(r#"{   "kid":"? ","alg":"HS256"}"#),
            encode("\t{\"alg\":\"HS256\"}"),
            encode("\n{\"alg\":\"HS256\"}"),
        ];
        assert_eq!(headers[1], "eyJraWQiOiI_ICJ9");
        assert_eq!(headers[2], "eyJraWQiOiI-ICJ9");
        assert_eq!(headers[3], "eyAgICJraWQiOiI_ICIsImFsZyI6IkhTMjU2In0");
        let tokens = headers
            .iter()
            .flat_map(|header| {
                let jwt = format!("{header}.{payload}.{signature}");
                [format!("{jwt}~WyJzIiwibiJd~"), jwt]
            });
        let prefixes = ["", "CSRF=", "session_", "Cisco-", "Cisco.", "Ci-", "a.b.", "X-CSRF-Token-"];

        for token in tokens {
            for prefix in prefixes {
                let whole = format!("{prefix}{token}");
                let sentence = format!("the value {prefix}{token} expired");

                assert_eq!(masked(&whole).0, Value::String(format!("{prefix}{REDACTED}")), "{whole}");
                assert_eq!(
                    masked(&sentence).0,
                    Value::String(format!("the value {prefix}{REDACTED} expired")),
                    "{sentence}"
                );
                let outcome = mask_outcome_text(&sentence);
                assert!(!outcome.contains(&payload) && !outcome.contains(signature), "{sentence} -> {outcome}");
            }
        }
    }

    #[test]
    fn a_jwt_whose_header_holds_more_header_like_runs_than_are_tried_is_still_masked() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let fields: Vec<String> = (0..25)
            .map(|i| format!(r#""k{i:02}":"? ""#))
            .collect();
        let header = encode(&format!("{{{}}}", fields.join(",")));
        let runs = Regex::new(r"[-_.](?:e[wy]|I[ACH]|C[QSXgin]|D[QSX])")
            .unwrap()
            .find_iter(&header)
            .count();
        assert!(runs > MAX_HEADER_STARTS, "{runs} runs in {header}");
        let payload = encode(r#"{"sub":"many-runs"}"#);
        let jwt = format!("{header}.{payload}.c2lnbmF0dXJl");

        for text in [format!("see {jwt} here"), format!("session_{jwt}"), format!("the cookie session_{jwt} expired")] {
            let (value, _) = masked(&text);
            let outcome = mask_outcome_text(&text);

            let value = value
                .as_str()
                .unwrap()
                .to_string();
            assert!(!value.contains(&payload) && !value.contains("c2lnbmF0dXJl"), "{text} -> {value}");
            assert!(!outcome.contains(&payload) && !outcome.contains("c2lnbmF0dXJl"), "{text} -> {outcome}");
        }
    }

    #[test]
    fn dotted_words_joined_to_the_word_before_them_are_kept() {
        for text in [
            "v1-2.3.4",
            "build-2024.11.17",
            "X-Request-Id=abc.def.ghi",
            "key=value.with.dots",
            "Cisco-Ci.a.b session_eyes.on.it",
        ] {
            assert_eq!(masked(text).0, Value::String(text.to_string()));
        }
    }

    fn masked(text: &str) -> (Value, std::time::Duration) {
        let mut value = Value::String(text.to_string());
        let started = thread_cpu_time();
        mask_credentials(&mut value);
        (value, thread_cpu_time() - started)
    }

    /// The CPU time this thread has used. Unlike wall time, it leaves out the time the tests
    /// running beside it take the CPU away.
    fn thread_cpu_time() -> std::time::Duration {
        let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) }, 0);
        std::time::Duration::new(
            u64::try_from(now.tv_sec).expect("CPU time is not negative"),
            u32::try_from(now.tv_nsec).expect("nanoseconds fit in u32"),
        )
    }

    /// The shortest text [`assert_masking_is_linear`] times. The regex engine that resolves
    /// captures changes as the text grows past a few tens of KiB, which raises the time per byte
    /// once and then holds it, so both timed sizes are kept past that change.
    const MIN_LINEAR_INPUT_BYTES: usize = 128 * 1024;

    /// Masks the text `build(scale)` makes, checks each result against the expected text it
    /// returns, and asserts that eight times the input takes under 24 times as long: linear
    /// masking takes about 8, quadratic 64. Runs are timed in this thread's CPU time, so tests
    /// running in parallel do not count. The scale doubles until the text is at least
    /// [`MIN_LINEAR_INPUT_BYTES`] long and a run takes at least 20 ms, so timer noise stays
    /// small next to it, and each size keeps the fastest of three runs. The bound compares the
    /// build with itself, so it holds however slow the build is, coverage instrumentation
    /// included.
    fn assert_masking_is_linear(build: impl Fn(usize) -> (String, String)) {
        let fastest = |scale| {
            let (text, expected) = build(scale);
            let elapsed = (0..3)
                .map(|_| {
                    let (value, elapsed) = masked(&text);
                    assert_eq!(value, Value::String(expected.clone()));
                    elapsed
                })
                .min()
                .unwrap();
            (elapsed, text.len())
        };
        let mut scale = 1;
        let (mut small, mut len) = fastest(scale);
        while len < MIN_LINEAR_INPUT_BYTES || (small < std::time::Duration::from_millis(20) && scale < 64) {
            scale *= 2;
            (small, len) = fastest(scale);
        }
        let (large, _) = fastest(scale * 8);

        assert!(large < small * 24, "{small:?} at scale {scale}, {large:?} at scale {}", scale * 8);
    }

    #[test]
    fn header_like_pieces_are_kept_in_linear_time() {
        let kept = |text: String| (text.clone(), text);
        assert_masking_is_linear(|scale| kept(format!("{}x.a.b", "Ci-".repeat(2_000 * scale))));
        assert_masking_is_linear(|scale| kept("Ci.a.b~".repeat(1_000 * scale)));
        assert_masking_is_linear(|scale| {
            kept(format!("{}{}x.a.b", "Ci.a.b~".repeat(500 * scale), "Ci-".repeat(1_250 * scale)))
        });
        assert_masking_is_linear(|scale| kept(format!("{}x.a.b", "a-".repeat(3_000 * scale))));
        assert_masking_is_linear(|scale| kept(format!("{}b.c", "a.".repeat(3_000 * scale))));
    }

    #[test]
    fn a_jwt_after_a_long_glued_run_is_masked_in_linear_time() {
        for unit in ["a-", "a-Ci-", "Ci-a.", "eyJh-Ci."] {
            assert_masking_is_linear(|scale| {
                let glue = unit.repeat(3_000 * scale);
                (format!("{glue}{JWT}"), format!("{glue}{REDACTED}"))
            });
        }
    }

    #[test]
    fn a_transit_point_policy_names_its_alias() {
        let _listening = listening("input-capture-transit");
        let input = json!({ "channel": { "config_id": "input-capture-transit" } });

        let update = update_json(
            begin("surface", "transit:input-capture-transit:tp-1", &input, Vec::new)
                .unwrap()
                .into_update(Ok((true, None))),
        );

        assert_eq!(update["slot"], "transit tp-1");
        assert_eq!(update["transit_point"], "tp-1");
    }

    #[test]
    fn each_engine_key_names_its_slot() {
        let slot = |plane, engine| slot_of(plane, engine, "s-1");

        assert_eq!(slot("surface", "s-1"), ("target".to_string(), None));
        assert_eq!(slot("surface", "inbound:s-1"), ("inbound".to_string(), None));
        assert_eq!(slot("surface", "outbound:s-1"), ("outbound".to_string(), None));
        assert_eq!(slot("surface", "inbound:variant:s-1:dev"), ("inbound variant dev".to_string(), None));
        assert_eq!(slot("surface", "variant:s-1:dev"), ("target variant dev".to_string(), None));
        assert_eq!(slot("surface", "transit:s-1:tp"), ("transit tp".to_string(), Some("tp".to_string())));
        assert_eq!(slot("surface", "response:def-1"), ("response".to_string(), None));
        assert_eq!(
            slot("surface", "response:transit:s-1:tp"),
            ("transit tp response".to_string(), Some("tp".to_string()))
        );
        assert_eq!(slot("gateway", "gw-1"), ("gateway".to_string(), None));
        assert_eq!(slot("appliance", "gateway"), ("appliance gateway".to_string(), None));
    }

    #[test]
    fn nothing_is_captured_for_a_surface_nobody_listens_to() {
        drop(listening("input-capture-stopped"));
        let stopped = json!({ "channel": { "config_id": "input-capture-stopped" } });
        let unheard = json!({ "channel": { "config_id": "input-capture-unheard" } });

        assert!(begin("surface", "input-capture-stopped", &stopped, Vec::new).is_none());
        assert!(begin("gateway", "self", &unheard, Vec::new).is_none());
        assert!(begin("gateway", "self", &json!({ "http": {} }), Vec::new).is_none());
    }

    #[test]
    fn nothing_is_captured_while_policy_input_capture_is_turned_off_even_for_a_listener() {
        let (_listening, mut received) = listening("input-capture-turned-off");
        let input = json!({ "channel": { "config_id": "input-capture-turned-off" } });
        set_turned_on_in_this_thread(false);

        let captured = begin("surface", "input-capture-turned-off", &input, Vec::new).is_some();

        set_turned_on_in_this_thread(true);
        assert!(!captured);
        assert!(received_captures(&mut received).is_empty());
        assert!(begin("surface", "input-capture-turned-off", &input, Vec::new).is_some());
    }

    #[test]
    fn policy_input_capture_is_on_only_while_its_flag_is_explicitly_true() {
        use crate::storage::settings_store::{DashboardSettings, SettingsStore};
        let directory = tempfile::TempDir::new().unwrap();
        let settings = SettingsStore::new(directory.path());
        let set = |flags: &[(&str, bool)]| {
            settings
                .update(DashboardSettings {
                    feature_flags: flags
                        .iter()
                        .map(|(flag, on)| (flag.to_string(), *on))
                        .collect(),
                    ..DashboardSettings::default()
                })
                .unwrap();
        };

        assert!(!turned_on_in(None), "no settings");
        assert!(!turned_on_in(Some(&settings)), "unset");
        set(&[(FLAG_POLICY_INPUT_CAPTURE, true)]);
        assert!(turned_on_in(Some(&settings)));
        set(&[(FLAG_POLICY_INPUT_CAPTURE, false)]);
        assert!(!turned_on_in(Some(&settings)));
        set(&[("agent_pay_delegation", true)]);
        assert!(!turned_on_in(Some(&settings)), "another flag");
    }

    #[test]
    fn a_dotted_string_that_is_not_a_jwt_is_kept() {
        assert!(!is_jwt("did:web:alpha.example.test"));
        assert!(!is_jwt("1.2.3"));
        assert!(!is_jwt("eyJ..sig"));
        assert!(is_jwt(JWT));
    }
}
