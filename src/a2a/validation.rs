//! A2A request-shape validation beyond the JSON-RPC envelope.
//!
//! [`crate::a2a::errors::validate_jsonrpc_value`] checks only that a body is
//! JSON-RPC 2.0 with a string `method`. This module adds the next layer: the
//! fields A2A itself requires on a request, so a malformed request is refused at
//! the gateway instead of being forwarded to the managed agent.
//!
//! **The spelling of the method picks the rules.** A v0.3 slash-form method
//! (`message/send`, `tasks/get`) is checked against what A2A 0.3 defines, and a
//! v1.0 PascalCase method (`SendMessage`, `GetTask`) against what A2A 1.0
//! defines:
//!
//! - `role` is `user` or `agent` in 0.3, and `ROLE_USER` or `ROLE_AGENT` in 1.0.
//! - A 0.3 `Part` carries one of `text`, `file` (with `bytes` or `uri`) or `data`,
//!   and a `kind`, when present, names it; a 1.0 `Part` carries one of `text`,
//!   `raw`, `url` or `data`.
//! - A 0.3 message's `kind`, when present, is `message`.
//! - `messageId` may be spelled `message_id` in 1.0, as proto JSON allows.
//! - The `status` filter of a task listing names a lowercase state in 0.3
//!   (`working`) and a `TASK_STATE_*` name in 1.0.
//!
//! **Fields a version does not define are ignored**, as A2A 1.0 §5.7 says
//! implementations SHOULD: a `kind` on a 1.0 request, or the other version's
//! part members, are not errors in themselves. A part whose only content is a
//! member of the other version still fails, since it then carries none of its
//! own version's, and the error points at the right member. The official SDKs
//! are stricter and refuse unknown fields; the agent stays free to.
//!
//! The negotiated `A2A-Version` plays no part: version negotiation and shape
//! validation are independent checks. A method outside the A2A method table is
//! checked only for a structured `params`.
//!
//! `kind` is optional in 0.3 here, though the 0.3 JSON schema lists it, because
//! the official 0.3 SDK accepts a message and parts without it. A message must
//! carry at least one part in both versions.
//!
//! Task states are checked only where a **request** carries one, which is the
//! optional `status` filter on a task listing. The states that matter
//! operationally travel on Task **responses** and on streaming events, and the
//! gateway does not inspect either: it forwards responses untouched, which is
//! what keeps it a proxy rather than a task engine.
//!
//! Identifier **format** is deliberately unchecked. A task identifier is required
//! to be present and non-blank on the methods that carry one, because a request
//! that forgot one is simply malformed, but nothing stricter is applied: A2A
//! defines no format for these identifiers, so a shape rule would be an
//! invention of ours that could refuse a conformant agent's ids. `contextId` is
//! not checked at all, being optional in both versions.
//!
//! These run when a surface's `access_point.a2a.validation` is `full`; the
//! default, `envelope`, checks only the JSON-RPC envelope. A request
//! that fails them was already going to fail: a conformant agent refuses it too,
//! just one hop later and with a vaguer error. Refusing here names the offending
//! field and spares the agent the round trip.
//! A surface whose target is `a2a-proxy://` never checks the shape, because the proxy
//! is the implementation rather than a pass-through, so there is no downstream
//! agent that would have refused the message and checking would only refuse
//! callers that work today. The call site is in
//! `src/proxy/handler.rs::proxy_handler_with_mcp_runtime`.
//!
//! The gateway stays a transparent proxy: this validates shape and never
//! rewrites, normalises or fills in a request.

use serde_json::Value;

use crate::a2a::methods::MethodEra as Era;

/// JSON-RPC 2.0 "Invalid params".
pub const ERR_INVALID_PARAMS: i32 = -32602;

/// Most field errors collected for one request. Validation stops walking a
/// message's `parts` once this many are held, so the work, the error response
/// and the log line stay bounded whatever the body size.
pub const MAX_FIELD_ERRORS: usize = 20;

/// One field-level validation problem, reported in the error response `data`
/// so a caller can fix the request without guessing which field was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// Dotted path to the offending field, e.g. `params.message.messageId`.
    pub field: String,
    /// What is wrong with it.
    pub message: String,
}

impl FieldError {
    fn new(
        field: &str,
        message: &str,
    ) -> Self {
        Self {
            field: field.to_string(),
            message: message.to_string(),
        }
    }
}

/// The field errors found on a request, capped at [`MAX_FIELD_ERRORS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldErrors {
    /// The first problems found, in request order.
    pub errors: Vec<FieldError>,
    /// True when more problems were found than [`MAX_FIELD_ERRORS`] allows.
    pub truncated: bool,
}

impl FieldErrors {
    fn push(
        &mut self,
        field: &str,
        message: &str,
    ) {
        if self.errors.len() < MAX_FIELD_ERRORS {
            self.errors
                .push(FieldError::new(field, message));
        } else {
            self.truncated = true;
        }
    }
}

/// Quote a caller-supplied value for an error message, escaped and cut to
/// [`crate::a2a::MAX_LOGGED_CHARS`] chars.
fn echo(value: &str) -> String {
    match crate::a2a::clip(value) {
        (head, true) => format!("{head:?}…"),
        (head, false) => format!("{head:?}"),
    }
}

/// Per-version rules: a request is checked against the A2A version its method
/// is spelled in.
impl Era {
    fn label(self) -> &'static str {
        match self {
            Self::V0_3 => "A2A 0.3",
            Self::V1_0 => "A2A 1.0",
        }
    }

    fn roles(self) -> &'static [&'static str] {
        match self {
            Self::V0_3 => &["user", "agent"],
            Self::V1_0 => &["ROLE_USER", "ROLE_AGENT"],
        }
    }

    /// The content members a `Part` may carry; exactly one must be present.
    fn part_members(self) -> &'static [&'static str] {
        match self {
            Self::V0_3 => &["text", "file", "data"],
            Self::V1_0 => &["text", "raw", "url", "data"],
        }
    }

    /// A pointer to this version's member for a member of the other version,
    /// added to the error of a part that carries no member of its own version.
    fn foreign_part_member(
        self,
        member: &str,
    ) -> Option<&'static str> {
        match (self, member) {
            (Self::V0_3, "raw" | "url") => Some("use file, with bytes or uri"),
            (Self::V1_0, "file") => Some("use raw or url"),
            _ => None,
        }
    }

    fn task_states(self) -> &'static [&'static str] {
        match self {
            Self::V0_3 => &[
                "submitted",
                "working",
                "input-required",
                "completed",
                "canceled",
                "failed",
                "rejected",
                "auth-required",
                "unknown",
            ],
            Self::V1_0 => &[
                "TASK_STATE_SUBMITTED",
                "TASK_STATE_WORKING",
                "TASK_STATE_INPUT_REQUIRED",
                "TASK_STATE_COMPLETED",
                "TASK_STATE_CANCELED",
                "TASK_STATE_FAILED",
                "TASK_STATE_REJECTED",
                "TASK_STATE_AUTH_REQUIRED",
                "TASK_STATE_UNSPECIFIED",
            ],
        }
    }
}

/// The rules a request is checked against: its version and its method as sent,
/// which error messages name.
#[derive(Clone, Copy)]
struct Rules<'a> {
    era: Era,
    method: &'a str,
}

impl Rules<'_> {
    fn context(&self) -> String {
        format!("{} ({})", self.era.label(), self.method)
    }
}

/// Validate an A2A request beyond its JSON-RPC envelope, against the rules of
/// the A2A version its method is spelled in.
///
/// Returns every problem found rather than the first, up to
/// [`MAX_FIELD_ERRORS`], so a caller can fix the request in one pass. `Ok(())`
/// means the request passed these checks; it does not mean the upstream agent
/// will accept it.
///
/// The envelope itself (`jsonrpc`, `method`) is assumed already validated by
/// [`crate::a2a::errors::validate_jsonrpc_value`]; a body without a string
/// `method` is passed through untouched here so the two layers report their own
/// errors rather than masking each other.
pub fn validate_request_shape(json: &Value) -> Result<(), FieldErrors> {
    let Some(method) = json
        .get("method")
        .and_then(Value::as_str)
    else {
        return Ok(());
    };

    let mut errors = FieldErrors::default();

    // JSON-RPC 2.0 allows `params` to be omitted, but when present it must be a
    // structured value. This holds for every method.
    if let Some(params) = json.get("params")
        && !params.is_object()
        && !params.is_array()
    {
        errors.push("params", "must be an object or an array when present");
        return Err(errors);
    }

    if let Some(era) = Era::of(method) {
        let rules = Rules { era, method };
        match crate::a2a::canonical_method(method) {
            "message/send" | "message/stream" => validate_message_params(json, rules, &mut errors),
            "tasks/list" => validate_list_tasks_params(json, rules, &mut errors),
            "tasks/get" | "tasks/cancel" | "tasks/resubscribe" => validate_task_id(json, &mut errors),
            _ => {}
        }
    }

    if errors.errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Checks for the methods that carry a `Message` in `params.message`.
fn validate_message_params(
    json: &Value,
    rules: Rules<'_>,
    errors: &mut FieldErrors,
) {
    let Some(params) = json.get("params") else {
        errors.push("params", "is required for this method");
        return;
    };
    let Some(params) = params.as_object() else {
        errors.push("params", "must be an object for this method");
        return;
    };

    let Some(message) = params.get("message") else {
        errors.push("params.message", "is required for this method");
        return;
    };
    let Some(message) = message.as_object() else {
        errors.push("params.message", "must be an object");
        return;
    };

    if rules.era == Era::V0_3
        && let Some(kind) = message.get("kind")
        && kind.as_str() != Some("message")
    {
        errors.push("params.message.kind", &format!("must be \"message\" in {}", rules.context()));
    }

    let message_id = match rules.era {
        Era::V0_3 => message.get("messageId"),
        Era::V1_0 => message
            .get("messageId")
            .or_else(|| message.get("message_id")),
    };
    match message_id {
        None => errors.push("params.message.messageId", "is required"),
        Some(value) => match value.as_str() {
            Some(s) if !s.trim().is_empty() => {}
            Some(_) => errors.push("params.message.messageId", "must not be empty"),
            None => errors.push("params.message.messageId", "must be a string"),
        },
    }

    validate_role(message.get("role"), rules, errors);

    match message.get("parts") {
        None => errors.push("params.message.parts", "is required"),
        Some(value) => match value.as_array() {
            Some(parts) if !parts.is_empty() => {
                for (index, part) in parts.iter().enumerate() {
                    if errors.truncated {
                        break;
                    }
                    validate_part(part, index, rules, errors);
                }
            }
            Some(_) => errors.push("params.message.parts", "must not be empty"),
            None => errors.push("params.message.parts", "must be an array"),
        },
    }
}

/// Check only that a task identifier is present and not blank.
///
/// The field is `params.id` in both versions. A2A does not define a format for
/// these identifiers, so anything stricter would be a rule of our own invention
/// that could refuse a conformant agent's ids. Presence is the useful check: it
/// catches the request that forgot one.
fn validate_task_id(
    json: &Value,
    errors: &mut FieldErrors,
) {
    let Some(params) = json.get("params") else {
        errors.push("params", "is required for this method");
        return;
    };
    match params.get("id") {
        None => errors.push("params.id", "is required for this method"),
        Some(value) => match value.as_str() {
            Some(id) if !id.trim().is_empty() => {}
            Some(_) => errors.push("params.id", "must not be empty"),
            None => errors.push("params.id", "must be a string"),
        },
    }
}

/// A task listing is the only request that carries a task state: an optional
/// `status` filter. Absence is fine; a value that names no task state of the
/// method's version is not, since the upstream would filter on something
/// meaningless.
fn validate_list_tasks_params(
    json: &Value,
    rules: Rules<'_>,
    errors: &mut FieldErrors,
) {
    let Some(status) = json
        .get("params")
        .and_then(|params| params.get("status"))
    else {
        return;
    };

    match status.as_str() {
        Some(value)
            if rules
                .era
                .task_states()
                .contains(&value) => {}
        Some(_) => errors.push(
            "params.status",
            &format!(
                "must be a task state of {}, such as {}",
                rules.context(),
                match rules.era {
                    Era::V0_3 => "working or completed",
                    Era::V1_0 => "TASK_STATE_WORKING or TASK_STATE_COMPLETED",
                }
            ),
        ),
        None => errors.push("params.status", "must be a string"),
    }
}

fn validate_role(
    role: Option<&Value>,
    rules: Rules<'_>,
    errors: &mut FieldErrors,
) {
    let Some(role) = role else {
        errors.push("params.message.role", "is required");
        return;
    };
    match role.as_str() {
        Some(value)
            if rules
                .era
                .roles()
                .contains(&value) => {}
        Some(_) => errors
            .push("params.message.role", &format!("must be {} in {}", rules.era.roles().join(" or "), rules.context())),
        None => errors.push("params.message.role", "must be a string"),
    }
}

fn validate_part(
    part: &Value,
    index: usize,
    rules: Rules<'_>,
    errors: &mut FieldErrors,
) {
    let field = |suffix: &str| format!("params.message.parts[{index}]{suffix}");

    let Some(part) = part.as_object() else {
        errors.push(&field(""), "must be an object");
        return;
    };

    let present: Vec<&str> = rules
        .era
        .part_members()
        .iter()
        .copied()
        .filter(|member| part.contains_key(*member))
        .collect();
    match present.as_slice() {
        [member] => validate_part_content(part, member, &field, rules, errors),
        [] => {
            let hints: Vec<String> = part
                .keys()
                .filter_map(|member| {
                    rules
                        .era
                        .foreign_part_member(member)
                        .map(|hint| format!("; {member} is not a part member there, {hint}"))
                })
                .collect();
            errors.push(
                &field(""),
                &format!(
                    "must carry exactly one content member ({}) in {}{}",
                    rules
                        .era
                        .part_members()
                        .join(", "),
                    rules.context(),
                    hints.concat()
                ),
            )
        }
        _ => errors.push(&field(""), &format!("must carry exactly one content member, found {}", present.join(", "))),
    }

    if rules.era == Era::V0_3
        && let Some(kind) = part.get("kind")
    {
        match kind.as_str() {
            Some(kind) => {
                if present.len() == 1 && present[0] != kind {
                    errors.push(&field(".kind"), &format!("says {} but the part carries '{}'", echo(kind), present[0]));
                }
            }
            None => errors.push(&field(".kind"), "must be a string"),
        }
    }
}

/// The value of a part's one content member must have its version's type.
fn validate_part_content(
    part: &serde_json::Map<String, Value>,
    member: &str,
    field: &dyn Fn(&str) -> String,
    rules: Rules<'_>,
    errors: &mut FieldErrors,
) {
    let value = &part[member];
    let path = field(&format!(".{member}"));
    match (rules.era, member) {
        (_, "text") | (Era::V1_0, "raw" | "url") if !value.is_string() => errors.push(&path, "must be a string"),
        (Era::V0_3, "data") if !value.is_object() => errors.push(&path, "must be an object"),
        (Era::V0_3, "file") => match value.as_object() {
            None => errors.push(&path, "must be an object"),
            Some(file) => match (file.get("bytes"), file.get("uri")) {
                (Some(_), Some(_)) => errors.push(&path, "must carry bytes or uri, not both"),
                (Some(content), None) | (None, Some(content)) if !content.is_string() => {
                    errors.push(&path, "bytes or uri must be a string")
                }
                (None, None) => errors.push(&path, "must carry bytes or uri"),
                _ => {}
            },
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(
        method: &str,
        params: Value,
    ) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    fn send_v0_3(message: Value) -> Value {
        request("message/send", json!({ "message": message }))
    }

    fn send_v1_0(message: Value) -> Value {
        request("SendMessage", json!({ "message": message }))
    }

    fn valid_v0_3_message() -> Value {
        json!({ "kind": "message", "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] })
    }

    fn valid_v1_0_message() -> Value {
        json!({ "role": "ROLE_USER", "messageId": "m-1", "parts": [{ "text": "hi" }] })
    }

    fn with(
        mut message: Value,
        field: &str,
        value: Value,
    ) -> Value {
        message[field] = value;
        message
    }

    fn without(
        mut message: Value,
        field: &str,
    ) -> Value {
        message
            .as_object_mut()
            .unwrap()
            .remove(field);
        message
    }

    fn errors(result: Result<(), FieldErrors>) -> Vec<(String, String)> {
        result
            .unwrap_err()
            .errors
            .into_iter()
            .map(|e| (e.field, e.message))
            .collect()
    }

    fn fields(result: Result<(), FieldErrors>) -> Vec<String> {
        errors(result)
            .into_iter()
            .map(|(field, _)| field)
            .collect()
    }

    // ── A valid request in each version ──────────────────────────────────

    #[test]
    fn accepts_a_valid_request_in_each_version() {
        assert_eq!(validate_request_shape(&send_v0_3(valid_v0_3_message())), Ok(()));
        assert_eq!(validate_request_shape(&send_v1_0(valid_v1_0_message())), Ok(()));
        for method in ["message/stream", "SendStreamingMessage"] {
            let message = if method == "message/stream" {
                valid_v0_3_message()
            } else {
                valid_v1_0_message()
            };
            assert_eq!(validate_request_shape(&request(method, json!({ "message": message }))), Ok(()), "{method}");
        }
    }

    /// The official 0.3 SDK accepts a message and parts without `kind`, so a 0.3
    /// request does not need it, although the 0.3 JSON schema lists it.
    #[test]
    fn a_v0_3_request_may_leave_out_kind() {
        let message = json!({ "role": "agent", "messageId": "m-1", "parts": [{ "text": "hi" }] });
        assert_eq!(validate_request_shape(&send_v0_3(message)), Ok(()));
    }

    /// The method's spelling alone picks the rules: nothing about the request,
    /// such as an `A2A-Version` header, is consulted. Of the other version's
    /// dialect, only what this version defines differently fails: the `role`
    /// values. Its `kind` fields are unrecognized here and ignored.
    #[test]
    fn the_other_versions_dialect_fails_on_what_this_version_defines() {
        assert_eq!(fields(validate_request_shape(&send_v1_0(valid_v0_3_message()))), vec!["params.message.role"]);
        assert_eq!(fields(validate_request_shape(&send_v0_3(valid_v1_0_message()))), vec!["params.message.role"]);
    }

    // ── messageId ────────────────────────────────────────────────────────

    #[test]
    fn rejects_a_missing_empty_or_non_string_message_id_in_either_version() {
        for (send, message) in
            [(send_v0_3 as fn(Value) -> Value, valid_v0_3_message()), (send_v1_0, valid_v1_0_message())]
        {
            for bad in [None, Some(json!("  ")), Some(json!(7))] {
                let message = match &bad {
                    None => without(message.clone(), "messageId"),
                    Some(value) => with(message.clone(), "messageId", value.clone()),
                };
                assert_eq!(fields(validate_request_shape(&send(message))), vec!["params.message.messageId"], "{bad:?}");
            }
        }
    }

    /// Proto JSON permits the original field name, so a 1.0 request may spell it
    /// `message_id`. 0.3 has no proto form, so it may not.
    #[test]
    fn only_a_v1_0_request_may_spell_message_id_in_snake_case() {
        let v1_0 = with(without(valid_v1_0_message(), "messageId"), "message_id", json!("m-1"));
        assert_eq!(validate_request_shape(&send_v1_0(v1_0)), Ok(()));

        let v0_3 = with(without(valid_v0_3_message(), "messageId"), "message_id", json!("m-1"));
        assert_eq!(fields(validate_request_shape(&send_v0_3(v0_3))), vec!["params.message.messageId"]);
    }

    // ── role ─────────────────────────────────────────────────────────────

    #[test]
    fn a_v0_3_request_takes_the_v0_3_roles_only() {
        for role in ["user", "agent"] {
            assert_eq!(validate_request_shape(&send_v0_3(with(valid_v0_3_message(), "role", json!(role)))), Ok(()));
        }
        for role in ["ROLE_USER", "ROLE_AGENT", "wizard"] {
            assert_eq!(
                errors(validate_request_shape(&send_v0_3(with(valid_v0_3_message(), "role", json!(role))))),
                vec![(
                    "params.message.role".to_string(),
                    "must be user or agent in A2A 0.3 (message/send)".to_string()
                )],
                "{role}"
            );
        }
    }

    #[test]
    fn a_v1_0_request_takes_the_v1_0_roles_only() {
        for role in ["ROLE_USER", "ROLE_AGENT"] {
            assert_eq!(validate_request_shape(&send_v1_0(with(valid_v1_0_message(), "role", json!(role)))), Ok(()));
        }
        for role in ["user", "agent", "ROLE_UNSPECIFIED"] {
            assert_eq!(
                errors(validate_request_shape(&send_v1_0(with(valid_v1_0_message(), "role", json!(role))))),
                vec![(
                    "params.message.role".to_string(),
                    "must be ROLE_USER or ROLE_AGENT in A2A 1.0 (SendMessage)".to_string()
                )],
                "{role}"
            );
        }
    }

    #[test]
    fn rejects_a_missing_or_non_string_role() {
        assert_eq!(
            fields(validate_request_shape(&send_v1_0(without(valid_v1_0_message(), "role")))),
            vec!["params.message.role"]
        );
        assert_eq!(
            fields(validate_request_shape(&send_v0_3(with(valid_v0_3_message(), "role", json!(1))))),
            vec!["params.message.role"]
        );
    }

    // ── message kind ─────────────────────────────────────────────────────

    #[test]
    fn a_v0_3_message_kind_must_be_message() {
        assert_eq!(
            errors(validate_request_shape(&send_v0_3(with(valid_v0_3_message(), "kind", json!("task"))))),
            vec![("params.message.kind".to_string(), "must be \"message\" in A2A 0.3 (message/send)".to_string())]
        );
    }

    /// A2A 1.0 has no `kind`, so it is an unrecognized field there and ignored,
    /// whatever its value (A2A 1.0 §5.7).
    #[test]
    fn a_kind_on_a_v1_0_request_is_ignored() {
        for kind in [json!("message"), json!("anything"), json!(3)] {
            let message = with(valid_v1_0_message(), "kind", kind.clone());
            let message = with(message, "parts", json!([{ "kind": kind, "text": "hi" }]));
            assert_eq!(validate_request_shape(&send_v1_0(message)), Ok(()), "{kind}");
        }
    }

    // ── parts ────────────────────────────────────────────────────────────

    fn v0_3_part(part: Value) -> Value {
        send_v0_3(with(valid_v0_3_message(), "parts", json!([part])))
    }

    fn v1_0_part(part: Value) -> Value {
        send_v1_0(with(valid_v1_0_message(), "parts", json!([part])))
    }

    #[test]
    fn rejects_missing_empty_or_non_array_parts_in_either_version() {
        for parts in [None, Some(json!([])), Some(json!("hi"))] {
            let v0_3 = match &parts {
                None => without(valid_v0_3_message(), "parts"),
                Some(value) => with(valid_v0_3_message(), "parts", value.clone()),
            };
            let v1_0 = match &parts {
                None => without(valid_v1_0_message(), "parts"),
                Some(value) => with(valid_v1_0_message(), "parts", value.clone()),
            };
            assert_eq!(fields(validate_request_shape(&send_v0_3(v0_3))), vec!["params.message.parts"], "{parts:?}");
            assert_eq!(fields(validate_request_shape(&send_v1_0(v1_0))), vec!["params.message.parts"], "{parts:?}");
        }
    }

    #[test]
    fn accepts_each_v0_3_part_shape() {
        for part in [
            json!({ "kind": "text", "text": "hi" }),
            json!({ "kind": "file", "file": { "bytes": "aGk=", "name": "a.txt" } }),
            json!({ "kind": "file", "file": { "uri": "https://example.com/a" } }),
            json!({ "kind": "data", "data": { "a": 1 } }),
            json!({ "text": "hi", "metadata": { "x": 1 } }),
        ] {
            assert_eq!(validate_request_shape(&v0_3_part(part.clone())), Ok(()), "{part}");
        }
    }

    #[test]
    fn accepts_each_v1_0_part_shape() {
        for part in [
            json!({ "text": "hi" }),
            json!({ "raw": "aGk=", "filename": "a.txt", "mediaType": "text/plain" }),
            json!({ "url": "https://example.com/a" }),
            json!({ "data": { "a": 1 } }),
            json!({ "data": [1, 2] }),
        ] {
            assert_eq!(validate_request_shape(&v1_0_part(part.clone())), Ok(()), "{part}");
        }
    }

    /// The other version's part members are unrecognized and ignored next to a
    /// member of this version.
    #[test]
    fn the_other_versions_part_members_are_ignored_next_to_a_valid_one() {
        assert_eq!(
            validate_request_shape(&v0_3_part(json!({ "kind": "text", "text": "hi", "url": "https://x" }))),
            Ok(())
        );
        assert_eq!(validate_request_shape(&v1_0_part(json!({ "text": "hi", "file": { "uri": "https://x" } }))), Ok(()));
    }

    /// A part whose only content is the other version's member carries none of
    /// its own, so it fails, and the error points at the right member.
    #[test]
    fn a_part_with_only_the_other_versions_member_is_refused_with_a_pointer() {
        assert_eq!(
            errors(validate_request_shape(&v0_3_part(json!({ "raw": "aGk=" })))),
            vec![(
                "params.message.parts[0]".to_string(),
                "must carry exactly one content member (text, file, data) in A2A 0.3 (message/send); raw is not a \
                 part member there, use file, with bytes or uri"
                    .to_string()
            )]
        );
        assert_eq!(
            errors(validate_request_shape(&v1_0_part(json!({ "file": { "uri": "https://example.com/a" } })))),
            vec![(
                "params.message.parts[0]".to_string(),
                "must carry exactly one content member (text, raw, url, data) in A2A 1.0 (SendMessage); file is not a \
                 part member there, use raw or url"
                    .to_string()
            )]
        );
    }

    #[test]
    fn rejects_a_part_with_no_or_more_than_one_content_member() {
        assert_eq!(
            fields(validate_request_shape(&v1_0_part(json!({ "mediaType": "text/plain" })))),
            vec!["params.message.parts[0]"]
        );
        let errs = errors(validate_request_shape(&v1_0_part(json!({ "text": "hi", "url": "https://example.com/a" }))));
        assert_eq!(
            errs,
            vec![(
                "params.message.parts[0]".to_string(),
                "must carry exactly one content member, found text, url".to_string()
            )]
        );
    }

    #[test]
    fn rejects_content_of_the_wrong_type() {
        for (body, field) in [
            (v0_3_part(json!({ "kind": "text", "text": 1 })), "params.message.parts[0].text"),
            (v0_3_part(json!({ "kind": "data", "data": "x" })), "params.message.parts[0].data"),
            (v0_3_part(json!({ "kind": "file", "file": "x" })), "params.message.parts[0].file"),
            (v0_3_part(json!({ "kind": "file", "file": { "name": "a" } })), "params.message.parts[0].file"),
            (
                v0_3_part(json!({ "kind": "file", "file": { "bytes": "a", "uri": "b" } })),
                "params.message.parts[0].file",
            ),
            (v0_3_part(json!({ "kind": "file", "file": { "uri": 3 } })), "params.message.parts[0].file"),
            (v1_0_part(json!({ "text": 1 })), "params.message.parts[0].text"),
            (v1_0_part(json!({ "raw": 1 })), "params.message.parts[0].raw"),
            (v1_0_part(json!({ "url": {} })), "params.message.parts[0].url"),
        ] {
            assert_eq!(fields(validate_request_shape(&body)), vec![field], "{body}");
        }
    }

    /// A 0.3 part that mislabels its own content is malformed even though each
    /// half is individually well-formed.
    #[test]
    fn rejects_a_v0_3_kind_that_disagrees_with_the_content() {
        assert_eq!(
            errors(validate_request_shape(&v0_3_part(json!({ "kind": "file", "text": "hi" })))),
            vec![("params.message.parts[0].kind".to_string(), "says \"file\" but the part carries 'text'".to_string())]
        );
    }

    #[test]
    fn reports_the_offending_part_by_index() {
        let body =
            send_v1_0(with(valid_v1_0_message(), "parts", json!([{ "text": "ok" }, { "text": "no", "data": {} }])));
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.message.parts[1]"]);
    }

    #[test]
    fn reports_every_problem_at_once() {
        let body = send_v1_0(json!({ "role": "user" }));
        assert_eq!(
            fields(validate_request_shape(&body)),
            vec!["params.message.messageId", "params.message.role", "params.message.parts"],
            "a caller should be able to fix the request in one pass"
        );
    }

    #[test]
    fn rejects_a_send_without_params_or_message() {
        let no_params = json!({ "jsonrpc": "2.0", "id": 1, "method": "SendMessage" });
        assert_eq!(fields(validate_request_shape(&no_params)), vec!["params"]);
        assert_eq!(fields(validate_request_shape(&request("message/send", json!({})))), vec!["params.message"]);
    }

    #[test]
    fn rejects_a_scalar_params_container_for_any_method() {
        for method in ["GetTask", "tasks/send", "custom/method"] {
            assert_eq!(fields(validate_request_shape(&request(method, json!("nope")))), vec!["params"], "{method}");
        }
    }

    /// Unknown extension fields must survive: A2A requires them to be preserved
    /// and ignored, and the gateway forwards the body unchanged.
    #[test]
    fn ignores_unknown_extension_fields() {
        let message = with(valid_v1_0_message(), "x-vendor-extension", json!({ "anything": true }));
        assert_eq!(validate_request_shape(&send_v1_0(message)), Ok(()));
    }

    /// A method outside the A2A method table, such as the pre-0.2 `tasks/send`,
    /// has no version to check against.
    #[test]
    fn a_method_outside_the_a2a_table_is_not_constrained() {
        for method in ["tasks/send", "custom/method"] {
            assert_eq!(validate_request_shape(&request(method, json!({ "message": {} }))), Ok(()), "{method}");
        }
    }

    // ── Task listings: the status filter ─────────────────────────────────

    #[test]
    fn a_task_listing_takes_the_states_of_its_methods_version() {
        let v0_3 = Era::V0_3.task_states();
        let v1_0 = Era::V1_0.task_states();
        for state in v0_3 {
            assert_eq!(validate_request_shape(&request("tasks/list", json!({ "status": state }))), Ok(()), "{state}");
            assert_eq!(
                fields(validate_request_shape(&request("ListTasks", json!({ "status": state })))),
                vec!["params.status"],
                "{state}"
            );
        }
        for state in v1_0 {
            assert_eq!(validate_request_shape(&request("ListTasks", json!({ "status": state }))), Ok(()), "{state}");
            assert_eq!(
                fields(validate_request_shape(&request("tasks/list", json!({ "status": state })))),
                vec!["params.status"],
                "{state}"
            );
        }
        assert_eq!(
            errors(validate_request_shape(&request("ListTasks", json!({ "status": "cancelled" })))),
            vec![(
                "params.status".to_string(),
                "must be a task state of A2A 1.0 (ListTasks), such as TASK_STATE_WORKING or TASK_STATE_COMPLETED"
                    .to_string()
            )]
        );
    }

    #[test]
    fn the_status_filter_is_optional_and_must_be_a_string() {
        for params in [json!({}), json!({ "contextId": "c-1" })] {
            assert_eq!(validate_request_shape(&request("ListTasks", params)), Ok(()));
        }
        assert_eq!(validate_request_shape(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ListTasks" })), Ok(()));
        assert_eq!(
            fields(validate_request_shape(&request("tasks/list", json!({ "status": 3 })))),
            vec!["params.status"]
        );
    }

    /// The status filter belongs to task listings alone.
    #[test]
    fn a_status_field_on_another_method_is_not_constrained() {
        assert_eq!(
            validate_request_shape(&request("GetTask", json!({ "id": "task-1", "status": "nonsense" }))),
            Ok(())
        );
    }

    #[test]
    fn does_not_constrain_push_config_methods() {
        for method in ["DeleteTaskPushNotificationConfig", "tasks/pushNotificationConfig/set"] {
            assert_eq!(validate_request_shape(&request(method, json!({ "id": "t-1" }))), Ok(()), "{method}");
        }
    }

    // ── Task identifiers: presence only ──────────────────────────────────

    #[test]
    fn accepts_a_task_id_in_either_version() {
        for method in ["tasks/get", "GetTask", "tasks/cancel", "CancelTask", "tasks/resubscribe", "SubscribeToTask"] {
            assert_eq!(validate_request_shape(&request(method, json!({ "id": "task-1" }))), Ok(()), "{method}");
        }
    }

    #[test]
    fn rejects_a_missing_or_blank_task_id() {
        for method in ["GetTask", "tasks/get"] {
            for params in [json!({}), json!({ "id": "  " }), json!({ "id": 7 })] {
                assert_eq!(fields(validate_request_shape(&request(method, params))), vec!["params.id"], "{method}");
            }
        }
    }

    /// A2A defines no format for task identifiers, so anything a caller chooses
    /// is accepted.
    #[test]
    fn does_not_impose_a_format_on_task_ids() {
        for id in ["550e8400-e29b-41d4-a716-446655440000", "task_42", "a", "urn:x:1"] {
            assert_eq!(validate_request_shape(&request("GetTask", json!({ "id": id }))), Ok(()), "{id}");
        }
    }

    /// A body the envelope layer will reject is left to that layer.
    #[test]
    fn defers_to_the_envelope_layer_when_method_is_absent() {
        assert_eq!(validate_request_shape(&json!({ "jsonrpc": "2.0", "id": 1 })), Ok(()));
    }

    // ── Bounded errors: body size must not amplify the error ─────────────

    fn body_with_bad_parts(count: usize) -> Value {
        send_v1_0(with(valid_v1_0_message(), "parts", json!(vec![json!(0); count])))
    }

    #[test]
    fn caps_the_errors_for_a_huge_run_of_bad_parts() {
        let errs = validate_request_shape(&body_with_bad_parts(10_000)).unwrap_err();
        assert_eq!(errs.errors.len(), MAX_FIELD_ERRORS);
        assert!(errs.truncated);
        assert_eq!(errs.errors[0].field, "params.message.parts[0]");
        assert_eq!(errs.errors[MAX_FIELD_ERRORS - 1].field, format!("params.message.parts[{}]", MAX_FIELD_ERRORS - 1));
    }

    #[test]
    fn exactly_the_cap_is_not_truncated() {
        let errs = validate_request_shape(&body_with_bad_parts(MAX_FIELD_ERRORS)).unwrap_err();
        assert_eq!(errs.errors.len(), MAX_FIELD_ERRORS);
        assert!(!errs.truncated);
    }

    #[test]
    fn one_past_the_cap_is_truncated() {
        let errs = validate_request_shape(&body_with_bad_parts(MAX_FIELD_ERRORS + 1)).unwrap_err();
        assert_eq!(errs.errors.len(), MAX_FIELD_ERRORS);
        assert!(errs.truncated);
    }

    #[test]
    fn bounds_and_escapes_a_huge_multibyte_kind() {
        let kind = "\u{1F600}\"".repeat(10_000);
        let errs = validate_request_shape(&v0_3_part(json!({ "kind": kind, "text": "hi" })))
            .unwrap_err()
            .errors;
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].field, "params.message.parts[0].kind");
        let expected_head = format!("{:?}…", "\u{1F600}\"".repeat(crate::a2a::MAX_LOGGED_CHARS / 2));
        assert!(
            errs[0]
                .message
                .starts_with(&format!("says {expected_head} ")),
            "{}",
            errs[0].message
        );
        assert!(
            errs[0]
                .message
                .contains("\\\""),
            "the quote should be escaped: {}",
            errs[0].message
        );
        assert!(
            errs[0]
                .message
                .chars()
                .count()
                < 200,
            "{}",
            errs[0].message
        );
    }
}
