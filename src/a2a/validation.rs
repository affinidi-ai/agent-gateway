//! A2A request-shape validation beyond the JSON-RPC envelope.
//!
//! [`crate::a2a::errors::validate_jsonrpc_value`] checks only that a body is
//! JSON-RPC 2.0 with a string `method`. This module adds the next layer: the
//! fields A2A itself requires on a request, so a malformed request is refused at
//! the gateway instead of being forwarded to the managed agent.
//!
//! **Both protocol eras are accepted everywhere.** Where a field is spelled the
//! same in v0.3 and v1.0 it is checked directly. Where the eras differ, the union
//! of both spellings is accepted rather than picking a side, because the gateway
//! serves callers of either era and must not reject one of them:
//!
//! - `role` is `"user"`/`"agent"` in v0.3 and `"ROLE_USER"`/`"ROLE_AGENT"` in v1.0.
//! - A `Part` carries a `kind` discriminator in v0.3 and none in v1.0, where it is
//!   a choice between `text`, `raw`, `url` and `data`. Exactly one content member
//!   must be present in either era.
//!
//! Task states are checked only where a **request** carries one, which is the
//! optional `status` filter on `ListTasks`. The states that matter operationally
//! travel on Task **responses** and on streaming events, and the gateway does not
//! inspect either: it forwards responses untouched, which is what keeps it a
//! proxy rather than a task engine.
//!
//! Identifier **format** is deliberately unchecked. A task identifier is required
//! to be present and non-blank on the methods that carry one (`tasks/get`,
//! `tasks/cancel`, `tasks/resubscribe` and their v1.0 spellings), because a
//! request that forgot one is simply malformed, but nothing stricter is applied:
//! A2A defines no format for these identifiers, so a shape rule would be an
//! invention of ours that could refuse a conformant agent's ids. `contextId` is
//! not checked at all, being optional in both eras.
//!
//! These run under the same per-surface setting as the envelope check,
//! `access_point.a2a.validate_messages`, which is **off by default**. A request
//! that fails them was already going to fail: a conformant agent refuses a
//! message with no `messageId` too, just one hop later and with a vaguer error.
//! Refusing here names the offending field and spares the agent the round trip.
//! A surface whose target is `a2a-proxy://` never validates, because the proxy
//! is the implementation rather than a pass-through, so there is no downstream
//! agent that would have refused the message and checking would only refuse
//! callers that work today. The call site is in
//! `src/proxy/handler.rs::proxy_handler_with_mcp_runtime`.
//!
//! The gateway stays a transparent proxy: this validates shape and never
//! rewrites, normalises or fills in a request.

use serde_json::Value;

/// JSON-RPC 2.0 "Invalid params".
pub const ERR_INVALID_PARAMS: i32 = -32602;

/// Most field errors collected for one request. Validation stops walking a
/// message's `parts` once this many are held, so the work, the error response
/// and the log line stay bounded whatever the body size.
pub const MAX_FIELD_ERRORS: usize = 20;

/// Longest caller-supplied value echoed back in an error message, in chars.
const MAX_ECHOED_CHARS: usize = 64;

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
/// [`MAX_ECHOED_CHARS`] chars.
fn echo(value: &str) -> String {
    let mut chars = value.chars();
    let head: String = chars
        .by_ref()
        .take(MAX_ECHOED_CHARS)
        .collect();
    if chars.next().is_some() {
        format!("{head:?}…")
    } else {
        format!("{head:?}")
    }
}

/// True when the method is one that carries a `Message` in `params.message`,
/// in either protocol era. Resolved through the canonical table so both the
/// v0.3 slash-form and the v1.0 PascalCase spellings are recognised.
fn is_message_carrying_method(method: &str) -> bool {
    matches!(crate::a2a::canonical_method(method), "message/send" | "message/stream")
}

/// Validate an A2A request beyond its JSON-RPC envelope.
///
/// Returns every problem found rather than the first, up to
/// [`MAX_FIELD_ERRORS`], so a caller can fix the request in one pass. `Ok(())`
/// means the request passed the era-agnostic checks; it does not mean the
/// upstream agent will accept it.
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
    // structured value. This holds for every method in both eras.
    if let Some(params) = json.get("params")
        && !params.is_object()
        && !params.is_array()
    {
        errors.push("params", "must be an object or an array when present");
        // Nothing further can be said about a malformed params container.
        return Err(errors);
    }

    if is_message_carrying_method(method) {
        validate_message_params(json, &mut errors);
    }

    if crate::a2a::canonical_method(method) == "tasks/list" {
        validate_list_tasks_params(json, &mut errors);
    }

    if is_task_id_method(method) {
        validate_task_id(json, &mut errors);
    }

    if errors.errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Checks for the methods that carry a `Message`: `message/send` and
/// `message/stream`, in either era.
fn validate_message_params(
    json: &Value,
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

    // `messageId` is required in both eras. Proto-JSON also permits the
    // original field name, so accept `message_id` rather than rejecting a
    // request a compliant generated client may produce.
    let message_id = message
        .get("messageId")
        .or_else(|| message.get("message_id"));
    match message_id {
        None => errors.push("params.message.messageId", "is required"),
        Some(value) => match value.as_str() {
            Some(s) if !s.trim().is_empty() => {}
            Some(_) => errors.push("params.message.messageId", "must not be empty"),
            None => errors.push("params.message.messageId", "must be a string"),
        },
    }

    validate_role(message.get("role"), errors);

    // `parts` is required and must carry at least one entry in both eras.
    match message.get("parts") {
        None => errors.push("params.message.parts", "is required"),
        Some(value) => match value.as_array() {
            Some(parts) if !parts.is_empty() => {
                for (index, part) in parts.iter().enumerate() {
                    if errors.truncated {
                        break;
                    }
                    validate_part(part, index, errors);
                }
            }
            Some(_) => errors.push("params.message.parts", "must not be empty"),
            None => errors.push("params.message.parts", "must be an array"),
        },
    }
}

/// Methods whose request carries a task identifier in `params.id`.
///
/// The field is spelled `id` in both eras: v1.0 `GetTaskRequest` and
/// `CancelTaskRequest` declare `string id` REQUIRED, and v0.3's `TaskIdParams`
/// and `TaskQueryParams` use `id` too, so no per-era handling is needed.
fn is_task_id_method(method: &str) -> bool {
    matches!(crate::a2a::canonical_method(method), "tasks/get" | "tasks/cancel" | "tasks/resubscribe")
}

/// Check only that a task identifier is present and not blank.
///
/// A2A does not define a format for these identifiers, so anything stricter
/// would be a rule of our own invention that could refuse a conformant agent's
/// ids. Presence is the useful check: it catches the request that forgot one.
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

/// Task states accepted on a request, across both eras.
///
/// A2A v1.0 serialises the proto `TaskState` enum by name; v0.3 used lowercase
/// hyphenated strings, plus an `unknown` value v1.0 renamed to
/// `TASK_STATE_UNSPECIFIED`. Both spellings are verified against the published
/// `specification/a2a.proto` (v1.0.1) and `specification/json/a2a.json` (v0.3).
const TASK_STATES: &[&str] = &[
    // v0.3
    "submitted",
    "working",
    "input-required",
    "completed",
    "canceled",
    "failed",
    "rejected",
    "auth-required",
    "unknown",
    // v1.0
    "TASK_STATE_SUBMITTED",
    "TASK_STATE_WORKING",
    "TASK_STATE_INPUT_REQUIRED",
    "TASK_STATE_COMPLETED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_FAILED",
    "TASK_STATE_REJECTED",
    "TASK_STATE_AUTH_REQUIRED",
    "TASK_STATE_UNSPECIFIED",
];

/// `ListTasks` is the only request that carries a task state: an optional
/// `status` filter. It is optional, so absence is fine; a value that names no
/// task state is not, since the upstream would filter on something meaningless.
fn validate_list_tasks_params(
    json: &Value,
    errors: &mut FieldErrors,
) {
    let Some(status) = json
        .get("params")
        .and_then(|params| params.get("status"))
    else {
        return;
    };

    match status.as_str() {
        Some(value) if TASK_STATES.contains(&value) => {}
        Some(_) => errors.push(
            "params.status",
            "must be a task state such as working or completed (A2A 0.3) or TASK_STATE_WORKING (A2A 1.0)",
        ),
        None => errors.push("params.status", "must be a string"),
    }
}

/// Roles accepted on a message, across both eras. v1.0 serialises the proto
/// `Role` enum by name; v0.3 used the lowercase forms.
const ROLES: &[&str] = &["user", "agent", "ROLE_USER", "ROLE_AGENT", "ROLE_UNSPECIFIED"];

fn validate_role(
    role: Option<&Value>,
    errors: &mut FieldErrors,
) {
    let Some(role) = role else {
        errors.push("params.message.role", "is required");
        return;
    };
    match role.as_str() {
        Some(value) if ROLES.contains(&value) => {}
        Some(_) => errors
            .push("params.message.role", "must be one of user, agent (A2A 0.3) or ROLE_USER, ROLE_AGENT (A2A 1.0)"),
        None => errors.push("params.message.role", "must be a string"),
    }
}

/// The content members a `Part` may carry, across both eras: `text`, `data` and
/// v0.3's `file` object, plus v1.0's `raw` and `url`. Exactly one must be
/// present, since a Part holds one piece of content.
const PART_CONTENT_MEMBERS: &[&str] = &["text", "file", "data", "raw", "url"];

fn validate_part(
    part: &Value,
    index: usize,
    errors: &mut FieldErrors,
) {
    let field = |suffix: &str| format!("params.message.parts[{index}]{suffix}");

    let Some(part) = part.as_object() else {
        errors.push(&field(""), "must be an object");
        return;
    };

    let present: Vec<&str> = PART_CONTENT_MEMBERS
        .iter()
        .copied()
        .filter(|member| part.contains_key(*member))
        .collect();

    match present.len() {
        1 => {}
        0 => errors.push(&field(""), "must carry exactly one content member (text, file, data, raw or url)"),
        _ => errors.push(&field(""), &format!("must carry exactly one content member, found {}", present.join(", "))),
    }

    // v0.3 also tags the part with `kind`. When present it must agree with the
    // member actually carried, otherwise the part describes itself incorrectly.
    // v1.0 parts have no `kind` and are left alone.
    if let Some(kind) = part.get("kind") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Wrap a message that already carries a valid `role`, so a test that is
    /// about `messageId` or `parts` is not also failing on the role.
    fn send_body(message: Value) -> Value {
        let mut message = message;
        if let Some(obj) = message.as_object_mut() {
            obj.entry("role")
                .or_insert_with(|| Value::String("user".into()));
        }
        raw_send_body(message)
    }

    fn raw_send_body(message: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": { "message": message } })
    }

    fn valid_message() -> Value {
        json!({ "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] })
    }

    fn fields(result: Result<(), FieldErrors>) -> Vec<String> {
        result
            .unwrap_err()
            .errors
            .into_iter()
            .map(|e| e.field)
            .collect()
    }

    #[test]
    fn accepts_a_valid_v0_3_send() {
        assert!(validate_request_shape(&send_body(valid_message())).is_ok());
    }

    #[test]
    fn accepts_a_valid_v1_0_send() {
        // v1.0: PascalCase method, part with no `kind`, ROLE_USER.
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
            "params": { "message": { "role": "ROLE_USER", "messageId": "m-1", "parts": [{ "text": "hi" }] } }
        });
        assert!(validate_request_shape(&body).is_ok());
    }

    #[test]
    fn accepts_the_proto_json_message_id_spelling() {
        let body = send_body(json!({ "message_id": "m-1", "parts": [{ "text": "hi" }] }));
        assert!(validate_request_shape(&body).is_ok());
    }

    #[test]
    fn rejects_a_missing_message_id() {
        let body = send_body(json!({ "role": "user", "parts": [{ "text": "hi" }] }));
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.message.messageId"]);
    }

    #[test]
    fn rejects_an_empty_message_id() {
        let body = send_body(json!({ "messageId": "  ", "parts": [{ "text": "hi" }] }));
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.message.messageId"]);
    }

    #[test]
    fn rejects_a_non_string_message_id() {
        let body = send_body(json!({ "messageId": 7, "parts": [{ "text": "hi" }] }));
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.message.messageId"]);
    }

    #[test]
    fn rejects_missing_and_empty_parts() {
        let missing = send_body(json!({ "messageId": "m-1" }));
        assert_eq!(fields(validate_request_shape(&missing)), vec!["params.message.parts"]);

        let empty = send_body(json!({ "messageId": "m-1", "parts": [] }));
        assert_eq!(fields(validate_request_shape(&empty)), vec!["params.message.parts"]);

        let not_array = send_body(json!({ "messageId": "m-1", "parts": "hi" }));
        assert_eq!(fields(validate_request_shape(&not_array)), vec!["params.message.parts"]);
    }

    #[test]
    fn reports_every_problem_at_once() {
        let body = send_body(json!({ "role": "user" }));
        assert_eq!(
            fields(validate_request_shape(&body)),
            vec!["params.message.messageId", "params.message.parts"],
            "a caller should be able to fix the request in one pass"
        );
    }

    #[test]
    fn rejects_a_send_without_params_or_message() {
        let no_params = json!({ "jsonrpc": "2.0", "id": 1, "method": "SendMessage" });
        assert_eq!(fields(validate_request_shape(&no_params)), vec!["params"]);

        let no_message = json!({ "jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {} });
        assert_eq!(fields(validate_request_shape(&no_message)), vec!["params.message"]);
    }

    #[test]
    fn rejects_a_scalar_params_container_for_any_method() {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": "nope" });
        assert_eq!(fields(validate_request_shape(&body)), vec!["params"]);
    }

    // ── ListTasks status filter (the only task state a request carries) ──

    #[test]
    fn accepts_every_task_state_in_either_era() {
        for state in [
            "submitted",
            "working",
            "input-required",
            "completed",
            "canceled",
            "failed",
            "rejected",
            "auth-required",
            "unknown",
            "TASK_STATE_SUBMITTED",
            "TASK_STATE_WORKING",
            "TASK_STATE_INPUT_REQUIRED",
            "TASK_STATE_COMPLETED",
            "TASK_STATE_CANCELED",
            "TASK_STATE_FAILED",
            "TASK_STATE_REJECTED",
            "TASK_STATE_AUTH_REQUIRED",
            "TASK_STATE_UNSPECIFIED",
        ] {
            for method in ["tasks/list", "ListTasks"] {
                let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": { "status": state } });
                assert!(validate_request_shape(&body).is_ok(), "{state} should be accepted on {method}");
            }
        }
    }

    #[test]
    fn the_status_filter_is_optional() {
        for params in [json!({}), json!({ "contextId": "c-1" })] {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "ListTasks", "params": params });
            assert!(validate_request_shape(&body).is_ok());
        }
        let no_params = json!({ "jsonrpc": "2.0", "id": 1, "method": "ListTasks" });
        assert!(validate_request_shape(&no_params).is_ok());
    }

    /// The v0.3 spelling is `canceled` with one l in both eras, so the common
    /// misspelling must not silently filter on nothing.
    #[test]
    fn rejects_a_state_that_names_nothing() {
        for bad in ["cancelled", "in-progress", "TASK_STATE_DONE", ""] {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "ListTasks", "params": { "status": bad } });
            assert_eq!(fields(validate_request_shape(&body)), vec!["params.status"], "{bad} should be refused");
        }
    }

    #[test]
    fn rejects_a_non_string_status() {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "ListTasks", "params": { "status": 3 } });
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.status"]);
    }

    /// The status filter belongs to ListTasks alone. On another method the same
    /// field name is just an unknown field, and unknown fields pass through.
    #[test]
    fn a_status_field_on_another_method_is_not_constrained() {
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "GetTask",
            "params": { "id": "task-1", "status": "nonsense" }
        });
        assert!(validate_request_shape(&body).is_ok());
    }

    /// Push-notification methods stay unconstrained: their identifiers sit at
    /// different paths and are not covered here.
    #[test]
    fn does_not_constrain_push_config_methods() {
        for method in ["DeleteTaskPushNotificationConfig", "tasks/pushNotificationConfig/set"] {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": { "id": "t-1" } });
            assert!(validate_request_shape(&body).is_ok(), "{method} should not be constrained");
        }
    }

    // ── Task identifiers: presence only, both eras ───────────────────────

    #[test]
    fn accepts_a_task_id_on_either_era_spelling() {
        for method in ["tasks/get", "GetTask", "tasks/cancel", "CancelTask", "tasks/resubscribe", "SubscribeToTask"] {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": { "id": "task-1" } });
            assert!(validate_request_shape(&body).is_ok(), "{method} with an id should pass");
        }
    }

    #[test]
    fn rejects_a_missing_or_blank_task_id() {
        for params in [json!({}), json!({ "id": "  " }), json!({ "id": 7 })] {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": params });
            assert_eq!(fields(validate_request_shape(&body)), vec!["params.id"]);
        }
    }

    /// A2A defines no format for task identifiers, so anything a caller chooses
    /// is accepted. Validating a shape here would refuse conformant agents.
    #[test]
    fn does_not_impose_a_format_on_task_ids() {
        for id in ["550e8400-e29b-41d4-a716-446655440000", "task_42", "a", "urn:x:1"] {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": { "id": id } });
            assert!(validate_request_shape(&body).is_ok(), "{id} should be accepted");
        }
    }

    /// Unknown extension fields must survive: A2A requires them to be preserved
    /// and ignored, and the gateway forwards the body unchanged.
    #[test]
    fn ignores_unknown_extension_fields() {
        let body = send_body(json!({
            "messageId": "m-1",
            "parts": [{ "text": "hi" }],
            "x-vendor-extension": { "anything": true }
        }));
        assert!(validate_request_shape(&body).is_ok());
    }

    // ── role (era-sensitive: both spellings accepted) ────────────────────

    #[test]
    fn accepts_either_era_role_spelling() {
        for role in ["user", "agent", "ROLE_USER", "ROLE_AGENT", "ROLE_UNSPECIFIED"] {
            let body = raw_send_body(json!({ "role": role, "messageId": "m-1", "parts": [{ "text": "hi" }] }));
            assert!(validate_request_shape(&body).is_ok(), "{role} should be accepted");
        }
    }

    #[test]
    fn rejects_a_missing_or_bogus_role() {
        let missing = raw_send_body(json!({ "messageId": "m-1", "parts": [{ "text": "hi" }] }));
        assert_eq!(fields(validate_request_shape(&missing)), vec!["params.message.role"]);

        let bogus = raw_send_body(json!({ "role": "wizard", "messageId": "m-1", "parts": [{ "text": "hi" }] }));
        assert_eq!(fields(validate_request_shape(&bogus)), vec!["params.message.role"]);

        let not_string = raw_send_body(json!({ "role": 1, "messageId": "m-1", "parts": [{ "text": "hi" }] }));
        assert_eq!(fields(validate_request_shape(&not_string)), vec!["params.message.role"]);
    }

    // ── Part content: exactly one member, in either era ──────────────────

    #[test]
    fn accepts_every_single_member_part_shape() {
        for part in [
            json!({ "kind": "text", "text": "hi" }),            // v0.3 text
            json!({ "kind": "file", "file": { "name": "a" } }), // v0.3 file
            json!({ "kind": "data", "data": { "a": 1 } }),      // v0.3 data
            json!({ "text": "hi" }),                            // v1.0 text
            json!({ "url": "https://example.com/a" }),          // v1.0 url
            json!({ "raw": "aGk=" }),                           // v1.0 raw
            json!({ "data": { "a": 1 } }),                      // v1.0 data
            json!({ "text": "hi", "mediaType": "text/plain" }), // non-content fields ignored
        ] {
            let body = send_body(json!({ "messageId": "m-1", "parts": [part.clone()] }));
            assert!(validate_request_shape(&body).is_ok(), "{part} should be accepted");
        }
    }

    #[test]
    fn rejects_a_part_with_no_content_member() {
        let body = send_body(json!({ "messageId": "m-1", "parts": [{ "mediaType": "text/plain" }] }));
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.message.parts[0]"]);
    }

    #[test]
    fn rejects_a_part_with_more_than_one_content_member() {
        let body = send_body(json!({
            "messageId": "m-1",
            "parts": [{ "text": "hi", "url": "https://example.com/a" }]
        }));
        let errs = validate_request_shape(&body)
            .unwrap_err()
            .errors;
        assert_eq!(errs[0].field, "params.message.parts[0]");
        assert!(
            errs[0]
                .message
                .contains("text")
                && errs[0]
                    .message
                    .contains("url"),
            "{}",
            errs[0].message
        );
    }

    /// A v0.3 part that mislabels its own content is malformed even though each
    /// half is individually well-formed.
    #[test]
    fn rejects_a_kind_that_disagrees_with_the_content() {
        let body = send_body(json!({ "messageId": "m-1", "parts": [{ "kind": "file", "text": "hi" }] }));
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.message.parts[0].kind"]);
    }

    #[test]
    fn reports_the_offending_part_by_index() {
        let body = send_body(json!({
            "messageId": "m-1",
            "parts": [{ "text": "ok" }, { "text": "no", "data": {} }]
        }));
        assert_eq!(fields(validate_request_shape(&body)), vec!["params.message.parts[1]"]);
    }

    /// A body the envelope layer will reject is left to that layer.
    #[test]
    fn defers_to_the_envelope_layer_when_method_is_absent() {
        assert!(validate_request_shape(&json!({ "jsonrpc": "2.0", "id": 1 })).is_ok());
    }

    // ── Bounded errors: body size must not amplify the error ─────────────

    fn body_with_bad_parts(count: usize) -> Value {
        send_body(json!({ "messageId": "m-1", "parts": vec![json!(0); count] }))
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
    fn a_short_list_is_complete_and_not_truncated() {
        let errs = validate_request_shape(&send_body(json!({ "role": "user" }))).unwrap_err();
        assert_eq!(errs.errors.len(), 2);
        assert!(!errs.truncated);
    }

    #[test]
    fn bounds_and_escapes_a_huge_multibyte_kind() {
        let kind = "\u{1F600}\"".repeat(10_000);
        let body = send_body(json!({ "messageId": "m-1", "parts": [{ "kind": kind, "text": "hi" }] }));
        let errs = validate_request_shape(&body)
            .unwrap_err()
            .errors;
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].field, "params.message.parts[0].kind");
        let expected_head = format!("{:?}…", "\u{1F600}\"".repeat(MAX_ECHOED_CHARS / 2));
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

    #[test]
    fn echoes_a_short_kind_in_full_without_an_ellipsis() {
        let body = send_body(json!({ "messageId": "m-1", "parts": [{ "kind": "file", "text": "hi" }] }));
        let errs = validate_request_shape(&body)
            .unwrap_err()
            .errors;
        assert_eq!(errs[0].message, "says \"file\" but the part carries 'text'");
    }
}
