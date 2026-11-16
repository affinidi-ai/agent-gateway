//! Policy input capture: while a dashboard connection listens to a surface's policy
//! input, each policy evaluation on that surface is sent as a `policy_input_captured`
//! WebSocket update with its input, credentials masked, and its outcome. Only the
//! listening connections receive it; capture stops when the last of them stops listening
//! or closes. Nothing is written to the log or stored.

use std::sync::{Arc, LazyLock, OnceLock};

use chrono::Utc;
use dashmap::DashMap;
use serde_json::Value;

use crate::observability::loggable::REDACTED;
use crate::server::{WsState, WsUpdate};

/// How many dashboard connections listen to each surface's policy input, by surface id.
static LISTENERS: LazyLock<DashMap<String, usize>> = LazyLock::new(DashMap::new);

/// The dashboard WebSocket the captures are sent to.
static DASHBOARD: OnceLock<Arc<WsState>> = OnceLock::new();

/// Send captures to the dashboard WebSocket `ws_state`.
pub fn init(ws_state: Arc<WsState>) {
    let _ = DASHBOARD.set(ws_state);
}

/// A dashboard connection listening to one surface's policy input. The surface is
/// captured while at least one exists; dropping it stops listening.
#[derive(Debug)]
pub struct Listening {
    surface_id: String,
}

/// Start listening to the policy input of `surface_id`.
pub fn listen(surface_id: &str) -> Listening {
    *LISTENERS
        .entry(surface_id.to_string())
        .or_insert(0) += 1;
    Listening {
        surface_id: surface_id.to_string(),
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        if let Some(mut count) = LISTENERS.get_mut(&self.surface_id) {
            *count = count.saturating_sub(1);
        }
        LISTENERS.remove_if(&self.surface_id, |_, count| *count == 0);
    }
}

pub(crate) fn is_captured(surface_id: &str) -> bool {
    LISTENERS
        .get(surface_id)
        .is_some_and(|count| *count > 0)
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
    input: Value,
}

/// Start capturing the evaluation of `input` by `plane` (`gateway`, `surface` or
/// `appliance`), `engine` naming the evaluated policy slot, when its surface has policy
/// input capture switched on.
pub fn begin(
    plane: &str,
    engine: &str,
    input: &Value,
) -> Option<Capture> {
    let surface_id = surface_of(input)?;
    if !is_captured(surface_id) {
        return None;
    }
    let (slot, transit_point) = slot_of(plane, engine, surface_id);
    let mut masked = input.clone();
    mask_credentials(&mut masked);
    Some(Capture {
        surface_id: surface_id.to_string(),
        plane: plane.to_string(),
        engine: engine.to_string(),
        slot,
        transit_point,
        input: masked,
    })
}

impl Capture {
    /// Send the capture with its outcome, `Ok((allow, deny reason))` or the evaluation
    /// error, to the dashboard.
    pub fn finish(
        self,
        outcome: Result<(bool, Option<&str>), &str>,
    ) {
        if let Some(ws_state) = DASHBOARD.get() {
            ws_state.broadcast(self.into_update(outcome));
        }
    }

    fn into_update(
        self,
        outcome: Result<(bool, Option<&str>), &str>,
    ) -> WsUpdate {
        let (decision, reason) = match outcome {
            Ok((true, _)) => ("allow", None),
            Ok((false, reason)) => ("deny", reason.map(str::to_string)),
            Err(error) => ("error", Some(error.to_string())),
        };
        WsUpdate::PolicyInputCaptured {
            config_id: self.surface_id,
            timestamp: Utc::now().to_rfc3339(),
            plane: self.plane,
            engine: self.engine,
            slot: self.slot,
            transit_point: self.transit_point,
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
        Value::String(text) if is_credential_text(text) => *text = REDACTED.to_string(),
        _ => {}
    }
}

fn is_credential_text(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("bearer ") || lower.starts_with("basic ") || is_jwt(trimmed)
}

fn is_jwt(text: &str) -> bool {
    let segments: Vec<&str> = text.split('.').collect();
    segments.len() == 3
        && segments[0].starts_with("eyJ")
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
        let first = listen("input-capture-listened");
        let second = listen("input-capture-listened");
        assert!(is_captured("input-capture-listened"));

        drop(first);
        assert!(is_captured("input-capture-listened"));

        drop(second);
        assert!(!is_captured("input-capture-listened"));
        assert!(!LISTENERS.contains_key("input-capture-listened"));
        assert!(!is_captured("input-capture-never-listened"));
    }

    #[test]
    fn the_surface_comes_from_the_channel_config_id() {
        let input = json!({ "channel": { "config_id": "alpha", "name": "Alpha" } });

        assert_eq!(surface_of(&input), Some("alpha"));
        assert_eq!(surface_of(&json!({ "http": {} })), None);
    }

    #[test]
    fn a_response_policy_input_names_its_surface_in_surface_id() {
        let input = json!({ "response": { "status_code": 200 }, "surface": { "id": "alpha", "name": "Alpha" } });

        assert_eq!(surface_of(&input), Some("alpha"));
    }

    #[test]
    fn a_response_policy_evaluation_is_captured() {
        let _listening = listen("input-capture-response");
        let input = json!({
            "response": { "status_code": 200, "body": { "result": "done" } },
            "surface": { "id": "input-capture-response" },
        });

        let update = serde_json::to_value(
            begin("surface", "response:pil-allow-message-send", &input)
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
        let _listening = listen("input-capture-sent");
        let input = json!({
            "channel": { "config_id": "input-capture-sent" },
            "source_auth": { "method": "jwt", "token": JWT },
            "mcp": { "tool_name": "lookup" },
        });

        let capture = begin("surface", "inbound:input-capture-sent", &input).unwrap();
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

    #[test]
    fn an_allow_has_no_reason_and_an_error_carries_its_message() {
        let _listening = listen("input-capture-decided");
        let input = json!({ "channel": { "config_id": "input-capture-decided" } });

        let allow = update_json(
            begin("surface", "input-capture-decided", &input)
                .unwrap()
                .into_update(Ok((true, None))),
        );
        let error = update_json(
            begin("surface", "input-capture-decided", &input)
                .unwrap()
                .into_update(Err("no allow rule")),
        );

        assert_eq!(allow["decision"], "allow");
        assert!(allow.get("reason").is_none(), "{allow}");
        assert_eq!(error["decision"], "error");
        assert_eq!(error["reason"], "no allow rule");
    }

    #[test]
    fn a_transit_point_policy_names_its_alias() {
        let _listening = listen("input-capture-transit");
        let input = json!({ "channel": { "config_id": "input-capture-transit" } });

        let update = update_json(
            begin("surface", "transit:input-capture-transit:tp-1", &input)
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
        drop(listen("input-capture-stopped"));
        let stopped = json!({ "channel": { "config_id": "input-capture-stopped" } });
        let unheard = json!({ "channel": { "config_id": "input-capture-unheard" } });

        assert!(begin("surface", "input-capture-stopped", &stopped).is_none());
        assert!(begin("gateway", "self", &unheard).is_none());
        assert!(begin("gateway", "self", &json!({ "http": {} })).is_none());
    }

    #[test]
    fn a_dotted_string_that_is_not_a_jwt_is_kept() {
        assert!(!is_jwt("did:web:alpha.example.test"));
        assert!(!is_jwt("1.2.3"));
        assert!(!is_jwt("eyJ..sig"));
        assert!(is_jwt(JWT));
    }
}
