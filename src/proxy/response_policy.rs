//! Response Policy Evaluation
//!
//! Evaluates OPA policies against upstream responses before returning them to callers.
//! This runs after the target responds but before the Gateway forwards the response back.
//!
//! The response policy can:
//! - Block responses containing sensitive data
//! - Redact fields based on caller role
//! - Enforce output contracts (required fields, forbidden patterns)

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Input document passed to the response OPA policy.
/// The Rego policy sees this as `input.*`.
///
/// Built with [`ResponsePolicyInput::new`], plus
/// [`ResponsePolicyInput::for_transit_point`] on a Transit Point leg, so every
/// call site gets a field added here.
#[derive(Debug, Clone, Serialize)]
pub struct ResponsePolicyInput {
    /// The upstream response body (JSON).
    pub response: ResponseContext,
    /// Caller context (who made the original request).
    pub caller: CallerContext,
    /// Channel/surface context.
    pub surface: SurfaceContext,
    /// Optional metadata carried forward from the request pipeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, Value>>,
    /// The caller of a Transit Point call, as its request policies see it.
    /// Set only for a Transit Point's response policy; undefined on the
    /// inbound legs, where a negated rule on it is always true.
    #[serde(skip_serializing_if = "Option::is_none")]
    transit: Option<crate::surface_context::TransitContext>,
    /// The identity the Transit Point itself verified, as its request
    /// policies see it. Set only for a Transit Point's response policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_auth: Option<crate::surface_context::SourceAuthContext>,
    /// The Transit Point's caller, the managed agent, as its request policies
    /// see it. Set only for a Transit Point's response policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    extension_identity: Option<crate::surface_context::ExtensionIdentityContext>,
}

impl ResponsePolicyInput {
    /// Input for a response policy on an inbound leg: no `transit` or
    /// `source_auth`.
    pub fn new(
        response: ResponseContext,
        caller: CallerContext,
        surface: SurfaceContext,
    ) -> Self {
        Self {
            response,
            caller,
            surface,
            metadata: None,
            transit: None,
            source_auth: None,
            extension_identity: None,
        }
    }

    /// Adds what a Transit Point's request policies see as `input.transit`,
    /// `input.source_auth` and `input.extension_identity`.
    pub fn for_transit_point(
        mut self,
        transit: crate::surface_context::TransitContext,
        source_auth: Option<crate::surface_context::SourceAuthContext>,
        extension_identity: Option<crate::surface_context::ExtensionIdentityContext>,
    ) -> Self {
        self.transit = Some(transit);
        self.source_auth = source_auth;
        self.extension_identity = extension_identity;
        self
    }
}

/// Response body context visible to the policy.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseContext {
    /// HTTP status code from upstream.
    pub status_code: u16,
    /// The response body as JSON (if parseable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// Content-Type header from the upstream response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Whether the response is a JSON-RPC error.
    #[serde(default)]
    pub is_error: bool,
    /// JSON-RPC method (if this is an RPC response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Caller identity context forwarded from the inbound pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct CallerContext {
    /// Caller DID (if resolved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Identity source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_source: Option<String>,
    /// DNA UAI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dna_uai: Option<String>,
}

/// Surface/channel routing context.
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceContext {
    /// Surface ID or channel config_id.
    pub id: String,
    /// Surface/channel name.
    pub name: String,
    /// Protocol (a2a, mcp, ap2).
    pub protocol: String,
}

/// Result of a response policy evaluation.
#[derive(Debug, Clone)]
pub struct ResponsePolicyDecision {
    /// Whether the response is allowed through.
    pub allow: bool,
    /// Reason for denial (if denied).
    pub reason: Option<String>,
    /// Set when the policy could not decide; the response is denied and the
    /// decision is recorded as `error`.
    pub error: Option<crate::observability::PolicyEvaluationError>,
}

/// Evaluate a response policy using the policy manager.
///
/// Returns `Ok(decision)` indicating allow/deny.
/// If no policy is configured or the engine is not found, allows by default.
pub fn evaluate_response_policy(
    policy_manager: &crate::policies::surface_manager::SurfacePolicyManager,
    policy_key: &str,
    input: ResponsePolicyInput,
) -> ResponsePolicyDecision {
    let input_value = match serde_json::to_value(&input) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                policy_key = %policy_key,
                error = %e,
                "Failed to serialize response policy input, allowing response"
            );
            return ResponsePolicyDecision {
                allow: true,
                reason: None,
                error: None,
            };
        }
    };

    match policy_manager.evaluate_policy_decision(policy_key, input_value) {
        Ok(decision) => {
            if !decision.allow {
                debug!(policy_key = %policy_key, "Response policy denied");
            }
            ResponsePolicyDecision {
                allow: decision.allow,
                reason: if decision.allow {
                    None
                } else {
                    decision
                        .reason
                        .or_else(|| Some("Response blocked by policy".to_string()))
                },
                error: None,
            }
        }
        Err(e) => {
            // The engine error stays in this log line; callers and audit
            // records only see the `evaluation_error` reason.
            warn!(
                policy_key = %policy_key,
                error = %e,
                "Response policy evaluation failed, denying response (fail-closed)"
            );
            ResponsePolicyDecision {
                allow: false,
                reason: None,
                error: Some(crate::observability::PolicyEvaluationError::EvaluationError),
            }
        }
    }
}

/// The policy engine key of the response policy with definition id
/// `policy_definition_id`: "response:{policy_definition_id}".
pub fn response_policy_key(policy_definition_id: &str) -> String {
    format!("response:{}", policy_definition_id)
}

/// The body of the `403` a caller gets when a response policy refuses an answer.
pub const DENIED_BODY: &str = r#"{"error":"Response blocked","code":"response_policy_denied"}"#;

/// The `403` a caller gets when a response policy refuses an answer.
pub fn denied_response() -> axum::response::Response {
    axum::response::Response::builder()
        .status(axum::http::StatusCode::FORBIDDEN)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(DENIED_BODY))
        .expect("a static response builds")
}

/// What a response policy sees of a Target answer with `status`, `body` and `content_type`.
pub fn response_context(
    status: u16,
    body: &[u8],
    content_type: Option<&str>,
) -> ResponseContext {
    ResponseContext {
        status_code: status,
        body: serde_json::from_slice(body).ok(),
        content_type: content_type.map(str::to_string),
        is_error: status >= 400,
        method: None,
    }
}

/// What a response policy sees of each event of a buffered `text/event-stream`
/// answer with `status`: one context per event that carries data, with that
/// event's JSON as the body, as a direct caller's event stream is checked. Empty
/// when `body` holds no such event.
pub fn event_stream_contexts(
    status: u16,
    body: &[u8],
) -> Vec<ResponseContext> {
    let text = String::from_utf8_lossy(body)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    text.split("\n\n")
        .filter_map(|event| {
            let data: Vec<&str> = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(|data| {
                    data.strip_prefix(' ')
                        .unwrap_or(data)
                })
                .collect();
            (!data.is_empty()).then(|| serde_json::from_str::<Value>(&data.join("\n")).ok())
        })
        .map(|event| ResponseContext {
            status_code: status,
            is_error: status >= 400
                || event
                    .as_ref()
                    .and_then(|event| event.get("error"))
                    .is_some_and(|error| !error.is_null()),
            body: event,
            content_type: Some(mime::TEXT_EVENT_STREAM.to_string()),
            method: None,
        })
        .collect()
}

/// What a response policy sees of a whole Target answer with `status`, `body`
/// and `content_type`: one context per event when it is still framed as an
/// event stream (see [`event_stream_contexts`]), otherwise one for the answer.
pub fn answer_contexts(
    status: u16,
    body: &[u8],
    content_type: Option<&str>,
) -> Vec<ResponseContext> {
    let events = match content_type {
        Some(content_type) if crate::mcp::sse_transport::is_sse_content_type(content_type) => {
            event_stream_contexts(status, body)
        }
        _ => Vec::new(),
    };
    if events.is_empty() {
        vec![response_context(status, body, content_type)]
    } else {
        events
    }
}

impl SurfaceContext {
    /// The response policy's view of `surface`.
    pub fn of(surface: &crate::config::agent_surface::AgentSurface) -> Self {
        Self {
            id: surface.surface_id.clone(),
            name: surface.name.clone(),
            protocol: format!("{:?}", surface.channel_protocol()).to_lowercase(),
        }
    }
}

/// Whether the response policy checks an `a2a-proxy://` answer with `status` and
/// `body`: only a successful one (2xx, and no JSON-RPC `error`), so the proxy
/// runtime's own JSON-RPC errors pass.
fn a2a_proxy_answer_is_checked(
    status: axum::http::StatusCode,
    body: &[u8],
) -> bool {
    status.is_success() && !serde_json::from_slice::<Value>(body).is_ok_and(|answer| answer.get("error").is_some())
}

/// An `a2a-proxy://` `answer`, or [`denied_response`] when `check` refuses it.
/// Only an answer [`a2a_proxy_answer_is_checked`] accepts is given to `check`.
pub async fn a2a_proxy_answer_under<Check, Decided>(
    answer: axum::response::Response,
    check: Check,
) -> axum::response::Response
where
    Check: FnOnce(ResponseContext) -> Decided,
    Decided: std::future::Future<Output = ResponsePolicyDecision>,
{
    let (parts, body) = answer.into_parts();
    let Ok(body) = axum::body::to_bytes(body, usize::MAX).await else {
        warn!("Failed to read an A2A proxy answer for its response policy; refusing it");
        return denied_response();
    };
    if !a2a_proxy_answer_is_checked(parts.status, &body) {
        return axum::response::Response::from_parts(parts, axum::body::Body::from(body));
    }
    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let response = response_context(parts.status.as_u16(), &body, content_type);
    if check(response).await.allow {
        axum::response::Response::from_parts(parts, axum::body::Body::from(body))
    } else {
        denied_response()
    }
}

/// The JSON-RPC error that replaces an MCP Proxy's `answer` to request `id` when
/// `check` refuses it, or `None` when it may go back.
pub async fn mcp_proxy_refusal<Check, Decided>(
    answer: &Value,
    id: Option<&Value>,
    check: Check,
) -> Option<Value>
where
    Check: FnOnce(ResponseContext) -> Decided,
    Decided: std::future::Future<Output = ResponsePolicyDecision>,
{
    let decision = check(ResponseContext {
        status_code: 200,
        body: Some(answer.clone()),
        content_type: Some("application/json".to_string()),
        is_error: false,
        method: None,
    })
    .await;
    (!decision.allow).then(|| {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": decision.reason.unwrap_or_else(|| "Response blocked by policy".to_string())
            }
        })
    })
}

/// Evaluates response policy `policy_id` on `input` and records the response-scope
/// decision with the request fields `context` carries.
pub async fn check_response_policy(
    policy_manager: &crate::policies::surface_manager::SurfacePolicyManager,
    policy_id: &str,
    input: ResponsePolicyInput,
    context: crate::observability::PolicyDecisionEvent<'_>,
) -> ResponsePolicyDecision {
    check_response_policy_on_each(policy_manager, policy_id, [input], context).await
}

/// Evaluates response policy `policy_id` on each of `inputs`, the parts of one
/// answer, until one is refused, and records one response-scope decision for
/// the answer: the refusal, or the allow when every part is allowed.
pub async fn check_response_policy_on_each(
    policy_manager: &crate::policies::surface_manager::SurfacePolicyManager,
    policy_id: &str,
    inputs: impl IntoIterator<Item = ResponsePolicyInput>,
    context: crate::observability::PolicyDecisionEvent<'_>,
) -> ResponsePolicyDecision {
    let attestation = policy_manager
        .resolve_policy_attestation(Some(policy_id))
        .await;
    let key = response_policy_key(policy_id);
    let mut decision = ResponsePolicyDecision {
        allow: true,
        reason: None,
        error: None,
    };
    for input in inputs {
        decision = evaluate_response_policy(policy_manager, &key, input);
        if !decision.allow {
            break;
        }
    }
    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
        scope: crate::observability::PolicyScope::Response,
        allow: decision.allow,
        reason: decision.reason.as_deref(),
        error: decision.error,
        policy_id: Some(policy_id),
        policy_definition_id: Some(policy_id),
        policy_name: attestation.name.as_deref(),
        policy_version: attestation.version,
        policy_content_hash: attestation
            .content_hash
            .as_deref(),
        ..context
    });
    decision
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_policy_input_serializes() {
        let input = ResponsePolicyInput::new(
            ResponseContext {
                status_code: 200,
                body: Some(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"tools": [{"name": "search"}]}
                })),
                content_type: Some("application/json".to_string()),
                is_error: false,
                method: Some("tools/list".to_string()),
            },
            CallerContext {
                did: Some("did:example:caller".to_string()),
                identity_source: Some("gateway_computed".to_string()),
                dna_uai: None,
            },
            SurfaceContext {
                id: "surf-001".to_string(),
                name: "research-agent".to_string(),
                protocol: "mcp".to_string(),
            },
        );

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["response"]["status_code"], 200);
        assert_eq!(json["caller"]["did"], "did:example:caller");
        assert_eq!(json["surface"]["protocol"], "mcp");
        assert!(json.get("transit").is_none(), "an inbound leg has no input.transit");
        assert!(
            json.get("source_auth")
                .is_none()
        );
        assert!(
            json.get("extension_identity")
                .is_none()
        );
    }

    fn minimal_input() -> ResponsePolicyInput {
        ResponsePolicyInput::new(
            ResponseContext {
                status_code: 200,
                body: None,
                content_type: None,
                is_error: false,
                method: None,
            },
            CallerContext {
                did: None,
                identity_source: None,
                dna_uai: None,
            },
            SurfaceContext {
                id: "surf-001".to_string(),
                name: "research-agent".to_string(),
                protocol: "mcp".to_string(),
            },
        )
    }

    #[test]
    fn a_negated_transit_rule_is_true_on_an_inbound_leg() {
        // Documents why `not input.transit.caller.verified` must not be used
        // in a response policy shared with the inbound legs.
        let manager = crate::policies::SurfacePolicyManager::new();
        manager
            .load_policy_text(
                "response:surf-001",
                "package surface.policy\n\ndefault allow := false\n\nallow if {\n    not input.transit.caller.verified\n}\n",
            )
            .unwrap();

        let decision = evaluate_response_policy(&manager, "response:surf-001", minimal_input());

        assert!(decision.allow);
    }

    #[test]
    fn a_transit_point_input_carries_transit() {
        let input = minimal_input().for_transit_point(
            crate::surface_context::TransitContext {
                caller: crate::surface_context::TransitCallerContext::anonymous(),
                client: None,
            },
            None,
            Some(crate::surface_context::ExtensionIdentityContext {
                did: Some("did:web:managed.example".to_string()),
                identity_hash: Some("hash".to_string()),
                verification: crate::surface_context::IdentityVerification::SourceAuth,
            }),
        );

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["transit"]["caller"]["verified"], false);
        assert_eq!(
            json["extension_identity"],
            serde_json::json!({
                "did": "did:web:managed.example",
                "identity_hash": "hash",
                "verified": true,
                "verification": "source_auth"
            })
        );
    }

    #[test]
    fn evaluation_error_is_an_error_decision_without_engine_detail() {
        let manager = crate::policies::SurfacePolicyManager::new();
        // Compiles, but `allow` gets two values for every input.
        manager
            .load_policy_text(
                "response:surf-001",
                "package surface.policy\n\nallow := true if {\n    true\n}\n\nallow := false if {\n    true\n}\n",
            )
            .unwrap();

        let decision = evaluate_response_policy(&manager, "response:surf-001", minimal_input());

        assert!(!decision.allow, "an evaluation error fails closed");
        assert_eq!(decision.error, Some(crate::observability::PolicyEvaluationError::EvaluationError));
        assert_eq!(decision.reason, None, "engine error text must not reach audit records or callers");
    }

    #[test]
    fn a_denial_is_not_an_error() {
        let manager = crate::policies::SurfacePolicyManager::new();
        manager
            .load_policy_text("response:surf-001", "package surface.policy\n\ndefault allow := false\n")
            .unwrap();

        let decision = evaluate_response_policy(&manager, "response:surf-001", minimal_input());

        assert!(!decision.allow);
        assert_eq!(decision.error, None);
    }

    fn manager_with(rego: &str) -> crate::policies::SurfacePolicyManager {
        let manager = crate::policies::SurfacePolicyManager::new();
        manager
            .load_policy_text("response:pol-1", rego)
            .unwrap();
        manager
    }

    const DENY_ALL: &str = "package surface.policy\n\ndefault allow := false\n\ndeny_reason := \"no secrets\"\n";
    const ALLOW_ALL: &str = "package surface.policy\n\ndefault allow := true\n";

    async fn checked(
        manager: &crate::policies::SurfacePolicyManager
    ) -> (ResponsePolicyDecision, Vec<crate::observability::policy_audit::PolicyDecisionSummary>) {
        use crate::observability::policy_audit::POLICY_DECISION_COLLECTOR;
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let decision = POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), async {
                check_response_policy(
                    manager,
                    "pol-1",
                    minimal_input(),
                    crate::observability::PolicyDecisionEvent {
                        surface_id: Some("surf-001"),
                        trace_id: Some("trace-1"),
                        ..Default::default()
                    },
                )
                .await
            })
            .await;
        let recorded = collector
            .lock()
            .unwrap()
            .clone();
        (decision, recorded)
    }

    #[tokio::test]
    async fn a_checked_allow_is_recorded_as_a_response_allow() {
        let (decision, recorded) = checked(&manager_with(ALLOW_ALL)).await;

        assert!(decision.allow);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].scope, "response");
        assert_eq!(recorded[0].decision, "allow");
        assert_eq!(
            recorded[0]
                .policy_definition_id
                .as_deref(),
            Some("pol-1")
        );
        assert_eq!(
            recorded[0]
                .surface_id
                .as_deref(),
            Some("surf-001")
        );
    }

    #[tokio::test]
    async fn a_checked_deny_is_recorded_with_its_reason() {
        let (decision, recorded) = checked(&manager_with(DENY_ALL)).await;

        assert!(!decision.allow);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].decision, "deny");
        assert_eq!(
            recorded[0]
                .deny_reason
                .as_deref(),
            Some("no secrets")
        );
    }

    #[tokio::test]
    async fn a_check_that_cannot_decide_is_recorded_as_an_error_and_refuses() {
        let manager = manager_with(
            "package surface.policy\n\nallow := true if {\n    true\n}\n\nallow := false if {\n    true\n}\n",
        );

        let (decision, recorded) = checked(&manager).await;

        assert!(!decision.allow);
        assert_eq!(recorded[0].decision, "error");
        assert_eq!(
            recorded[0]
                .deny_reason
                .as_deref(),
            Some("evaluation_error")
        );
    }

    fn a2a_answer(body: Value) -> axum::response::Response {
        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    async fn answered(response: axum::response::Response) -> (u16, String) {
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn decided(allow: bool) -> ResponsePolicyDecision {
        ResponsePolicyDecision {
            allow,
            reason: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn a_refused_a2a_proxy_answer_becomes_a_403() {
        let answer = a2a_answer(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"secret": "s"}}));

        let (status, body) = answered(a2a_proxy_answer_under(answer, |_| async { decided(false) }).await).await;

        assert_eq!(status, 403);
        assert_eq!(body, DENIED_BODY);
    }

    #[tokio::test]
    async fn an_allowed_a2a_proxy_answer_is_given_unchanged() {
        let sent = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}});

        let (status, body) = answered(
            a2a_proxy_answer_under(a2a_answer(sent.clone()), |response| async move {
                assert_eq!(
                    response.body,
                    Some(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}))
                );
                assert_eq!(
                    response
                        .content_type
                        .as_deref(),
                    Some("application/json")
                );
                decided(true)
            })
            .await,
        )
        .await;

        assert_eq!(status, 200);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), sent);
    }

    #[tokio::test]
    async fn an_a2a_proxy_error_answer_is_not_checked() {
        let sent =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "backend failed"}});

        let (status, body) = answered(
            a2a_proxy_answer_under(a2a_answer(sent.clone()), |_| async {
                panic!("an A2A proxy error answer must not reach the response policy")
            })
            .await,
        )
        .await;

        assert_eq!(status, 200);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), sent);
    }

    #[tokio::test]
    async fn a_refused_mcp_proxy_answer_is_a_json_rpc_error_with_the_policy_reason() {
        let answer = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"secret": "s"}});

        let denied = mcp_proxy_refusal(&answer, Some(&serde_json::json!(7)), |response| async move {
            assert_eq!(response.body, Some(serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"secret": "s"}})));
            ResponsePolicyDecision {
                allow: false,
                reason: Some("no secrets".to_string()),
                error: None,
            }
        })
        .await;

        assert_eq!(
            denied,
            Some(serde_json::json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -32000, "message": "no secrets"}}))
        );
    }

    #[tokio::test]
    async fn an_allowed_mcp_proxy_answer_is_not_refused() {
        let answer = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {}});

        let denied = mcp_proxy_refusal(&answer, Some(&serde_json::json!(7)), |_| async { decided(true) }).await;

        assert_eq!(denied, None);
    }

    #[test]
    fn each_data_event_of_an_event_stream_is_its_own_context() {
        let body = b"event: message\r\ndata: {\"id\":1,\"result\":{\"kind\":\"task\"}}\r\n\r\n: keep-alive\n\ndata: {\"id\":1,\"error\":{\"code\":-1}}\n\n";

        let contexts = event_stream_contexts(200, body);

        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0].body, Some(serde_json::json!({"id": 1, "result": {"kind": "task"}})));
        assert!(!contexts[0].is_error);
        assert!(contexts[1].is_error);
        assert_eq!(
            contexts[1]
                .content_type
                .as_deref(),
            Some("text/event-stream")
        );
    }

    #[test]
    fn a_body_with_no_data_event_gives_no_contexts() {
        assert!(event_stream_contexts(200, b"{\"result\":{}}").is_empty());
    }

    fn input_with_body(body: Value) -> ResponsePolicyInput {
        let mut input = minimal_input();
        input.response.body = Some(body);
        input
    }

    #[tokio::test]
    async fn one_refused_part_refuses_the_answer_with_one_record() {
        use crate::observability::policy_audit::POLICY_DECISION_COLLECTOR;
        let manager = manager_with(
            "package surface.policy\n\ndefault allow := true\n\nallow := false if {\n    input.response.body.result.secret\n}\n",
        );
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let decision = POLICY_DECISION_COLLECTOR
            .scope(
                collector.clone(),
                check_response_policy_on_each(
                    &manager,
                    "pol-1",
                    [
                        input_with_body(serde_json::json!({"result": {"kind": "task"}})),
                        input_with_body(serde_json::json!({"result": {"secret": "s"}})),
                    ],
                    crate::observability::PolicyDecisionEvent::default(),
                ),
            )
            .await;

        assert!(!decision.allow);
        let recorded = collector
            .lock()
            .unwrap()
            .clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].decision, "deny");
    }

    #[tokio::test]
    async fn every_allowed_part_is_recorded_as_one_allow() {
        use crate::observability::policy_audit::POLICY_DECISION_COLLECTOR;
        let manager = manager_with(ALLOW_ALL);
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let decision = POLICY_DECISION_COLLECTOR
            .scope(
                collector.clone(),
                check_response_policy_on_each(
                    &manager,
                    "pol-1",
                    [minimal_input(), minimal_input(), minimal_input()],
                    crate::observability::PolicyDecisionEvent::default(),
                ),
            )
            .await;

        assert!(decision.allow);
        let recorded = collector
            .lock()
            .unwrap()
            .clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].decision, "allow");
    }

    #[test]
    fn a_target_error_status_is_an_error_response() {
        assert!(response_context(502, b"{}", None).is_error);
        assert!(!response_context(200, b"{}", None).is_error);
    }

    #[test]
    fn test_response_policy_key() {
        assert_eq!(response_policy_key("surf-001"), "response:surf-001");
        assert_eq!(response_policy_key("abc-123-def"), "response:abc-123-def");
    }
}
