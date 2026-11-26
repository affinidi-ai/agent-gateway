//! The surface response policy and MCP tool gating on the Target answers a
//! direct caller gets.

use axum::{http::HeaderMap, response::Response};

use crate::channel_info;
use crate::proxy::response_policy::{
    CallerContext, ResponseContext, ResponsePolicyDecision, ResponsePolicyInput, SurfaceContext,
    a2a_proxy_answer_under, answer_contexts, check_response_policy_on_each, denied_response,
    pass_without_policy_manager, refuse_unreadable_answer, response_context,
};
use crate::state::ProxyState;

/// The request a direct `tools/list` answer is filtered for: what its per-tool
/// policies and MCP tool gating decide on, and the fields the filtering is
/// recorded with.
pub(super) struct DirectToolsListRequest<'a> {
    pub(super) state: &'a ProxyState,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) headers: &'a HeaderMap,
    pub(super) source_auth: Option<&'a crate::surface_context::SourceAuthContext>,
    pub(super) mcp: Option<crate::surface_context::McpContext>,
    pub(super) agent: Option<&'a crate::surface_context::AgentContext>,
    pub(super) a2a: Option<&'a crate::surface_context::A2aContext>,
    pub(super) extension_identity: Option<&'a crate::surface_context::ExtensionIdentityContext>,
    pub(super) payment: Option<&'a crate::surface_context::PaymentContext>,
    pub(super) identity_binding: Option<&'a crate::surface_context::IdentityBindingContext>,
    pub(super) trace_id: &'a str,
    pub(super) identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    pub(super) actor_did: Option<&'a str>,
}

/// Removes from a `tools/list` answer the tools the surface's per-tool policies
/// and MCP tool gating hide from this caller, and records what it removed.
pub(super) fn filter_direct_tools_list(
    json_response: &mut serde_json::Value,
    request: &DirectToolsListRequest<'_>,
) {
    let state = request.state;
    let (Some(policy_manager), Some(config_id)) = (&state.policy_manager, state.surface.config_id()) else {
        return;
    };
    let Some(tools_array_mut) = json_response
        .get_mut("result")
        .and_then(|result| result.get_mut("tools"))
        .and_then(|tools| tools.as_array_mut())
    else {
        return;
    };
    let tool_names: Vec<String> = tools_array_mut
        .iter()
        .filter_map(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    if tool_names.is_empty() {
        return;
    }
    let original_count = tools_array_mut.len();

    // Build a full PolicyInput template so per-tool decisions see the same
    // context as the inbound channel OPA gate (source_auth, agent,
    // extension_identity, payment, identity_binding, a2a). `filter_mcp_tools`
    // clones the template per tool and overrides `mcp` with the synthesized
    // tools/call probe.
    let mut template = crate::surface_context::PolicyInput::new(
        request.method,
        request.path,
        crate::surface_context::filter_sensitive_headers(request.headers),
        "inbound",
        None,
        None,
        Some(config_id.to_string()),
        &state.surface.name,
    );
    template.source_auth = request.source_auth.cloned();
    template.mcp = request.mcp.clone();
    template.agent = request.agent.cloned();
    template.a2a = request.a2a.cloned();
    template.extension_identity = request
        .extension_identity
        .cloned();
    template.payment = request.payment.cloned();
    template.identity_binding = request
        .identity_binding
        .cloned();
    template.normalize_caller_did();

    let listed_names = tool_names.clone();
    let filtered_names = policy_manager.filter_mcp_tools_for_variant(
        config_id,
        state
            .active_variant_alias
            .as_deref(),
        tool_names,
        &template,
    );
    tools_array_mut.retain(|t| {
        t.get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|name| filtered_names.contains(&name.to_string()))
    });
    channel_info!(
        config_id,
        "Filtered tools based on OPA policy original_count={} filtered_count={}",
        original_count,
        tools_array_mut.len()
    );

    // MCP Tool Gating — apply the surface's condition-gated allow/deny
    // firewall on top of the per-tool OPA filter. The gate condition sees the
    // request `PolicyInput` (with `mcp.method = tools/list`), so a tool hidden
    // here is the same one the tools/call gate blocks.
    if let Some(gating) = policy_manager
        .compiled_mcp_tool_gating(
            config_id,
            state
                .active_variant_alias
                .as_deref(),
        )
        .filter(|g| !g.is_empty())
    {
        let gating_input_value = if gating.has_policy_conditions() {
            let mut gating_input = template.clone();
            gating_input.mcp = request
                .mcp
                .clone()
                .or_else(|| {
                    Some(crate::surface_context::McpContext {
                        method: "tools/list".to_string(),
                        tool_name: None,
                        resource_uri: None,
                        prompt_name: None,
                        params: None,
                        ..Default::default()
                    })
                });
            serde_json::to_value(&gating_input).unwrap_or_default()
        } else {
            serde_json::Value::Null
        };
        let current_names: Vec<String> = tools_array_mut
            .iter()
            .filter_map(|t| {
                t.get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        let gated_count_before = tools_array_mut.len();
        let allowed_names = gating.filter_tools(current_names, &gating_input_value);
        tools_array_mut.retain(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|name| allowed_names.contains(&name.to_string()))
        });
        if tools_array_mut.len() < gated_count_before {
            channel_info!(
                config_id,
                "MCP tool gating filtered tools/list before={} after={}",
                gated_count_before,
                tools_array_mut.len()
            );
        }
    }

    let kept_names: Vec<String> = tools_array_mut
        .iter()
        .filter_map(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .map(str::to_string)
        })
        .collect();
    crate::observability::policy_audit::record_tools_list_filtering(
        &listed_names,
        &kept_names,
        crate::observability::PolicyDecisionEvent {
            surface_id: Some(config_id),
            surface_name: Some(state.surface.name.as_str()),
            trace_id: Some(request.trace_id),
            http_method: Some(request.method),
            path: Some(request.path),
            identity: request.identity,
            actor_did: request.actor_did,
            ..Default::default()
        },
    );
}

/// The direct caller as the managed agent and its response policy are told:
/// the identity source comes from caller-presented metadata, not from the
/// channel's own DID:webvh identity, which represents the managed agent or
/// gateway.
pub(super) fn direct_caller_identity(
    agent_context: Option<&crate::surface_context::AgentContext>,
    extension_identity: Option<&crate::surface_context::ExtensionIdentityContext>,
) -> crate::proxy::caller_identity::CallerIdentity {
    use crate::proxy::caller_identity::CallerIdentity;
    let caller_did = agent_context
        .and_then(|ctx| ctx.did.as_deref())
        .unwrap_or("anonymous")
        .to_string();
    #[cfg(feature = "didwebvh")]
    {
        let caller_presented_did = extension_identity
            .and_then(|ctx| ctx.did.as_ref())
            .is_some();
        let caller_agent_dna = agent_context.and_then(|ctx| ctx.agent_dna.clone());
        if caller_presented_did || caller_agent_dna.is_some() {
            return CallerIdentity::from_self_presented(caller_did, None, caller_agent_dna);
        }
    }
    #[cfg(not(feature = "didwebvh"))]
    let _ = extension_identity;
    CallerIdentity::from_gateway_computed(caller_did, std::collections::HashMap::new())
}

/// The caller DID the response policy of a surface with a `fabric://` Target
/// sees: the agent context's, else the caller's own identity only when it was
/// verified, never a DID nothing in the request proves.
pub(super) fn fabric_send_caller_did<'a>(
    agent: Option<&'a crate::surface_context::AgentContext>,
    extension_identity: Option<&'a crate::surface_context::ExtensionIdentityContext>,
) -> Option<&'a str> {
    agent
        .and_then(|ctx| ctx.did.as_deref())
        .or_else(|| {
            extension_identity
                .filter(|identity| {
                    identity
                        .verification
                        .is_verified()
                })
                .and_then(|identity| identity.did.as_deref())
        })
}

/// The direct request a [`DirectResponsePolicy`] decides for.
pub(super) struct DirectRequest<'a> {
    pub(super) config_id: &'a str,
    pub(super) trace_id: &'a str,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) caller_did: Option<&'a str>,
    pub(super) agent: Option<&'a crate::surface_context::AgentContext>,
    pub(super) extension_identity: Option<&'a crate::surface_context::ExtensionIdentityContext>,
    pub(super) identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    pub(super) actor_did: Option<&'a str>,
}

/// The surface's response policy on the answers to one direct request, with the
/// caller it sees and the request fields its decisions are recorded with.
pub(super) struct DirectResponsePolicy {
    policy_id: String,
    policy_manager: Option<std::sync::Arc<crate::policies::SurfacePolicyManager>>,
    surface: SurfaceContext,
    caller: CallerContext,
    config_id: String,
    trace_id: String,
    method: String,
    path: String,
    identity: Option<crate::source_auth::AuthenticatedIdentity>,
    actor_did: Option<String>,
}

impl DirectResponsePolicy {
    /// The response policy `request` meets on the surface `state` serves, or
    /// `None` when the surface has none.
    pub(super) fn for_request(
        state: &ProxyState,
        request: DirectRequest<'_>,
    ) -> Option<Self> {
        let policy_id = state
            .surface
            .response_policy_definition_id()?
            .to_string();
        let policy_manager = state.policy_manager.clone();
        let caller = CallerContext {
            did: request
                .caller_did
                .map(str::to_string),
            identity_source: Some(
                direct_caller_identity(request.agent, request.extension_identity)
                    .identity_source
                    .to_string(),
            ),
            dna_uai: request
                .agent
                .and_then(|ctx| ctx.agent_dna.as_ref())
                .map(|dna| dna.uai.clone()),
        };
        Some(Self {
            policy_id,
            policy_manager,
            surface: SurfaceContext::of(&state.surface),
            caller,
            config_id: request.config_id.to_string(),
            trace_id: request.trace_id.to_string(),
            method: request.method.to_string(),
            path: request.path.to_string(),
            identity: request.identity.cloned(),
            actor_did: request
                .actor_did
                .map(str::to_string),
        })
    }

    /// Evaluates the policy on a Target answer `response` and records the decision.
    async fn check(
        &self,
        response: ResponseContext,
    ) -> ResponsePolicyDecision {
        self.check_each(Some(vec![response]))
            .await
    }

    /// Evaluates the policy on each part of one Target answer and records one
    /// decision for the answer. `None` is an event-stream answer with an event
    /// that is not JSON, which is refused. Without a policy manager the answer
    /// goes back unchecked, logged and recorded as an error. An answer with no
    /// part to check (an event stream with no data event) goes back with no
    /// decision.
    async fn check_each(
        &self,
        responses: Option<Vec<ResponseContext>>,
    ) -> ResponsePolicyDecision {
        if responses
            .as_ref()
            .is_some_and(Vec::is_empty)
        {
            return ResponsePolicyDecision {
                allow: true,
                reason: None,
                error: None,
            };
        }
        let context = crate::observability::PolicyDecisionEvent {
            surface_id: Some(&self.config_id),
            surface_name: Some(&self.surface.name),
            trace_id: Some(&self.trace_id),
            http_method: Some(&self.method),
            path: Some(&self.path),
            identity: self.identity.as_ref(),
            actor_did: self.actor_did.as_deref(),
            ..Default::default()
        };
        let Some(policy_manager) = self.policy_manager.as_deref() else {
            return pass_without_policy_manager(&self.policy_id, context);
        };
        let Some(responses) = responses else {
            return refuse_unreadable_answer(&self.policy_id, context);
        };
        let inputs = responses
            .into_iter()
            .map(|response| ResponsePolicyInput::new(response, self.caller.clone(), self.surface.clone()));
        check_response_policy_on_each(policy_manager, &self.policy_id, inputs, context).await
    }

    /// The `403` the caller gets when the policy refuses a whole Target answer
    /// with `status`, `body` and `content_type`, or `None` when it may go back.
    pub(super) async fn refusal(
        &self,
        status: u16,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Option<Response> {
        let decision = self
            .check(response_context(status, body, content_type))
            .await;
        (!decision.allow).then(denied_response)
    }

    /// The `403` the caller gets when the policy refuses the answer a peer
    /// gateway sent back for a `fabric://` Target, or `None` when it may go
    /// back. An answer still framed as an event stream is checked event by
    /// event, as on Fabric receive.
    pub(super) async fn refusal_of_fabric_answer(
        &self,
        status: u16,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Option<Response> {
        let decision = self
            .check_each(answer_contexts(status, body, content_type))
            .await;
        (!decision.allow).then(denied_response)
    }

    /// The A2A proxy's `answer`, or the `403` the policy gives when it refuses a
    /// successful one.
    pub(super) async fn a2a_proxy_answer(
        &self,
        answer: Response,
    ) -> Response {
        a2a_proxy_answer_under(answer, |response| self.check(response)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn surface(response_policy: Option<&str>) -> crate::config::agent_surface::AgentSurface {
        let mut target = serde_json::json!({"endpoint": "https://agent.example"});
        if let Some(id) = response_policy {
            target["response_policy"] = serde_json::json!({"policy_definition_id": id});
        }
        serde_json::from_value(serde_json::json!({
            "surface_id": "orders", "name": "orders",
            "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
            "target": target
        }))
        .unwrap()
    }

    async fn state(
        surface: crate::config::agent_surface::AgentSurface,
        policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    ) -> ProxyState {
        let surface_id = surface.surface_id.clone();
        let mut router = super::super::variant_routing_tests::router(surface);
        router.policy_manager = policy_manager;
        router
            .base_proxy_state(&surface_id)
            .await
            .unwrap()
    }

    fn deny_all_manager() -> Arc<crate::policies::SurfacePolicyManager> {
        let manager = crate::policies::SurfacePolicyManager::new();
        manager
            .load_policy_text("response:deny-responses", "package surface.policy\n\ndefault allow := false\n")
            .unwrap();
        Arc::new(manager)
    }

    fn request() -> DirectRequest<'static> {
        DirectRequest {
            config_id: "orders",
            trace_id: "trace-1",
            method: "POST",
            path: "/a2a",
            caller_did: Some("did:example:caller"),
            agent: None,
            extension_identity: None,
            identity: None,
            actor_did: Some("did:example:caller"),
        }
    }

    /// A Target that refuses the plain POST with `405`, so the direct MCP forward
    /// falls back to Legacy SSE, and answers over its Legacy SSE session: a
    /// `tools/list` with the tools `get_news` and `summarize`, any other request
    /// with a result naming a secret.
    async fn legacy_sse_only_target() -> String {
        use axum::response::IntoResponse;
        use axum::response::sse::{Event, Sse};
        use futures::StreamExt;

        let (events, receiver) = tokio::sync::mpsc::channel::<Event>(16);
        let receiver = Arc::new(tokio::sync::Mutex::new(Some(receiver)));
        let app = axum::Router::new()
            .route(
                "/sse",
                axum::routing::get(move || {
                    let receiver = receiver.clone();
                    async move {
                        let Some(receiver) = receiver.lock().await.take() else {
                            return axum::http::StatusCode::CONFLICT.into_response();
                        };
                        let endpoint = futures::stream::once(async {
                            Event::default()
                                .event("endpoint")
                                .data("/messages")
                        });
                        Sse::new(
                            endpoint
                                .chain(tokio_stream::wrappers::ReceiverStream::new(receiver))
                                .map(Ok::<_, std::convert::Infallible>),
                        )
                        .into_response()
                    }
                }),
            )
            .route(
                "/messages",
                axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                    let events = events.clone();
                    async move {
                        if request.get("id").is_some() {
                            let result = if request["method"] == "tools/list" {
                                serde_json::json!({"tools": [
                                    {"name": "get_news", "inputSchema": {"type": "object"}},
                                    {"name": "summarize", "inputSchema": {"type": "object"}}
                                ]})
                            } else {
                                serde_json::json!({"secret": "s"})
                            };
                            let answer = serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": result});
                            let _ = events
                                .send(Event::default().data(answer.to_string()))
                                .await;
                        }
                        axum::http::StatusCode::ACCEPTED
                    }
                }),
            )
            .fallback(|| async { axum::http::StatusCode::METHOD_NOT_ALLOWED });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        url
    }

    /// An MCP surface on `target` with `target_extra` merged into its Target.
    fn mcp_surface(
        target: &str,
        target_extra: serde_json::Value,
    ) -> crate::config::agent_surface::AgentSurface {
        let mut target_config = serde_json::json!({"endpoint": target});
        if let (Some(config), Some(extra)) = (target_config.as_object_mut(), target_extra.as_object()) {
            config.extend(extra.clone());
        }
        serde_json::from_value(serde_json::json!({
            "surface_id": "legacy-sse", "name": "legacy-sse",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": target_config
        }))
        .unwrap()
    }

    /// Sends the JSON-RPC `method` call to the MCP Access Point of `surface`
    /// under `policy_manager`, and returns the status and body.
    async fn send_mcp(
        surface: crate::config::agent_surface::AgentSurface,
        policy_manager: Arc<crate::policies::SurfacePolicyManager>,
        method: &str,
    ) -> (axum::http::StatusCode, String) {
        let mut router = super::super::variant_routing_tests::router(surface);
        router.policy_manager = Some(policy_manager);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
            .body(axum::body::Body::from(
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).to_string(),
            ))
            .unwrap();
        let response = Box::pin(super::super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            router,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        ))
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_response_policy_refuses_an_answer_from_a_legacy_sse_session() {
        let target = legacy_sse_only_target().await;
        let surface =
            mcp_surface(&target, serde_json::json!({"response_policy": {"policy_definition_id": "deny-responses"}}));

        let (status, body) = send_mcp(surface, deny_all_manager(), "tools/call").await;

        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("response_policy_denied"), "{body}");
        assert!(!body.contains("secret"), "the Target's answer reached the caller: {body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_tool_gating_hides_a_tool_from_a_legacy_sse_tools_list() {
        let target = legacy_sse_only_target().await;
        let surface = mcp_surface(
            &target,
            serde_json::json!({"mcp_tool_gating": {"default_effect": "deny", "gates": [
                {"id": "allow-news", "action": {"effect": "allow", "patterns": ["^get_news$"]}}
            ]}}),
        );
        let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        manager
            .update_channel_policy(&surface)
            .await
            .unwrap();

        let (status, body) = send_mcp(surface, manager, "tools/list").await;

        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert!(body.contains("get_news"), "{body}");
        assert!(!body.contains("summarize"), "a gated tool reached the caller: {body}");
    }

    #[test]
    fn a_fabric_send_caller_did_comes_only_from_a_verified_identity() {
        use crate::surface_context::{ExtensionIdentityContext, IdentityVerification};
        let identity = |verification| ExtensionIdentityContext {
            verification,
            did: Some("did:example:caller".to_string()),
            identity_hash: None,
        };

        assert_eq!(fabric_send_caller_did(None, Some(&identity(IdentityVerification::Vp))), Some("did:example:caller"));
        assert_eq!(fabric_send_caller_did(None, Some(&identity(IdentityVerification::Unverified))), None);
        assert_eq!(fabric_send_caller_did(None, None), None);
    }

    #[tokio::test]
    async fn a_surface_without_a_response_policy_meets_none() {
        let state = state(surface(None), Some(deny_all_manager())).await;

        assert!(DirectResponsePolicy::for_request(&state, request()).is_none());
    }

    #[tokio::test]
    async fn a_gateway_without_a_policy_manager_lets_the_answer_through_and_records_why() {
        let state = state(surface(Some("deny-responses")), None).await;
        let policy = DirectResponsePolicy::for_request(&state, request()).unwrap();
        let collector = Arc::new(std::sync::Mutex::new(Vec::new()));

        let refusal = crate::observability::policy_audit::POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), policy.refusal(200, b"{\"result\":{}}", Some("application/json")))
            .await;

        assert!(refusal.is_none());
        let recorded = collector
            .lock()
            .unwrap()
            .clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].decision, "error");
        assert_eq!(
            recorded[0]
                .deny_reason
                .as_deref(),
            Some("no_policy_manager")
        );
    }

    #[tokio::test]
    async fn a_direct_answer_framed_as_an_event_stream_is_checked_whole() {
        let manager = crate::policies::SurfacePolicyManager::new();
        manager
            .load_policy_text("response:deny-responses", "package surface.policy\n\ndefault allow := true\n")
            .unwrap();
        let state = state(surface(Some("deny-responses")), Some(Arc::new(manager))).await;
        let policy = DirectResponsePolicy::for_request(&state, request()).unwrap();
        let body = b"data: not json\n\n";

        assert!(
            policy
                .refusal(200, body, Some("text/event-stream"))
                .await
                .is_none()
        );
        assert!(
            policy
                .refusal_of_fabric_answer(200, body, Some("text/event-stream"))
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_refused_answer_is_a_403_recorded_with_the_caller_and_the_request() {
        let state = state(surface(Some("deny-responses")), Some(deny_all_manager())).await;
        let policy = DirectResponsePolicy::for_request(&state, request()).unwrap();
        let collector = Arc::new(std::sync::Mutex::new(Vec::new()));

        let refusal = crate::observability::policy_audit::POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), policy.refusal(200, b"{\"result\":{}}", Some("application/json")))
            .await;

        assert_eq!(refusal.map(|response| response.status()), Some(axum::http::StatusCode::FORBIDDEN));
        let recorded = collector
            .lock()
            .unwrap()
            .clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].scope, "response");
        assert_eq!(recorded[0].decision, "deny");
        assert_eq!(
            recorded[0]
                .surface_id
                .as_deref(),
            Some("orders")
        );
        assert_eq!(
            recorded[0]
                .caller_did
                .as_deref(),
            Some("did:example:caller")
        );
        assert_eq!(
            policy
                .caller
                .identity_source
                .as_deref(),
            Some("gateway-computed")
        );
    }
}
