//! The surface response policy and MCP tool gating on the Target answers a
//! direct caller gets.

use axum::{http::HeaderMap, response::Response};

use crate::channel_info;
use crate::proxy::response_policy::{
    CallerContext, ResponseContext, ResponsePolicyDecision, ResponsePolicyInput, SurfaceContext,
    a2a_proxy_answer_under, check_response_policy, denied_response, response_context,
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

/// The direct request a [`DirectResponsePolicy`] decides for.
pub(super) struct DirectRequest<'a> {
    pub(super) config_id: &'a str,
    pub(super) trace_id: &'a str,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) agent: Option<&'a crate::surface_context::AgentContext>,
    pub(super) extension_identity: Option<&'a crate::surface_context::ExtensionIdentityContext>,
    pub(super) identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    pub(super) actor_did: Option<&'a str>,
}

/// The surface's response policy on the answers to one direct request, with the
/// caller it sees and the request fields its decisions are recorded with.
pub(super) struct DirectResponsePolicy {
    policy_id: String,
    policy_manager: std::sync::Arc<crate::policies::SurfacePolicyManager>,
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
    /// `None` when the surface has none or the gateway has no policy manager.
    pub(super) fn for_request(
        state: &ProxyState,
        request: DirectRequest<'_>,
    ) -> Option<Self> {
        let policy_id = state
            .surface
            .response_policy_definition_id()?
            .to_string();
        let policy_manager = state.policy_manager.clone()?;
        let caller = CallerContext {
            did: request
                .agent
                .and_then(|ctx| ctx.did.clone()),
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
        let input = ResponsePolicyInput::new(response, self.caller.clone(), self.surface.clone());
        check_response_policy(
            &self.policy_manager,
            &self.policy_id,
            input,
            crate::observability::PolicyDecisionEvent {
                surface_id: Some(&self.config_id),
                surface_name: Some(&self.surface.name),
                trace_id: Some(&self.trace_id),
                http_method: Some(&self.method),
                path: Some(&self.path),
                identity: self.identity.as_ref(),
                actor_did: self.actor_did.as_deref(),
                ..Default::default()
            },
        )
        .await
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

    /// The A2A proxy's `answer`, or the `403` the policy gives when it refuses a
    /// successful one.
    pub(super) async fn a2a_proxy_answer(
        &self,
        answer: Response,
    ) -> Response {
        a2a_proxy_answer_under(answer, |response| self.check(response)).await
    }
}
