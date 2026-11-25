//! The surface response policy and MCP tool gating on the Target answers GW2
//! returns to a peer gateway over Fabric.

use serde_json::Value;

use super::{
    GLOBAL_POLICY_MANAGER, ProcessingResult, axum_response_to_forward_result, fabric_caller_did_and_source,
    filter_mcp_tools_list_for_fabric,
};
use crate::proxy::response_policy::{
    CallerContext, ResponseContext, ResponsePolicyDecision, ResponsePolicyInput, SurfaceContext, check_response_policy,
    denied_response, response_context,
};

/// The response policy of the surface variant serving a Fabric request, with the
/// request fields its decisions are recorded with.
pub(super) struct FabricResponsePolicy {
    policy_id: String,
    surface: SurfaceContext,
    caller: CallerContext,
    surface_id: String,
    trace_id: Option<String>,
    method: String,
    path: String,
    identity: Option<crate::source_auth::AuthenticatedIdentity>,
    actor_did: Option<String>,
}

/// The Fabric request a [`FabricResponsePolicy`] decides for.
pub(super) struct FabricResponseRequest<'a> {
    pub(super) config_id: &'a str,
    pub(super) trace_id: Option<&'a str>,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    pub(super) caller_identity: Option<&'a str>,
    pub(super) verification: crate::surface_context::IdentityVerification,
}

impl FabricResponsePolicy {
    /// The response policy `request` meets on `served`, the surface variant
    /// serving it, or `None` when that variant has none.
    pub(super) fn for_request(
        served: &crate::config::agent_surface::AgentSurface,
        request: FabricResponseRequest<'_>,
    ) -> Option<Self> {
        let policy_id = served
            .response_policy_definition_id()?
            .to_string();
        let (did, identity_source) = fabric_caller_did_and_source(request.caller_identity, request.verification);
        Some(Self {
            policy_id,
            surface: SurfaceContext::of(served),
            caller: CallerContext {
                did: did.map(str::to_string),
                identity_source: Some(identity_source.to_string()),
                dna_uai: None,
            },
            surface_id: request.config_id.to_string(),
            trace_id: request
                .trace_id
                .map(str::to_string),
            method: request.method.to_string(),
            path: request.path.to_string(),
            identity: request.identity.cloned(),
            actor_did: request
                .caller_identity
                .map(str::to_string),
        })
    }

    /// Evaluates the policy on a Target answer `response` with the gateway's
    /// policy manager and records the decision.
    pub(super) async fn check(
        &self,
        response: ResponseContext,
    ) -> ResponsePolicyDecision {
        self.check_with(
            GLOBAL_POLICY_MANAGER
                .get()
                .map(std::sync::Arc::as_ref),
            response,
        )
        .await
    }

    /// Evaluates the policy on `response` with `policy_manager` and records the
    /// decision. Without a policy manager the answer is refused and the decision
    /// recorded as `no_policy_manager`, as the request plane does.
    async fn check_with(
        &self,
        policy_manager: Option<&crate::policies::SurfacePolicyManager>,
        response: ResponseContext,
    ) -> ResponsePolicyDecision {
        let context = crate::observability::PolicyDecisionEvent {
            flow: crate::observability::PolicyFlow::Fabric,
            surface_id: Some(&self.surface_id),
            surface_name: Some(&self.surface.name),
            trace_id: self.trace_id.as_deref(),
            http_method: Some(&self.method),
            path: Some(&self.path),
            identity: self.identity.as_ref(),
            actor_did: self.actor_did.as_deref(),
            ..Default::default()
        };
        let Some(policy_manager) = policy_manager else {
            let error = crate::observability::PolicyEvaluationError::NoPolicyManager;
            crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                scope: crate::observability::PolicyScope::Response,
                allow: false,
                error: Some(error),
                policy_id: Some(&self.policy_id),
                policy_definition_id: Some(&self.policy_id),
                ..context
            });
            return ResponsePolicyDecision {
                allow: false,
                reason: None,
                error: Some(error),
            };
        };
        let input = ResponsePolicyInput::new(response, self.caller.clone(), self.surface.clone());
        check_response_policy(policy_manager, &self.policy_id, input, context).await
    }

    /// The `403` the peer gets when the policy refuses a whole Target answer
    /// with `status`, `body` and `content_type`, or `None` when it may go back.
    pub(super) async fn refusal_of_buffered(
        &self,
        status: u16,
        body: &str,
        content_type: Option<&str>,
    ) -> Option<ProcessingResult> {
        if self
            .check(response_context(status, body.as_bytes(), content_type))
            .await
            .allow
        {
            return None;
        }
        Some(axum_response_to_forward_result(denied_response()).await)
    }

    /// The A2A proxy's `answer`, or the `403` the policy gives when it refuses a
    /// successful one.
    pub(super) async fn a2a_proxy_answer(
        &self,
        answer: axum::response::Response,
    ) -> axum::response::Response {
        crate::proxy::response_policy::a2a_proxy_answer_under(answer, |response| self.check(response)).await
    }
}

/// What MCP tool gating filters a `tools/list` answer to a Fabric request with.
pub(super) struct FabricToolsListGate<'a> {
    pub(super) surface: &'a crate::config::agent_surface::AgentSurface,
    pub(super) config_id: &'a str,
    pub(super) variant_alias: Option<&'a str>,
    pub(super) request_body: bytes::Bytes,
    pub(super) headers: Option<&'a serde_json::Map<String, Value>>,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) from_did: Option<&'a str>,
    pub(super) source_auth_context: Option<&'a crate::surface_context::SourceAuthContext>,
    pub(super) modern_mcp_context: Option<&'a crate::surface_context::McpContext>,
    pub(super) metadata: crate::mcp::meta::McpMetadataContext,
}

impl FabricToolsListGate<'_> {
    /// `answer` without the tools MCP tool gating hides from this caller.
    pub(super) fn apply(
        &self,
        answer: String,
    ) -> String {
        filter_mcp_tools_list_for_fabric(
            self.surface,
            self.config_id,
            self.variant_alias,
            &self.request_body,
            &answer,
            self.headers,
            self.method,
            self.path,
            self.from_did
                .map(str::to_string),
            self.source_auth_context,
            self.modern_mcp_context,
            self.metadata,
        )
        .unwrap_or(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_with_response_policies() -> crate::config::agent_surface::AgentSurface {
        let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surface-1", "name": "surface-1",
            "access_point": {"listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a"},
            "target": {
                "endpoint": "https://agent.example",
                "response_policy": {"policy_definition_id": "base-response"}
            }
        }))
        .unwrap();
        surface.variants.push(
            serde_json::from_value(serde_json::json!({
                "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": {"target": {"response_policy": {"policy_definition_id": "beta-response"}}}
            }))
            .unwrap(),
        );
        surface
    }

    fn fabric_response_request() -> FabricResponseRequest<'static> {
        FabricResponseRequest {
            config_id: "surface-1",
            trace_id: Some("peer-trace"),
            method: "POST",
            path: "/agent",
            identity: None,
            caller_identity: Some("did:example:caller"),
            verification: crate::surface_context::IdentityVerification::Vp,
        }
    }

    fn served(alias: Option<&str>) -> crate::config::agent_surface::AgentSurface {
        surface_with_response_policies()
            .serve_variant(alias)
            .map(crate::config::agent_surface_variants::ServedVariant::into_parts)
            .unwrap()
            .1
    }

    #[test]
    fn a_fabric_request_meets_the_response_policy_of_the_variant_serving_it() {
        let beta = FabricResponsePolicy::for_request(&served(Some("beta")), fabric_response_request()).unwrap();
        let base = FabricResponsePolicy::for_request(&served(None), fabric_response_request()).unwrap();

        assert_eq!(beta.policy_id, "beta-response");
        assert_eq!(base.policy_id, "base-response");
    }

    #[test]
    fn a_fabric_request_to_a_surface_without_a_response_policy_meets_none() {
        let mut surface = served(None);
        surface.target.response_policy = None;

        assert!(FabricResponsePolicy::for_request(&surface, fabric_response_request()).is_none());
    }

    #[test]
    fn a_fabric_response_policy_sees_the_caller_the_peer_vouched_for() {
        let policy = FabricResponsePolicy::for_request(&served(None), fabric_response_request()).unwrap();

        assert_eq!(policy.caller.did.as_deref(), Some("did:example:caller"));
        assert_eq!(
            policy
                .caller
                .identity_source
                .as_deref(),
            Some("fabric-presentation")
        );
    }

    #[tokio::test]
    async fn a_fabric_response_decision_carries_the_peer_trace_and_the_fabric_flow() {
        let manager = crate::policies::SurfacePolicyManager::new();
        manager
            .load_policy_text("response:base-response", "package surface.policy\n\ndefault allow := false\n")
            .unwrap();
        let policy = FabricResponsePolicy::for_request(&served(None), fabric_response_request()).unwrap();

        let (decision, decisions) = fabric_response_checked(&policy, Some(&manager)).await;

        assert!(!decision.allow);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].scope, "response");
        assert_eq!(decisions[0].flow, "fabric");
        assert_eq!(decisions[0].decision, "deny");
        assert_eq!(
            decisions[0]
                .surface_id
                .as_deref(),
            Some("surface-1")
        );
        assert_eq!(
            decisions[0]
                .caller_did
                .as_deref(),
            Some("did:example:caller")
        );
    }

    #[tokio::test]
    async fn a_fabric_response_policy_without_a_policy_manager_refuses_and_records_why() {
        let policy = FabricResponsePolicy::for_request(&served(None), fabric_response_request()).unwrap();

        let (decision, decisions) = fabric_response_checked(&policy, None).await;

        assert!(!decision.allow);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].scope, "response");
        assert_eq!(decisions[0].decision, "error");
        assert_eq!(
            decisions[0]
                .deny_reason
                .as_deref(),
            Some("no_policy_manager")
        );
    }

    async fn fabric_response_checked(
        policy: &FabricResponsePolicy,
        manager: Option<&crate::policies::SurfacePolicyManager>,
    ) -> (ResponsePolicyDecision, Vec<crate::observability::policy_audit::PolicyDecisionSummary>) {
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let decision = crate::observability::policy_audit::POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), policy.check_with(manager, response_context(200, b"{}", None)))
            .await;
        let decisions = collector
            .lock()
            .unwrap()
            .clone();
        (decision, decisions)
    }
}
