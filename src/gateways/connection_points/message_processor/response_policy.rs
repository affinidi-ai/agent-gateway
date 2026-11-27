//! The surface response policy and MCP tool gating on the Target answers GW2
//! returns to a peer gateway over Fabric.

use serde_json::Value;

use super::{
    GLOBAL_POLICY_MANAGER, ProcessingResult, axum_response_to_forward_result, fabric_caller_did_and_source,
    filter_mcp_tools_list_for_fabric,
};
use crate::proxy::response_policy::{
    CallerContext, ResponseContext, ResponsePolicyDecision, ResponsePolicyInput, SurfaceContext, answer_contexts,
    check_response_policy_on_each, denied_response, pass_without_policy_manager, refuse_unreadable_answer,
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
        self.check_each(Some(vec![response]))
            .await
    }

    /// Evaluates the policy on each part of one Target answer with the gateway's
    /// policy manager and records one decision for the answer. `None` is an
    /// event-stream answer with an event that is not JSON, which is refused.
    async fn check_each(
        &self,
        responses: Option<Vec<ResponseContext>>,
    ) -> ResponsePolicyDecision {
        self.check_each_with(
            GLOBAL_POLICY_MANAGER
                .get()
                .map(std::sync::Arc::as_ref),
            responses,
        )
        .await
    }

    /// Evaluates the policy on each of `responses` with `policy_manager` and
    /// records one decision. Without a policy manager the answer goes back
    /// unchecked, as on the direct path, logged and recorded as an error. An
    /// answer with no part to check (an event stream with no data event) goes
    /// back with no decision.
    async fn check_each_with(
        &self,
        policy_manager: Option<&crate::policies::SurfacePolicyManager>,
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
            return pass_without_policy_manager(&self.policy_id, context);
        };
        let Some(responses) = responses else {
            return refuse_unreadable_answer(policy_manager, &self.policy_id, context).await;
        };
        let inputs = responses
            .into_iter()
            .map(|response| ResponsePolicyInput::new(response, self.caller.clone(), self.surface.clone()));
        check_response_policy_on_each(policy_manager, &self.policy_id, inputs, context).await
    }

    /// The `403` the peer gets when the policy refuses a whole Target answer
    /// with `status`, `body` and `content_type`, or `None` when it may go back.
    /// An answer still framed as an event stream (an A2A one) is first reduced
    /// in `body` to the lines the peer receives, then checked event by event,
    /// as a direct caller's is.
    pub(super) async fn refusal_of_buffered(
        &self,
        status: u16,
        body: &mut String,
        content_type: Option<&str>,
    ) -> Option<ProcessingResult> {
        if self
            .check_each(answer_contexts(status, body, content_type))
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

/// Whether the answer to a Fabric request `method` `path` is the public agent
/// card, which the response policy does not check: a `GET` or `HEAD` of a
/// well-known card path, or a `GET` of the surface's configured card location
/// (`card_location_fetch`) that was `sent_to_card_url`. A configured location
/// sent anywhere else reaches an ordinary Target route, whose answer is checked.
pub(super) fn answers_with_public_agent_card(
    method: &str,
    path: &str,
    card_location_fetch: bool,
    sent_to_card_url: bool,
) -> bool {
    crate::proxy::paths::is_public_agent_card_read(method, path) || (card_location_fetch && sent_to_card_url)
}

/// A Fabric exchange whose Target answer the response policy refused, recorded in
/// payload capture and the connection metrics with the refusal the peer gets in
/// place of the Target's answer, so the exchange is not missing from either.
pub(super) struct RefusedExchange<'a> {
    pub(super) surface_id: &'a str,
    pub(super) capture_channel: &'a str,
    pub(super) source: &'a str,
    pub(super) destination: &'a str,
    pub(super) caller_identity: Option<&'a str>,
    pub(super) request: &'a Value,
    pub(super) request_bytes: u64,
    pub(super) latency_ms: u64,
}

impl RefusedExchange<'_> {
    /// Records the exchange as failed, with `refusal` as its answer.
    pub(super) async fn record(
        &self,
        refusal: &Value,
    ) {
        if let (Some(ws_state), Some(metrics_store)) = (super::GLOBAL_WS_STATE.get(), super::GLOBAL_METRICS_STORE.get())
        {
            crate::observability::payload_capture::broadcast_payload_capture_async(
                &Some(ws_state.clone()),
                &Some(metrics_store.clone()),
                self.capture_channel,
                self.surface_id,
                self.request,
                Some(refusal.clone()),
                "client_error",
                None,
            )
            .await;
        }
        let Some(metrics_store) = super::GLOBAL_METRICS_STORE.get() else {
            return;
        };
        let trace = uuid::Uuid::new_v4().to_string();
        metrics_store
            .record_connection_with_bytes(
                self.surface_id.to_string(),
                self.source.to_string(),
                self.destination.to_string(),
                crate::metrics::ConnectionStatus::Failed,
                Some(self.latency_ms),
                self.caller_identity
                    .map(str::to_string),
                crate::metrics::ConnectionDirection::Request,
                trace.clone(),
                self.request_bytes,
                0,
                None,
                None,
                self.latency_ms,
            )
            .await;
        metrics_store
            .record_connection_with_bytes(
                self.surface_id.to_string(),
                self.destination.to_string(),
                self.source.to_string(),
                crate::metrics::ConnectionStatus::Failed,
                Some(self.latency_ms),
                None,
                crate::metrics::ConnectionDirection::Response,
                trace,
                0,
                refusal.to_string().len() as u64,
                None,
                None,
                self.latency_ms,
            )
            .await;
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

    /// The JSON `answer` to a `tools/list` without the tools MCP tool gating
    /// hides from this caller; the answer to any other request, unchanged.
    pub(super) fn apply_value(
        &self,
        answer: Value,
    ) -> Value {
        if !crate::mcp::is_tools_list_request(&self.request_body) {
            return answer;
        }
        let gated = self.apply(answer.to_string());
        serde_json::from_str(&gated).unwrap_or_else(|error| {
            tracing::warn!(%error, "MCP tool gating could not read the gated tools/list answer; failing closed");
            serde_json::from_str(&crate::mcp::fail_closed_tools_list(&self.request_body, self.metadata))
                .expect("the fail-closed tools/list answer is JSON")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_response_policy_refusal_counts_as_delivered() {
        use crate::config::ChannelProtocol;
        use crate::proxy::handler::agent_pay_gate::delivered;
        let mcp_proxy_refusal =
            serde_json::json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -32000, "message": "no"}});

        assert!(!delivered(
            &ChannelProtocol::A2a,
            axum::http::StatusCode::FORBIDDEN,
            Some(crate::proxy::response_policy::DENIED_BODY.as_bytes())
        ));
        assert!(!delivered(
            &ChannelProtocol::Mcp,
            axum::http::StatusCode::OK,
            Some(
                mcp_proxy_refusal
                    .to_string()
                    .as_bytes()
            )
        ));
    }

    /// Funds agent-pay only held for a peer's request are voided, not captured,
    /// when the receiving surface's response policy refuses the Target's answer.
    #[tokio::test]
    async fn funds_held_for_a_fabric_request_whose_answer_the_response_policy_refuses_are_voided() {
        use super::super::fabric_transit_tests::{
            CALLER_KEY, forward_request, forward_response, ran_in_child, receiver, surface,
        };
        use crate::payments_ledger::SettleAction;
        use crate::payments_ledger::settlement::SettlementStatus;
        use crate::payments_ledger::settlement::tests::{Scripted, answer};
        use crate::proxy::handler::agent_pay_gate::{install_test_transport, tests::MockGate};

        if ran_in_child("ATG_FABRIC_RESPONSE_POLICY_VOID_CHILD").await {
            return;
        }
        let app = axum::Router::new().fallback(|| async {
            axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"secret": "s"}}))
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let target = format!("http://{}", listener.local_addr().unwrap());
        let _server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });
        let gateway = format!("fabric-response-policy-gate-{}", uuid::Uuid::new_v4());
        install_test_transport(
            &gateway,
            MockGate::answering(
                200,
                &[
                    ("Payment-Receipt", "authorization-receipt"),
                    ("payment-authorization", "auth-fabric-response-policy"),
                    ("payment-capture-deadline", "2099-01-01T00:00:00Z"),
                ],
                serde_json::json!({}),
            ),
        );
        let settlement = Scripted::settling(vec![answer(SettlementStatus::Voided)]);
        crate::payments_ledger::settlement::install_test_client(&gateway, settlement.clone());
        let mut charged = surface("a2a", &target, &[]);
        charged.target.payment_policy = Some(
            serde_json::from_value(serde_json::json!({"type": "agent_pay", "payment_gateway_id": gateway,
                "payment_surface_id": "pay-1", "require_all": true}))
            .unwrap(),
        );
        charged.target.response_policy =
            Some(serde_json::from_value(serde_json::json!({"policy_definition_id": "deny-every-response"})).unwrap());
        let policies = crate::policies::SurfacePolicyManager::new();
        policies
            .load_policy_text("response:deny-every-response", "package surface.policy\n\ndefault allow := false\n")
            .unwrap();
        super::super::init_policy_manager(std::sync::Arc::new(policies)).await;
        let root = tempfile::tempdir().unwrap();
        let _receiver = receiver(root.path(), &charged).await;
        let message = forward_request(
            root.path(),
            serde_json::json!({ "x-api-key": CALLER_KEY, "Content-Type": "application/json",
                "payment-signature": format!("proof-{}", uuid::Uuid::new_v4()) }),
            serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": "message/send",
                "params": { "message": { "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] } } }),
        );

        let response = forward_response(&message).await;

        assert_eq!(response["status"], 403, "{response}");
        let mut settled = Vec::new();
        for _ in 0..200 {
            settled = settlement
                .settled
                .lock()
                .unwrap()
                .iter()
                .map(|(_, action, _)| *action)
                .collect();
            if !settled.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(settled, vec![SettleAction::Void]);
    }

    /// `surface` with `target_extra` merged into its Target.
    fn with_target(
        surface: crate::config::agent_surface::AgentSurface,
        target_extra: serde_json::Value,
    ) -> crate::config::agent_surface::AgentSurface {
        let mut surface = serde_json::to_value(surface).unwrap();
        if let (Some(target), Some(extra)) = (surface["target"].as_object_mut(), target_extra.as_object()) {
            target.extend(extra.clone());
        }
        serde_json::from_value(surface).unwrap()
    }

    type Received = (serde_json::Value, Vec<crate::observability::policy_audit::PolicyDecisionSummary>);

    /// `sends` Fabric receives of the JSON-RPC `method` call to `surface`, one
    /// after another under `policies`, each with the policy decisions it
    /// recorded. Against a Legacy SSE-only Target the first opens the session
    /// and the next ones reuse it.
    async fn receive_mcp(
        surface: &crate::config::agent_surface::AgentSurface,
        policies: crate::policies::SurfacePolicyManager,
        method: &str,
        sends: usize,
    ) -> Vec<Received> {
        use super::super::fabric_transit_tests::{CALLER_KEY, forward_request, forward_response, receiver};

        super::super::init_policy_manager(std::sync::Arc::new(policies)).await;
        let root = tempfile::tempdir().unwrap();
        let _receiver = receiver(root.path(), surface).await;
        let mut received = Vec::new();
        for _ in 0..sends {
            let message = forward_request(
                root.path(),
                serde_json::json!({ "x-api-key": CALLER_KEY, "content-type": "application/json",
                    "accept": "application/json, text/event-stream" }),
                serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": {} }),
            );
            let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let response = crate::observability::policy_audit::POLICY_DECISION_COLLECTOR
                .scope(collector.clone(), forward_response(&message))
                .await;
            let decisions = collector
                .lock()
                .unwrap()
                .clone();
            received.push((response, decisions));
        }
        received
    }

    /// The `(decision, flow)` of each response policy record in `decisions`.
    fn response_decisions(
        decisions: &[crate::observability::policy_audit::PolicyDecisionSummary]
    ) -> Vec<(&'static str, &'static str)> {
        decisions
            .iter()
            .filter(|decision| decision.scope == "response")
            .map(|decision| (decision.decision, decision.flow))
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_response_policy_refuses_a_legacy_sse_answer_to_a_fabric_caller() {
        use super::super::fabric_transit_tests::{ran_in_child, surface};

        if ran_in_child("ATG_FABRIC_LEGACY_SSE_RESPONSE_POLICY_CHILD").await {
            return;
        }
        let target = crate::proxy::response_policy::test_targets::legacy_sse_only_target().await;
        let served = with_target(
            surface("mcp", &target, &[]),
            serde_json::json!({"response_policy": {"policy_definition_id": "deny-every-response"}}),
        );
        let policies = crate::policies::SurfacePolicyManager::new();
        policies
            .load_policy_text("response:deny-every-response", "package surface.policy\n\ndefault allow := false\n")
            .unwrap();

        for (response, decisions) in receive_mcp(&served, policies, "tools/call", 2).await {
            assert_eq!(response["status"], 403, "{response}");
            assert!(
                response
                    .to_string()
                    .contains("response_policy_denied"),
                "{response}"
            );
            assert_eq!(response_decisions(&decisions), vec![("deny", "fabric")]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_tool_gating_hides_a_tool_from_a_legacy_sse_tools_list_sent_over_fabric() {
        use super::super::fabric_transit_tests::{ran_in_child, surface};

        if ran_in_child("ATG_FABRIC_LEGACY_SSE_GATING_CHILD").await {
            return;
        }
        let target = crate::proxy::response_policy::test_targets::legacy_sse_only_target().await;
        let served = with_target(
            surface("mcp", &target, &[]),
            serde_json::json!({"mcp_tool_gating": {"default_effect": "deny", "gates": [
                {"id": "allow-news", "action": {"effect": "allow", "patterns": ["^get_news$"]}}
            ]}}),
        );
        let policies = crate::policies::SurfacePolicyManager::new();
        policies
            .update_channel_policy(&served)
            .await
            .unwrap();

        for (response, decisions) in receive_mcp(&served, policies, "tools/list", 2).await {
            assert_eq!(response["status"], 200, "{response}");
            let body = response["body"]
                .as_str()
                .unwrap_or_default();
            assert!(body.contains("get_news"), "{response}");
            assert!(!body.contains("summarize"), "a gated tool reached the peer: {response}");
            let filtering = decisions
                .iter()
                .find(|decision| decision.scope == "mcp_tool_list")
                .unwrap_or_else(|| panic!("no tools/list filtering record: {decisions:?}"));
            assert_eq!(filtering.flow, "fabric");
        }
    }

    /// The Fabric receive of a `tools/call` to an MCP surface whose response
    /// policy denies an answer carrying `stamped-by-gateway`, with that stamp
    /// added as response custom metadata when `stamped`.
    async fn receive_under_a_policy_denying_the_stamp(stamped: bool) -> Received {
        use super::super::fabric_transit_tests::surface;

        let app = axum::Router::new().fallback(|| async {
            axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"content": []}}))
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let target = format!("http://{}", listener.local_addr().unwrap());
        let _server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });
        let mut target_extra = serde_json::json!({"response_policy": {"policy_definition_id": "deny-stamped"}});
        if stamped {
            target_extra["response_custom_metadata"] = serde_json::json!({"enabled": true,
                "payload": {"stamp": "stamped-by-gateway"}, "injection_target": "meta"});
        }
        let served = with_target(surface("mcp", &target, &[]), target_extra);
        let policies = crate::policies::SurfacePolicyManager::new();
        policies
            .load_policy_text(
                "response:deny-stamped",
                "package surface.policy\n\ndefault allow := true\n\nallow := false if {\n    contains(json.marshal(input.response.body), \"stamped-by-gateway\")\n}\n",
            )
            .unwrap();
        receive_mcp(&served, policies, "tools/call", 1)
            .await
            .remove(0)
    }

    /// A Target answering every request with `body` as `content_type`.
    async fn target_answering(
        content_type: &'static str,
        body: &'static str,
    ) -> String {
        let app = axum::Router::new()
            .fallback(move || async move { ([(axum::http::header::CONTENT_TYPE, content_type)], body) });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let target = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });
        target
    }

    fn a2a_message() -> serde_json::Value {
        serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": "message/send",
            "params": { "message": { "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] } } })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_legacy_sse_answer_a_fabric_response_policy_allows_goes_back_with_an_allow() {
        use super::super::fabric_transit_tests::{ran_in_child, surface};

        if ran_in_child("ATG_FABRIC_LEGACY_SSE_RESPONSE_ALLOW_CHILD").await {
            return;
        }
        let target = crate::proxy::response_policy::test_targets::legacy_sse_only_target().await;
        let served = with_target(
            surface("mcp", &target, &[]),
            serde_json::json!({"response_policy": {"policy_definition_id": "allow-every-response"}}),
        );
        let policies = crate::policies::SurfacePolicyManager::new();
        policies
            .load_policy_text("response:allow-every-response", "package surface.policy\n\ndefault allow := true\n")
            .unwrap();

        for (response, decisions) in receive_mcp(&served, policies, "tools/call", 2).await {
            assert_eq!(response["status"], 200, "{response}");
            assert!(
                response["body"]
                    .as_str()
                    .is_some_and(|body| body.contains("secret")),
                "{response}"
            );
            assert_eq!(response_decisions(&decisions), vec![("allow", "fabric")]);
        }
    }

    #[tokio::test]
    async fn a_comment_in_an_event_stream_answer_is_not_relayed_to_a_fabric_caller() {
        use super::super::fabric_transit_tests::{
            CALLER_KEY, forward_request, forward_response, ran_in_child, receiver, surface,
        };

        if ran_in_child("ATG_FABRIC_STREAM_COMMENT_CHILD").await {
            return;
        }
        let target = target_answering(
            "text/event-stream",
            ": unchecked-note\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"kind\":\"message\",\"note\":\"delivered\"}}\n\n",
        )
        .await;
        let served = with_target(
            surface("a2a", &target, &[]),
            serde_json::json!({"response_policy": {"policy_definition_id": "allow-every-response"}}),
        );
        let policies = crate::policies::SurfacePolicyManager::new();
        policies
            .load_policy_text("response:allow-every-response", "package surface.policy\n\ndefault allow := true\n")
            .unwrap();
        super::super::init_policy_manager(std::sync::Arc::new(policies)).await;
        let root = tempfile::tempdir().unwrap();
        let _receiver = receiver(root.path(), &served).await;

        let response = forward_response(&forward_request(
            root.path(),
            serde_json::json!({ "x-api-key": CALLER_KEY, "content-type": "application/json" }),
            a2a_message(),
        ))
        .await;

        assert_eq!(response["status"], 200, "{response}");
        let body = response["body"]
            .as_str()
            .unwrap_or_default();
        assert!(body.contains("delivered"), "{response}");
        assert!(!body.contains("unchecked-note"), "the comment reached the peer: {response}");
    }

    #[tokio::test]
    async fn a_fabric_response_decision_shares_the_trace_of_the_request_decisions() {
        use super::super::fabric_transit_tests::{
            CALLER_KEY, forward_request, forward_response, ran_in_child, receiver, surface,
        };
        use crate::delegation_vault::audit::DelegationAuditAction;

        if ran_in_child("ATG_FABRIC_RESPONSE_TRACE_CHILD").await {
            return;
        }
        let target = target_answering("application/json", "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}").await;
        let served = with_target(
            surface("a2a", &target, &[]),
            serde_json::json!({
                "policy": {"policy_definition_id": "allow-requests"},
                "response_policy": {"policy_definition_id": "deny-every-response"}
            }),
        );
        let policies = crate::policies::SurfacePolicyManager::new();
        policies
            .load_policy_text(&served.surface_id, "package surface.policy\n\ndefault allow := true\n")
            .unwrap();
        policies
            .load_policy_text("response:deny-every-response", "package surface.policy\n\ndefault allow := false\n")
            .unwrap();
        super::super::init_policy_manager(std::sync::Arc::new(policies)).await;
        let root = tempfile::tempdir().unwrap();
        let _receiver = receiver(root.path(), &served).await;
        let mut message = forward_request(
            root.path(),
            serde_json::json!({ "x-api-key": CALLER_KEY, "content-type": "application/json" }),
            a2a_message(),
        );
        message.message_body["otel_context"] = serde_json::json!({
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "span_id": "00f067aa0ba902b7",
            "trace_flags": 1
        });

        let (response, events) = crate::audit::producer::capture(forward_response(&message)).await;

        assert_eq!(response["status"], 403, "{response}");
        let traces: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.event {
                DelegationAuditAction::PolicyDecision { scope, .. } => Some((scope.clone(), event.trace_id.clone())),
                _ => None,
            })
            .collect();
        let trace_of = |scope: &str| {
            traces
                .iter()
                .find(|(decided, _)| decided == scope)
                .map(|(_, trace)| trace.clone())
                .unwrap_or_else(|| panic!("no {scope} decision: {traces:?}"))
        };
        assert_eq!(trace_of("surface"), Some("trace-from-the-peer".to_string()));
        assert_eq!(trace_of("response"), trace_of("surface"));
    }

    #[tokio::test]
    async fn a_response_policy_over_fabric_sees_the_response_custom_metadata() {
        if super::super::fabric_transit_tests::ran_in_child("ATG_FABRIC_RESPONSE_METADATA_POLICY_CHILD").await {
            return;
        }

        let (response, decisions) = receive_under_a_policy_denying_the_stamp(true).await;

        assert_eq!(response["status"], 403, "{response}");
        assert!(
            response
                .to_string()
                .contains("response_policy_denied"),
            "{response}"
        );
        assert_eq!(response_decisions(&decisions), vec![("deny", "fabric")]);
    }

    #[tokio::test]
    async fn an_answer_without_the_metadata_a_fabric_response_policy_denies_goes_back() {
        if super::super::fabric_transit_tests::ran_in_child("ATG_FABRIC_RESPONSE_UNSTAMPED_POLICY_CHILD").await {
            return;
        }

        let (response, decisions) = receive_under_a_policy_denying_the_stamp(false).await;

        assert_eq!(response["status"], 200, "{response}");
        assert_eq!(response_decisions(&decisions), vec![("allow", "fabric")]);
    }

    #[test]
    fn only_the_public_agent_card_skips_the_response_policy_over_fabric() {
        assert!(answers_with_public_agent_card("GET", "/a2a/.well-known/agent-card.json", false, false));
        assert!(answers_with_public_agent_card("GET", "/cards/main.json", true, true));
        assert!(!answers_with_public_agent_card("GET", "/cards/main.json", true, false));
        assert!(!answers_with_public_agent_card("POST", "/a2a/.well-known/agent-card.json", false, false));
        assert!(!answers_with_public_agent_card("GET", "/api?x=/.well-known/agent.json", false, false));
    }

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
    async fn a_fabric_response_policy_without_a_policy_manager_lets_the_answer_through_and_records_why() {
        let policy = FabricResponsePolicy::for_request(&served(None), fabric_response_request()).unwrap();

        let (decision, decisions) = fabric_response_checked(&policy, None).await;

        assert!(decision.allow);
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

    #[tokio::test]
    async fn a_fabric_event_stream_answer_of_only_keep_alives_goes_back_with_no_decision() {
        let manager = crate::policies::SurfacePolicyManager::new();
        manager
            .load_policy_text("response:base-response", "package surface.policy\n\ndefault allow := false\n")
            .unwrap();
        let policy = FabricResponsePolicy::for_request(&served(None), fabric_response_request()).unwrap();
        let mut body = ": keep-alive\n\nretry: 100\n\n".to_string();
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let decision = crate::observability::policy_audit::POLICY_DECISION_COLLECTOR
            .scope(
                collector.clone(),
                policy.check_each_with(
                    Some(&manager),
                    crate::proxy::response_policy::answer_contexts(200, &mut body, Some("text/event-stream")),
                ),
            )
            .await;

        assert!(decision.allow);
        assert!(
            collector
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(body, "\n\n");
    }

    async fn fabric_response_checked(
        policy: &FabricResponsePolicy,
        manager: Option<&crate::policies::SurfacePolicyManager>,
    ) -> (ResponsePolicyDecision, Vec<crate::observability::policy_audit::PolicyDecisionSummary>) {
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let decision = crate::observability::policy_audit::POLICY_DECISION_COLLECTOR
            .scope(
                collector.clone(),
                policy.check_each_with(
                    manager,
                    Some(vec![crate::proxy::response_policy::response_context(200, b"{}", None)]),
                ),
            )
            .await;
        let decisions = collector
            .lock()
            .unwrap()
            .clone();
        (decision, decisions)
    }
}
