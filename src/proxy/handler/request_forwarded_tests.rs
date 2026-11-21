//! The `request_forwarded` record an Access Point writes for each request it
//! hands to its target.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::component_tests::helpers::MockServer;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};

const CALLERS_TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

/// The `request_forwarded` records among `events`, as stored.
pub(super) fn forwarded(events: &[DelegationAuditEvent]) -> Vec<Value> {
    events
        .iter()
        .filter(|event| matches!(event.event, DelegationAuditAction::RequestForwarded { .. }))
        .map(|event| serde_json::to_value(event).unwrap())
        .collect()
}

/// Sends one A2A message carrying the caller's `traceparent` and planted
/// values through the Access Point, and returns the status with every audit
/// record the request wrote.
async fn send_with_planted_values(
    router: crate::state::MultiSurfaceProxyState
) -> (axum::http::StatusCode, Vec<DelegationAuditEvent>) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
        "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "planted-body-text"}]
    }}});
    let request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/a2a/rpc")
        .header("content-type", "application/json")
        .header("traceparent", CALLERS_TRACEPARENT)
        .header("authorization", "Bearer planted-token")
        .header("x-planted", "planted-header-value")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let (response, events) =
        crate::audit::producer::capture(Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            router,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        )))
        .await;
    (response.status(), events)
}

/// [`super::variant_routing_tests::router`] with a request policy that denies
/// every request. Returns the directory holding the policy, which the caller
/// keeps alive.
async fn router_denying_requests(
    mut surface: crate::config::agent_surface::AgentSurface
) -> (crate::state::MultiSurfaceProxyState, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let policies = std::sync::Arc::new(
        crate::policies::policy_definitions::FileSystemPolicyDefinitionStore::new(
            directory
                .path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap(),
    );
    policies
        .save(
            serde_json::from_value(json!({
                "id": "deny-requests", "name": "Deny requests", "policy_type": "agent_surface",
                "policy": "package surface.policy\ndefault allow = false", "created_at": "2026-11-21T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    surface.target.policy = serde_json::from_value(json!({"policy_definition_id": "deny-requests"})).unwrap();
    let manager = std::sync::Arc::new(crate::policies::SurfacePolicyManager::new());
    manager.set_policy_definition_store(policies);
    manager
        .update_channel_policy(&surface)
        .await
        .unwrap();
    let mut router = super::variant_routing_tests::router(surface);
    router.policy_manager = Some(manager);
    (router, directory)
}

#[tokio::test]
async fn a_refused_request_is_not_recorded_as_forwarded() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string())
            .await;
    let (router, _policies) =
        router_denying_requests(super::variant_routing_tests::surface(&target.url(), json!([]), None)).await;

    let (status, events) = send_with_planted_values(router).await;

    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        0
    );
    assert!(forwarded(&events).is_empty(), "no request_forwarded record for a refused request, got {events:?}");
}

#[tokio::test]
async fn an_access_point_records_the_request_it_forwards() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string())
            .await;
    let surface = super::variant_routing_tests::surface(&target.url(), json!([]), None);

    let (status, events) = send_with_planted_values(super::variant_routing_tests::router(surface)).await;

    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        1
    );
    let records = forwarded(&events);
    assert_eq!(records.len(), 1, "one request_forwarded record, got {events:?}");
    let record = &records[0];
    assert_eq!(record["event"]["request_forwarded"]["flow"], "access_point");
    assert_eq!(record["trace_id"], "0af7651916cd43dd8448eb211c80319c");
    assert_eq!(record["parent_span_id"], "b7ad6b7169203331");
    assert_eq!(record["trace_source"], "header");
    assert_eq!(record["span_id"], record["request_id"]);
    assert_eq!(record["surface_id"], "orders");
    assert_eq!(record["protocol"], "a2a");
    assert_eq!(record["via_fabric"], false);
    assert!(record.get("caller").is_none(), "an unauthenticated caller is not named: {record}");
    let stored = record.to_string();
    for planted in ["planted-body-text", "planted-token", "planted-header-value"] {
        assert!(!stored.contains(planted), "the record holds {planted}: {stored}");
    }
}
