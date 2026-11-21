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
