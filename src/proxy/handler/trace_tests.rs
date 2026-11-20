//! The trace id an Access Point records and the one it sends its Target.

use serde_json::json;

use super::variant_routing_tests::{router, send, surface};
use crate::component_tests::helpers::RecordingTarget;
use crate::delegation_vault::audit::DelegationAuditAction;

#[tokio::test]
async fn terminate_trace_id_records_both_ids() {
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let mut terminating = surface(&target.url, json!([]), None);
    terminating
        .access_point
        .terminate_trace_id = true;

    let (status, events) = send(router(terminating), "/a2a").await;

    assert_eq!(status, axum::http::StatusCode::OK);
    let terminated: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::TraceTerminated {
                own_trace_id,
                downstream_trace_id,
                flow,
            } => Some((event.trace_id.clone(), own_trace_id.clone(), downstream_trace_id.clone(), flow.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(terminated.len(), 1, "{events:?}");
    let (record_trace_id, own, downstream, flow) = &terminated[0];
    assert_eq!(record_trace_id.as_deref(), Some(own.as_str()), "the record stays in the request's own trace");
    assert_ne!(own, downstream);
    assert_eq!(flow, "access_point");
    let received = target.received();
    assert_eq!(received.len(), 1);
    let sent: Vec<_> = received[0]
        .get_all("x-gateway-trace-id")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(sent, [downstream.as_str()], "the Target receives only the fresh trace id");
}
