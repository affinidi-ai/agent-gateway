//! The trace id an Access Point records and the one it sends its Target.

use serde_json::json;

use super::variant_routing_tests::{dispatch, router, send, surface};
use crate::component_tests::helpers::RecordingTarget;
use crate::delegation_vault::audit::DelegationAuditAction;

const CALLERS_TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
const CALLERS_TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const CALLERS_TRACESTATE: &str = "congo=t61rcWkgMzE";

/// Every value of `name` that `received` carries.
fn values<'a>(
    received: &'a axum::http::HeaderMap,
    name: &str,
) -> Vec<&'a str> {
    received
        .get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect()
}

/// The headers the Target received for one A2A message the caller sent through
/// the Access Point with `headers`.
async fn received_by_the_target(headers: &[(&str, &str)]) -> axum::http::HeaderMap {
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let mut request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/a2a")
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
        "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hello"}]
    }}});
    let (status, _) = dispatch(
        router(surface(&target.url, json!([]), None)),
        request
            .body(axum::body::Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let received = target.received();
    assert_eq!(received.len(), 1);
    received[0].clone()
}

#[tokio::test]
async fn an_access_point_sends_its_target_one_set_of_trace_headers() {
    let continued = received_by_the_target(&[
        ("traceparent", CALLERS_TRACEPARENT),
        ("tracestate", CALLERS_TRACESTATE),
        ("x-gateway-trace-id", CALLERS_TRACE_ID),
    ])
    .await;
    assert_eq!(
        values(&continued, "x-gateway-trace-id"),
        [CALLERS_TRACE_ID],
        "one X-Gateway-Trace-Id, the caller's trace"
    );
    let [traceparent] = values(&continued, "traceparent")[..] else {
        panic!("one traceparent: {continued:?}");
    };
    let parts: Vec<&str> = traceparent
        .split('-')
        .collect();
    assert_eq!((parts[0], parts[1], parts[3]), ("00", CALLERS_TRACE_ID, "01"), "{traceparent}");
    assert_ne!(parts[2], "b7ad6b7169203331", "the gateway's span, not the caller's: {traceparent}");
    assert_eq!(values(&continued, "tracestate"), [CALLERS_TRACESTATE], "a continued trace keeps its tracestate");

    let started = received_by_the_target(&[
        ("traceparent", "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01"),
        ("tracestate", CALLERS_TRACESTATE),
    ])
    .await;
    let [traceparent] = values(&started, "traceparent")[..] else {
        panic!("one traceparent: {started:?}");
    };
    let parts: Vec<&str> = traceparent
        .split('-')
        .collect();
    assert_ne!(parts[1].to_ascii_lowercase(), CALLERS_TRACE_ID, "a new trace: {traceparent}");
    assert_eq!(parts[3], "00", "a trace the gateway starts is not sampled when it does not export: {traceparent}");
    assert_eq!(values(&started, "x-gateway-trace-id"), [parts[1]], "the new trace in X-Gateway-Trace-Id");
    assert!(values(&started, "tracestate").is_empty(), "a new trace drops the caller's tracestate: {started:?}");
}

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
