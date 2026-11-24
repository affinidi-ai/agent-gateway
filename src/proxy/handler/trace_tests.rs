//! The trace id an Access Point records and the one it sends its Target.

use serde_json::{Value, json};

use super::variant_routing_tests::{dispatch, router, send, surface};
use crate::component_tests::helpers::RecordingTarget;
use crate::delegation_vault::audit::DelegationAuditAction;
use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};

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

/// An MCP surface whose Target is the managed agent at `agent`, with
/// `networking` as its Target's networking settings.
fn mcp_surface(
    agent: &RecordingServer,
    networking: Value,
) -> crate::config::agent_surface::AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "tools", "name": "Tools",
        "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": format!("{}/mcp", agent.origin()), "networking": networking}
    }))
    .unwrap()
}

fn an_mcp_server() -> Vec<Answer> {
    vec![Answer::json(200, json!({"jsonrpc": "2.0", "id": 7, "result": {"content": []}}))]
}

/// Sends `body` as an MCP request with the caller's `traceparent` through the
/// Access Point of `surface`.
async fn send_mcp(
    surface: crate::config::agent_surface::AgentSurface,
    body: &str,
) {
    let request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
        .header("traceparent", CALLERS_TRACEPARENT)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let (status, _) = dispatch(router(surface), request).await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

/// Every value of header `name` in a recorded request `head`.
fn header_values<'a>(
    head: &'a str,
    name: &str,
) -> Vec<&'a str> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(sent, _)| sent.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

/// Every `traceparent` header in a recorded request `head`.
fn traceparents(head: &str) -> Vec<&str> {
    header_values(head, "traceparent")
}

/// The `traceparent` headers and the body the managed agent received for one
/// MCP request the caller sent through the Access Point with `body`.
async fn mcp_received_by_the_managed_agent(body: &str) -> (Vec<String>, String) {
    let agent = RecordingServer::start_answering(an_mcp_server()).await;
    send_mcp(mcp_surface(&agent, json!({})), body).await;
    let received = agent.requests();
    assert_eq!(received.len(), 1);
    let (head, body) = &received[0];
    (
        traceparents(head)
            .into_iter()
            .map(str::to_string)
            .collect(),
        body.clone(),
    )
}

/// Toward its Managed Agent, a Fabric target, the Access Point replaces the
/// `traceparent` an MCP request carries in `params._meta` with the one it
/// sends in the header, and keeps every other key.
#[tokio::test]
async fn an_access_point_writes_its_traceparent_into_mcp_metadata() {
    let sent = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "lookup",
        "arguments": {"city": "Paris"},
        "_meta": {"traceparent": CALLERS_TRACEPARENT, "tracestate": CALLERS_TRACESTATE, "progressToken": "progress-1"}}});

    let (traceparents, body) = mcp_received_by_the_managed_agent(&sent.to_string()).await;

    let [traceparent] = &traceparents[..] else {
        panic!("one traceparent header: {traceparents:?}");
    };
    let received: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        received["params"]["_meta"]["traceparent"],
        traceparent.as_str(),
        "the body names the traceparent the header sends: {body}"
    );
    let mut expected = sent;
    expected["params"]["_meta"]["traceparent"] = json!(traceparent);
    assert_eq!(received, expected, "every other key as the caller sent it");
}

/// An MCP request without a `traceparent` in `params._meta` gains none, and
/// reaches the Managed Agent byte for byte as the caller sent it.
#[tokio::test]
async fn an_mcp_body_without_a_traceparent_reaches_the_managed_agent_as_sent() {
    for sent in [
        r#"{"jsonrpc": "2.0", "method": "tools/call", "id": 7, "params": {"name": "lookup", "arguments": {}, "_meta": {"progressToken": "progress-1"}}}"#,
        r#"{"jsonrpc": "2.0", "method": "tools/call", "id": 7, "params": {"name": "lookup", "arguments": {}}}"#,
    ] {
        let (traceparents, body) = mcp_received_by_the_managed_agent(sent).await;

        assert_eq!(traceparents.len(), 1, "the header is sent: {traceparents:?}");
        assert_eq!(body, sent);
    }
}

/// A traffic mirror is sent the MCP body the Managed Agent is sent.
#[tokio::test]
async fn a_mirror_is_sent_the_mcp_body_its_managed_agent_is_sent() {
    let agent = RecordingServer::start_answering(an_mcp_server()).await;
    let mirror = RecordingServer::start_answering(vec![Answer::status(200)]).await;
    let sent = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "lookup",
        "arguments": {}, "_meta": {"traceparent": CALLERS_TRACEPARENT, "progressToken": "progress-1"}}});

    send_mcp(
        mcp_surface(
            &agent,
            json!({"mirror": {"endpoint": format!("{}/copy", mirror.origin()), "wait_for_response": true}}),
        ),
        &sent.to_string(),
    )
    .await;

    let to_the_agent: Vec<String> = agent
        .requests()
        .into_iter()
        .map(|(_, body)| body)
        .collect();
    let to_the_mirror: Vec<String> = mirror
        .requests()
        .into_iter()
        .map(|(_, body)| body)
        .collect();
    assert_eq!(to_the_agent.len(), 1);
    assert_eq!(to_the_mirror, to_the_agent);
}

/// A traffic mirror's copy is marked as one and names the request's trace id
/// followed by `-mirror`.
#[tokio::test]
async fn a_mirror_copy_names_the_trace_with_the_mirror_suffix() {
    let agent = RecordingServer::start_answering(an_mcp_server()).await;
    let mirror = RecordingServer::start_answering(vec![Answer::status(200)]).await;
    let call =
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "lookup", "arguments": {}}});

    send_mcp(
        mcp_surface(
            &agent,
            json!({"mirror": {"endpoint": format!("{}/copy", mirror.origin()), "wait_for_response": true}}),
        ),
        &call.to_string(),
    )
    .await;

    let copies = mirror.requests();
    let [(head, _)] = &copies[..] else {
        panic!("one copy: {copies:?}");
    };
    assert_eq!(header_values(head, "x-mirrored-request"), ["true"], "{head}");
    assert_eq!(header_values(head, "x-gateway-trace-id"), [format!("{CALLERS_TRACE_ID}-mirror")], "{head}");
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
