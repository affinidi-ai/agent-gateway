//! Upstream response bounds — end-to-end.
//!
//! A legacy MCP response that is not `text/event-stream` is buffered by the
//! inbound Access Point, and every MCP response is buffered by the outbound
//! Transit Point. A buffered body must be capped at `a2a.max_body_size` and must
//! fail at the target's `timeout.idle_secs` when it stalls, even when the
//! caller's `Accept` makes the request SSE-shaped. A `text/event-stream`
//! passthrough is not buffered and keeps streaming past that idle deadline,
//! except a `tools/list` answered as SSE, which is buffered for tool gating and
//! gets the same bounds.
//! The same bounds apply to every other protocol's buffered responses, shown
//! here for A2A.

use std::time::{Duration, Instant};

use super::helpers::{self, GatewayHarness, MockServer};
use crate::config::agent_surface::{AgentSurface, NetworkingConfig};
use serde_json::json;

const LIMIT: usize = 4096;
const STALL_BUDGET: Duration = Duration::from_secs(10);
const PARTIAL_JSON: &str = r#"{"jsonrpc":"2.0","id":7,"#;

fn tools_call() -> String {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "echo", "arguments": {}}}).to_string()
}

fn result_with_text(length: usize) -> String {
    json!({"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "x".repeat(length)}]}})
        .to_string()
}

fn one_second_idle() -> NetworkingConfig {
    serde_json::from_value(json!({"timeout": {"idle_secs": 1}})).expect("NetworkingConfig JSON")
}

fn tools_list() -> String {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}).to_string()
}

fn sse_shaped_request(url: &str) -> reqwest::RequestBuilder {
    sse_shaped_request_with(url, tools_call())
}

fn sse_shaped_request_with(
    url: &str,
    body: String,
) -> reqwest::RequestBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body)
}

async fn post_sse_shaped(url: &str) -> (reqwest::StatusCode, String, Duration) {
    post_sse_shaped_with(url, tools_call()).await
}

async fn post_sse_shaped_with(
    url: &str,
    body: String,
) -> (reqwest::StatusCode, String, Duration) {
    let started = Instant::now();
    let response = sse_shaped_request_with(url, body)
        .send()
        .await
        .expect("gateway must answer before the client timeout");
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_default();
    (status, body, started.elapsed())
}

fn access_point_surface(networking: Option<NetworkingConfig>) -> AgentSurface {
    let mut surface = helpers::build_minimal_mcp_surface();
    surface.target.networking = networking;
    surface
}

fn transit_surface(point_networking: Option<NetworkingConfig>) -> AgentSurface {
    serde_json::from_value(json!({
        "name": "smoke-mcp-outbound",
        "description": "Legacy MCP response bounds transit surface",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "mcp"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "sign_requests": false,
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "protocol": "mcp",
                "require_transit_token": false,
                "networking": point_networking
            }]
        }
    }))
    .expect("transit_surface: AgentSurface JSON")
}

fn transit_url(harness: &GatewayHarness) -> String {
    format!(
        "{}/outbound/smoke/target/rpc",
        harness
            .outbound_url
            .as_ref()
            .expect("outbound_url must be set")
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn access_point_forwards_a_legacy_mcp_body_within_the_limit_and_rejects_a_larger_one() {
    let (mock, upstream_body) = MockServer::start_with_response_channel(result_with_text(LIMIT / 2)).await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.a2a.max_body_size = LIMIT;
        config.surfaces = vec![access_point_surface(None)];
    })
    .await;

    let (status, body, _) = post_sse_shaped(&harness.gateway_url).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(&"x".repeat(LIMIT / 2)), "{body}");

    upstream_body
        .send(result_with_text(LIMIT * 2))
        .unwrap();
    let (status, body, _) = post_sse_shaped(&harness.gateway_url).await;
    assert_eq!(status, 502, "{body}");
    assert!(body.contains("Upstream response too large"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn access_point_stops_a_stalled_legacy_mcp_body_at_the_idle_deadline() {
    let mock =
        MockServer::start_with_streamed_body("application/json", vec![(Duration::ZERO, PARTIAL_JSON.into())]).await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![access_point_surface(Some(one_second_idle()))];
    })
    .await;

    let (status, body, elapsed) = post_sse_shaped(&harness.gateway_url).await;

    assert_eq!(status, 504, "{body}");
    assert!(body.contains("Upstream response timed out"), "{body}");
    assert!(elapsed < STALL_BUDGET, "stalled body held the caller for {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn access_point_keeps_streaming_an_sse_passthrough_past_the_idle_deadline() {
    let progress =
        r#"data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1}}"#;
    let result = r#"data: {"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#;
    let mock = MockServer::start_with_streamed_body(
        "text/event-stream",
        vec![(Duration::ZERO, format!("{progress}\n\n")), (Duration::from_millis(2500), format!("{result}\n\n"))],
    )
    .await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![access_point_surface(Some(one_second_idle()))];
    })
    .await;
    let started = Instant::now();

    let mut response = sse_shaped_request(&harness.gateway_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut received = String::new();
    while !received.contains(r#""id":7"#) {
        let chunk = tokio::time::timeout(STALL_BUDGET, response.chunk())
            .await
            .expect("SSE passthrough stopped delivering")
            .unwrap()
            .expect("SSE passthrough ended before the result event");
        received.push_str(&String::from_utf8_lossy(&chunk));
    }

    assert!(received.contains("notifications/progress"), "{received}");
    assert!(started.elapsed() >= Duration::from_secs(2), "result arrived after {:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread")]
async fn access_point_rejects_an_sse_tools_list_over_the_limit() {
    let result = json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": [{"name": "x".repeat(LIMIT * 2)}]}});
    let mock = MockServer::start_with_streamed_body(
        "text/event-stream",
        vec![(Duration::ZERO, format!("data: {result}\n\n"))],
    )
    .await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.a2a.max_body_size = LIMIT;
        config.surfaces = vec![access_point_surface(None)];
    })
    .await;

    let (status, body, _) = post_sse_shaped_with(&harness.gateway_url, tools_list()).await;

    assert_eq!(status, 502, "{body}");
    assert!(body.contains("Upstream response too large"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn access_point_stops_a_stalled_sse_tools_list_at_the_idle_deadline() {
    let progress =
        r#"data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1}}"#;
    let mock =
        MockServer::start_with_streamed_body("text/event-stream", vec![(Duration::ZERO, format!("{progress}\n\n"))])
            .await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![access_point_surface(Some(one_second_idle()))];
    })
    .await;

    let (status, body, elapsed) = post_sse_shaped_with(&harness.gateway_url, tools_list()).await;

    assert_eq!(status, 504, "{body}");
    assert!(body.contains("Upstream response timed out"), "{body}");
    assert!(elapsed < STALL_BUDGET, "stalled tools/list held the caller for {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn transit_point_forwards_a_legacy_mcp_body_within_the_limit_and_rejects_a_larger_one() {
    let (mock, upstream_body) = MockServer::start_with_response_channel(result_with_text(LIMIT / 2)).await;
    let harness = GatewayHarness::start_with_outbound_mock(mock, |_, config, _| {
        config.a2a.max_body_size = LIMIT;
        config.surfaces = vec![transit_surface(None)];
    })
    .await;

    let (status, body, _) = post_sse_shaped(&transit_url(&harness)).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(&"x".repeat(LIMIT / 2)), "{body}");

    upstream_body
        .send(result_with_text(LIMIT * 2))
        .unwrap();
    let (status, body, _) = post_sse_shaped(&transit_url(&harness)).await;
    assert_eq!(status, 502, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn transit_point_stops_a_stalled_legacy_mcp_body_at_the_idle_deadline() {
    let mock =
        MockServer::start_with_streamed_body("application/json", vec![(Duration::ZERO, PARTIAL_JSON.into())]).await;
    let harness = GatewayHarness::start_with_outbound_mock(mock, |_, config, _| {
        config.surfaces = vec![transit_surface(Some(one_second_idle()))];
    })
    .await;

    let (status, body, elapsed) = post_sse_shaped(&transit_url(&harness)).await;

    assert_eq!(status, 504, "{body}");
    assert!(elapsed < STALL_BUDGET, "stalled body held the caller for {elapsed:?}");
}

async fn post_a2a(url: &str) -> (reqwest::StatusCode, String, Duration) {
    let started = Instant::now();
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
        .post(url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":7}"#)
        .send()
        .await
        .expect("gateway must answer before the client timeout");
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_default();
    (status, body, started.elapsed())
}

#[tokio::test(flavor = "multi_thread")]
async fn access_point_rejects_an_a2a_body_over_the_limit_and_stops_a_stalled_one() {
    let (mock, upstream_body) = MockServer::start_with_response_channel(result_with_text(LIMIT * 2)).await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.a2a.max_body_size = LIMIT;
        config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;
    let (status, body, _) = post_a2a(&harness.gateway_url).await;
    assert_eq!(status, 502, "{body}");
    assert!(body.contains("Upstream response too large"), "{body}");
    upstream_body
        .send(result_with_text(LIMIT / 2))
        .unwrap();
    let (status, body, _) = post_a2a(&harness.gateway_url).await;
    assert_eq!(status, 200, "{body}");

    let mock =
        MockServer::start_with_streamed_body("application/json", vec![(Duration::ZERO, PARTIAL_JSON.into())]).await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        let mut surface = helpers::build_minimal_channel();
        surface.target.networking = Some(one_second_idle());
        config.surfaces = vec![surface];
    })
    .await;
    let (status, body, elapsed) = post_a2a(&harness.gateway_url).await;
    assert_eq!(status, 504, "{body}");
    assert!(elapsed < STALL_BUDGET, "stalled body held the caller for {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn access_point_rejects_an_agent_card_over_the_limit() {
    let card = |length: usize| json!({"name": "x".repeat(length), "url": "https://agent.example"}).to_string();
    let (mock, upstream_body) = MockServer::start_with_response_channel(card(LIMIT * 2)).await;
    let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.a2a.max_body_size = LIMIT;
        config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;
    let card_url = harness
        .gateway_url
        .replace("/rpc", "/.well-known/agent-card.json");
    let get_card = || async {
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap()
            .get(&card_url)
            .send()
            .await
            .expect("gateway must answer before the client timeout");
        let status = response.status();
        (
            status,
            response
                .text()
                .await
                .unwrap_or_default(),
        )
    };

    let (status, body) = get_card().await;
    assert_eq!(status, 502, "{body}");
    assert!(body.contains("Upstream response too large"), "{body}");

    upstream_body
        .send(card(LIMIT / 4))
        .unwrap();
    let (status, body) = get_card().await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn transit_point_rejects_an_a2a_body_over_the_limit() {
    let mock = MockServer::start_with_response_channel(result_with_text(LIMIT * 2))
        .await
        .0;
    let harness = GatewayHarness::start_with_outbound_mock(mock, |_, config, _| {
        config.a2a.max_body_size = LIMIT;
        config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;
    let (status, body, _) = post_a2a(&transit_url(&harness)).await;
    assert_eq!(status, 502, "{body}");
}
