//! Extended agent card E2E tests
//!
//! An extended agent card returned as the JSON-RPC result of
//! `GetExtendedAgentCard` (A2A 1.0) or `agent/getAuthenticatedExtendedCard`
//! (A2A 0.3) must have every endpoint URL rewritten to the gateway, in both the
//! inbound and outbound directions, so callers never learn the backend address.

use super::helpers;
use helpers::{GatewayHarness, MockServer};
use serde_json::json;

const BACKEND: &str = "https://backend.internal";

const EXTENDED_CARD_METHODS: [&str; 2] = ["GetExtendedAgentCard", "agent/getAuthenticatedExtendedCard"];

fn v1_card() -> serde_json::Value {
    json!({
        "name": "extended-agent",
        "version": "1.0.0",
        "supportedInterfaces": [
            {"url": format!("{BACKEND}/a2a/v1"), "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
            {"url": format!("{BACKEND}/a2a/rest"), "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}
        ],
        "supported_interfaces": [
            {"url": format!("{BACKEND}/a2a/grpc"), "protocol_binding": "GRPC"}
        ]
    })
}

fn v03_card() -> serde_json::Value {
    json!({
        "name": "extended-agent",
        "version": "1.0.0",
        "protocolVersion": "0.3.0",
        "url": format!("{BACKEND}/a2a"),
        "preferredTransport": "JSONRPC",
        "additionalInterfaces": [
            {"url": format!("{BACKEND}/a2a"), "transport": "JSONRPC"},
            {"url": format!("{BACKEND}/grpc"), "transport": "GRPC"}
        ],
        "additional_interfaces": [
            {"url": format!("{BACKEND}/rest"), "transport": "HTTP+JSON"}
        ]
    })
}

fn result_envelope(result: serde_json::Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
}

fn request(method: &str) -> String {
    let params = if method == "SendMessage" {
        json!({"message": {"role": "ROLE_USER", "messageId": "msg-001", "parts": [{"text": "hello"}]}})
    } else {
        json!({})
    };
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string()
}

enum Direction {
    Inbound,
    Outbound,
}

struct GatewayReply {
    status: reqwest::StatusCode,
    body: String,
    upstream_requests: usize,
}

async fn start_gateway(
    upstream_body: String,
    validate_messages: bool,
) -> GatewayHarness {
    let mock = MockServer::start_with_response(upstream_body).await;
    GatewayHarness::start_with_outbound_mock(mock, move |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
        gw_config
            .a2a
            .validate_messages = validate_messages;
    })
    .await
}

/// Start a gateway whose Target and transit point destination sit under `/base`
/// on the mock.
async fn start_gateway_with_target_base(upstream_body: String) -> GatewayHarness {
    let mock = MockServer::start_with_response(upstream_body).await;
    let endpoint = format!("{}/base", mock.url());
    GatewayHarness::start_with_outbound_mock(mock, move |_, gw_config, _| {
        let mut surface = helpers::build_minimal_outbound_channel();
        surface.target.endpoint = endpoint.clone();
        for point in &mut surface
            .transit
            .as_mut()
            .expect("transit config")
            .points
        {
            point.target_endpoint = endpoint.clone();
        }
        gw_config.surfaces = vec![surface];
    })
    .await
}

/// The surface route (inbound) or transit point path (outbound) that request
/// paths are relative to.
fn route_url(
    h: &GatewayHarness,
    direction: &Direction,
) -> String {
    match direction {
        Direction::Inbound => h
            .gateway_url
            .trim_end_matches("/rpc")
            .to_string(),
        Direction::Outbound => format!(
            "{}/outbound/smoke/target",
            h.outbound_url
                .as_ref()
                .expect("outbound_url must be set")
        ),
    }
}

fn upstream_requests(h: &GatewayHarness) -> usize {
    h.mock
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst)
}

async fn post_to_gateway(
    direction: Direction,
    upstream_body: String,
    request_body: impl Into<reqwest::Body>,
    validate_messages: bool,
) -> GatewayReply {
    let h = start_gateway(upstream_body, validate_messages).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/rpc", route_url(&h, &direction)))
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .expect("request through gateway failed");
    GatewayReply {
        status: resp.status(),
        body: resp
            .text()
            .await
            .expect("response body unreadable"),
        upstream_requests: upstream_requests(&h),
    }
}

async fn send_request_through_gateway(
    direction: Direction,
    upstream_body: String,
    request_body: String,
) -> GatewayReply {
    post_to_gateway(direction, upstream_body, request_body, true).await
}

/// Send `GET {route}{path}` over a raw connection, so a non-canonical path such as
/// `/x/../extendedAgentCard` reaches the gateway exactly as written.
async fn get_through_gateway(
    direction: Direction,
    upstream_body: String,
    path: &str,
) -> GatewayReply {
    let h = start_gateway(upstream_body, true).await;
    get_raw(&h, &direction, path).await
}

async fn get_raw(
    h: &GatewayHarness,
    direction: &Direction,
    path: &str,
) -> GatewayReply {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let route = url::Url::parse(&route_url(h, direction)).expect("route url");
    let authority = format!(
        "{}:{}",
        route
            .host_str()
            .expect("route host"),
        route
            .port_or_known_default()
            .expect("route port")
    );
    let mut stream = tokio::net::TcpStream::connect(&authority)
        .await
        .expect("connect to gateway");
    let request = format!(
        "GET {}{path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        route.path()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("read response");
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .expect("response head");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .expect("status code");
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked(body)
    } else {
        body.to_string()
    };
    GatewayReply {
        status: reqwest::StatusCode::from_u16(status).expect("valid status"),
        body,
        upstream_requests: upstream_requests(h),
    }
}

fn decode_chunked(mut rest: &str) -> String {
    let mut body = String::new();
    while let Some((size, after)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        body.push_str(&after[..size]);
        rest = &after[size + 2..];
    }
    body
}

async fn send_through_gateway(
    direction: Direction,
    upstream_body: String,
    method: &str,
) -> serde_json::Value {
    let reply = send_request_through_gateway(direction, upstream_body, request(method)).await;
    assert_eq!(reply.status, 200, "expected 200, got {}: {}", reply.status, reply.body);
    serde_json::from_str(&reply.body).expect("response is not JSON")
}

fn interface_urls<'a>(
    card: &'a serde_json::Value,
    key: &str,
) -> Vec<&'a str> {
    card[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} should be an array, card: {card}"))
        .iter()
        .map(|i| {
            i["url"]
                .as_str()
                .expect("interface url should be a string")
        })
        .collect()
}

fn assert_no_backend_url(response: &serde_json::Value) {
    assert!(
        !response
            .to_string()
            .contains(BACKEND),
        "extended card still exposes the backend endpoint: {response}"
    );
}

fn assert_v1_card_rewritten(response: &serde_json::Value) {
    assert_no_backend_url(response);
    assert_eq!(response["id"], 1);
    let card = &response["result"];
    assert_eq!(card["name"], "extended-agent");

    let urls = interface_urls(card, "supportedInterfaces");
    let gateway_url = urls[0];
    assert!(gateway_url.starts_with("http"), "rewritten url should be absolute: {gateway_url}");
    assert!(
        urls.iter()
            .all(|u| *u == gateway_url),
        "all interfaces should point at the gateway: {urls:?}"
    );
    assert_eq!(interface_urls(card, "supported_interfaces"), vec![gateway_url]);

    let bindings: Vec<&str> = card["supportedInterfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i["protocolBinding"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(bindings, vec!["JSONRPC", "HTTP+JSON"], "interface order must be preserved");
}

fn assert_v03_card_rewritten(response: &serde_json::Value) {
    assert_no_backend_url(response);
    let card = &response["result"];
    let gateway_url = card["url"]
        .as_str()
        .expect("url should be a string");

    let urls = interface_urls(card, "additionalInterfaces");
    assert!(
        urls.iter()
            .all(|u| *u == gateway_url),
        "all interfaces should point at the gateway: {urls:?}"
    );
    assert_eq!(interface_urls(card, "additional_interfaces"), vec![gateway_url]);

    let transports: Vec<&str> = card["additionalInterfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i["transport"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(transports, vec!["JSONRPC", "GRPC"], "interface order must be preserved");
}

// ── Inbound ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn inbound_extended_card_v1_shape_is_rewritten_for_both_methods() {
    for method in EXTENDED_CARD_METHODS {
        let response = send_through_gateway(Direction::Inbound, result_envelope(v1_card()), method).await;
        assert_v1_card_rewritten(&response);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_extended_card_v03_shape_is_rewritten_for_both_methods() {
    for method in EXTENDED_CARD_METHODS {
        let response = send_through_gateway(Direction::Inbound, result_envelope(v03_card()), method).await;
        assert_v03_card_rewritten(&response);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn extended_card_with_null_error_member_is_rewritten() {
    let upstream = json!({"jsonrpc": "2.0", "id": 1, "result": v1_card(), "error": null}).to_string();
    for direction in [Direction::Inbound, Direction::Outbound] {
        let response = send_through_gateway(direction, upstream.clone(), "GetExtendedAgentCard").await;
        assert_v1_card_rewritten(&response);
    }
}

// ── Outbound ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn outbound_extended_card_v1_shape_is_rewritten_for_both_methods() {
    for method in EXTENDED_CARD_METHODS {
        let response = send_through_gateway(Direction::Outbound, result_envelope(v1_card()), method).await;
        assert_v1_card_rewritten(&response);
        let gateway_url = response["result"]["supportedInterfaces"][0]["url"]
            .as_str()
            .unwrap();
        assert!(
            gateway_url.ends_with("/outgoing/smoke/target"),
            "outbound card should point at the transit point, got {gateway_url}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn outbound_extended_card_v03_shape_is_rewritten_for_both_methods() {
    for method in EXTENDED_CARD_METHODS {
        let response = send_through_gateway(Direction::Outbound, result_envelope(v03_card()), method).await;
        assert_v03_card_rewritten(&response);
    }
}

// ── Negative ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn other_method_results_are_not_rewritten() {
    for direction in [Direction::Inbound, Direction::Outbound] {
        let response = send_through_gateway(direction, result_envelope(v1_card()), "SendMessage").await;
        assert_eq!(
            response["result"]["supportedInterfaces"][0]["url"],
            format!("{BACKEND}/a2a/v1"),
            "non-extended-card results must be forwarded unchanged"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn extended_card_error_response_is_not_rewritten() {
    let error = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32007, "message": "Authenticated extended card is not configured", "data": {"url": BACKEND}}
    });
    for direction in [Direction::Inbound, Direction::Outbound] {
        let response = send_through_gateway(direction, error.to_string(), "GetExtendedAgentCard").await;
        assert_eq!(response, error, "JSON-RPC errors must be forwarded unchanged");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn extended_card_response_that_cannot_be_rewritten_is_refused() {
    let unusable_bodies = [
        format!("event: message\ndata: {}\n\n", result_envelope(v1_card())),
        json!({"jsonrpc": "2.0", "id": 1, "result": format!("{BACKEND}/a2a")}).to_string(),
    ];
    let call = json!({"jsonrpc": "2.0", "id": "card-1", "method": "GetExtendedAgentCard", "params": {}}).to_string();
    for body in unusable_bodies {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let reply = send_request_through_gateway(direction, body.clone(), call.clone()).await;
            assert_eq!(reply.status, 502, "expected 502, got {}: {}", reply.status, reply.body);
            assert!(!reply.body.contains(BACKEND), "refusal must not expose the backend: {}", reply.body);
            let refusal: serde_json::Value = serde_json::from_str(&reply.body).expect("refusal is not JSON");
            assert_eq!(refusal["jsonrpc"], "2.0", "{refusal}");
            assert_eq!(refusal["id"], "card-1", "{refusal}");
            assert_eq!(refusal["error"]["code"], -32603, "{refusal}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_with_extended_card_request_is_rejected_before_forwarding() {
    for method in EXTENDED_CARD_METHODS {
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}
        ])
        .to_string();
        for direction in [Direction::Inbound, Direction::Outbound] {
            let reply = send_request_through_gateway(
                direction,
                json!([{"jsonrpc": "2.0", "id": 1, "result": v1_card()}]).to_string(),
                batch.clone(),
            )
            .await;
            assert_eq!(reply.status, 400, "expected 400, got {}: {}", reply.status, reply.body);
            let body: serde_json::Value = serde_json::from_str(&reply.body).expect("rejection is not JSON");
            assert_eq!(body["error"]["code"], -32600, "{body}");
            assert_eq!(reply.upstream_requests, 0, "a rejected batch must not reach the upstream");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_batch_with_extended_card_request_is_rejected_without_message_validation() {
    let batch = json!([{"jsonrpc": "2.0", "id": 1, "method": "GetExtendedAgentCard", "params": {}}]).to_string();
    let upstream = json!([{"jsonrpc": "2.0", "id": 1, "result": v1_card()}]).to_string();
    let reply = post_to_gateway(Direction::Inbound, upstream, batch, false).await;
    assert_eq!(reply.status, 400, "expected 400, got {}: {}", reply.status, reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).expect("rejection is not JSON");
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(reply.upstream_requests, 0, "a rejected batch must not reach the upstream");
}

async fn upstream_accept_encoding(
    direction: Direction,
    upstream_body: String,
    send: impl FnOnce(reqwest::Client, String) -> reqwest::RequestBuilder,
) -> Option<String> {
    let h = start_gateway(upstream_body, true).await;
    let resp = send(reqwest::Client::new(), route_url(&h, &direction))
        .header("accept-encoding", "gzip, br")
        .send()
        .await
        .expect("request through gateway failed");
    assert!(resp.status().is_success(), "expected success, got {}", resp.status());
    h.mock
        .last_request_rx
        .borrow()
        .as_ref()
        .expect("upstream received the request")
        .headers
        .get("accept-encoding")
        .cloned()
}

#[tokio::test(flavor = "multi_thread")]
async fn extended_card_fetches_ask_the_upstream_for_an_uncompressed_card() {
    for direction in [Direction::Inbound, Direction::Outbound] {
        let rpc = upstream_accept_encoding(direction, result_envelope(v1_card()), |client, route| {
            client
                .post(format!("{route}/rpc"))
                .header("content-type", "application/json")
                .body(request("GetExtendedAgentCard"))
        })
        .await;
        assert_eq!(rpc.as_deref(), Some("identity"));
    }
    for direction in [Direction::Inbound, Direction::Outbound] {
        let rest = upstream_accept_encoding(direction, v1_card().to_string(), |client, route| {
            client.get(format!("{route}/extendedAgentCard"))
        })
        .await;
        assert_eq!(rest.as_deref(), Some("identity"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn other_requests_keep_the_callers_accept_encoding() {
    for direction in [Direction::Inbound, Direction::Outbound] {
        let forwarded = upstream_accept_encoding(direction, result_envelope(v1_card()), |client, route| {
            client
                .post(format!("{route}/rpc"))
                .header("content-type", "application/json")
                .body(request("SendMessage"))
        })
        .await;
        assert_eq!(forwarded.as_deref(), Some("gzip, br"));
    }
}

// ── HTTP+JSON binding ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn rest_extended_card_is_rewritten_for_both_eras() {
    for (path, card) in [("/extendedAgentCard", v1_card()), ("/v1/card", v03_card())] {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let reply = get_through_gateway(direction, card.to_string(), path).await;
            assert_eq!(reply.status, 200, "{path}: expected 200, got {}: {}", reply.status, reply.body);
            assert!(!reply.body.contains(BACKEND), "{path}: card still exposes the backend: {}", reply.body);
            let rewritten: serde_json::Value = serde_json::from_str(&reply.body).expect("card is not JSON");
            assert_eq!(rewritten["name"], "extended-agent", "{path}: {rewritten}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_extended_card_reached_through_a_non_canonical_path_is_rewritten() {
    for path in ["/x/../extendedAgentCard", "/./v1/card", "/x/%2e%2e/extendedAgentCard"] {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let reply = get_through_gateway(direction, v1_card().to_string(), path).await;
            assert_eq!(reply.status, 200, "{path}: expected 200, got {}: {}", reply.status, reply.body);
            assert!(!reply.body.contains(BACKEND), "{path}: card still exposes the backend: {}", reply.body);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_extended_card_that_is_not_an_object_is_refused() {
    let not_a_card = json!([format!("{BACKEND}/a2a")]).to_string();
    for direction in [Direction::Inbound, Direction::Outbound] {
        let reply = get_through_gateway(direction, not_a_card.clone(), "/extendedAgentCard").await;
        assert_eq!(reply.status, 502, "expected 502, got {}: {}", reply.status, reply.body);
        assert!(!reply.body.contains(BACKEND), "refusal must not expose the backend: {}", reply.body);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_path_ending_like_the_card_path_is_not_treated_as_a_card() {
    let resource = json!({"url": format!("{BACKEND}/payments")}).to_string();
    for direction in [Direction::Inbound, Direction::Outbound] {
        let reply = get_through_gateway(direction, resource.clone(), "/payments/v1/card").await;
        assert_eq!(reply.status, 200, "expected 200, got {}: {}", reply.status, reply.body);
        assert!(reply.body.contains(BACKEND), "a non-card resource must be forwarded unchanged: {}", reply.body);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_extended_card_reached_by_climbing_out_of_the_target_base_is_rewritten() {
    for (path, card, forwarded) in [
        ("/../base/extendedAgentCard", v1_card(), "/base/extendedAgentCard"),
        ("/%2e%2e/base/extendedAgentCard", v1_card(), "/base/extendedAgentCard"),
        ("/..;/base/v1/card", v03_card(), "/base/..;/base/v1/card"),
    ] {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let h = start_gateway_with_target_base(card.to_string()).await;
            let reply = get_raw(&h, &direction, path).await;
            assert_eq!(reply.status, 200, "{path}: expected 200, got {}: {}", reply.status, reply.body);
            assert!(!reply.body.contains(BACKEND), "{path}: card still exposes the backend: {}", reply.body);
            let upstream_path = h
                .mock
                .last_request_rx
                .borrow()
                .as_ref()
                .expect("upstream received the request")
                .path
                .clone();
            assert_eq!(upstream_path, forwarded, "{path}: the Target saw a different path");
        }
    }
}
