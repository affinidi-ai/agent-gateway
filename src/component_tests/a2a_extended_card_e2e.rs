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

async fn send_through_gateway(
    direction: Direction,
    upstream_body: String,
    method: &str,
) -> serde_json::Value {
    let mock = MockServer::start_with_response(upstream_body).await;
    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let url = match direction {
        Direction::Inbound => h.gateway_url.clone(),
        Direction::Outbound => format!(
            "{}/outbound/smoke/target/rpc",
            h.outbound_url
                .as_ref()
                .expect("outbound_url must be set")
        ),
    };

    let resp = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .body(request(method))
        .send()
        .await
        .expect("request through gateway failed");
    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());
    resp.json()
        .await
        .expect("response is not JSON")
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
