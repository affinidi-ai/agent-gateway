//! A surface with an `agent_pay` payment policy, served end to end, with
//! agent-pay played by an in-process payment gate.

use serde_json::{Value, json};

use super::helpers::{self, GatewayHarness, MockServer};
use crate::proxy::handler::agent_pay_gate::{install_test_transport, tests::MockGate};

const UPSTREAM_RESULT: &str = r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"done"}]}}"#;
const MODERN_UPSTREAM_RESULT: &str =
    r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","content":[{"type":"text","text":"done"}]}}"#;

fn paid_mcp_surface(gateway_id: &str) -> crate::config::agent_surface::AgentSurface {
    let mut surface = helpers::build_minimal_mcp_surface();
    surface.surface_id = format!("surface-{gateway_id}");
    surface.target.payment_policy = Some(
        serde_json::from_value(json!({
            "type": "agent_pay", "payment_gateway_id": gateway_id, "payment_surface_id": "pay-1",
            "mcp_payment_triggers": {"mode": "match", "patterns": ["^paid_"]}
        }))
        .unwrap(),
    );
    surface
}

async fn start_with(
    gateway_id: &str,
    mock: MockServer,
    adjust: impl FnOnce(&mut crate::config::agent_surface::AgentSurface),
) -> GatewayHarness {
    let mut surface = paid_mcp_surface(gateway_id);
    adjust(&mut surface);
    GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![surface];
    })
    .await
}

async fn start(gateway_id: &str) -> GatewayHarness {
    start_with(gateway_id, MockServer::start_with_response(UPSTREAM_RESULT).await, |_| {}).await
}

/// A payment gate that takes any credential and answers a request without one
/// with a challenge.
fn taking_gate() -> std::sync::Arc<MockGate> {
    MockGate::answering(200, &[("Payment-Receipt", "settled-receipt"), ("Cache-Control", "no-store")], json!({}))
        .challenging(
            &[("payment-required", "eyJhY2NlcHRzIjpbXX0="), ("content-type", "application/json")],
            json!({"accepts": [], "x402Version": 2}),
        )
}

fn tool_call(
    tool: &str,
    arguments: Value,
) -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
}

async fn post(
    harness: &GatewayHarness,
    body: &Value,
    headers: &[(&str, &str)],
) -> (u16, reqwest::header::HeaderMap, Value) {
    let mut request = reqwest::Client::new()
        .post(&harness.gateway_url)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request
        .body(body.to_string())
        .send()
        .await
        .expect("POST to the Access Point failed");
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    (
        status,
        headers,
        response
            .json()
            .await
            .unwrap_or(Value::Null),
    )
}

/// A `tools/call` of the modern MCP revision.
fn modern_call(
    tool: &str,
    arguments: Value,
) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments, "_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}
    })
}

fn modern_headers(tool: &str) -> [(&str, &str); 4] {
    [
        ("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION),
        ("mcp-method", "tools/call"),
        ("mcp-name", tool),
        ("accept", "application/json, text/event-stream"),
    ]
}

fn forwarded(harness: &GatewayHarness) -> usize {
    harness
        .mock
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst)
}

fn upstream_request(harness: &GatewayHarness) -> helpers::ReceivedRequest {
    harness
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the call reached the Target")
}

fn carries_a_payment_credential(request: &helpers::ReceivedRequest) -> bool {
    request
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("payment-signature") || name.eq_ignore_ascii_case("x-payment"))
        || request
            .headers
            .get("authorization")
            .is_some_and(|value| value.starts_with("Payment "))
        || request
            .body
            .contains("payment_signature")
        || request
            .body
            .contains("org.paymentauth/credential")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_free_call_makes_no_payment_hop_and_its_credential_never_reaches_the_target() {
    let gate = MockGate::answering(402, &[], json!({}));
    install_test_transport("e2e-free", gate.clone());
    let harness = start("e2e-free").await;

    let (status, headers, body) = post(
        &harness,
        &tool_call("free_lookup", json!({"payment_signature": "unconsumed", "q": 1})),
        &[("PAYMENT-SIGNATURE", "unconsumed")],
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["content"][0]["text"], "done");
    assert!(!headers.contains_key("payment-response"), "a free call has no receipt");
    assert_eq!(gate.calls(), 0);
    assert_eq!(forwarded(&harness), 1);
    let upstream = upstream_request(&harness);
    assert!(!carries_a_payment_credential(&upstream), "{upstream:?}");
    let forwarded_body: Value = serde_json::from_str(&upstream.body).unwrap();
    assert_eq!(forwarded_body["params"]["arguments"], json!({"q": 1}));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_legacy_delegated_policy_naming_no_triggers_still_charges_every_tool_call() {
    use crate::storage::filesystem::StorableEntity;

    let gate = taking_gate();
    install_test_transport("e2e-legacy", gate.clone());
    let harness = start_with("e2e-legacy", MockServer::start_with_response(UPSTREAM_RESULT).await, |surface| {
        let mut stored = serde_json::to_value(&*surface).unwrap();
        stored["target"]["payment_policy"] = json!({
            "type": "x402", "enabled": true, "provider": "agent_pay",
            "payment_gateway_id": "e2e-legacy", "payment_surface_id": "pay-1"
        });
        crate::config::agent_surface::AgentSurface::migrate_raw_json(&mut stored).unwrap();
        *surface = serde_json::from_value(stored).unwrap();
    })
    .await;

    let (status, _, body) = post(&harness, &tool_call("free_lookup", json!({})), &[]).await;
    assert_eq!(status, 402, "{body}");
    assert_eq!(gate.calls(), 1);
    assert_eq!(forwarded(&harness), 0, "an unpaid call to a migrated paid surface never reaches the Target");

    let (status, headers, body) =
        post(&harness, &tool_call("free_lookup", json!({})), &[("PAYMENT-SIGNATURE", "legacy-proof")]).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(headers["payment-response"], "settled-receipt");
    assert_eq!(forwarded(&harness), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chargeable_call_without_a_credential_gets_the_challenge() {
    let gate = MockGate::answering(
        402,
        &[("payment-required", "eyJhY2NlcHRzIjpbXX0="), ("content-type", "application/json")],
        json!({"accepts": [], "x402Version": 2}),
    );
    install_test_transport("e2e-challenge", gate.clone());
    let harness = start("e2e-challenge").await;

    let (status, headers, body) = post(&harness, &tool_call("paid_report", json!({})), &[]).await;

    assert_eq!(status, 402, "{body}");
    assert_eq!(body["id"], 7);
    assert_eq!(
        body["error"]["code"], -32042,
        "a caller on the legacy MCP revision is answered with the MPP MCP transport's payment-required code"
    );
    assert_eq!(body["error"]["data"]["x402"], json!({"accepts": [], "x402Version": 2}));
    assert_eq!(headers["payment-required"], "eyJhY2NlcHRzIjpbXX0=");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(gate.calls(), 1);
    assert_eq!(forwarded(&harness), 0, "an unpaid call never reaches the Target");
    assert_eq!(
        gate.last().body,
        json!({"kind": "payment_request", "protocol": "mcp", "resource": "paid_report",
            "caller_surface_id": "surface-e2e-challenge"})
    );

    let (status, _, body) =
        post(&harness, &modern_call("paid_report", json!({})), &modern_headers("paid_report")).await;

    assert_eq!(status, 402, "{body}");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], 1001, "a modern MCP caller gets the application code");
    assert_eq!(forwarded(&harness), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_paid_call_reaches_the_target_without_the_credential_and_returns_the_receipt() {
    let gate = taking_gate();
    install_test_transport("e2e-paid", gate.clone());
    let harness = start("e2e-paid").await;

    let (status, headers, body) = post(
        &harness,
        &tool_call("paid_report", json!({"q": "x", "payment_signature": "body-proof"})),
        &[("PAYMENT-SIGNATURE", "header-proof"), ("cookie", "sid=secret")],
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(headers["payment-response"], "settled-receipt");
    assert_eq!(headers["cache-control"], "no-store", "agent-pay's cache-control comes with the receipt");
    assert_eq!(body["result"]["_meta"]["org.paymentauth/receipt"], "settled-receipt");
    assert_eq!(body["result"]["content"][0]["text"], "done");
    let sent = gate.last();
    assert_eq!(sent.headers["PAYMENT-SIGNATURE"], "header-proof");
    assert!(
        !sent
            .headers
            .contains_key("cookie")
    );
    let upstream = upstream_request(&harness);
    assert!(!carries_a_payment_credential(&upstream), "{upstream:?}");
    let forwarded_body: Value = serde_json::from_str(&upstream.body).unwrap();
    assert_eq!(forwarded_body["params"]["arguments"], json!({"q": "x"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_paid_modern_call_carries_the_receipt_in_its_streamed_response() {
    let gate = taking_gate();
    install_test_transport("e2e-modern", gate.clone());
    let harness = start_with("e2e-modern", MockServer::start_with_response(MODERN_UPSTREAM_RESULT).await, |_| {}).await;
    let mut headers = modern_headers("paid_report").to_vec();
    headers.push(("PAYMENT-SIGNATURE", "modern-proof"));

    let (status, response_headers, body) = post(&harness, &modern_call("paid_report", json!({})), &headers).await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(response_headers["payment-response"], "settled-receipt");
    assert_eq!(body["result"]["_meta"]["org.paymentauth/receipt"], "settled-receipt");
    assert_eq!(body["result"]["resultType"], "complete");
    assert_eq!(body["result"]["content"][0]["text"], "done");
    assert_eq!(gate.calls(), 1);
    assert_eq!(forwarded(&harness), 1);
    assert!(!carries_a_payment_credential(&upstream_request(&harness)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_credential_is_refused_with_a_fresh_challenge_and_reaches_the_target_once() {
    let gate = taking_gate();
    install_test_transport("e2e-replay", gate.clone());
    let harness = start("e2e-replay").await;
    let headers = [("PAYMENT-SIGNATURE", "single-use-proof")];

    let (status, _, body) = post(&harness, &tool_call("paid_report", json!({"q": 1})), &headers).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(forwarded(&harness), 1);
    assert_eq!(gate.calls(), 1);

    // Agent-pay answers the retry as paid again; this gateway has already forwarded it.
    let mut retry = tool_call("paid_report", json!({"q": 1}));
    retry["id"] = json!(8);
    let (status, response_headers, body) = post(&harness, &retry, &headers).await;

    assert_eq!(status, 402, "{body}");
    assert_eq!(body["id"], 8);
    assert_eq!(body["error"]["data"]["failure"]["reason"], "payment_already_used");
    assert_eq!(
        body["error"]["data"]["x402"],
        json!({"accepts": [], "x402Version": 2}),
        "a fresh challenge comes with it"
    );
    assert_eq!(response_headers["payment-required"], "eyJhY2NlcHRzIjpbXX0=");
    assert!(!response_headers.contains_key("payment-response"));
    assert_eq!(forwarded(&harness), 1, "the paid call is not forwarded a second time");
    assert_eq!(gate.calls(), 3, "the replayed payment, then a request for a fresh challenge");
    assert!(
        !gate
            .last()
            .headers
            .contains_key("PAYMENT-SIGNATURE")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_concurrent_calls_reach_the_target_once() {
    let gate = taking_gate().delayed(std::time::Duration::from_millis(40));
    install_test_transport("e2e-concurrent", gate.clone());
    let harness = start("e2e-concurrent").await;
    let call = tool_call("paid_report", json!({"q": 1}));

    let answers =
        futures::future::join_all((0..6).map(|_| post(&harness, &call, &[("PAYMENT-SIGNATURE", "racing-proof")])))
            .await;

    let statuses: Vec<u16> = answers
        .iter()
        .map(|(status, _, _)| *status)
        .collect();
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == 200)
            .count(),
        1,
        "{statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .filter(|status| **status != 200)
            .all(|status| matches!(status, 402 | 409)),
        "a racing request is asked to retry while the first is dispatched, or is refused once it was: {statuses:?}"
    );
    assert_eq!(forwarded(&harness), 1, "one payment buys one forwarded call");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_credential_on_another_tool_is_a_different_request_to_agent_pay() {
    let gate = taking_gate();
    install_test_transport("e2e-keys", gate.clone());
    let harness = start("e2e-keys").await;
    let headers = [("PAYMENT-SIGNATURE", "shared-proof")];

    post(&harness, &tool_call("paid_cheap", json!({})), &headers).await;
    post(&harness, &tool_call("paid_premium", json!({})), &headers).await;

    let keys: Vec<Value> = gate
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.payment_context["correlation"]["idempotency_key"].clone())
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|key| {
        key.as_str()
            .is_some_and(|key| key.len() == 64)
    }));
    assert_ne!(keys[0], keys[1], "agent-pay can tell the two calls apart, so one payment cannot buy both");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_refused_before_payment_is_never_charged() {
    let gate = taking_gate();
    install_test_transport("e2e-refused", gate.clone());
    let harness = start_with(
        "e2e-refused",
        MockServer::start_with_response(UPSTREAM_RESULT).await,
        |surface| {
            surface.target.mcp_tool_gating = Some(
                serde_json::from_value(json!({
                    "gates": [{"id": "g1", "name": "no premium", "action": {"effect": "deny", "patterns": ["^paid_premium"]}}]
                }))
                .unwrap(),
            );
        },
    )
    .await;

    let (status, _, body) =
        post(&harness, &tool_call("paid_premium", json!({})), &[("PAYMENT-SIGNATURE", "refused-proof")]).await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["error"]["code"], -32001);
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not allowed by policy")),
        "{body}"
    );
    assert_eq!(gate.calls(), 0, "tool gating refused it before any payment");
    assert_eq!(forwarded(&harness), 0);

    let (status, headers, body) =
        post(&harness, &tool_call("paid_report", json!({})), &[("PAYMENT-SIGNATURE", "allowed-proof")]).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(headers["payment-response"], "settled-receipt");
    assert_eq!(gate.calls(), 1, "a call that passes every refusal is charged once");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_whose_target_authentication_fails_is_never_charged() {
    let gate = taking_gate();
    install_test_transport("e2e-target-auth", gate.clone());
    let harness = start_with("e2e-target-auth", MockServer::start_with_response(UPSTREAM_RESULT).await, |surface| {
        surface.target.auth = Some(
            serde_json::from_value(json!({
                "method": {"static_secret": {"secret_id": "no-such-secret", "header_name": "Authorization"}},
                "fallback": "reject"
            }))
            .unwrap(),
        );
    })
    .await;

    let (status, _, _) =
        post(&harness, &tool_call("paid_report", json!({})), &[("PAYMENT-SIGNATURE", "unserved-proof")]).await;

    assert_eq!(status, 502);
    assert_eq!(gate.calls(), 0, "the Target could not be authenticated to, so nothing was charged");
    assert_eq!(forwarded(&harness), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_for_a_target_with_an_open_circuit_is_refused_before_it_is_charged() {
    let gate = taking_gate();
    install_test_transport("e2e-breaker", gate.clone());
    let unreachable = crate::component_tests::helpers::closing_endpoint();
    let harness = start_with(
        "e2e-breaker",
        MockServer::start_with_response(UPSTREAM_RESULT).await,
        |surface| {
            surface.target.endpoint = format!("http://{unreachable}");
            surface.target.networking = Some(
                serde_json::from_value(json!({
                    "circuit_breaker": {"failure_threshold": 1, "success_threshold": 1, "timeout_secs": 60, "window_secs": 60}
                }))
                .unwrap(),
            );
        },
    )
    .await;

    let (status, headers, body) =
        post(&harness, &tool_call("paid_report", json!({})), &[("PAYMENT-SIGNATURE", "first-proof")]).await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(headers["payment-response"], "settled-receipt", "a payment that was taken is reported");
    assert_eq!(gate.calls(), 1);

    let (status, headers, body) =
        post(&harness, &tool_call("paid_report", json!({})), &[("PAYMENT-SIGNATURE", "second-proof")]).await;
    assert_eq!(status, 503, "{body}");
    assert!(!headers.contains_key("payment-response"));
    assert_eq!(gate.calls(), 1, "the open circuit refused the call before agent-pay was asked");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_paid_call_that_fails_upstream_still_carries_its_receipt() {
    let gate = taking_gate();
    install_test_transport("e2e-upstream-failure", gate.clone());
    let harness = start_with(
        "e2e-upstream-failure",
        MockServer::start_with_status(500, "application/json", r#"{"error":"boom"}"#).await,
        |_| {},
    )
    .await;

    let (status, headers, body) =
        post(&harness, &tool_call("paid_report", json!({})), &[("PAYMENT-SIGNATURE", "failed-proof")]).await;

    assert_eq!(status, 500, "{body}");
    assert_eq!(headers["payment-response"], "settled-receipt", "the caller can see it was charged");
    assert_eq!(gate.calls(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_paid_event_stream_response_carries_the_receipt_header() {
    let gate = taking_gate();
    install_test_transport("e2e-stream", gate.clone());
    let harness = start_with(
        "e2e-stream",
        MockServer::start_with_streamed_body(
            "text/event-stream",
            vec![(
                std::time::Duration::ZERO,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n\n".to_string(),
            )],
        )
        .await,
        |_| {},
    )
    .await;

    let response = reqwest::Client::new()
        .post(&harness.gateway_url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("PAYMENT-SIGNATURE", "streamed-proof")
        .body(tool_call("paid_report", json!({})).to_string())
        .send()
        .await
        .expect("POST to the Access Point failed");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(
        response.headers()["payment-response"],
        "settled-receipt",
        "a streamed response cannot carry the receipt in its body, so it carries the header"
    );
    assert_eq!(gate.calls(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_payment_answers_payment_pending_with_the_case() {
    let gate = MockGate::answering(
        202,
        &[],
        json!({"status": "held_for_oversight", "case_id": "case-42", "reason": "over limit"}),
    );
    install_test_transport("e2e-held", gate.clone());
    let harness = start("e2e-held").await;

    let (status, headers, body) =
        post(&harness, &tool_call("paid_report", json!({})), &[("PAYMENT-SIGNATURE", "proof")]).await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["error"]["code"], 1003);
    assert_eq!(body["error"]["data"]["case_id"], "case-42");
    assert_eq!(body["error"]["data"]["httpStatus"], 202);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(forwarded(&harness), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_payment_on_a_plain_http_request_answers_202() {
    let gate = MockGate::answering(202, &[], json!({"status": "held_for_oversight", "case_id": "case-7"}));
    install_test_transport("e2e-held-http", gate.clone());
    let mut surface = helpers::build_minimal_channel();
    surface.access_point.a2a = Some(crate::config::agent_surface::A2aAccessPointSettings {
        validation: crate::config::agent_surface::A2aValidation::Off,
        ..Default::default()
    });
    surface.target.payment_policy = Some(
        serde_json::from_value(json!({
            "type": "agent_pay", "payment_gateway_id": "e2e-held-http", "payment_surface_id": "pay-1",
            "require_all": true
        }))
        .unwrap(),
    );
    let harness = GatewayHarness::start(|_, config, _| config.surfaces = vec![surface]).await;

    let (status, headers, body) = post(&harness, &json!({"order": 1}), &[("PAYMENT-SIGNATURE", "proof")]).await;

    assert_eq!(status, 202, "{body}");
    assert_eq!(body, json!({"status": "held_for_oversight", "case_id": "case-7", "reason": null}));
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(forwarded(&harness), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_agent_pay_fails_closed_and_opens_the_breaker() {
    let gate = MockGate::failing("unreachable");
    install_test_transport("e2e-down", gate.clone());
    let harness = start("e2e-down").await;
    let call = tool_call("paid_report", json!({}));

    for _ in 0..5 {
        let (status, _, body) = post(&harness, &call, &[]).await;
        assert_eq!(status, 502, "{body}");
        assert_eq!(body["error"]["data"]["error"], "payment_unavailable");
    }
    let (status, headers, body) = post(&harness, &call, &[]).await;

    assert_eq!(status, 503, "{body}");
    assert!(headers.contains_key("retry-after"));
    assert_eq!(gate.calls(), 5, "an open breaker answers without a hop");
    assert_eq!(forwarded(&harness), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_local_payment_surface_answers_503() {
    let mut surface = helpers::build_minimal_mcp_surface();
    surface.target.payment_policy = Some(serde_json::from_value(json!({"type": "x402", "enabled": true})).unwrap());
    let harness = GatewayHarness::start(|_, config, _| config.surfaces = vec![surface]).await;

    let (status, _, body) = post(&harness, &tool_call("anything", json!({})), &[]).await;

    assert_eq!(status, 503, "{body}");
    assert_eq!(body, json!({"error": "payment_unavailable"}));
    assert_eq!(forwarded(&harness), 0);
}
