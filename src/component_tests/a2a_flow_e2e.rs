//! A2A flow E2E tests
//!
//! Verify the basic A2A `message/send` flow works end-to-end in both
//! inbound (external → gateway → agent) and outbound (agent → gateway → external)
//! directions. The mock server acts as the upstream target and returns a
//! realistic A2A JSON-RPC response with message parts.

use super::helpers;
use helpers::jwt::{JwksFixture, now_secs, setup_jwt_bearer_auth_rejects_missing_then_accepts_valid, sign_jwt};
use helpers::{GatewayHarness, MockServer};
use serde_json::json;

/// Realistic A2A JSON-RPC request body used by both tests.
fn a2a_request_body() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "kind": "message",
                "messageId": "msg-001",
                "parts": [
                    { "kind": "text", "text": "Hello, agent!" }
                ]
            }
        }
    })
}

/// `surface` with both versions and the given `access_point.a2a.validation`.
fn with_validation(
    mut surface: crate::config::agent_surface::AgentSurface,
    validation: crate::config::agent_surface::A2aValidation,
) -> crate::config::agent_surface::AgentSurface {
    surface.access_point.a2a = Some(crate::config::agent_surface::A2aAccessPointSettings {
        validation,
        ..Default::default()
    });
    surface
}

/// `surface` with full validation: the envelope and the A2A request shape.
fn with_message_validation(
    surface: crate::config::agent_surface::AgentSurface
) -> crate::config::agent_surface::AgentSurface {
    with_validation(surface, crate::config::agent_surface::A2aValidation::Full)
}

/// A managed-agent A2A surface that checks the envelope but not the request shape.
fn surface_with_envelope_validation() -> crate::config::agent_surface::AgentSurface {
    with_validation(helpers::build_minimal_channel(), crate::config::agent_surface::A2aValidation::Envelope)
}

/// A managed-agent A2A surface that validates nothing.
fn surface_without_validation() -> crate::config::agent_surface::AgentSurface {
    with_validation(helpers::build_minimal_channel(), crate::config::agent_surface::A2aValidation::Off)
}

/// Realistic A2A JSON-RPC response returned by the mock target.
fn a2a_response_body() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-resp-001",
            "role": "agent",
            "parts": [
                { "kind": "text", "text": "Hello from agent" }
            ]
        }
    })
}

/// Assert the gateway returned a well-formed A2A response with the expected
/// envelope structure and message content intact.
async fn assert_a2a_response(resp: reqwest::Response) {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .expect("read body");

    assert_eq!(status, 200, "expected 200 from gateway, got {status}");

    let body: serde_json::Value = serde_json::from_str(&text).expect("response body is not valid JSON");

    // JSON-RPC envelope
    assert_eq!(body["jsonrpc"], "2.0", "jsonrpc field must be 2.0");
    assert_eq!(body["id"], 1, "id field must match request");

    // A2A message structure inside result
    let result = &body["result"];
    assert_eq!(result["kind"], "message", "result.kind must be 'message'");
    assert_eq!(result["messageId"], "msg-resp-001", "result.messageId must match mock response");

    let parts = result["parts"]
        .as_array()
        .expect("result.parts should be an array");
    assert_eq!(parts.len(), 1, "expected exactly one part");
    assert_eq!(parts[0]["kind"], "text");
    assert_eq!(parts[0]["text"], "Hello from agent");
}

/// Assert the mock received the original request unmodified.
fn assert_mock_received_request(
    mock: &MockServer,
    expected_body: &str,
) {
    let received = mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");

    assert_eq!(received.method, "POST", "forwarded method should be POST");
    assert_eq!(received.body, expected_body, "forwarded body should match");
}

// ── Inbound ──────────────────────────────────────────────────────────────────

/// Inbound A2A: an external caller sends a well-formed `message/send` request
/// through the gateway. The mock agent returns a valid A2A response. The
/// gateway proxies it back with the envelope structure intact and no errors.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_message_send_happy_path() {
    //
    // Given — mock agent returns a realistic A2A response
    //
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let request = a2a_request_body();
    let request_str = serde_json::to_string(&request).unwrap();

    //
    // When — external caller sends A2A message/send to the gateway
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str.clone())
        .send()
        .await
        .expect("inbound request failed");

    //
    // Then — response envelope is intact, mock received the request
    //
    assert_a2a_response(resp).await;
    assert_mock_received_request(&h.mock, &request_str);
}

/// Inbound A2A **v1.0**: a caller sends the PascalCase `SendMessage` with the
/// `A2A-Version: 1.0` header. A2A v1.0 renamed the JSON-RPC methods, and the
/// gateway forwards the method **as-sent** without translating between eras, so
/// the upstream must receive the v1.0 spelling byte-for-byte.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_v1_send_message_forwarded_unchanged() {
    //
    // Given — mock agent returns a realistic A2A response
    //
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    // Same envelope as the v0.3 body, but carrying the v1.0 method name.
    let mut request = a2a_request_body();
    request["method"] = json!("SendMessage");
    let request_str = serde_json::to_string(&request).unwrap();

    //
    // When — a v1.0 caller sends SendMessage, negotiating 1.0
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "1.0")
        .body(request_str.clone())
        .send()
        .await
        .expect("inbound v1.0 request failed");

    //
    // Then — the response envelope is intact and the upstream saw `SendMessage`
    // exactly as sent (no canonicalisation to `message/send`)
    //
    assert_a2a_response(resp).await;
    assert_mock_received_request(&h.mock, &request_str);
}

/// A method that only exists in A2A v1.0 (`ListTasks`) must be recognised and
/// forwarded rather than refused at the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_v1_list_tasks_reaches_the_agent() {
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "ListTasks", "params": {} });
    let request_str = serde_json::to_string(&request).unwrap();

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "1.0")
        .body(request_str.clone())
        .send()
        .await
        .expect("inbound ListTasks request failed");

    assert_eq!(resp.status(), 200, "ListTasks should be forwarded, not refused");
    assert_mock_received_request(&h.mock, &request_str);
}

/// An `A2A-Version` the gateway does not accept is rejected at its own boundary
/// with `VersionNotSupportedError` (-32009), and the upstream agent is never
/// contacted. The error also reports the versions the gateway does accept, so a
/// caller can renegotiate without guessing.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_unsupported_version_rejected_before_forwarding() {
    //
    // Given
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let request = a2a_request_body();
    let rejected_series = || {
        crate::metrics::backends::prometheus::A2A_PROTOCOL_VERSION
            .with_label_values(&["smoke-test", "rejected", "0.3"])
            .get()
    };
    let rejected_before = rejected_series();

    //
    // When — the caller asks for a protocol version the gateway does not support
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "2.0")
        .body(serde_json::to_string(&request).unwrap())
        .send()
        .await
        .expect("request failed");

    //
    // Then — 400 with -32009, listing the supported versions, and nothing forwarded
    //
    assert_eq!(resp.status(), 400, "expected 400 for an unsupported A2A-Version");

    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(resp_body["jsonrpc"], "2.0");
    assert_eq!(resp_body["error"]["code"], -32009);

    let supported = resp_body["error"]["data"]["supported"]
        .as_array()
        .expect("error data should list supported versions")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    assert!(supported.contains(&"1.0"), "supported should include 1.0, got {supported:?}");
    assert!(supported.contains(&"0.3"), "supported should include 0.3, got {supported:?}");

    assert!(
        rejected_series() > rejected_before,
        "the refused request should be counted with negotiated_version=\"rejected\""
    );

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received a request with an unsupported A2A-Version"
    );
}

/// An unsupported `A2A-Version` is reported ahead of a malformed body.
///
/// Both checks would refuse this request. Version negotiation reads only the
/// headers, so it runs first and answers with `VersionNotSupportedError`
/// (-32009). Reporting the field errors instead would send the caller round a
/// second time: they would fix the fields named by -32602, resend, and only then
/// learn the gateway cannot serve their protocol version at all.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_unsupported_version_reported_before_shape_errors() {
    //
    // Given
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();

    //
    // When — the version is unsupported AND the message omits `messageId`
    //
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "both-wrong",
        "method": "message/send",
        "params": { "message": {
            "kind": "message",
            "role": "user",
            "parts": [{ "kind": "text", "text": "hello" }]
        }}
    });

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "2.0")
        .body(serde_json::to_string(&request).unwrap())
        .send()
        .await
        .expect("request failed");

    //
    // Then — the version error wins, not the field errors
    //
    assert_eq!(resp.status(), 400, "expected 400 for an unsupported A2A-Version");

    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(
        resp_body["error"]["code"], -32009,
        "the unsupported version must be reported before the request shape, got {resp_body}"
    );
    assert_eq!(resp_body["error"]["data"]["requested"], "2.0");

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received a request refused at the gateway"
    );
}

/// Omitting `A2A-Version` means v0.3 per the spec, which is supported — so the
/// request must still be served. This is the common case for a client written
/// before the header existed, including one that already uses v1.0 method names.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_absent_version_header_is_served() {
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    // A v1.0 method name with NO version header: the eras are deliberately not
    // cross-checked, so this must be served rather than refused.
    let mut request = a2a_request_body();
    request["method"] = json!("SendMessage");
    let request_str = serde_json::to_string(&request).unwrap();

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str.clone())
        .send()
        .await
        .expect("request failed");

    assert_a2a_response(resp).await;
    assert_mock_received_request(&h.mock, &request_str);
}

/// An empty `A2A-Version` is interpreted as v0.3, which is supported, so the
/// request is served rather than refused with `-32009`.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_empty_version_header_is_served() {
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();
    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "")
        .body(request_str.clone())
        .send()
        .await
        .expect("request failed");

    assert_a2a_response(resp).await;
    assert_mock_received_request(&h.mock, &request_str);
}

// ── Outbound ─────────────────────────────────────────────────────────────────

/// Outbound A2A: the protected agent sends a well-formed `message/send`
/// request through the gateway's outbound listener. The mock external target
/// returns a valid A2A response. The gateway proxies it back intact.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_a2a_message_send_happy_path() {
    //
    // Given — mock external target returns a realistic A2A response
    //
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let outbound_url = h
        .outbound_url
        .as_ref()
        .expect("outbound_url must be set");
    let request = a2a_request_body();
    let request_str = serde_json::to_string(&request).unwrap();

    //
    // When — protected agent sends A2A message/send via outbound listener
    //
    let resp = client
        .post(format!("{}/outbound/smoke/target/rpc", outbound_url))
        .header("content-type", "application/json")
        .body(request_str.clone())
        .send()
        .await
        .expect("outbound request failed");

    //
    // Then — response envelope is intact, mock received the request
    //
    assert_a2a_response(resp).await;
    assert_mock_received_request(&h.mock, &request_str);
}

// ── Tampered signature ───────────────────────────────────────────────────────

/// A channel with JWT Bearer source auth no longer blocks an A2A request whose
/// JWT signature has been tampered with: the caller-attributable failure is
/// non-blocking, so with no denying policy configured the request is forwarded
/// to the target with no asserted caller identity.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_tampered_jwt_signature_forwarded_without_policy() {
    //
    // Given — channel requires JWT Bearer auth
    //
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let request = a2a_request_body();
    let request_str = serde_json::to_string(&request).unwrap();

    // Sign a valid JWT, then corrupt the signature segment.
    let valid_token = sign_jwt(
        json!({
            "iss": fixture.issuer,
            "sub": "user-e2e",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        &fixture.kid,
    );
    // A JWT has three dot-separated segments: header.payload.signature.
    // Flip the last character of the signature to corrupt it.
    let parts: Vec<&str> = valid_token
        .rsplitn(2, '.')
        .collect();
    let sig = parts[0];
    let prefix = parts[1];
    let tampered_char = if sig.ends_with('A') {
        'B'
    } else {
        'A'
    };
    let tampered_token = format!("{}.{}{}", prefix, &sig[..sig.len() - 1], tampered_char);

    //
    // When — request is sent with the tampered JWT
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", tampered_token))
        .body(request_str.clone())
        .send()
        .await
        .expect("request with tampered token failed");

    //
    // Then — non-blocking: request is forwarded and the mock receives it
    //
    assert_eq!(resp.status(), 200, "expected the failed-auth request to be forwarded, got {}", resp.status());
    assert_mock_received_request(&h.mock, &request_str);
}

// ── Envelope structure enforcement ───────────────────────────────────────────

/// Sending invalid JSON to an A2A channel returns a JSON-RPC parse error
/// (-32700) and the request is never forwarded to the upstream agent.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_invalid_json_rejected() {
    //
    // Given — a plain A2A channel, which checks the envelope by default
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();

    //
    // When — send a body that is not valid JSON
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body("this is not json{{{")
        .send()
        .await
        .expect("request failed");

    //
    // Then — 400 with JSON-RPC error code -32700
    //
    assert_eq!(resp.status(), 400, "expected 400 for invalid JSON, got {}", resp.status());

    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["error"]["code"], -32700);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Parse error"),
        "error message should mention parse error, got: {}",
        body["error"]["message"]
    );

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received a request for invalid JSON"
    );
}

/// Sending a JSON object without the required `jsonrpc` field returns a
/// JSON-RPC invalid-request error (-32600).
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_missing_jsonrpc_field_rejected() {
    //
    // Given
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = json!({
        "method": "message/send",
        "id": 1,
        "params": { "message": {
                "role": "user",
                "messageId": "msg-fixture", "parts": [{ "kind": "text", "text": "hi" }] } }
    });

    //
    // When — send a request missing the `jsonrpc` field
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .expect("request failed");

    //
    // Then — 400 with JSON-RPC error code -32600
    //
    assert_eq!(resp.status(), 400, "expected 400 for missing jsonrpc, got {}", resp.status());

    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(resp_body["jsonrpc"], "2.0");
    assert_eq!(resp_body["error"]["code"], -32600);
    assert!(
        resp_body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("jsonrpc"),
        "error message should mention 'jsonrpc', got: {}",
        resp_body["error"]["message"]
    );

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received a request with missing jsonrpc"
    );
}

/// Sending a JSON-RPC envelope without the required `method` field returns
/// a JSON-RPC invalid-request error (-32600).
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_missing_method_field_rejected() {
    //
    // Given
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "params": { "message": {
                "role": "user",
                "messageId": "msg-fixture", "parts": [{ "kind": "text", "text": "hi" }] } }
    });

    //
    // When — send a request missing the `method` field
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .expect("request failed");

    //
    // Then — 400 with JSON-RPC error code -32600
    //
    assert_eq!(resp.status(), 400, "expected 400 for missing method, got {}", resp.status());

    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(resp_body["jsonrpc"], "2.0");
    assert_eq!(resp_body["error"]["code"], -32600);
    assert!(
        resp_body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("method"),
        "error message should mention 'method', got: {}",
        resp_body["error"]["message"]
    );

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received a request with missing method"
    );
}

// ── Large payload stability ──────────────────────────────────────────────────

/// Sending a request near the max allowed payload size (just under 10 MB)
/// should be processed without memory or serialisation errors.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_large_payload_near_max_succeeds() {
    //
    // Given — mock agent returns a simple response
    //
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();

    // Build a valid JSON-RPC envelope with a large text payload.
    // Default max_body_size is 10 MB; we target ~9.5 MB to stay under the limit
    // while still exercising the large-buffer path.
    let large_text = "x".repeat(9_500_000);
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "kind": "message",
                "messageId": "msg-large-001",
                "parts": [
                    { "kind": "text", "text": large_text }
                ]
            }
        }
    });
    let request_str = serde_json::to_string(&request).unwrap();

    //
    // When — send the large payload through the gateway
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str.clone())
        .send()
        .await
        .expect("large payload request failed");

    //
    // Then — gateway proxies successfully, mock received the request
    //
    assert_eq!(resp.status(), 200, "expected 200 for large payload, got {}", resp.status());
    assert_mock_received_request(&h.mock, &request_str);
}

/// Sending a request that exceeds the max allowed payload size returns 413
/// Payload Too Large and the request is never forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_payload_exceeding_max_rejected() {
    //
    // Given — a plain A2A channel with the default 10 MB limit
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();

    // Build a payload that exceeds the 10 MB limit.
    let oversized_text = "x".repeat(11_000_000);
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "kind": "message",
                "messageId": "msg-oversized",
                "parts": [
                    { "kind": "text", "text": oversized_text }
                ]
            }
        }
    });
    let request_str = serde_json::to_string(&request).unwrap();

    //
    // When — send the oversized payload
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str)
        .send()
        .await
        .expect("oversized payload request failed");

    //
    // Then — 413, mock never received the request
    //
    assert_eq!(resp.status(), 413, "expected 413 for oversized payload, got {}", resp.status());

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received an oversized request"
    );
}

// ── Observability ────────────────────────────────────────────────────────────

/// A valid A2A request produces a correlation ID (`X-Gateway-Trace-Id`)
/// in the upstream request, the response carries expected metadata headers,
/// and sensitive headers (like `authorization`) are NOT forwarded upstream.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_observability_headers() {
    //
    // Given — mock agent returns a realistic A2A response
    //
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let request = a2a_request_body();
    let request_str = serde_json::to_string(&request).unwrap();

    //
    // When — send a valid request with hop-by-hop security headers and an
    // Authorization header that must NOT be forwarded to upstream.
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", "Bearer caller-token")
        .header("proxy-authorization", "Basic secret-proxy-creds")
        .header("connection", "keep-alive")
        .body(request_str)
        .send()
        .await
        .expect("request failed");

    //
    // Then — response succeeds
    //
    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());

    // Verify response content-type metadata is present
    let resp_content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        resp_content_type.contains("application/json"),
        "response should have application/json content-type, got: {}",
        resp_content_type
    );

    // Inspect what the upstream mock received
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");

    // 1. Correlation ID: X-Gateway-Trace-Id is present and is a valid UUID
    let trace_id = received
        .headers
        .get("x-gateway-trace-id")
        .expect("upstream request must have X-Gateway-Trace-Id header");
    assert!(uuid::Uuid::parse_str(trace_id).is_ok(), "X-Gateway-Trace-Id should be a valid UUID, got: {}", trace_id);

    // 2. Request metadata: content-type is forwarded
    let upstream_ct = received
        .headers
        .get("content-type")
        .expect("upstream request must have content-type header");
    assert!(
        upstream_ct.contains("application/json"),
        "upstream content-type should be application/json, got: {}",
        upstream_ct
    );

    // 3. No sensitive data leaked: hop-by-hop security headers must NOT reach upstream
    assert!(
        !received
            .headers
            .contains_key("proxy-authorization"),
        "proxy-authorization header must NOT be forwarded — hop-by-hop security header leaked"
    );
    assert!(
        !received
            .headers
            .contains_key("connection"),
        "connection header must NOT be forwarded — hop-by-hop header leaked"
    );

    // 4. Authorization header must NOT be forwarded — it is consumed by the
    //    gateway for source authentication and must not leak to upstream.
    assert!(
        !received
            .headers
            .contains_key("authorization"),
        "authorization header must NOT be forwarded to upstream — consumed by gateway for source auth"
    );
}

// ── Timeout / slow agent ─────────────────────────────────────────────────────

/// When the upstream agent does not respond within the configured request
/// timeout, the gateway returns 502 Bad Gateway with a message indicating
/// the timeout. The mock does receive the request (the agent is slow, not
/// unreachable) but the gateway gives up before the response arrives.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_slow_agent_timeout() {
    //
    // Given — mock agent that takes 5 seconds to respond, channel timeout = 1s
    //
    let mock = MockServer::start_with_delay(
        std::time::Duration::from_secs(5),
        serde_json::to_string(&a2a_response_body()).unwrap(),
    )
    .await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        let json = serde_json::json!({
            "name": "slow-agent-test",
            "description": "Timeout test channel",
            "access_point": {
                "listen_address": "inbound_port_placeholder",
                "route": "/smoke",
                "protocol": "a2a"
            },
            "target": {
                "endpoint": "inbound_target_placeholder",
                "networking": {
                    "timeout": {
                        "request_secs": 1,
                        "connect_secs": 5,
                        "idle_secs": 5
                    }
                }
            }
        });
        gw_config.surfaces = vec![serde_json::from_value(json).expect("timeout channel: AgentSurface JSON")];
    })
    .await;

    let client = reqwest::Client::new();
    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();

    //
    // When — send a valid A2A request to the slow agent
    //
    let start = std::time::Instant::now();
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str)
        .send()
        .await
        .expect("request to slow agent failed");
    let elapsed = start.elapsed();

    //
    // Then — 502 with timeout message; completed in ~1s (not 5s)
    //
    assert_eq!(resp.status(), 502, "expected 502 for upstream timeout, got {}", resp.status());

    let body = resp
        .text()
        .await
        .expect("read timeout error body");
    let error: serde_json::Value = serde_json::from_str(&body).expect("timeout response should be JSON");
    let detail = error["detail"]
        .as_str()
        .unwrap_or("");
    assert!(
        detail
            .to_lowercase()
            .contains("timeout"),
        "error detail should mention timeout, got: {}",
        detail
    );

    // Sanity: elapsed should be around 1s (the timeout), not 5s (the mock delay)
    assert!(
        elapsed < std::time::Duration::from_secs(4),
        "gateway should have timed out quickly (~1s), but took {:?}",
        elapsed
    );
}

/// When retry is configured and the upstream times out on every attempt,
/// the gateway exhausts retries and still returns 502.
/// Mock request counter proves that multiple attempts occurred.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_retry_exhausted_returns_error() {
    //
    // Given — mock delays 30s, channel timeout = 3s, retry max_attempts = 2
    //
    let mock = MockServer::start_with_delay(
        std::time::Duration::from_secs(30),
        serde_json::to_string(&a2a_response_body()).unwrap(),
    )
    .await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        let json = serde_json::json!({
            "name": "retry-exhaust-test",
            "description": "Retry exhaustion test channel",
            "access_point": {
                "listen_address": "inbound_port_placeholder",
                "route": "/smoke",
                "protocol": "a2a"
            },
            "target": {
                "endpoint": "inbound_target_placeholder",
                "networking": {
                    "timeout": {
                        "request_secs": 3,
                        "connect_secs": 10,
                        "idle_secs": 10
                    },
                    "retry": {
                        "max_attempts": 2,
                        "initial_backoff_ms": 100,
                        "max_backoff_ms": 500,
                        "backoff_multiplier": 2.0,
                        "retryable_status_codes": [408, 429, 500, 502, 503, 504]
                    }
                }
            }
        });
        gw_config.surfaces = vec![serde_json::from_value(json).expect("retry channel: AgentSurface JSON")];
    })
    .await;

    let client = reqwest::Client::new();
    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();

    //
    // When — send request that will time out on every retry
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str)
        .send()
        .await
        .expect("request with retries failed");

    //
    // Then — still 502 after retries
    //
    assert_eq!(resp.status(), 502, "expected 502 after retry exhaustion, got {}", resp.status());

    let body = resp
        .text()
        .await
        .expect("read error body");
    let error: serde_json::Value = serde_json::from_str(&body).expect("error response should be JSON");
    let detail = error["detail"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        detail.contains("timeout") || detail.contains("failed") || detail.contains("error"),
        "error detail should mention the upstream failure, got: {}",
        detail
    );

    // Give the mock server a moment to register in-flight requests
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // request_count proves retries happened: 1 initial + 2 retries = 3
    let count = h
        .mock
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(count >= 2, "expected at least 2 requests to prove retries, got {}", count);
}

// ── Auth: missing token ──────────────────────────────────────────────────────

/// A channel requiring JWT Bearer auth no longer blocks a request with no
/// Authorization header: the missing credential is a non-blocking, caller-
/// attributable failure, so without a denying policy the request is forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_missing_auth_token_forwarded_without_policy() {
    //
    // Given — channel requires JWT Bearer auth
    //
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();

    //
    // When — send request WITHOUT any Authorization header
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str.clone())
        .send()
        .await
        .expect("request without auth failed");

    //
    // Then — non-blocking: request is forwarded and the mock receives it
    //
    assert_eq!(resp.status(), 200, "expected the failed-auth request to be forwarded, got {}", resp.status());
    assert_mock_received_request(&h.mock, &request_str);
}

/// A channel requiring JWT Bearer auth no longer blocks a request carrying a
/// syntactically invalid token (not three dot-separated segments): the invalid
/// credential is a non-blocking failure, so without a denying policy the
/// request is forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_malformed_token_forwarded_without_policy() {
    //
    // Given — channel requires JWT Bearer auth
    //
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();

    //
    // When — send request with a garbage token (not a JWT at all)
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", "Bearer not-a-jwt-at-all")
        .body(request_str.clone())
        .send()
        .await
        .expect("request with malformed token failed");

    //
    // Then — non-blocking: request is forwarded and the mock receives it
    //
    assert_eq!(resp.status(), 200, "expected the failed-auth request to be forwarded, got {}", resp.status());
    assert_mock_received_request(&h.mock, &request_str);
}

/// A channel requiring JWT Bearer auth no longer blocks a request carrying a
/// structurally valid but expired JWT: the invalid credential is a non-blocking
/// failure, so without a denying policy the request is forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_expired_token_forwarded_without_policy() {
    //
    // Given — channel requires JWT Bearer auth
    //
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();

    // Sign a JWT that expired 5 minutes ago.
    let expired_token = sign_jwt(
        json!({
            "iss": fixture.issuer,
            "sub": "user-e2e",
            "aud": "any",
            "exp": now_secs() - 300,
            "iat": now_secs() - 600,
        }),
        &fixture.kid,
    );

    //
    // When — send request with the expired JWT
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", expired_token))
        .body(request_str.clone())
        .send()
        .await
        .expect("request with expired token failed");

    //
    // Then — non-blocking: request is forwarded and the mock receives it
    //
    assert_eq!(resp.status(), 200, "expected the failed-auth request to be forwarded, got {}", resp.status());
    assert_mock_received_request(&h.mock, &request_str);
}

// ── Auth: error response body format ─────────────────────────────────────────

/// When JWT auth fails (tampered signature) the failure is non-blocking, so with
/// no denying policy the request is forwarded to the target instead of producing
/// an error envelope. (The 401/500 `deny_response` envelope is covered by unit
/// tests in `source_auth::errors`.)
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_tampered_jwt_forwarded_reaches_target() {
    //
    // Given — channel requires JWT Bearer auth
    //
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();

    // Create a tampered JWT
    let valid_token = sign_jwt(
        json!({
            "iss": fixture.issuer,
            "sub": "user-e2e",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        &fixture.kid,
    );
    let parts: Vec<&str> = valid_token
        .rsplitn(2, '.')
        .collect();
    let sig = parts[0];
    let prefix = parts[1];
    let tampered_char = if sig.ends_with('A') {
        'B'
    } else {
        'A'
    };
    let tampered_token = format!("{}.{}{}", prefix, &sig[..sig.len() - 1], tampered_char);

    //
    // When — request with tampered JWT
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", tampered_token))
        .body(request_str.clone())
        .send()
        .await
        .expect("request with tampered token failed");

    //
    // Then — non-blocking: request is forwarded and the mock receives it
    //
    assert_eq!(resp.status(), 200, "expected the failed-auth request to be forwarded, got {}", resp.status());
    assert_mock_received_request(&h.mock, &request_str);
}

// ── Strict request-shape validation (opt-in) ─────────────────────────────────

/// A2A marks `messageId` required, so a message without one is refused at the
/// gateway with `Invalid params` (-32602) naming the field, and the upstream is
/// never contacted. A conformant agent refuses the same message anyway, one hop
/// later and with a vaguer error, so nothing that worked stops working: the
/// caller just learns sooner and more precisely why.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_malformed_message_rejected_before_forwarding() {
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":null,"result":"ok"}"#).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![with_message_validation(helpers::build_minimal_channel())];
    })
    .await;

    // No `messageId`, and no `role`: both required by A2A in either era.
    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":[{"kind":"text","text":"hi"}]}}}"#)
        .send()
        .await
        .expect("default-config request failed");

    assert_eq!(resp.status(), 400, "a malformed A2A message should be refused");

    let body: serde_json::Value = resp
        .json()
        .await
        .expect("error body should be JSON");
    assert_eq!(body["error"]["code"], -32602, "must use JSON-RPC Invalid params");

    let fields: Vec<&str> = body["error"]["data"]["errors"]
        .as_array()
        .expect("data.errors should be an array")
        .iter()
        .map(|e| {
            e["field"]
                .as_str()
                .unwrap_or_default()
        })
        .collect();
    assert!(
        fields.contains(&"params.message.messageId") && fields.contains(&"params.message.role"),
        "every offending field should be named, got {fields:?}"
    );

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "the upstream must never be contacted for a request refused at the gateway"
    );
}

/// The same shape check applies to a v1.0 caller using the PascalCase method, and
/// names every missing required field in one response.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_v1_send_message_missing_required_fields_rejected() {
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":null,"result":"ok"}"#).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![with_message_validation(helpers::build_minimal_channel())];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "1.0")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{}}}"#)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400, "a malformed A2A message should be refused");

    let body: serde_json::Value = resp
        .json()
        .await
        .expect("error body should be JSON");
    assert_eq!(body["error"]["code"], -32602, "must use JSON-RPC Invalid params");

    let fields: Vec<&str> = body["error"]["data"]["errors"]
        .as_array()
        .expect("data.errors should be an array")
        .iter()
        .map(|e| {
            e["field"]
                .as_str()
                .unwrap_or_default()
        })
        .collect();
    for required in ["params.message.messageId", "params.message.role", "params.message.parts"] {
        assert!(fields.contains(&required), "{required} should be named, got {fields:?}");
    }

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "the upstream must never be contacted for a request refused at the gateway"
    );
}

/// A body of many bad parts gets a bounded error: the list is capped and marked
/// truncated, so request size does not amplify into response size.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_many_bad_parts_get_a_bounded_error() {
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":null,"result":"ok"}"#).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![with_message_validation(helpers::build_minimal_channel())];
    })
    .await;

    let parts = vec!["0"; 10_000].join(",");
    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"message/send","params":{{"message":{{"role":"user","messageId":"m-1","parts":[{parts}]}}}}}}"#
        ))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400);
    let bytes = resp
        .bytes()
        .await
        .expect("error body should be readable");
    assert!(bytes.len() < 4096, "error body should be bounded, got {} bytes", bytes.len());

    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("error body should be JSON");
    assert_eq!(body["error"]["code"], -32602);
    assert_eq!(
        body["error"]["data"]["errors"]
            .as_array()
            .expect("data.errors should be an array")
            .len(),
        crate::a2a::validation::MAX_FIELD_ERRORS
    );
    assert_eq!(body["error"]["data"]["truncated"], true);

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "the upstream must never be contacted for a request refused at the gateway"
    );
}

/// A well-formed message still reaches the upstream byte-for-byte, so the checks
/// refuse only what A2A itself would.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_well_formed_message_still_forwarded() {
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let request_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","messageId":"m-1","parts":[{"text":"hi"}]}}}"#;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "1.0")
        .body(request_str)
        .send()
        .await
        .expect("well-formed request failed");

    assert_eq!(resp.status(), 200, "a conformant v1.0 send must pass validation");
    assert_mock_received_request(&h.mock, request_str);
}

// ── Validation bypass ────────────────────────────────────────────────────────

/// With envelope validation, the default, a body with neither `jsonrpc` nor
/// `method` is refused and never forwarded, though the request shape is not checked.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_envelope_is_checked_without_shape_validation() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![surface_with_envelope_validation()];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(r#"{"hello": "world"}"#)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400, "a malformed envelope is refused with envelope validation");
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(body["error"]["code"], -32600, "got {body}");
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "the malformed request must not be forwarded"
    );
}

/// A JSON-RPC batch carries no single `method`, so policy could not match it on
/// one. Envelope validation refuses it as an invalid request.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_batch_is_refused_with_envelope_validation() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![surface_with_envelope_validation()];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "1.0")
        .body(r#"[{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t1"}}]"#)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400, "a batch is refused");
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(body["error"]["code"], -32600, "got {body}");
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "the batch must not be forwarded"
    );
}

/// With validation `off`, a body that is not valid JSON-RPC, a batch included,
/// is forwarded unmodified for the agent to decide.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_validation_off_forwards_a_malformed_envelope() {
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":null,"result":"ok"}"#).await;
    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![surface_without_validation()];
    })
    .await;

    for request_str in
        [r#"{"hello": "world"}"#, r#"[{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t1"}}]"#]
    {
        let resp = reqwest::Client::new()
            .post(&h.gateway_url)
            .header("content-type", "application/json")
            .body(request_str)
            .send()
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 200, "with validation off, {request_str} should be forwarded");
        assert_mock_received_request(&h.mock, request_str);
    }
}

/// Message-shape validation is off unless the surface turns it on, so a surface
/// that stores no `access_point.a2a` forwards a malformed message whose envelope
/// is valid.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_messages_are_not_validated_by_default() {
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let request_str = r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{}}}"#;
    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "an unvalidated surface forwards the malformed message");
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(body["result"], "ok", "the upstream's response should come back, got {body}");
    assert_mock_received_request(&h.mock, request_str);
}

/// With envelope validation the A2A message-shape check is skipped, so a
/// v1.0 `SendMessage` with a valid envelope but missing every required message
/// field reaches the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_validation_disabled_forwards_v1_message_missing_required_fields() {
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![surface_with_envelope_validation()];
    })
    .await;

    let request_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{}}}"#;
    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "1.0")
        .body(request_str)
        .send()
        .await
        .expect("request with validation disabled failed");

    assert_eq!(resp.status(), 200, "without shape validation the malformed message should be forwarded");
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(body["result"], "ok", "the upstream's response should come back, got {body}");
    assert_mock_received_request(&h.mock, request_str);
}

/// Version negotiation is not part of message validation: with
/// validation `off` an unsupported `A2A-Version` is still refused with
/// -32009 and the upstream is never contacted.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_validation_disabled_still_rejects_unsupported_version() {
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![surface_without_validation()];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", "2.0")
        .body(serde_json::to_string(&a2a_request_body()).unwrap())
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400, "an unsupported A2A-Version must be refused whatever the validation level");
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response is not JSON");
    assert_eq!(body["error"]["code"], -32009, "expected VersionNotSupportedError, got {body}");
    assert_eq!(body["error"]["data"]["requested"], "2.0");
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "the upstream must never be contacted for a request refused at the gateway"
    );
}

// ── Access-point protocol enforcement ────────────────────────────────────────

/// An MCP access point rejects an inbound body positively identified as A2A
/// (`message/send`) with 422, and never forwards it to the upstream agent.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_body_on_mcp_access_point_rejected() {
    //
    // Given — the access point is configured for MCP
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_mcp_surface()];
    })
    .await;

    let client = reqwest::Client::new();
    let request_str = serde_json::to_string(&a2a_request_body()).unwrap();

    //
    // When — an A2A `message/send` body is sent to the MCP access point
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str)
        .send()
        .await
        .expect("request failed");

    //
    // Then — 422 and the mock never received the request
    //
    assert_eq!(resp.status(), 422, "expected 422 for A2A body on MCP access point, got {}", resp.status());
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received a protocol-mismatched request"
    );
}

/// An A2A access point rejects an inbound body positively identified as MCP
/// (`tools/call`) with 422, and never forwards it to the upstream agent.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_mcp_body_on_a2a_access_point_rejected() {
    //
    // Given — the access point is configured for A2A
    //
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "echo", "arguments": {} }
    });
    let request_str = serde_json::to_string(&request).unwrap();

    //
    // When — an MCP `tools/call` body is sent to the A2A access point
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(request_str)
        .send()
        .await
        .expect("request failed");

    //
    // Then — 422 and the mock never received the request
    //
    assert_eq!(resp.status(), 422, "expected 422 for MCP body on A2A access point, got {}", resp.status());
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should NOT have received a protocol-mismatched request"
    );
}

// ── Per-surface accepted versions ────────────────────────────────────────────

/// The minimal surface accepting only `versions`, on `route`.
fn surface_accepting(
    route: &str,
    versions: &[&str],
) -> crate::config::agent_surface::AgentSurface {
    let mut surface = helpers::build_minimal_channel();
    surface.name = format!("surface{}", route.replace('/', "-"));
    surface.surface_id = surface.name.clone();
    surface.access_point.route = route.to_string();
    surface.access_point.a2a = Some(crate::config::agent_surface::A2aAccessPointSettings {
        accepted_versions: versions
            .iter()
            .map(|v| v.to_string())
            .collect(),
        ..Default::default()
    });
    surface
}

async fn post_with_version(
    url: &str,
    version: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut request = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .json(&a2a_request_body());
    if let Some(version) = version {
        request = request.header("A2A-Version", version);
    }
    let response = request
        .send()
        .await
        .expect("request failed");
    let status = response.status().as_u16();
    let text = response
        .text()
        .await
        .expect("response body");
    (status, serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)))
}

/// A surface that accepts 1.0 only refuses v0.3, including a caller that sends
/// no `A2A-Version` (which A2A defines as 0.3), and names only 1.0 as supported.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_1_0_only_surface_refuses_v0_3_and_lists_only_1_0() {
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;
    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![surface_accepting("/smoke", &["1.0"])];
    })
    .await;

    for version in [None, Some("0.3")] {
        let (status, body) = post_with_version(&h.gateway_url, version).await;
        assert_eq!(status, 400, "{version:?}");
        assert_eq!(body["error"]["code"], -32009, "{version:?}");
        assert_eq!(body["error"]["data"]["requested"], "0.3");
        assert_eq!(body["error"]["data"]["supported"], json!(["1.0"]));
    }
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "a refused request never reaches the agent"
    );

    let (status, body) = post_with_version(&h.gateway_url, Some("1.0")).await;
    assert_eq!(status, 200, "1.0 is served, got {body}");
    assert_eq!(body["result"]["messageId"], "msg-resp-001");
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_0_3_only_surface_refuses_v1_0() {
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;
    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![surface_accepting("/smoke", &["0.3"])];
    })
    .await;

    let (status, body) = post_with_version(&h.gateway_url, Some("1.0")).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], -32009);
    assert_eq!(body["error"]["data"]["supported"], json!(["0.3"]));

    let (status, body) = post_with_version(&h.gateway_url, None).await;
    assert_eq!(status, 200, "an absent header is 0.3, which this surface serves, got {body}");
}

/// Accepted versions are per surface: two surfaces on one gateway negotiate
/// the same request differently.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_surfaces_negotiate_with_their_own_accepted_versions() {
    let mock = MockServer::start_with_response(serde_json::to_string(&a2a_response_body()).unwrap()).await;
    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, bootstrap| {
        helpers::configure_gateway_route_prefixes(
            bootstrap,
            &[("smoke", "smoke", "/smoke"), ("v1only", "v1only", "/v1only")],
        );
        gw_config.surfaces = vec![surface_accepting("/smoke", &["0.3", "1.0"]), surface_accepting("/v1only", &["1.0"])];
    })
    .await;

    let (status, body) = post_with_version(&h.gateway_url, None).await;
    assert_eq!(status, 200, "the surface accepting both serves a header-less caller, got {body}");

    let (status, body) = post_with_version(&format!("{}/v1only/rpc", h.gateway_base), None).await;
    assert_eq!(status, 400, "the 1.0-only surface refuses the same caller, got {body}");
    assert_eq!(body["error"]["data"]["supported"], json!(["1.0"]));
}

// ── Refusals ahead of delegated payment ──────────────────────────────────────

const DELEGATION_MISCONFIGURED: &str = "payment delegation misconfigured";

/// A direct A2A surface whose x402 policy delegates to a remote payment gateway
/// (`provider = agent_pay`) without naming one. Every request that reaches the
/// delegation step is recorded as a failed delegated payment and answered with a
/// 502 carrying [`DELEGATION_MISCONFIGURED`], so that 502 marks exactly the
/// requests the payment step saw.
fn agent_pay_surface(
    name: &str,
    endpoint: Option<&str>,
) -> crate::config::agent_surface::AgentSurface {
    let mut surface = helpers::build_minimal_channel();
    surface.name = name.to_string();
    if let Some(endpoint) = endpoint {
        surface.target.endpoint = endpoint.to_string();
    }
    surface.target.payment_policy = Some(
        serde_json::from_value(json!({ "type": "x402", "enabled": true, "provider": "agent_pay" }))
            .expect("agent_pay x402 policy"),
    );
    surface
}

fn rejected_version_count(channel: &str) -> u64 {
    crate::metrics::backends::prometheus::A2A_PROTOCOL_VERSION
        .with_label_values(&[channel, "rejected", "0.3"])
        .get()
}

async fn post_a2a(
    h: &GatewayHarness,
    version: &str,
    body: String,
) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("A2A-Version", version)
        .body(body)
        .send()
        .await
        .expect("request failed");
    let status = resp.status().as_u16();
    (
        status,
        resp.text()
            .await
            .expect("read body"),
    )
}

fn jsonrpc_error_code(body: &str) -> Option<i64> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .pointer("/error/code")?
        .as_i64()
}

/// An unsupported `A2A-Version` is refused before the delegated payment step, so
/// the caller is never charged for a request the gateway cannot serve.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_unsupported_version_refused_before_delegated_payment() {
    let channel = "prepay-version";
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![agent_pay_surface(channel, None)];
    })
    .await;
    let rejected_before = rejected_version_count(channel);

    let (status, body) = post_a2a(&h, "2.0", serde_json::to_string(&a2a_request_body()).unwrap()).await;

    assert_eq!(status, 400, "expected -32009 ahead of payment, got {status}: {body}");
    assert_eq!(jsonrpc_error_code(&body), Some(-32009), "got {body}");
    assert!(!body.contains(DELEGATION_MISCONFIGURED), "payment step must not run, got {body}");
    assert_eq!(rejected_version_count(channel), rejected_before + 1);
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none()
    );
}

/// A message missing A2A's required fields is refused with `Invalid params`
/// before the delegated payment step.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_malformed_message_refused_before_delegated_payment() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![with_message_validation(agent_pay_surface("prepay-shape", None))];
    })
    .await;

    let (status, body) = post_a2a(
        &h,
        "1.0",
        r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":[{"kind":"text","text":"hi"}]}}}"#.to_string(),
    )
    .await;

    assert_eq!(status, 400, "expected -32602 ahead of payment, got {status}: {body}");
    assert_eq!(jsonrpc_error_code(&body), Some(-32602), "got {body}");
    assert!(!body.contains(DELEGATION_MISCONFIGURED), "payment step must not run, got {body}");
}

/// A request without a JSON-RPC `jsonrpc` field is refused with `Invalid
/// Request` before the delegated payment step.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_invalid_envelope_refused_before_delegated_payment() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![agent_pay_surface("prepay-envelope", None)];
    })
    .await;

    let mut request = a2a_request_body();
    request
        .as_object_mut()
        .unwrap()
        .remove("jsonrpc");
    let (status, body) = post_a2a(&h, "1.0", serde_json::to_string(&request).unwrap()).await;

    assert_eq!(status, 400, "expected -32600 ahead of payment, got {status}: {body}");
    assert_eq!(jsonrpc_error_code(&body), Some(-32600), "got {body}");
    assert!(!body.contains(DELEGATION_MISCONFIGURED), "payment step must not run, got {body}");
}

/// A supported version with a well-formed message still reaches the delegated
/// payment step.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_valid_request_reaches_delegated_payment() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![agent_pay_surface("prepay-valid", None)];
    })
    .await;

    let (status, body) = post_a2a(&h, "1.0", serde_json::to_string(&a2a_request_body()).unwrap()).await;

    assert_eq!(status, 502, "expected the delegation step to answer, got {status}: {body}");
    assert!(body.contains(DELEGATION_MISCONFIGURED), "got {body}");
}

/// A `fabric://` target is version-negotiated on the sending gateway, ahead of
/// delegated payment and before the request is dispatched over the fabric.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_fabric_target_is_version_negotiated_before_delegated_payment() {
    let channel = "prepay-fabric";
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![agent_pay_surface(channel, Some("fabric://unknown/ch"))];
    })
    .await;
    let rejected_before = rejected_version_count(channel);

    let (status, body) = post_a2a(&h, "2.0", serde_json::to_string(&a2a_request_body()).unwrap()).await;

    assert_eq!(status, 400, "expected -32009 ahead of payment, got {status}: {body}");
    assert_eq!(jsonrpc_error_code(&body), Some(-32009), "got {body}");
    assert!(!body.contains(DELEGATION_MISCONFIGURED), "payment step must not run, got {body}");
    assert_eq!(rejected_version_count(channel), rejected_before + 1, "the refusal is counted");
}

/// Starts a gateway with one delegated-payment `fabric://` surface at `validation`.
async fn fabric_harness(validation: crate::config::agent_surface::A2aValidation) -> GatewayHarness {
    GatewayHarness::start(move |_, gw_config, _| {
        let surface = agent_pay_surface(&format!("fabric-{}", validation.as_str()), Some("fabric://unknown/ch"));
        gw_config.surfaces = vec![with_validation(surface, validation)];
    })
    .await
}

const BATCH_REQUEST: &str = r#"[{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t1"}}]"#;

fn message_without_message_id() -> String {
    let mut request = a2a_request_body();
    request["params"]["message"]
        .as_object_mut()
        .unwrap()
        .remove("messageId");
    serde_json::to_string(&request).unwrap()
}

/// With the default envelope validation, a `fabric://` target refuses a batch
/// before payment, but lets a message missing A2A fields through to payment.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_fabric_target_checks_the_envelope_by_default() {
    let h = fabric_harness(crate::config::agent_surface::A2aValidation::Envelope).await;

    let (status, body) = post_a2a(&h, "1.0", BATCH_REQUEST.to_string()).await;
    assert_eq!((status, jsonrpc_error_code(&body)), (400, Some(-32600)), "a batch is refused: {body}");
    assert!(!body.contains(DELEGATION_MISCONFIGURED), "payment step must not run, got {body}");

    let (status, body) = post_a2a(&h, "1.0", message_without_message_id()).await;
    assert_eq!(status, 502, "a malformed message reaches payment: {status} {body}");
    assert!(body.contains(DELEGATION_MISCONFIGURED), "got {body}");
}

/// With `full` validation, a `fabric://` target also refuses a malformed message.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_fabric_target_checks_the_request_shape_when_full() {
    let h = fabric_harness(crate::config::agent_surface::A2aValidation::Full).await;

    let (status, body) = post_a2a(&h, "1.0", message_without_message_id()).await;
    assert_eq!((status, jsonrpc_error_code(&body)), (400, Some(-32602)), "got {body}");
    assert!(!body.contains(DELEGATION_MISCONFIGURED), "payment step must not run, got {body}");
}

/// With validation `off`, a `fabric://` target lets a batch through to payment.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_fabric_target_checks_nothing_when_off() {
    let h = fabric_harness(crate::config::agent_surface::A2aValidation::Off).await;

    let (status, body) = post_a2a(&h, "1.0", BATCH_REQUEST.to_string()).await;
    assert_eq!(status, 502, "a batch reaches payment: {status} {body}");
    assert!(body.contains(DELEGATION_MISCONFIGURED), "got {body}");
}

/// An `a2a-proxy://` target is version-negotiated, ahead of delegated payment.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_proxy_target_is_version_negotiated_before_delegated_payment() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        let mut surface = agent_pay_surface("prepay-a2a-proxy", Some("a2a-proxy://prepay-proxy"));
        surface.target.a2a_proxy_id = Some("prepay-proxy".to_string());
        gw_config.surfaces = vec![surface];
    })
    .await;

    let (status, body) = post_a2a(&h, "2.0", serde_json::to_string(&a2a_request_body()).unwrap()).await;

    assert_eq!(status, 400, "expected -32009 ahead of payment, got {status}: {body}");
    assert_eq!(jsonrpc_error_code(&body), Some(-32009), "got {body}");
    assert!(!body.contains(DELEGATION_MISCONFIGURED), "payment step must not run, got {body}");
}
