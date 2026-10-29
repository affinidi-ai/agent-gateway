//! Channel E2E smoke tests
//!
//! These tests start the agent-gateway in-process via `run_axum_proxy`, spin up
//! a lightweight axum mock target, and verify that inbound HTTP requests sent to
//! the channel's listen port are correctly forwarded.

use super::helpers;
use helpers::GatewayHarness;
use helpers::jwt::{JwksFixture, now_secs, setup_jwt_bearer_auth_rejects_missing_then_accepts_valid, sign_jwt};
use serde_json::json;

// Run tests sequentially to avoid port-allocation races on CI.
// Each test gets its own GatewayHarness with its own free port.

async fn assert_response(resp: reqwest::Response) {
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let text = resp
        .text()
        .await
        .expect("read body");

    assert_eq!(status, 200, "expected 200 from gateway");

    let body: serde_json::Value = serde_json::from_str(&text).expect("response body is not valid JSON");
    assert_eq!(body["result"], "ok", "gateway response body did not match mock's response");

    assert_eq!(
        content_type.as_deref(),
        Some("application/json"),
        "gateway response content-type did not match mock's response"
    );
}

fn assert_forwarded_request(
    mock: &helpers::MockServer,
    expected_body: &str,
) {
    let received = mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");

    assert_eq!(received.method, "POST", "forwarded method did not match");
    assert_eq!(
        received
            .headers
            .get("content-type")
            .map(String::as_str),
        Some("application/json"),
        "forwarded content-type header did not match"
    );
    assert_eq!(received.body, expected_body, "forwarded request body did not match");
}

/// A `POST /` to the gateway is forwarded to the mock target.
/// The response returned matches what the mock emitted.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_request_forwarded_to_target() {
    //
    // Given
    //

    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    //
    // When a request is sent to the channel
    //

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request failed");

    //
    // Then
    //

    assert_response(resp).await;
    assert_forwarded_request(&h.mock, body);
}

/// A `POST` through the outbound listener is forwarded to the external mock target.
/// The route pattern is `/outgoing/<channel-route>/<alias>/<path>`.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_request_forwarded_to_target() {
    //
    // Given
    //

    let h = GatewayHarness::start_with_outbound(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_outbound_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
    let outbound_url = h
        .outbound_url
        .as_ref()
        .expect("outbound_url must be set");

    //
    // When a request is sent via the outbound listener
    //

    let resp = client
        .post(format!("{}/outbound/smoke/target/rpc", outbound_url))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("outbound request failed");

    //
    // Then
    //

    assert_response(resp).await;
    assert_forwarded_request(&h.mock, body);
}

/// A channel with `source_auth` (JWT Bearer) no longer blocks requests without a
/// valid token: a caller-attributable failure is non-blocking, so with no denying
/// policy both an unauthenticated request and a valid one are forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn jwt_bearer_auth_forwards_missing_and_valid_without_policy() {
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    //
    // 1. Missing token → non-blocking, request is forwarded to the target
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request without token failed");

    assert_response(resp).await;
    assert_forwarded_request(&h.mock, body);

    //
    // 2. Valid token → request forwarded to mock target
    //
    let token = sign_jwt(
        json!({
            "iss": fixture.issuer,
            "sub": "user-e2e",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        &fixture.kid,
    );

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(body)
        .send()
        .await
        .expect("request with valid token failed");

    assert_response(resp).await;
    assert_forwarded_request(&h.mock, body);
}

/// When source auth is configured, the credential header used for authentication
/// must NOT be forwarded to the upstream target — it is consumed by the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn source_auth_credential_header_not_forwarded_upstream() {
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let token = sign_jwt(
        json!({
            "iss": fixture.issuer,
            "sub": "user-e2e",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        &fixture.kid,
    );

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(body)
        .send()
        .await
        .expect("request failed");

    assert_response(resp).await;
    assert_forwarded_request(&h.mock, body);

    // The source auth credential header must NOT appear in the upstream request.
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");
    assert!(
        !received
            .headers
            .contains_key("authorization"),
        "source auth credential header 'authorization' was leaked to upstream"
    );
}

// ── Surface variant URL routing (plan §2.3) ─────────────────────────────────

/// Plan §2.3: a request whose URL matches `/route$alias[/rest]` selects the
/// variant whose alias is `<alias>` and forwards the (alias-stripped) tail.
/// Here the alias is `default` (the one variant defined on the smoke channel)
/// so behaviour is byte-identical to a request without the suffix.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_with_dollar_alias_routes_and_strips_suffix() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let resp = client
        .post(format!("{}/smoke$default/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request failed");

    assert_response(resp).await;

    // Mock must have received the request at `/rpc` (alias suffix stripped).
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");
    assert_eq!(received.path, "/rpc", "alias suffix `$default` should have been stripped before forwarding");
    assert_eq!(received.body, body);
}

/// Plan §2.3: percent-encoded `%24` is tolerated equivalently to `$`.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_with_percent_encoded_alias_routes() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let resp = client
        .post(format!("{}/smoke%24default/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request failed");

    assert_response(resp).await;

    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");
    assert_eq!(received.path, "/rpc", "percent-encoded alias suffix should be stripped");
}

/// Plan §4: an unknown variant alias is rejected before any forwarding occurs.
/// Today the inbound handler returns 400; the spec calls for 404 once
/// surface-side variants land. Either is acceptable here — what matters is
/// that the mock target never receives the request.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_with_unknown_alias_is_rejected() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let resp = client
        .post(format!("{}/smoke$nope/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request failed");

    let status = resp.status().as_u16();
    assert!(matches!(status, 400 | 404), "expected 400 or 404 for unknown alias, got {status}");

    // Mock must NOT have seen the request.
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should not have received a request when alias is unknown"
    );
}

/// Plan §4.5: a disabled variant returns 503 ("listener temporarily
/// unavailable") and is never forwarded. The route exists and is
/// recognised — an operator has intentionally switched it off — so 404
/// (which means "no such variant") would be misleading.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_with_disabled_variant_returns_503() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_channel_with_disabled_variant()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let resp = client
        .post(format!("{}/smoke$dev/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 503, "disabled variant should return 503");

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should not have received a request when variant is disabled"
    );
}

/// Sanity: a request with no `$alias` continues to work after the
/// suffix-parser refactor — the default variant is selected by an unmarked
/// URL even when other variants exist on the channel.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_default_variant_unmarked_url_still_forwarded() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_channel_with_disabled_variant()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let resp = client
        .post(format!("{}/smoke/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request failed");

    assert_response(resp).await;
    assert_forwarded_request(&h.mock, body);
}

/// A gateway serving one surface at `route` under the `/smoke` prefix, with `policy` as
/// its Target policy and `variants`, whose Access Point refuses no caller without a token.
async fn start_with_surface_policy(
    fixture: &JwksFixture,
    route: &'static str,
    policy: &'static str,
    variants: serde_json::Value,
) -> GatewayHarness {
    const POLICY_ID: &str = "variant-alias-policy";
    GatewayHarness::start(move |temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(fixture, temp_dir, gw_config);
        let dir = temp_dir.join("policy_definitions");
        std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
        let definition = json!({
            "id": POLICY_ID,
            "name": POLICY_ID,
            "policy_type": "agent_surface",
            "policy": policy,
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        });
        std::fs::write(dir.join(format!("{POLICY_ID}.json")), definition.to_string()).expect("write policy definition");
        let mut surface = serde_json::to_value(&gw_config.surfaces[0]).expect("serialize surface");
        surface["access_point"]["route"] = json!(route);
        surface["target"]["policy"] = json!({"policy_definition_id": POLICY_ID});
        surface["variants"] = variants;
        gw_config.surfaces = vec![serde_json::from_value(surface).expect("surface with policy")];
    })
    .await
}

async fn post_rpc(
    h: &GatewayHarness,
    route: &str,
    body: &'static str,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}{route}/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request to the gateway failed")
}

/// A surface policy reads `input.channel.variant_alias` from the request URL, so a
/// rule that denies failed callers on one variant denies them there and nowhere else.
#[tokio::test(flavor = "multi_thread")]
async fn surface_policy_sees_the_variant_alias_of_the_request_url() {
    let fixture = JwksFixture::start().await;
    let h = start_with_surface_policy(
        &fixture,
        "/smoke",
        "package surface.policy\ndefault allow := true\nallow := false if {\n  input.source_auth.method == \"failed\"\n  input.channel.variant_alias == \"strict\"\n}\n",
        json!([{"id": "vc-strict", "alias": "strict", "name": "strict", "enabled": true, "overrides": {}}]),
    )
    .await;
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let strict = post_rpc(&h, "/smoke$strict", body).await;
    assert_eq!(strict.status(), 403, "a failed caller on the strict variant must be denied");
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "a denied request must not reach the target"
    );

    let base = post_rpc(&h, "/smoke", body).await;
    assert_response(base).await;
    assert_forwarded_request(&h.mock, body);
}

/// An alias in the URL of a surface without variants selects nothing, so policy does
/// not see it and a rule that admits failed callers on that alias does not apply. The
/// surface sits under a wider route prefix, so such a URL reaches it.
#[tokio::test(flavor = "multi_thread")]
async fn policy_does_not_see_an_alias_that_selects_no_variant() {
    let fixture = JwksFixture::start().await;
    let h = start_with_surface_policy(
        &fixture,
        "/smoke/inner",
        "package surface.policy\ndefault allow := false\nallow if input.source_auth.method != \"failed\"\nallow if input.channel.variant_alias == \"public\"\n",
        json!([]),
    )
    .await;
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    let forged = post_rpc(&h, "/smoke/inner$public", body).await;
    assert_eq!(forged.status(), 403, "an alias that selects no variant must not admit a failed caller");
    let base = post_rpc(&h, "/smoke/inner", body).await;
    assert_eq!(base.status(), 403, "a failed caller on the base surface is denied");
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "a denied request must not reach the target"
    );
}
