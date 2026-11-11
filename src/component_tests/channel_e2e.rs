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
/// The route pattern is `/outbound/<channel-route>/<alias>/<path>`.
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

/// The machine's address on its default route, which is not a loopback
/// address, or `None` on a machine without one. Finding it sends nothing.
fn non_loopback_local_address() -> Option<std::net::IpAddr> {
    let local = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    local
        .connect("192.0.2.1:9")
        .ok()?;
    let address = local.local_addr().ok()?.ip();
    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

/// An inbound listener whose `bind_address` is the loopback address binds there
/// alone: it answers on `127.0.0.1` and refuses the machine's other address,
/// when the machine has one.
#[tokio::test(flavor = "multi_thread")]
async fn an_inbound_listener_binds_its_configured_address() {
    let h = GatewayHarness::start(|_, gw_config, bootstrap| {
        let path = &bootstrap.config_files.gateway;
        let mut network: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        network["listeners"][0]["bind_address"] = json!("127.0.0.1");
        std::fs::write(path, serde_json::to_vec(&network).unwrap()).unwrap();
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;
    let port: u16 = h
        .gateway_base
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();

    let on_loopback = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#)
        .send()
        .await
        .expect("the listener answers on its bind address");
    assert_response(on_loopback).await;

    let Some(other_address) = non_loopback_local_address() else {
        eprintln!("skipped the check that other addresses are refused: this machine has no non-loopback address");
        return;
    };
    let elsewhere =
        tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::TcpStream::connect((other_address, port)))
            .await;
    assert!(!matches!(elsewhere, Ok(Ok(_))), "the listener must not accept on {other_address}:{port}");
}

/// Two inbound listeners that share a port with different `bind_address`
/// values are both served: the gateway answers on `127.0.0.1` and on `::1`.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_listeners_sharing_a_port_are_each_served_on_their_address() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("skipped: this host has no IPv6 loopback address");
        return;
    }
    let h = GatewayHarness::start(|_, gw_config, bootstrap| {
        let path = &bootstrap.config_files.gateway;
        let mut network: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        network["listeners"][0]["bind_address"] = json!("127.0.0.1");
        let mut on_ipv6 = network["listeners"][0].clone();
        on_ipv6["id"] = json!("smoke-test-ipv6");
        on_ipv6["bind_address"] = json!("::1");
        network["listeners"]
            .as_array_mut()
            .unwrap()
            .push(on_ipv6);
        std::fs::write(path, serde_json::to_vec(&network).unwrap()).unwrap();
        gw_config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;
    let path = h
        .gateway_url
        .strip_prefix(&h.gateway_base)
        .unwrap()
        .to_string();
    let port = h
        .gateway_base
        .rsplit(':')
        .next()
        .unwrap()
        .to_string();

    for base in [format!("http://127.0.0.1:{port}"), format!("http://[::1]:{port}")] {
        let response = reqwest::Client::new()
            .post(format!("{base}{path}"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .unwrap_or_else(|error| panic!("the listener on {base} must answer: {error}"));
        assert_response(response).await;
    }
}

/// A closed Access Point with JWT Bearer source auth refuses a request without
/// a token with `401` before the target, and forwards one with a valid token.
#[tokio::test(flavor = "multi_thread")]
async fn jwt_bearer_auth_refuses_a_missing_token_and_forwards_a_valid_one() {
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;

    //
    // 1. Missing token → refused before the target
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request without token failed");

    assert_eq!(resp.status(), 401);
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the target is never called"
    );

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

/// With `forward_header`, the caller's token reaches the target only when it
/// verified; an expired token, one from another issuer, or a second token
/// beside a valid one is refused with `401` before the target, and a public
/// Access Point forwards such a caller without its token.
#[tokio::test(flavor = "multi_thread")]
async fn forward_header_passes_on_only_a_verified_token() {
    let fixture = JwksFixture::start().await;

    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
        if let Some(crate::source_auth::SourceAuthConfig::JwtBearer(jwt)) = gw_config.surfaces[0]
            .access_point
            .caller_authentication
            .as_mut()
            .and_then(|caller| caller.methods.first_mut())
        {
            jwt.forward_header = true;
        }
    })
    .await;

    let client = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
    let sign = |issuer: &str, exp: u64| {
        sign_jwt(json!({"iss": issuer, "sub": "user-e2e", "aud": "any", "exp": exp, "iat": now_secs()}), &fixture.kid)
    };

    let valid = sign(&fixture.issuer, now_secs() + 300);
    let expired = sign(&fixture.issuer, now_secs() - 3600);
    for (case, tokens, verified) in [
        ("valid", vec![valid.clone()], true),
        ("expired", vec![expired.clone()], false),
        ("another issuer", vec![sign("https://other-issuer.example", now_secs() + 300)], false),
        ("valid then expired", vec![valid, expired], false),
    ] {
        let reached = h
            .mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst);
        let resp = tokens
            .iter()
            .fold(client.post(&h.gateway_url), |request, token| {
                request.header("authorization", format!("Bearer {token}"))
            })
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .expect("request failed");

        if !verified {
            assert_eq!(resp.status(), 401, "{case}");
            assert_eq!(
                h.mock
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                reached,
                "{case}: the target is never called"
            );
            continue;
        }
        assert_response(resp).await;
        assert_forwarded_request(&h.mock, body);
        let received = h
            .mock
            .last_request_rx
            .borrow()
            .clone()
            .expect("mock did not receive a request");
        assert_eq!(
            received
                .headers
                .get("authorization")
                .map(String::as_str),
            Some(format!("Bearer {}", tokens[0])).as_deref(),
            "{case}"
        );
    }

    let public = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, temp_dir, gw_config);
        let surface = &mut gw_config.surfaces[0];
        surface.access_point.public = Some(true);
        if let Some(crate::source_auth::SourceAuthConfig::JwtBearer(jwt)) = surface
            .access_point
            .caller_authentication
            .as_mut()
            .and_then(|caller| caller.methods.first_mut())
        {
            jwt.forward_header = true;
        }
    })
    .await;
    let resp = client
        .post(&public.gateway_url)
        .header("authorization", format!("Bearer {}", sign(&fixture.issuer, now_secs() - 3600)))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request failed");
    assert_response(resp).await;
    assert_forwarded_request(&public.mock, body);
    let received = public
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");
    assert!(
        !received
            .headers
            .contains_key("authorization"),
        "a public Access Point forwards an unverified caller without its token: {:?}",
        received.headers
    );
}

/// The managed agent learns who is calling only from the caller-info and DID
/// identity headers the gateway sets: a caller's own copies, in any case, are
/// dropped, so the agent gets the gateway's one value of each it sets and none
/// of the others.
#[tokio::test(flavor = "multi_thread")]
async fn the_agent_receives_the_caller_info_headers_only_as_the_gateway_sets_them() {
    let target = helpers::RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let target_url = target.url.clone();
    let h = GatewayHarness::start(move |_, gw_config, _| {
        let mut surface = helpers::build_minimal_channel();
        surface.target.endpoint = target_url;
        gw_config.surfaces = vec![surface];
    })
    .await;

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-caller-did", "did:web:caller-sent.example")
        .header("X-Caller-Identity-Source", "verified-presentation")
        .header("x-caller-dna-uai", "uai:caller-sent")
        .header("X-Gateway-DID", "did:web:caller-sent-gateway.example")
        .header("X-DID-Identity", "did:web:caller-sent-surface.example")
        .header("x-did-signed-identity", r#"{"id":"did:web:caller-sent-surface.example"}"#)
        .header("x-caller-context", "kept")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#)
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), 200);

    let received = target.received();
    assert_eq!(received.len(), 1);
    let values = |name: &str| -> Vec<String> {
        received[0]
            .get_all(name)
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    };
    assert_eq!(values("x-caller-did"), ["anonymous"]);
    assert_eq!(values("x-caller-identity-source"), ["gateway-computed"]);
    for unset in ["x-caller-dna-uai", "x-gateway-did", "x-did-identity", "x-did-signed-identity"] {
        assert!(values(unset).is_empty(), "{unset}: {:?}", values(unset));
    }
    assert_eq!(values("x-caller-context"), ["kept"], "headers that are not caller-info headers still pass");
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

/// An unknown variant alias is refused with 404 before any forwarding occurs.
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

    assert_eq!(resp.status(), 404, "unknown alias is refused with 404");

    // Mock must NOT have seen the request.
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "mock should not have received a request when alias is unknown"
    );
}

/// A disabled variant is refused with 404, the same answer as an unknown
/// alias: nothing is served at that URL. It is never forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_with_disabled_variant_returns_404() {
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

    assert_eq!(resp.status(), 404, "disabled variant is refused with 404");

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
