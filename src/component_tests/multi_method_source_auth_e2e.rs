//! An Access Point with more than one caller authentication method, proven at
//! the wire: each request is verified by the method whose credential it
//! carries, and no method's credential reaches the target.

use super::helpers::jwt::{JwksFixture, now_secs, sign_jwt, write_jwt_strategy};
use super::helpers::{self, GatewayHarness, RecordingTarget, write_api_key_secret};
use axum::http::StatusCode;
use serde_json::json;

const API_KEY_SECRET_ID: &str = "multi-method-source-key";
const API_KEY: &str = "partner-key";
const DENY_FAILED_POLICY_ID: &str = "deny-failed-source-auth";

fn write_deny_failed_policy(temp_dir: &std::path::Path) {
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    let definition = json!({
        "id": DENY_FAILED_POLICY_ID,
        "name": DENY_FAILED_POLICY_ID,
        "description": "Refuses callers whose source authentication failed",
        "policy_type": "agent_surface",
        "policy": "package surface.policy\n\ndefault allow := false\n\nallow if not deny\n\ndeny if input.source_auth.method == \"failed\"\n",
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(
        dir.join(format!("{DENY_FAILED_POLICY_ID}.json")),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write policy definition fixture");
}

fn jwt_method(
    strategy_id: &str,
    forward_header: bool,
) -> serde_json::Value {
    json!({
        "type": "jwt_bearer",
        "jwt_verification_strategy_id": strategy_id,
        "audiences": [],
        "forward_header": forward_header
    })
}

fn api_key_method() -> serde_json::Value {
    json!({
        "type": "api_key",
        "extraction": { "source": "http_header", "field": "x-api-key" },
        "secret_id": API_KEY_SECRET_ID
    })
}

async fn start_gateway(
    fixture: &JwksFixture,
    target: &RecordingTarget,
    methods: impl Fn(&str) -> serde_json::Value,
) -> GatewayHarness {
    let target_url = target.url.clone();
    GatewayHarness::start(move |temp_dir, gw_config, bootstrap| {
        let strategy_id = write_jwt_strategy(fixture, temp_dir);
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            API_KEY_SECRET_ID,
            API_KEY,
        );
        write_deny_failed_policy(temp_dir);
        let mut surface = helpers::build_minimal_channel();
        surface
            .access_point
            .caller_authentication =
            Some(serde_json::from_value(json!({ "methods": methods(strategy_id) })).expect("caller authentication"));
        surface.target.endpoint = target_url.clone();
        surface.target.policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: DENY_FAILED_POLICY_ID.to_string(),
            require_agent_context: false,
        });
        gw_config.surfaces = vec![surface];
    })
    .await
}

fn valid_jwt(issuer: &str) -> String {
    sign_jwt(
        json!({
            "iss": issuer,
            "sub": "internal-user",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        "e2e-test-key",
    )
}

async fn send(
    h: &GatewayHarness,
    headers: &[(&str, String)],
) -> u16 {
    let mut request = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"message/send","id":1,"params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"hi"}]}}}"#);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    request
        .send()
        .await
        .expect("inbound request failed")
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn each_caller_authenticates_with_the_method_its_credential_belongs_to() {
    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(StatusCode::OK, &[]).await;
    let h =
        start_gateway(&fixture, &target, |strategy_id| json!([jwt_method(strategy_id, false), api_key_method()])).await;
    let jwt = format!("Bearer {}", valid_jwt(&fixture.issuer));

    assert_eq!(send(&h, &[("authorization", jwt.clone())]).await, 200, "a JWT caller is authenticated");
    assert_eq!(send(&h, &[("x-api-key", API_KEY.to_string())]).await, 200, "an API-key caller is authenticated");
    assert_eq!(send(&h, &[]).await, 403, "a caller with no credential fails source auth");
    assert_eq!(send(&h, &[("x-api-key", "wrong".to_string())]).await, 403, "a wrong API key fails source auth");
    assert_eq!(
        send(&h, &[("authorization", "Bearer not-a-jwt".to_string()), ("x-api-key", API_KEY.to_string())]).await,
        403,
        "the first configured method among the presented credentials decides, with no fallback"
    );
    assert_eq!(
        send(&h, &[("authorization", jwt), ("x-api-key", API_KEY.to_string())]).await,
        200,
        "the JWT, configured first, authenticates a caller presenting both"
    );

    let received = target.received();
    assert_eq!(received.len(), 3, "only authenticated callers are forwarded");
    for sent in &received {
        assert!(!sent.contains_key("authorization"), "{sent:?}");
        assert!(!sent.contains_key("x-api-key"), "{sent:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forwarded_jwt_reaches_the_target_only_when_the_jwt_method_verified_the_request() {
    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(StatusCode::OK, &[]).await;
    let h =
        start_gateway(&fixture, &target, |strategy_id| json!([api_key_method(), jwt_method(strategy_id, true)])).await;
    let jwt = format!("Bearer {}", valid_jwt(&fixture.issuer));

    assert_eq!(send(&h, &[("authorization", jwt.clone())]).await, 200);
    assert_eq!(send(&h, &[("authorization", jwt.clone()), ("x-api-key", API_KEY.to_string())]).await, 200);

    let received = target.received();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0]["authorization"], jwt.as_str(), "the selected JWT method forwards its token");
    assert!(
        !received[1].contains_key("authorization"),
        "the API key, configured first, verified the request, so the JWT stays at the gateway: {:?}",
        received[1]
    );
    assert!(!received[1].contains_key("x-api-key"), "{:?}", received[1]);
}
