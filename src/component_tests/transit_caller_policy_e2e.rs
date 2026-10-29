//! Transit Point caller in policy input E2E: a Transit Point policy reads the
//! verified caller from `input.transit.caller`, so it can admit one caller and
//! refuse another, and a refused call never reaches the target.

use super::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
use super::helpers::{GatewayHarness, MockServer};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;

const POLICY_ID: &str = "only-alice-at-the-transit-point";
const STRATEGY_ID: &str = "transit-caller-strategy";

/// The identity hash of a JWT caller on a surface with no tenant, computed as
/// an operator would: `printf '%s' '["jwt_bearer","<iss>",null,"<sub>"]' | shasum -a 256`.
fn jwt_caller_hash(
    issuer: &str,
    subject: &str,
) -> String {
    format!("{:x}", Sha256::digest(format!(r#"["jwt_bearer","{issuer}",null,"{subject}"]"#).as_bytes()))
}

fn write_policy_definition(
    temp_dir: &std::path::Path,
    rego: &str,
) {
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    let definition = json!({
        "id": POLICY_ID,
        "name": "Transit Point caller policy",
        "description": "Admits a Transit Point call by its verified caller.",
        "policy_type": "agent_surface",
        "policy": rego,
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(dir.join(format!("{POLICY_ID}.json")), serde_json::to_string_pretty(&definition).unwrap())
        .expect("write policy definition");
}

fn write_jwt_strategy(
    temp_dir: &std::path::Path,
    fixture: &JwksFixture,
) {
    let dir = temp_dir.join("jwt_verification_strategies");
    std::fs::create_dir_all(&dir).expect("create strategy dir");
    let strategy = json!({
        "id": STRATEGY_ID,
        "name": "Transit caller strategy",
        "expected_issuer": fixture.issuer,
        "jwks_source": { "type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer) },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(dir.join(format!("{STRATEGY_ID}.json")), serde_json::to_string_pretty(&strategy).unwrap())
        .expect("write strategy");
}

fn surface(require_transit_token: bool) -> crate::config::agent_surface::AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "transit-caller-policy",
        "name": "transit-caller-policy",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a",
            "caller_authentication": {
                "methods": [{ "type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID, "audiences": [] }]
            }
        },
        "target": { "endpoint": "inbound_target_placeholder" },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "require_transit_token": require_transit_token,
                "allow_unauthenticated_callers": !require_transit_token,
                "policy": { "policy_definition_id": POLICY_ID }
            }]
        }
    }))
    .expect("transit caller policy surface")
}

async fn start_gateway(
    rego: impl FnOnce(&str) -> String,
    require_transit_token: bool,
) -> (GatewayHarness, JwksFixture) {
    let fixture = JwksFixture::start().await;
    let rego = rego(&fixture.issuer);
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |temp_dir, gw_config, _| {
        write_jwt_strategy(temp_dir, &fixture);
        write_policy_definition(temp_dir, &rego);
        gw_config.surfaces = vec![surface(require_transit_token)];
    })
    .await;
    (h, fixture)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

/// The transit token the Access Point hands the managed agent for `subject`.
async fn transit_token_for(
    h: &GatewayHarness,
    fixture: &JwksFixture,
    subject: &str,
) -> String {
    let jwt = sign_jwt(
        json!({
            "iss": fixture.issuer, "sub": subject, "aud": "any",
            "exp": now_secs() + 300, "iat": now_secs(),
        }),
        &fixture.kid,
    );
    let response = client()
        .post(format!("{}/smoke/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {jwt}"))
        .body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "the Access Point must admit {subject}");
    h.mock
        .last_request_rx
        .borrow()
        .as_ref()
        .and_then(|request| {
            request
                .headers
                .get("x-transit-token")
                .cloned()
        })
        .expect("the managed agent must receive a transit token")
}

async fn call_transit_point(
    h: &GatewayHarness,
    token: Option<&str>,
) -> reqwest::StatusCode {
    let mut request = client()
        .post(format!(
            "{}/outbound/smoke/target",
            h.outbound_url
                .as_ref()
                .unwrap()
        ))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":2}"#);
    if let Some(token) = token {
        request = request.header("x-transit-token", token);
    }
    request
        .send()
        .await
        .unwrap()
        .status()
}

fn requests_seen(h: &GatewayHarness) -> usize {
    h.mock
        .request_count
        .load(Ordering::SeqCst)
}

/// A Transit Point policy that admits only the caller whose verified identity
/// hash is Alice's admits her and refuses Bob, and the target sees only
/// Alice's call.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_policy_can_allow_only_a_named_caller() {
    let rego = |issuer: &str| {
        format!(
            r#"package surface.policy

default allow := false

allow if {{
    input.transit.caller.verified
    input.transit.caller.verification == "transit_token"
    input.transit.caller.user_identity_hash == "{}"
}}
"#,
            jwt_caller_hash(issuer, "alice")
        )
    };
    let (h, fixture) = start_gateway(rego, true).await;
    let alice = transit_token_for(&h, &fixture, "alice").await;
    let bob = transit_token_for(&h, &fixture, "bob").await;

    let before = requests_seen(&h);
    assert_eq!(call_transit_point(&h, Some(&alice)).await, 200);
    assert_eq!(requests_seen(&h), before + 1, "the target must see the call of the admitted caller");
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .as_ref()
            .is_some_and(|request| request
                .body
                .contains(r#""id":2"#)),
        "the admitted call is the one the target last received"
    );

    let before = requests_seen(&h);
    assert_eq!(call_transit_point(&h, Some(&bob)).await, 403);
    assert_eq!(requests_seen(&h), before, "a refused caller's call must not reach the target");
}

/// A Transit Point that does not require a transit token sees an anonymous
/// caller: `verified` is false and `verification` says `anonymous`, so a policy
/// that needs a verified caller refuses the call and one that names the
/// anonymous case admits it.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_without_a_transit_token_is_anonymous_in_the_policy_input() {
    let requires_verified = r#"package surface.policy

default allow := false

allow if {
    input.transit.caller.verified
}
"#;
    let (h, _fixture) = start_gateway(|_| requires_verified.to_string(), false).await;
    let before = requests_seen(&h);
    assert_eq!(call_transit_point(&h, None).await, 403);
    assert_eq!(requests_seen(&h), before, "an anonymous call must not reach the target of a verified-only policy");

    let admits_anonymous = r#"package surface.policy

default allow := false

allow if {
    input.transit.caller.verification == "anonymous"
    input.transit.caller.verified == false
    not input.transit.caller.user_identity_hash
}
"#;
    let (h, _fixture) = start_gateway(|_| admits_anonymous.to_string(), false).await;
    let before = requests_seen(&h);
    assert_eq!(call_transit_point(&h, None).await, 200);
    assert_eq!(requests_seen(&h), before + 1, "the anonymous call is admitted by the policy that names it");
}
