use std::collections::HashMap;
use std::time::Duration;

use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::caller::post_json;
use crate::bdd_support::config::target_auth::{
    TARGET_AUTH_CLIENT_SECRET_SECRET, TARGET_AUTH_JWT_ISSUER, TARGET_AUTH_PROVIDER_ID, TARGET_AUTH_PROVIDER_TOKEN,
    target_auth_signing_key,
};
use crate::bdd_support::json_rpc::build_a2a_message_send_body;
use crate::bdd_support::mock_server::{MockResponse, MockServer};
use crate::steps::when::{
    ensure_admin_session, ensure_gateway_running, record_mock_observation, send_request_and_record,
};
use crate::world::{RecordedResponse, SurfaceWorld};

fn token_endpoint(world: &SurfaceWorld) -> &MockServer {
    world
        .infra
        .as_ref()
        .and_then(|infra| {
            infra
                .target_token_endpoint
                .as_ref()
        })
        .expect("the target's credential provider must serve a token endpoint")
}

async fn token_requests(world: &SurfaceWorld) -> Vec<HashMap<String, String>> {
    token_endpoint(world)
        .requests()
        .await
        .iter()
        .map(|request| serde_urlencoded::from_str(&request.raw_body).expect("a token request is form encoded"))
        .collect()
}

async fn latest_token_request(world: &SurfaceWorld) -> HashMap<String, String> {
    token_requests(world)
        .await
        .pop()
        .expect("the token endpoint received a grant")
}

fn issued_token(expires_in: u64) -> MockResponse {
    MockResponse::json(json!({
        "access_token": TARGET_AUTH_PROVIDER_TOKEN,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }))
}

#[given("the target's credential provider accepts token requests")]
async fn target_credential_provider_accepts_tokens(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    token_endpoint(world)
        .set_response(issued_token(3600))
        .await;
}

#[given(expr = "the caller has sent a request to the surface and received status {int}")]
async fn caller_has_sent_a_request(
    world: &mut SurfaceWorld,
    expected: u16,
) {
    send_request_and_record(world, vec![]).await;
    let status = world
        .caller_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(status, Some(expected), "the first request must answer {expected}");
}

#[given(expr = "the target's credential provider answers token requests only after {int} ms")]
async fn target_credential_provider_answers_slowly(
    world: &mut SurfaceWorld,
    delay_ms: u64,
) {
    ensure_gateway_running(world).await;
    token_endpoint(world)
        .set_response_delay(delay_ms, delay_ms)
        .await;
}

#[given(expr = "the target's credential provider refuses token requests with error {string} and description {string}")]
async fn target_credential_provider_refuses_with_error(
    world: &mut SurfaceWorld,
    error: String,
    description: String,
) {
    ensure_gateway_running(world).await;
    let mut response = MockResponse::json(json!({ "error": error, "error_description": description }));
    response.status = 401;
    token_endpoint(world)
        .set_response(response)
        .await;
}

#[given(expr = "the gateway gives a token request {int} second(s) before it gives up")]
fn gateway_token_request_timeout(
    world: &mut SurfaceWorld,
    seconds: u64,
) {
    assert!(
        world.infra.is_none(),
        "the token request timeout must be set before the gateway starts, which reads it once at boot"
    );
    world
        .surface_config
        .token_request_timeout_secs = Some(seconds);
}

#[given("the provider's signing key is a service account JSON key file")]
fn provider_signing_key_is_service_account_file(world: &mut SurfaceWorld) {
    world
        .surface_config
        .target_auth_provider
        .as_mut()
        .expect("the surface must authenticate its target with a credential provider first")
        .signing_key_is_service_account_file = true;
}

#[given(expr = "the caller has waited {int} second(s)")]
async fn caller_has_waited(
    _world: &mut SurfaceWorld,
    seconds: u64,
) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

/// Records the first answer that is not a 200, or the first answer when every caller got a
/// 200, so a following status check holds only when every caller was served.
#[when(expr = "{int} callers send a request to the surface at the same time")]
async fn callers_send_requests_at_the_same_time(
    world: &mut SurfaceWorld,
    callers: usize,
) {
    ensure_gateway_running(world).await;
    let url = format!(
        "http://127.0.0.1:{}{}/foo",
        world
            .infra
            .as_ref()
            .expect("the gateway is running")
            .gateway_port,
        world.surface_config.route
    );
    let body = build_a2a_message_send_body("hello");
    world.sent_body = Some(body.clone());
    let client = reqwest::Client::new();
    let responses = futures::future::join_all((0..callers).map(|_| post_json(&client, &url, &body, &[]))).await;
    let mut recorded: Vec<RecordedResponse> = responses
        .into_iter()
        .map(|response| {
            let response = response.expect("send a request to the gateway");
            RecordedResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            }
        })
        .collect();
    assert_eq!(recorded.len(), callers, "every caller must receive an answer");
    let position = recorded
        .iter()
        .position(|response| response.status != 200)
        .unwrap_or(0);
    world.caller_response = Some(recorded.swap_remove(position));
    record_mock_observation(world).await;
}

#[given(expr = "the operator has changed the credential provider's scope to {string}")]
async fn operator_has_changed_provider_scope(
    world: &mut SurfaceWorld,
    scope: String,
) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(
            Method::PUT,
            &format!("/api/v1/credential-providers/{TARGET_AUTH_PROVIDER_ID}"),
            Some(&json!({ "default_scopes": [scope] })),
        )
        .await
        .expect("update the credential provider through the admin API");
    assert_eq!(response.status, 200, "updating the credential provider answered {}", response.body);
}

#[given(expr = "the operator has replaced the provider's client secret with {string}")]
async fn operator_has_replaced_client_secret(
    world: &mut SurfaceWorld,
    value: String,
) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(
            Method::PUT,
            &format!("/api/v1/secrets/{TARGET_AUTH_CLIENT_SECRET_SECRET}"),
            Some(&json!({ "value": value, "update_value": true })),
        )
        .await
        .expect("update the secret through the admin API");
    assert_eq!(response.status, 200, "updating the secret answered {}", response.body);
}

#[then(expr = "the target's credential provider's latest token request asks for scope {string}")]
async fn latest_token_request_asks_for_scope(
    world: &mut SurfaceWorld,
    scope: String,
) {
    let grant = latest_token_request(world).await;
    assert_eq!(grant.get("scope"), Some(&scope), "the latest token request asked for {:?}", grant.get("scope"));
}

#[then(expr = "the target's credential provider's latest token request carries client secret {string}")]
async fn latest_token_request_carries_client_secret(
    world: &mut SurfaceWorld,
    secret: String,
) {
    let grant = latest_token_request(world).await;
    assert_eq!(
        grant
            .get("client_secret")
            .map(String::as_str),
        Some(secret.as_str()),
        "the latest token request carried a different client secret"
    );
}

#[then(expr = "the target's credential provider received a JWT Bearer grant signed with key id {string}")]
async fn token_request_is_jwt_bearer_signed_with_key_id(
    world: &mut SurfaceWorld,
    key_id: String,
) {
    let grant = latest_token_request(world).await;
    assert_eq!(grant["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
    let token_endpoint = world
        .surface_config
        .target_auth_provider
        .as_ref()
        .and_then(|provider| {
            provider
                .token_endpoint
                .clone()
        })
        .expect("the token endpoint was configured");
    let header = jsonwebtoken::decode_header(&grant["assertion"]).expect("the assertion is a JWT");
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(header.kid.as_deref(), Some(key_id.as_str()));
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[token_endpoint]);
    validation.set_issuer(&[TARGET_AUTH_JWT_ISSUER]);
    jsonwebtoken::decode::<Value>(
        &grant["assertion"],
        &jsonwebtoken::DecodingKey::from_rsa_pem(
            target_auth_signing_key()
                .public_pem
                .as_bytes(),
        )
        .unwrap(),
        &validation,
    )
    .expect("the grant is signed with the key from the service account file");
}

#[then(expr = "the gateway log does not contain {string}")]
fn gateway_log_does_not_contain(
    world: &mut SurfaceWorld,
    text: String,
) {
    let path = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        ._temp_dir
        .path()
        .join("gateway.log");
    let log = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the scenario must keep the gateway log first: {}: {error}", path.display()));
    assert!(!log.contains(&text), "the gateway log contains {text:?}");
}

#[then(expr = "the response body does not contain {string}")]
fn response_body_does_not_contain(
    world: &mut SurfaceWorld,
    text: String,
) {
    let body = world
        .caller_response
        .as_ref()
        .expect("the caller must have received a response")
        .body
        .to_string();
    assert!(!body.contains(&text), "the response body contains {text:?}: {body}");
}

#[then(expr = "the delegation audit trail has no record containing {string}")]
async fn delegation_audit_trail_has_no_record_containing(
    world: &mut SurfaceWorld,
    text: String,
) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json::<Value>(Method::GET, "/v1/delegation-audit?page_size=100", None)
        .await
        .expect("read the delegation audit trail through the admin API");
    assert_eq!(response.status, 200, "reading the delegation audit trail answered {}", response.body);
    let trail = response.body.to_string();
    assert!(!trail.contains(&text), "the delegation audit trail contains {text:?}: {trail}");
}
