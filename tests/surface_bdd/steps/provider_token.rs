use std::collections::HashMap;
use std::time::Duration;

use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::caller::post_json;
use crate::bdd_support::config::single_surface_fixture::TargetAuthClientAuthentication;
use crate::bdd_support::config::target_auth::{
    TARGET_AUTH_CLIENT_SECRET_SECRET, TARGET_AUTH_CLIENT_SECRET_VALUE, TARGET_AUTH_JWT_ISSUER, TARGET_AUTH_PROVIDER_ID,
    TARGET_AUTH_PROVIDER_TOKEN, target_auth_signing_key,
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
        .expect("the credential provider must serve a token endpoint")
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

#[given("the credential provider accepts token requests")]
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

#[given(expr = "the credential provider answers token requests only after {int} ms")]
async fn target_credential_provider_answers_slowly(
    world: &mut SurfaceWorld,
    delay_ms: u64,
) {
    ensure_gateway_running(world).await;
    token_endpoint(world)
        .set_response_delay(delay_ms, delay_ms)
        .await;
}

#[given(expr = "the credential provider refuses token requests with error {string} and description {string}")]
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
        .expect("the gateway must authenticate to the managed agent with a credential provider first")
        .signing_key_is_service_account_file = true;
}

#[given(expr = "the caller has waited {int} second(s)")]
async fn caller_has_waited(
    _world: &mut SurfaceWorld,
    seconds: u64,
) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

/// Moves the issue time of every token the gateway holds back by `seconds`. The vault is read
/// from disk on every request, so the gateway sees the older time without a restart.
#[given(expr = "the gateway's token from the credential provider has aged {int} seconds")]
fn provider_token_has_aged(
    world: &mut SurfaceWorld,
    seconds: i64,
) {
    let vault_dir = world
        .infra
        .as_ref()
        .expect("the gateway must hold a token before it can age")
        ._temp_dir
        .path()
        .join("_storage/delegation_vault");
    let mut aged = 0;
    for entry in std::fs::read_dir(&vault_dir).expect("read the delegation vault directory") {
        let path = entry
            .expect("delegation vault entry")
            .path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            != Some("json")
        {
            continue;
        }
        let mut token: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read a stored token"))
            .expect("a stored token is JSON");
        let issued_at = chrono::DateTime::parse_from_rfc3339(
            token["consent_granted_at"]
                .as_str()
                .expect("a stored token has an issue time"),
        )
        .expect("the issue time is RFC 3339");
        token["consent_granted_at"] = json!((issued_at - chrono::Duration::seconds(seconds)).to_rfc3339());
        std::fs::write(&path, serde_json::to_string_pretty(&token).unwrap()).expect("write the aged token");
        aged += 1;
    }
    assert_eq!(aged, 1, "the gateway must hold exactly one token from the credential provider");
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

async fn change_stored_provider(
    world: &mut SurfaceWorld,
    mut changes: Value,
    subject: Option<String>,
) {
    ensure_admin_session(world).await;
    if let Some(subject) = subject {
        changes["jwt_subject"] = json!(subject);
    }
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(
            Method::PUT,
            &format!("/api/v1/credential-providers/{TARGET_AUTH_PROVIDER_ID}"),
            Some(&changes),
        )
        .await
        .expect("update the credential provider through the admin API");
    world.admin_response = Some(response);
}

#[when(expr = "the operator changes the credential provider's scope to {string}")]
async fn operator_changes_provider_scope(
    world: &mut SurfaceWorld,
    scope: String,
) {
    change_stored_provider(world, json!({ "default_scopes": [scope] }), None).await;
}

#[when(expr = "the operator changes the credential provider's scope to {string} and names the subject {string}")]
async fn operator_changes_provider_scope_with_subject(
    world: &mut SurfaceWorld,
    scope: String,
    subject: String,
) {
    change_stored_provider(world, json!({ "default_scopes": [scope] }), Some(subject)).await;
}

#[when(expr = "the operator changes the credential provider's signing key to the secret {string}")]
async fn operator_changes_provider_signing_key(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    change_stored_provider(world, json!({ "jwt_signing_key_secret_ref": secret_id }), None).await;
}

#[when(
    expr = "the operator changes the credential provider's signing key to the secret {string} and names the subject {string}"
)]
async fn operator_changes_provider_signing_key_with_subject(
    world: &mut SurfaceWorld,
    secret_id: String,
    subject: String,
) {
    change_stored_provider(world, json!({ "jwt_signing_key_secret_ref": secret_id }), Some(subject)).await;
}

#[when("the operator clears the credential provider's subject")]
async fn operator_clears_provider_subject(world: &mut SurfaceWorld) {
    change_stored_provider(world, json!({ "jwt_subject": "" }), None).await;
}

#[given("the operator has cleared the credential provider's client authentication")]
async fn operator_has_cleared_provider_client_authentication(world: &mut SurfaceWorld) {
    change_stored_provider(world, json!({ "client_authentication": "" }), None).await;
    let response = world
        .admin_response
        .as_ref()
        .expect("the update was recorded");
    assert_eq!(response.status, 200, "clearing the client authentication answered {}", response.body);
}

#[given("the operator has cleared the credential provider's client authentication and client ID")]
async fn operator_has_cleared_provider_client_authentication_and_client_id(world: &mut SurfaceWorld) {
    change_stored_provider(
        world,
        json!({ "client_authentication": "", "client_id_secret_ref": "", "client_secret_secret_ref": "" }),
        None,
    )
    .await;
    let response = world
        .admin_response
        .as_ref()
        .expect("the update was recorded");
    assert_eq!(response.status, 200, "clearing the client authentication answered {}", response.body);
}

#[when(expr = "the operator changes the credential provider's client authentication to {string}")]
async fn operator_changes_provider_client_authentication(
    world: &mut SurfaceWorld,
    authentication: String,
) {
    let method = TargetAuthClientAuthentication::from_wording(&authentication).api_value();
    change_stored_provider(world, json!({ "client_authentication": method }), None).await;
}

#[when(expr = "the operator changes the credential provider's type to {string}")]
async fn operator_changes_provider_type(
    world: &mut SurfaceWorld,
    provider_type: String,
) {
    change_stored_provider(world, json!({ "provider_type": provider_type }), None).await;
}

#[then("the stored credential provider is still a JWT Bearer provider")]
async fn stored_provider_is_still_a_jwt_bearer_provider(world: &mut SurfaceWorld) {
    let stored = stored_target_auth_provider(world).await;
    assert_eq!(stored["provider_type"], json!("oauth2_jwt_bearer"), "the stored provider: {stored}");
}

#[then(expr = "the stored credential provider has the client authentication {string}")]
async fn stored_provider_has_client_authentication(
    world: &mut SurfaceWorld,
    authentication: String,
) {
    let expected = TargetAuthClientAuthentication::from_wording(&authentication).api_value();
    let stored = stored_target_auth_provider(world).await;
    assert_eq!(stored["client_authentication"], json!(expected), "the stored provider: {stored}");
}

#[then("the stored credential provider has no client authentication")]
async fn stored_provider_has_no_client_authentication(world: &mut SurfaceWorld) {
    let stored = stored_target_auth_provider(world).await;
    assert!(
        stored
            .get("client_authentication")
            .is_none(),
        "the stored provider: {stored}"
    );
}

/// The Target's credential provider as the admin API returns it.
async fn stored_target_auth_provider(world: &mut SurfaceWorld) -> Value {
    ensure_admin_session(world).await;
    world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json::<Value>(
            Method::GET,
            &format!("/api/v1/credential-providers/{TARGET_AUTH_PROVIDER_ID}"),
            None,
        )
        .await
        .expect("read the credential provider through the admin API")
        .body
}

#[then(expr = "the credential provider stores the subject {string}")]
async fn stored_provider_has_subject(
    world: &mut SurfaceWorld,
    subject: String,
) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json::<Value>(
            Method::GET,
            &format!("/api/v1/credential-providers/{TARGET_AUTH_PROVIDER_ID}"),
            None,
        )
        .await
        .expect("read the credential provider through the admin API");
    assert_eq!(response.body["jwt_subject"], json!(subject), "the stored provider: {}", response.body);
}

#[then("the credential provider stores no subject")]
async fn stored_provider_has_no_subject(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json::<Value>(
            Method::GET,
            &format!("/api/v1/credential-providers/{TARGET_AUTH_PROVIDER_ID}"),
            None,
        )
        .await
        .expect("read the credential provider through the admin API");
    let subject = &response.body["jwt_subject"];
    assert!(subject.is_null() || subject == "", "the stored provider has a subject: {}", response.body);
}

#[then("no JWT Bearer assertion the credential provider received carries a subject")]
async fn no_assertion_has_subject(world: &mut SurfaceWorld) {
    let requests = token_requests(world).await;
    assert!(!requests.is_empty(), "the token endpoint received no grant");
    for request in requests {
        let claims = assertion_claims(&request["assertion"]);
        assert!(claims.get("sub").is_none(), "the assertion carries a subject: {claims}");
        assert!(
            claims["jti"]
                .as_str()
                .is_some_and(|jti| !jti.is_empty()),
            "the assertion carries no jti: {claims}"
        );
    }
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

#[then(expr = "the credential provider's latest token request asks for scope {string}")]
async fn latest_token_request_asks_for_scope(
    world: &mut SurfaceWorld,
    scope: String,
) {
    let grant = latest_token_request(world).await;
    assert_eq!(grant.get("scope"), Some(&scope), "the latest token request asked for {:?}", grant.get("scope"));
}

#[then(expr = "the credential provider's latest token request carries client secret {string}")]
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

async fn latest_token_request_authorization(world: &SurfaceWorld) -> Option<String> {
    token_endpoint(world)
        .requests()
        .await
        .pop()
        .expect("the token endpoint received a grant")
        .headers
        .get("authorization")
        .cloned()
}

#[then(expr = "the credential provider's latest token request carries client ID {string}")]
async fn latest_token_request_carries_client_id(
    world: &mut SurfaceWorld,
    client_id: String,
) {
    let grant = latest_token_request(world).await;
    assert_eq!(
        grant
            .get("client_id")
            .map(String::as_str),
        Some(client_id.as_str()),
        "the latest token request carried a different client ID"
    );
}

#[then("the credential provider's latest token request has no client ID or secret in its form body")]
async fn latest_token_request_carries_no_client_identity(world: &mut SurfaceWorld) {
    let grant = latest_token_request(world).await;
    for field in ["client_id", "client_secret"] {
        assert!(!grant.contains_key(field), "the latest token request carries {field}");
    }
}

#[then(
    expr = "the credential provider's latest token request carries HTTP Basic credentials for client {string} and secret {string}"
)]
async fn latest_token_request_carries_basic_credentials(
    world: &mut SurfaceWorld,
    client_id: String,
    secret: String,
) {
    use base64::Engine;
    // RFC 6749 section 2.3.1: the client ID and secret are form-urlencoded before the Basic encoding.
    let encode = |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", encode(&client_id), encode(&secret)))
    );
    let authorization = latest_token_request_authorization(world).await;
    assert!(
        authorization.as_deref() == Some(expected.as_str()),
        "the latest token request carried HTTP Basic credentials other than those of client {client_id}"
    );
}

#[then("the credential provider's latest token request carries no HTTP Basic credentials")]
async fn latest_token_request_carries_no_basic_credentials(world: &mut SurfaceWorld) {
    let authorization = latest_token_request_authorization(world).await;
    assert!(
        authorization.is_none_or(|value| !value
            .to_ascii_lowercase()
            .starts_with("basic ")),
        "the latest token request carries HTTP Basic credentials"
    );
}

#[then(expr = "the credential provider received a JWT Bearer grant signed with key id {string}")]
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

#[given(expr = "the credential provider stores the JWT subject {string}")]
fn provider_jwt_subject_is(
    world: &mut SurfaceWorld,
    subject: String,
) {
    world
        .surface_config
        .target_auth_provider
        .as_mut()
        .expect("the gateway must authenticate to the managed agent with a credential provider first")
        .jwt_subject = Some(subject);
}

#[given("the credential provider's token endpoint is not listening")]
async fn token_endpoint_is_not_listening(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let endpoint = world
        .infra
        .as_mut()
        .and_then(|infra| {
            infra
                .target_token_endpoint
                .take()
        });
    drop(endpoint.expect("the credential provider must serve a token endpoint"));
}

#[given("the credential provider answers token requests with no access token")]
async fn target_credential_provider_answers_without_access_token(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    token_endpoint(world)
        .set_response(MockResponse::json(json!({ "token_type": "Bearer" })))
        .await;
}

fn assertion_claims(assertion: &str) -> Value {
    use base64::Engine as _;
    let payload = assertion
        .split('.')
        .nth(1)
        .expect("an assertion has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("the assertion payload is base64url");
    serde_json::from_slice(&bytes).expect("the assertion payload is JSON")
}

#[then(expr = "every JWT Bearer assertion the credential provider received has subject {string}")]
async fn every_assertion_has_subject(
    world: &mut SurfaceWorld,
    subject: String,
) {
    let requests = token_requests(world).await;
    assert!(!requests.is_empty(), "the token endpoint received no grant");
    for request in requests {
        let claims = assertion_claims(&request["assertion"]);
        assert_eq!(claims["sub"], json!(subject), "the assertion's claims: {claims}");
    }
}

#[then("no two JWT Bearer assertions the credential provider received share a jti")]
async fn assertions_have_distinct_jti(world: &mut SurfaceWorld) {
    let requests = token_requests(world).await;
    assert!(requests.len() >= 2, "the token endpoint received {} grants", requests.len());
    let mut seen = std::collections::HashSet::new();
    for request in requests {
        let claims = assertion_claims(&request["assertion"]);
        let jti = claims["jti"]
            .as_str()
            .filter(|jti| !jti.is_empty())
            .unwrap_or_else(|| panic!("the assertion carries no jti: {claims}"))
            .to_string();
        assert!(seen.insert(jti.clone()), "the jti {jti} was used twice");
    }
}

const TOKEN_REQUEST_METRIC: &str = "agent_gateway_credential_provider_token_requests_total";

#[then(expr = "the token request metric counts {int} {string} request(s) for provider type {string}")]
async fn token_request_metric_counts(
    world: &mut SurfaceWorld,
    expected: u64,
    outcome: String,
    provider_type: String,
) {
    let exposition = crate::steps::then::scrape_prometheus(world).await;
    let counted = crate::steps::then::sum_labeled_counter(
        &exposition,
        TOKEN_REQUEST_METRIC,
        &[("provider_type", provider_type.as_str()), ("outcome", outcome.as_str())],
    );
    assert_eq!(counted, expected, "{TOKEN_REQUEST_METRIC} for {provider_type} {outcome}");
}

#[then("the token request metric counts no requests")]
async fn token_request_metric_counts_nothing(world: &mut SurfaceWorld) {
    let exposition = crate::steps::then::scrape_prometheus(world).await;
    assert_eq!(crate::steps::then::sum_labeled_counter(&exposition, TOKEN_REQUEST_METRIC, &[]), 0);
}

#[then("the token request metric is labelled only by provider type and outcome")]
async fn token_request_metric_labels_are_bounded(world: &mut SurfaceWorld) {
    let endpoint = token_endpoint(world).url();
    let exposition = crate::steps::then::scrape_prometheus(world).await;
    let samples: Vec<&str> = exposition
        .lines()
        .filter(|line| line.starts_with(TOKEN_REQUEST_METRIC))
        .collect();
    assert!(!samples.is_empty(), "the metric has no sample");
    for sample in samples {
        let labels = sample
            .split_once('{')
            .and_then(|(_, rest)| rest.split_once('}'))
            .map_or("", |(labels, _)| labels);
        for pair in labels.split(',') {
            let key = pair
                .split('=')
                .next()
                .unwrap_or_default()
                .trim();
            assert!(matches!(key, "provider_type" | "outcome"), "unexpected label in {sample}");
        }
        for leaked in
            [TARGET_AUTH_PROVIDER_ID, endpoint.as_str(), TARGET_AUTH_CLIENT_SECRET_VALUE, TARGET_AUTH_PROVIDER_TOKEN]
        {
            assert!(!labels.contains(leaked), "the labels of {sample} hold {leaked}");
        }
    }
}
