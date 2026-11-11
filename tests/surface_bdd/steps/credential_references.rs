use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{RecordedResponse, recorded_response};
use crate::steps::credential_save::{create_provider, send, surface_id};
use crate::steps::when::build_primary_target_surface_payload;
use crate::world::SurfaceWorld;

async fn stored_secrets(world: &mut SurfaceWorld) -> Vec<Value> {
    let response = send(world, Method::GET, "/v1/secrets", None).await;
    assert_eq!(response.status, 200, "listing secrets: {}", response.body);
    response
        .body
        .as_array()
        .expect("the secret list is an array")
        .clone()
}

async fn secret_record_id(
    world: &mut SurfaceWorld,
    secret_id: &str,
) -> String {
    stored_secrets(world)
        .await
        .iter()
        .find(|secret| secret["secret_id"] == secret_id)
        .and_then(|secret| secret["id"].as_str())
        .unwrap_or_else(|| panic!("no secret {secret_id} is stored"))
        .to_string()
}

pub(crate) async fn provider_record_id(
    world: &mut SurfaceWorld,
    provider_id: &str,
) -> String {
    let response = send(world, Method::GET, "/v1/credential-providers", None).await;
    assert_eq!(response.status, 200, "listing credential providers: {}", response.body);
    response
        .body
        .as_array()
        .expect("the provider list is an array")
        .iter()
        .find(|provider| provider["provider_id"] == provider_id)
        .and_then(|provider| provider["id"].as_str())
        .unwrap_or_else(|| panic!("no credential provider {provider_id} is stored"))
        .to_string()
}

fn refusal(world: &SurfaceWorld) -> &Value {
    &world
        .admin_response
        .as_ref()
        .expect("the operator must have been answered")
        .body
}

pub(crate) fn references(world: &SurfaceWorld) -> Vec<(String, String)> {
    refusal(world)["references"]
        .as_array()
        .unwrap_or_else(|| panic!("the refusal lists no references: {}", refusal(world)))
        .iter()
        .map(|reference| {
            (
                reference["kind"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                reference["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

#[given(expr = "the operator has created the credential provider {string} using secrets {string} and {string}")]
async fn operator_has_created_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    create_provider(world, &provider_id, "https://192.0.2.1/token", None, (&client_id_secret, &client_secret_secret))
        .await;
    let response = world
        .admin_response
        .take()
        .expect("the provider create was answered");
    assert_eq!(response.status, 201, "creating credential provider {provider_id}: {}", response.body);
}

#[given(
    expr = "the operator has created the surface for route {string} authenticating its target with credential provider {string} and its callers with secret {string}"
)]
async fn operator_has_created_provider_surface(
    world: &mut SurfaceWorld,
    route: String,
    provider_id: String,
    caller_secret: String,
) {
    let provider = provider_record_id(world, &provider_id).await;
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    payload["target"]["endpoint"] = json!("https://127.0.0.1:9/");
    payload["target"]["auth"] = json!({"method": {"credential_provider": {"provider_id": provider}}});
    payload["access_point"]["caller_authentication"] = json!({"methods": [{
        "type": "api_key", "secret_id": caller_secret,
        "extraction": {"source": "http_header", "field": "X-Caller-Key"}
    }]});
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    assert_eq!(response.status, 201, "creating surface {route}: {}", response.body);
    world.surface_under_test_id = response.body["surface_id"]
        .as_str()
        .map(str::to_string);
}

#[when(expr = "the operator deletes the secret {string}")]
async fn operator_deletes_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let id = secret_record_id(world, &secret_id).await;
    let response = send(world, Method::DELETE, &format!("/v1/secrets/{id}"), None).await;
    world.admin_response = Some(response);
}

#[when(expr = "the operator deletes the secret {string} with force")]
async fn operator_force_deletes_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let id = secret_record_id(world, &secret_id).await;
    let response = send(world, Method::DELETE, &format!("/v1/secrets/{id}?force=true"), None).await;
    world.admin_response = Some(response);
}

#[when(
    expr = "an access token that may view secrets and surfaces but not credential providers deletes the secret {string}"
)]
async fn restricted_token_deletes_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let id = secret_record_id(world, &secret_id).await;
    let scopes = ["secrets.view", "secrets.delete", "surfaces.view"];
    world.admin_response = Some(delete_with_scoped_token(world, &scopes, &format!("/api/v1/secrets/{id}")).await);
}

/// Deletes `path` (under `/api`) with a new access token holding only `scopes`.
pub(crate) async fn delete_with_scoped_token(
    world: &mut SurfaceWorld,
    scopes: &[&str],
    path: &str,
) -> RecordedResponse {
    let request = json!({"name": "scoped cleanup token", "scopes": scopes});
    let created = send(world, Method::POST, "/v1/access-tokens", Some(&request)).await;
    assert!(matches!(created.status, 200 | 201), "creating the access token: {}", created.body);
    let token = created.body["token"]
        .as_str()
        .expect("the access token is returned once")
        .to_string();
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .gateway_port;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("an HTTP client")
        .delete(format!("http://127.0.0.1:{port}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("deleting with the access token");
    recorded_response(response)
        .await
        .expect("reading the delete answer")
}

#[when(expr = "the operator deletes the credential provider {string}")]
async fn operator_deletes_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let id = provider_record_id(world, &provider_id).await;
    let response = send(world, Method::DELETE, &format!("/v1/credential-providers/{id}"), None).await;
    world.admin_response = Some(response);
}

#[when(expr = "the operator changes the type of credential provider {string} to {string}")]
async fn operator_retypes_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    provider_type: String,
) {
    let id = provider_record_id(world, &provider_id).await;
    let body = json!({"provider_type": provider_type});
    let response = send(world, Method::PUT, &format!("/v1/credential-providers/{id}"), Some(&body)).await;
    world.admin_response = Some(response);
}

#[then("the refusal names the surface under test as a record that uses it")]
fn refusal_names_surface(world: &mut SurfaceWorld) {
    let expected = ("surface".to_string(), surface_id(world));
    let listed = references(world);
    assert!(listed.contains(&expected), "expected {expected:?} among {listed:?}");
}

#[then(expr = "the refusal names credential provider {string} as a record that uses it")]
async fn refusal_names_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let expected = ("credential_provider".to_string(), provider_record_id(world, &provider_id).await);
    let listed = references(world);
    assert!(listed.contains(&expected), "expected {expected:?} among {listed:?}");
}

#[then(expr = "the refusal names {int} referencing record(s)")]
fn refusal_names_records(
    world: &mut SurfaceWorld,
    expected: usize,
) {
    let listed = references(world);
    assert_eq!(listed.len(), expected, "the refusal names {listed:?}");
}

#[then(expr = "the refusal hides {int} referencing record(s)")]
fn refusal_counts_hidden_records(
    world: &mut SurfaceWorld,
    expected: u64,
) {
    assert_eq!(refusal(world)["hidden_references"], json!(expected), "{}", refusal(world));
}

#[then(expr = "the secret {string} is stored")]
async fn secret_is_stored(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let secrets = stored_secrets(world).await;
    assert!(
        secrets
            .iter()
            .any(|secret| secret["secret_id"] == secret_id),
        "secret {secret_id} is not stored"
    );
}

#[then(expr = "no secret {string} is stored")]
async fn secret_is_not_stored(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let secrets = stored_secrets(world).await;
    assert!(
        !secrets
            .iter()
            .any(|secret| secret["secret_id"] == secret_id),
        "secret {secret_id} is still stored"
    );
}
