use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::RecordedResponse;
use crate::steps::when::{build_primary_target_surface_payload, ensure_admin_session};
use crate::world::SurfaceWorld;

async fn send(
    world: &mut SurfaceWorld,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    ensure_admin_session(world).await;
    world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(method, path, body)
        .await
        .unwrap_or_else(|error| panic!("{path} through admin API: {error}"))
}

async fn create_secret(
    world: &mut SurfaceWorld,
    secret_id: &str,
    tenant: Option<&str>,
) {
    let body = json!({"name": secret_id, "secret_id": secret_id, "value": "bdd-secret-value", "tenant_id": tenant});
    let response = send(world, Method::POST, "/v1/secrets/new", Some(&body)).await;
    assert_eq!(response.status, 201, "creating a secret for tenant {tenant:?}: {}", response.body);
}

async fn create_provider(
    world: &mut SurfaceWorld,
    provider_id: &str,
    token_endpoint: &str,
    tenant: Option<&str>,
    client_secrets: (&str, &str),
) {
    let body = json!({
        "name": provider_id, "provider_id": provider_id, "provider_type": "oauth2_client_credentials",
        "token_endpoint": token_endpoint,
        "client_id_secret_ref": client_secrets.0, "client_secret_secret_ref": client_secrets.1,
        "tenant_id": tenant
    });
    let response = send(world, Method::POST, "/v1/credential-providers", Some(&body)).await;
    world.admin_response = Some(response);
}

fn static_secret(secret_id: &str) -> Value {
    json!({"method": {"static_secret": {"secret_id": secret_id, "header_name": "Authorization"}}})
}

async fn create_surface_with_secret(
    world: &mut SurfaceWorld,
    route: &str,
    tenant: Option<&str>,
    secret_id: &str,
) {
    let mut payload = build_primary_target_surface_payload(world, route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    payload["tenant_id"] = json!(tenant);
    payload["target"]["auth"] = static_secret(secret_id);
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    assert_eq!(response.status, 201, "creating surface {route}: {}", response.body);
    world.surface_under_test_id = response.body["surface_id"]
        .as_str()
        .map(str::to_string);
    assert!(
        world
            .surface_under_test_id
            .is_some(),
        "the created surface has an id: {}",
        response.body
    );
}

const SEEDED_SURFACE_ID: &str = "bdd-surface";

fn surface_id(world: &SurfaceWorld) -> String {
    world
        .surface_under_test_id
        .clone()
        .or_else(|| {
            world
                .surface_config
                .seed_surface
                .then(|| SEEDED_SURFACE_ID.to_string())
        })
        .expect("the surface under test must exist")
}

async fn stored_surface(world: &mut SurfaceWorld) -> Value {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 200, "reading the stored surface: {}", response.body);
    response.body
}

async fn save_surface(
    world: &mut SurfaceWorld,
    surface: &Value,
) {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = send(world, Method::PUT, &path, Some(surface)).await;
    world.admin_response = Some(response);
}

async fn provider_ids(world: &mut SurfaceWorld) -> Vec<String> {
    let response = send(world, Method::GET, "/v1/credential-providers", None).await;
    assert_eq!(response.status, 200, "listing credential providers: {}", response.body);
    response
        .body
        .as_array()
        .expect("the provider list is an array")
        .iter()
        .filter_map(|provider| {
            provider["provider_id"]
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

#[given(expr = "the appliance holds the secret {string}")]
async fn appliance_holds_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    create_secret(world, &secret_id, None).await;
}

#[given(expr = "tenant {string} holds the secret {string}")]
async fn tenant_holds_secret(
    world: &mut SurfaceWorld,
    tenant: String,
    secret_id: String,
) {
    create_secret(world, &secret_id, Some(&tenant)).await;
}

#[given(
    expr = "the operator has created the surface for route {string} owned by tenant {string} authenticating its target with secret {string}"
)]
async fn operator_created_tenant_surface(
    world: &mut SurfaceWorld,
    route: String,
    tenant: String,
    secret_id: String,
) {
    create_surface_with_secret(world, &route, Some(&tenant), &secret_id).await;
}

#[given(
    expr = "the operator has created the appliance-wide surface for route {string} authenticating its target with secret {string}"
)]
async fn operator_created_appliance_surface(
    world: &mut SurfaceWorld,
    route: String,
    secret_id: String,
) {
    create_surface_with_secret(world, &route, None, &secret_id).await;
}

#[when(
    expr = "the operator creates the credential provider {string} with token endpoint {string} using secrets {string} and {string}"
)]
async fn operator_creates_appliance_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    token_endpoint: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    create_provider(world, &provider_id, &token_endpoint, None, (&client_id_secret, &client_secret_secret)).await;
}

#[when(
    expr = "the operator creates the credential provider {string} for tenant {string} using secrets {string} and {string}"
)]
async fn operator_creates_tenant_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    tenant: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    create_provider(
        world,
        &provider_id,
        "https://192.0.2.1/token",
        Some(&tenant),
        (&client_id_secret, &client_secret_secret),
    )
    .await;
}

#[when(expr = "the operator saves the surface authenticating its target with secret {string}")]
async fn operator_saves_surface_with_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let mut surface = stored_surface(world).await;
    surface["target"]["auth"] = static_secret(&secret_id);
    save_surface(world, &surface).await;
}

#[when(expr = "the operator saves the surface with the description {string}")]
async fn operator_saves_surface_with_description(
    world: &mut SurfaceWorld,
    description: String,
) {
    let mut surface = stored_surface(world).await;
    surface["description"] = json!(description);
    save_surface(world, &surface).await;
}

#[when(expr = "the operator reassigns the surface to tenant {string}")]
async fn operator_reassigns_surface(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let path = format!("/v1/tenant-ownership/surfaces/{}", surface_id(world));
    let response = send(world, Method::PUT, &path, Some(&json!({"tenant_id": tenant}))).await;
    world.admin_response = Some(response);
}

#[then(expr = "the credential provider {string} is stored")]
async fn credential_provider_is_stored(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let ids = provider_ids(world).await;
    assert!(ids.contains(&provider_id), "provider {provider_id} is not among {ids:?}");
}

#[then(expr = "no credential provider {string} is stored")]
async fn no_credential_provider_is_stored(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let ids = provider_ids(world).await;
    assert!(!ids.contains(&provider_id), "provider {provider_id} is stored among {ids:?}");
}

#[then(expr = "the stored surface authenticates its target with secret {string}")]
async fn stored_surface_authenticates_with_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["target"]["auth"]["method"]["static_secret"]["secret_id"], secret_id, "{surface}");
}

#[then(expr = "the stored surface belongs to tenant {string}")]
async fn stored_surface_belongs_to_tenant(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["tenant_id"], tenant, "{surface}");
}

#[then("the stored surface belongs to no tenant")]
async fn stored_surface_belongs_to_no_tenant(world: &mut SurfaceWorld) {
    let surface = stored_surface(world).await;
    assert!(surface["tenant_id"].is_null(), "{surface}");
}

#[then(expr = "the stored surface has the description {string}")]
async fn stored_surface_has_description(
    world: &mut SurfaceWorld,
    description: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["description"], description, "{surface}");
}
