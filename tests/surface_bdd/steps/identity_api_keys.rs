use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::steps::credential_save::{save_surface, send, stored_surface, surface_id};
use crate::steps::when::build_primary_target_surface_payload;
use crate::world::SurfaceWorld;

fn from_api_key(key_id: &str) -> Value {
    json!({"type": "from_api_key", "api_key_id": key_id})
}

fn api_key(
    world: &SurfaceWorld,
    name: &str,
) -> (String, String) {
    world
        .api_keys
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("API key {name:?} must be created first"))
}

async fn create_api_key(
    world: &mut SurfaceWorld,
    owner: &str,
    name: &str,
) {
    let path = format!("/v1/api-keys/{owner}");
    let response = send(world, Method::POST, &path, Some(&json!({"client_id": name}))).await;
    assert_eq!(response.status, 201, "creating API key {name:?}: {}", response.body);
    let key_id = response.body["key_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the created API key has an id: {}", response.body))
        .to_string();
    world
        .api_keys
        .insert(name.to_string(), (owner.to_string(), key_id));
}

async fn surface_naming_in_protected_identity(
    world: &mut SurfaceWorld,
    name: &str,
) -> Value {
    let (_, key_id) = api_key(world, name);
    let mut surface = stored_surface(world).await;
    surface["identity_slots"]["protected"] = from_api_key(&key_id);
    surface
}

#[given(expr = "the surface has an API key {string}")]
async fn surface_has_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let owner = surface_id(world);
    world.surface_under_test_id = Some(owner.clone());
    create_api_key(world, &owner, &name).await;
}

#[given(expr = "the surface for route {string} has an API key {string}")]
async fn other_surface_has_api_key(
    world: &mut SurfaceWorld,
    route: String,
    name: String,
) {
    create_surface_with_api_key(world, &route, None, &name).await;
}

#[given(expr = "the surface for route {string} of tenant {string} has an API key {string}")]
async fn other_tenants_surface_has_api_key(
    world: &mut SurfaceWorld,
    route: String,
    tenant: String,
    name: String,
) {
    create_surface_with_api_key(world, &route, Some(&tenant), &name).await;
}

async fn create_surface_with_api_key(
    world: &mut SurfaceWorld,
    route: &str,
    tenant: Option<&str>,
    name: &str,
) {
    let mut payload = build_primary_target_surface_payload(world, route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    payload["tenant_id"] = json!(tenant);
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    assert_eq!(response.status, 201, "creating surface {route}: {}", response.body);
    let owner = response.body["surface_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the created surface has an id: {}", response.body))
        .to_string();
    create_api_key(world, &owner, name).await;
}

#[given(expr = "the surface's protected Identity takes its DID from API key {string}")]
async fn protected_identity_takes_did_from_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let surface = surface_naming_in_protected_identity(world, &name).await;
    save_surface(world, &surface).await;
    let response = world
        .admin_response
        .take()
        .expect("the save has a response");
    assert_eq!(response.status, 200, "naming API key {name:?} in the protected Identity: {}", response.body);
}

#[given(expr = "the operator has revoked API key {string}")]
async fn operator_has_revoked_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}/revoke");
    let response = send(world, Method::POST, &path, Some(&json!({}))).await;
    assert_eq!(response.status, 204, "revoking API key {name:?}: {}", response.body);
}

#[given(expr = "the operator has deleted API key {string}")]
async fn operator_has_deleted_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}");
    let response = send(world, Method::DELETE, &path, None).await;
    assert_eq!(response.status, 204, "deleting API key {name:?}: {}", response.body);
}

#[when(expr = "the operator saves the surface with its protected Identity taking its DID from API key {string}")]
async fn operator_saves_protected_identity_from_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let surface = surface_naming_in_protected_identity(world, &name).await;
    save_surface(world, &surface).await;
}

#[when("the operator deletes the surface")]
async fn operator_deletes_surface(world: &mut SurfaceWorld) {
    crate::steps::when::delete_surface(world).await;
}

#[when("the operator creates a surface with the deleted surface's id")]
async fn operator_creates_surface_with_deleted_id(world: &mut SurfaceWorld) {
    let deleted = surface_id(world);
    let mut payload = build_primary_target_surface_payload(world, "/reused").await;
    payload["surface_id"] = json!(deleted);
    payload["name"] = json!("reused");
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    world.admin_response = Some(response);
}

#[then(expr = "the surface reports API key {string} as {string}")]
fn surface_reports_api_key_status(
    world: &mut SurfaceWorld,
    name: String,
    status: String,
) {
    let (_, key_id) = api_key(world, &name);
    let surface = &world
        .surface_lookup_response
        .as_ref()
        .expect("the surface was read")
        .body;
    let expected = json!({"key_id": key_id, "status": status});
    let references = surface["api_key_references"]
        .as_array()
        .unwrap_or_else(|| panic!("the surface reports no api_key_references: {surface}"));
    assert!(references.contains(&expected), "expected API key {name:?} reported as {status:?}, got {references:?}");
}

#[then(expr = "the admin API error response does not mention {string}")]
fn admin_api_error_response_does_not_mention(
    world: &mut SurfaceWorld,
    unexpected: String,
) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("the admin API answered")
        .body;
    assert!(
        !body
            .to_string()
            .contains(&unexpected),
        "the error response mentions {unexpected:?}: {body}"
    );
}

#[then(expr = "the stored surface's protected Identity takes its DID from API key {string}")]
async fn stored_protected_identity_takes_did_from_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (_, key_id) = api_key(world, &name);
    let surface = stored_surface(world).await;
    assert_eq!(surface["identity_slots"]["protected"], from_api_key(&key_id), "{surface}");
}

#[then(expr = "the operator reads API key {string} as revoked, with its surface deleted")]
async fn operator_reads_api_key_revoked_with_surface_deleted(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}");
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 200, "reading API key {name:?}: {}", response.body);
    assert_eq!(response.body["status"], "revoked", "{}", response.body);
    assert_eq!(response.body["surface_deleted"], true, "{}", response.body);
}

#[then("no surface with the deleted surface's id is stored")]
async fn no_surface_with_deleted_id_is_stored(world: &mut SurfaceWorld) {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 404, "reading the deleted surface's id: {}", response.body);
}
