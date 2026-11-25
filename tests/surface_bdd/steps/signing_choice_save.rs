use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::steps::credential_save::{save_surface, send, stored_surface, surface_id};
use crate::steps::management_routes::{self, Caller};
use crate::world::SurfaceWorld;

const MISSING_CONNECTION: &str = "00000000-0000-0000-0000-000000000000";

fn connection_id(
    world: &SurfaceWorld,
    name: &str,
) -> String {
    world
        .trust_agent_connections
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("no trust agent connection named {name} was created"))
}

fn issuer_id(
    world: &SurfaceWorld,
    name: &str,
) -> String {
    world
        .issuers
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("no issuer named {name} was created"))
}

fn through(connection_id: &str) -> Value {
    json!({
        "backend": "vta",
        "connection_id": connection_id,
        "context_id": "ctx-signing",
        "key_id": "key-signing",
    })
}

async fn set_default_signing(
    world: &mut SurfaceWorld,
    caller: Option<Caller<'_>>,
    signing: Value,
) {
    let body = json!({ "default_signing": signing });
    let response = match caller {
        Some(caller) => management_routes::send(world, caller, Method::POST, "/v1/settings", Some(&body)).await,
        None => send(world, Method::POST, "/v1/settings", Some(&body)).await,
    };
    world.admin_response = Some(response);
}

async fn default_signing(world: &mut SurfaceWorld) -> Value {
    let response = send(world, Method::GET, "/v1/settings", None).await;
    assert_eq!(response.status, 200, "reading the settings: {}", response.body);
    response.body["default_signing"].clone()
}

#[when(expr = "the operator sets the gateway-wide signing through the trust agent connection {string}")]
async fn operator_sets_default_signing(
    world: &mut SurfaceWorld,
    connection: String,
) {
    let id = connection_id(world, &connection);
    set_default_signing(world, None, through(&id)).await;
}

#[given(expr = "the operator has set the gateway-wide signing through the trust agent connection {string}")]
async fn operator_has_set_default_signing(
    world: &mut SurfaceWorld,
    connection: String,
) {
    operator_sets_default_signing(world, connection).await;
    let response = world
        .admin_response
        .as_ref()
        .expect("the settings response");
    assert_eq!(response.status, 200, "setting the gateway-wide signing: {}", response.body);
}

#[when("the operator sets the gateway-wide signing through a trust agent connection that does not exist")]
async fn operator_sets_default_signing_through_missing_connection(world: &mut SurfaceWorld) {
    set_default_signing(world, None, through(MISSING_CONNECTION)).await;
}

#[when(
    expr = "the operator sets the gateway-wide signing through the trust agent connection {string} without naming a key"
)]
async fn operator_sets_default_signing_without_a_key(
    world: &mut SurfaceWorld,
    connection: String,
) {
    let id = connection_id(world, &connection);
    let mut signing = through(&id);
    signing
        .as_object_mut()
        .expect("a signing block")
        .remove("key_id");
    set_default_signing(world, None, signing).await;
}

#[when(expr = "the personal access token sets the gateway-wide signing through the trust agent connection {string}")]
async fn token_sets_default_signing(
    world: &mut SurfaceWorld,
    connection: String,
) {
    let id = connection_id(world, &connection);
    set_default_signing(world, Some(Caller::PersonalAccessToken), through(&id)).await;
}

#[then(expr = "the gateway-wide signing goes through the trust agent connection {string}")]
async fn default_signing_goes_through(
    world: &mut SurfaceWorld,
    connection: String,
) {
    let expected = connection_id(world, &connection);
    let signing = default_signing(world).await;
    assert_eq!(signing["backend"], "vta", "{signing}");
    assert_eq!(signing["connection_id"], expected, "{signing}");
}

#[then("the gateway has no gateway-wide signing choice")]
async fn no_default_signing(world: &mut SurfaceWorld) {
    let signing = default_signing(world).await;
    assert!(signing.is_null(), "{signing}");
}

async fn save_issuer_as(
    world: &mut SurfaceWorld,
    operator: &str,
    issuer: &str,
    body: Value,
) {
    let path = format!("/v1/issuers/{}", issuer_id(world, issuer));
    let response = management_routes::send(world, Caller::Operator(operator), Method::PUT, &path, Some(&body)).await;
    world.admin_response = Some(response);
}

#[when(expr = "operator {string} saves the issuer {string} signing through the trust agent connection {string}")]
async fn operator_saves_issuer_signing_as(
    world: &mut SurfaceWorld,
    operator: String,
    issuer: String,
    connection: String,
) {
    let id = connection_id(world, &connection);
    let body = json!({ "name": issuer, "signing": through(&id) });
    save_issuer_as(world, &operator, &issuer, body).await;
}

#[when(expr = "operator {string} deletes the issuer {string}")]
async fn operator_deletes_issuer_as(
    world: &mut SurfaceWorld,
    operator: String,
    issuer: String,
) {
    let path = format!("/v1/issuers/{}", issuer_id(world, &issuer));
    let response = management_routes::send(world, Caller::Operator(&operator), Method::DELETE, &path, None).await;
    world.admin_response = Some(response);
}

#[when(expr = "operator {string} renames the issuer {string} to {string} leaving its signing as it is")]
async fn operator_renames_issuer_as(
    world: &mut SurfaceWorld,
    operator: String,
    issuer: String,
    name: String,
) {
    let path = format!("/v1/issuers/{}", issuer_id(world, &issuer));
    let read = send(world, Method::GET, &path, None).await;
    assert_eq!(read.status, 200, "reading issuer {issuer}: {}", read.body);
    let body = json!({ "name": name, "signing": read.body["signing"] });
    save_issuer_as(world, &operator, &issuer, body).await;
}

async fn save_surface_with_token(
    world: &mut SurfaceWorld,
    surface: &Value,
) {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = management_routes::send(world, Caller::PersonalAccessToken, Method::PUT, &path, Some(surface)).await;
    world.admin_response = Some(response);
}

#[when(expr = "the personal access token saves the surface signing through the trust agent connection {string}")]
async fn token_saves_surface_signing(
    world: &mut SurfaceWorld,
    connection: String,
) {
    let id = connection_id(world, &connection);
    let mut surface = stored_surface(world).await;
    surface["signing"] = through(&id);
    save_surface_with_token(world, &surface).await;
}

#[when(expr = "the personal access token moves the surface to the issuer {string}")]
async fn token_moves_surface_to_issuer(
    world: &mut SurfaceWorld,
    issuer: String,
) {
    let id = issuer_id(world, &issuer);
    let mut surface = stored_surface(world).await;
    surface["issuer_id"] = json!(id);
    save_surface_with_token(world, &surface).await;
}

#[then("the answer is the one for an issuer that does not exist")]
async fn answered_as_for_a_missing_issuer(world: &mut SurfaceWorld) {
    let refused = world
        .admin_response
        .take()
        .expect("the save was answered");
    let mut surface = stored_surface(world).await;
    surface["issuer_id"] = json!(uuid::Uuid::new_v4().to_string());
    save_surface_with_token(world, &surface).await;
    let missing = world
        .admin_response
        .as_ref()
        .expect("the save was answered");

    assert_eq!(refused.status, missing.status, "{} / {}", refused.body, missing.body);
    assert_eq!(refused.body, missing.body);
}

#[when(expr = "the personal access token saves the surface with the description {string}")]
async fn token_saves_surface_description(
    world: &mut SurfaceWorld,
    description: String,
) {
    let mut surface = stored_surface(world).await;
    surface["description"] = json!(description);
    save_surface_with_token(world, &surface).await;
}

#[given(expr = "the operator has saved the surface signing through the trust agent connection {string}")]
async fn operator_has_saved_surface_signing(
    world: &mut SurfaceWorld,
    connection: String,
) {
    let id = connection_id(world, &connection);
    let mut surface = stored_surface(world).await;
    surface["signing"] = through(&id);
    save_surface(world, &surface).await;
    let response = world
        .admin_response
        .as_ref()
        .expect("the surface save response");
    assert_eq!(response.status, 200, "saving the surface signing: {}", response.body);
}

#[when(expr = "the operator saves the surface with a variant that signs through the trust agent connection {string}")]
async fn operator_saves_variant_signing(
    world: &mut SurfaceWorld,
    connection: String,
) {
    let id = connection_id(world, &connection);
    let mut surface = stored_surface(world).await;
    surface["variants"] = json!([{
        "id": "6f1c8a52-3b0e-4f0a-9d55-0b3f6f1a2c11",
        "alias": "beta",
        "name": "beta",
        "overrides": { "signing": through(&id) },
    }]);
    save_surface(world, &surface).await;
}

async fn reassign(
    world: &mut SurfaceWorld,
    family: &str,
    id: &str,
    tenant: &str,
) {
    let path = format!("/v1/tenant-ownership/{family}/{id}");
    let response = send(world, Method::PUT, &path, Some(&json!({ "tenant_id": tenant }))).await;
    world.admin_response = Some(response);
}

#[when(expr = "the operator reassigns the trust agent connection {string} to tenant {string}")]
async fn operator_reassigns_connection(
    world: &mut SurfaceWorld,
    connection: String,
    tenant: String,
) {
    let id = connection_id(world, &connection);
    reassign(world, "vta-connections", &id, &tenant).await;
}

#[when(expr = "the operator reassigns the issuer {string} to tenant {string}")]
async fn operator_reassigns_issuer(
    world: &mut SurfaceWorld,
    issuer: String,
    tenant: String,
) {
    let id = issuer_id(world, &issuer);
    reassign(world, "issuers", &id, &tenant).await;
}
