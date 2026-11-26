use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::steps::credential_save::{save_surface, send, stored_surface};
use crate::world::SurfaceWorld;

async fn create_issuer(
    world: &mut SurfaceWorld,
    name: &str,
    tenant: Option<&str>,
) {
    request_issuer(world, name, tenant).await;
    let response = world
        .admin_response
        .as_ref()
        .expect("the create response");
    assert_eq!(response.status, 201, "creating issuer {name}: {}", response.body);
}

async fn request_issuer(
    world: &mut SurfaceWorld,
    name: &str,
    tenant: Option<&str>,
) {
    let body = json!({
        "name": name,
        "description": format!("{name} team"),
        "tenant_id": tenant,
    });
    let response = send(world, Method::POST, "/v1/issuers", Some(&body)).await;
    if let Some(id) = response.body["id"].as_str() {
        world
            .issuers
            .insert(name.to_string(), id.to_string());
    }
    world.admin_response = Some(response);
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

async fn save_issuer_signing(
    world: &mut SurfaceWorld,
    issuer: &str,
    signing: Value,
) {
    let id = issuer_id(world, issuer);
    let body = json!({ "name": issuer, "description": format!("{issuer} team"), "signing": signing });
    let response = send(world, Method::PUT, &format!("/v1/issuers/{id}"), Some(&body)).await;
    world.admin_response = Some(response);
}

fn through_connection(connection_id: &str) -> Value {
    json!({
        "backend": "vta",
        "connection_id": connection_id,
        "context_id": "ctx-issuer",
        "key_id": "key-issuer",
    })
}

async fn read_issuer(
    world: &mut SurfaceWorld,
    issuer: &str,
) -> Value {
    let id = issuer_id(world, issuer);
    let response = send(world, Method::GET, &format!("/v1/issuers/{id}"), None).await;
    assert_eq!(response.status, 200, "reading issuer {issuer}: {}", response.body);
    response.body
}

#[given(expr = "the operator has created the issuer {string}")]
async fn operator_created_issuer(
    world: &mut SurfaceWorld,
    name: String,
) {
    create_issuer(world, &name, None).await;
}

#[when(expr = "the operator creates the issuer {string}")]
async fn operator_creates_issuer(
    world: &mut SurfaceWorld,
    name: String,
) {
    request_issuer(world, &name, None).await;
}

#[given(expr = "the operator has created the issuer {string} owned by tenant {string}")]
async fn operator_created_tenant_issuer(
    world: &mut SurfaceWorld,
    name: String,
    tenant: String,
) {
    create_issuer(world, &name, Some(&tenant)).await;
}

#[given(expr = "the operator has saved the issuer {string} signing through the trust agent connection {string}")]
async fn operator_has_saved_issuer_signing(
    world: &mut SurfaceWorld,
    issuer: String,
    connection: String,
) {
    let id = connection_id(world, &connection);
    save_issuer_signing(world, &issuer, through_connection(&id)).await;
    let status = world
        .admin_response
        .as_ref()
        .map(|r| r.status);
    assert_eq!(status, Some(200), "{:?}", world.admin_response);
}

#[when(expr = "the operator saves the issuer {string} signing through the trust agent connection {string}")]
async fn operator_saves_issuer_signing(
    world: &mut SurfaceWorld,
    issuer: String,
    connection: String,
) {
    let id = connection_id(world, &connection);
    save_issuer_signing(world, &issuer, through_connection(&id)).await;
}

#[when(
    expr = "the operator saves the issuer {string} signing through the trust agent connection {string} without naming a key"
)]
async fn operator_saves_issuer_signing_without_a_key(
    world: &mut SurfaceWorld,
    issuer: String,
    connection: String,
) {
    let id = connection_id(world, &connection);
    let mut signing = through_connection(&id);
    signing
        .as_object_mut()
        .expect("a signing block")
        .remove("key_id");
    save_issuer_signing(world, &issuer, signing).await;
}

#[when(expr = "the operator clears the signing of the issuer {string}")]
async fn operator_clears_issuer_signing(
    world: &mut SurfaceWorld,
    issuer: String,
) {
    save_issuer_signing(world, &issuer, json!({})).await;
}

#[then(expr = "the issuer {string} signs through the trust agent connection {string}")]
async fn issuer_signs_through_connection(
    world: &mut SurfaceWorld,
    issuer: String,
    connection: String,
) {
    let expected = connection_id(world, &connection);
    let read = read_issuer(world, &issuer).await;
    assert_eq!(read["signing"]["backend"], "vta", "{read}");
    assert_eq!(read["signing"]["connection_id"], expected, "{read}");
}

#[then(expr = "the issuer {string} follows the appliance default")]
async fn issuer_follows_appliance_default(
    world: &mut SurfaceWorld,
    issuer: String,
) {
    let read = read_issuer(world, &issuer).await;
    assert!(
        read.get("signing")
            .is_none_or(Value::is_null),
        "{read}"
    );
}

#[given(expr = "the operator has made the surface owned by the issuer {string}")]
async fn operator_made_surface_owned_by_issuer(
    world: &mut SurfaceWorld,
    issuer: String,
) {
    let id = issuer_id(world, &issuer);
    let mut surface = stored_surface(world).await;
    surface["issuer_id"] = json!(id);
    save_surface(world, &surface).await;
    let status = world
        .admin_response
        .as_ref()
        .map(|r| r.status);
    assert_eq!(status, Some(200), "{:?}", world.admin_response);
}

#[given("the operator has saved the surface signing as the gateway's own key")]
async fn operator_saved_surface_signing_local(world: &mut SurfaceWorld) {
    let mut surface = stored_surface(world).await;
    surface["signing"] = json!({ "backend": "local" });
    save_surface(world, &surface).await;
    let status = world
        .admin_response
        .as_ref()
        .map(|r| r.status);
    assert_eq!(status, Some(200), "{:?}", world.admin_response);
}

#[when("the operator reads the key inventory")]
async fn operator_reads_key_inventory(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/key-management/inventory", None).await;
    assert_eq!(response.status, 200, "reading the key inventory: {}", response.body);
    world.admin_response = Some(response);
}

async fn surface_mapping(world: &mut SurfaceWorld) -> Value {
    let surface = stored_surface(world).await;
    let surface_id = surface["surface_id"]
        .as_str()
        .expect("the stored surface has an id")
        .to_string();
    let inventory = world
        .admin_response
        .as_ref()
        .expect("the key inventory was read")
        .body
        .clone();
    inventory["mappings"]
        .as_array()
        .expect("the inventory lists mappings")
        .iter()
        .find(|mapping| mapping["surface_id"] == surface_id && mapping["variant_id"].is_null())
        .cloned()
        .unwrap_or_else(|| panic!("no mapping for the surface in {inventory}"))
}

#[then(
    expr = "the key inventory shows the surface signing through the trust agent connection {string} on behalf of the issuer {string}"
)]
async fn inventory_shows_surface_following_issuer(
    world: &mut SurfaceWorld,
    connection: String,
    issuer: String,
) {
    let expected = connection_id(world, &connection);
    let mapping = surface_mapping(world).await;
    assert_eq!(mapping["backend"], "vta", "{mapping}");
    assert_eq!(mapping["connection_id"], expected, "{mapping}");
    assert_eq!(mapping["via_issuer"], issuer, "{mapping}");
}

#[then("the key inventory shows the surface signing with the gateway's own key and not following an issuer")]
async fn inventory_shows_surface_with_own_key(world: &mut SurfaceWorld) {
    let mapping = surface_mapping(world).await;
    assert_eq!(mapping["backend"], "local", "{mapping}");
    assert!(
        mapping
            .get("via_issuer")
            .is_none_or(Value::is_null),
        "{mapping}"
    );
}
