use cucumber::{given, when};
use reqwest::Method;
use serde_json::json;

use crate::steps::credential_save::{save_surface, send, stored_surface};
use crate::world::SurfaceWorld;

async fn create_connection(
    world: &mut SurfaceWorld,
    name: &str,
    tenant: Option<&str>,
) {
    let body = json!({
        "name": name,
        "tenant_id": tenant,
        "endpoint": "https://trust-agent.example.test",
        "vta_did": "did:key:z6MkvnxZrB5vsAFb8AGaDVAqSYYNoz5y2Rgvhccn7xSvx3Aj",
        "default_context_id": "gateway",
        "control_identity": "did_key",
    });
    let response = send(world, Method::POST, "/v1/vta/connections", Some(&body)).await;
    assert_eq!(response.status, 201, "creating trust agent connection {name}: {}", response.body);
    let id = response.body["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the new connection has an id: {}", response.body))
        .to_string();
    world
        .trust_agent_connections
        .insert(name.to_string(), id);
}

#[given(expr = "the appliance holds the trust agent connection {string}")]
async fn appliance_holds_trust_agent_connection(
    world: &mut SurfaceWorld,
    name: String,
) {
    create_connection(world, &name, None).await;
}

#[given(expr = "tenant {string} holds the trust agent connection {string}")]
async fn tenant_holds_trust_agent_connection(
    world: &mut SurfaceWorld,
    tenant: String,
    name: String,
) {
    create_connection(world, &name, Some(&tenant)).await;
}

#[when(expr = "the operator saves the surface signing through the trust agent connection {string}")]
async fn operator_saves_surface_signing_through_connection(
    world: &mut SurfaceWorld,
    name: String,
) {
    let connection_id = world
        .trust_agent_connections
        .get(&name)
        .cloned()
        .unwrap_or_else(|| panic!("no trust agent connection named {name} was created"));
    save_signing_through(world, &connection_id).await;
}

#[when(
    expr = "the operator saves the surface signing through the trust agent connection {string} without naming a key"
)]
async fn operator_saves_surface_signing_without_a_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let connection_id = world
        .trust_agent_connections
        .get(&name)
        .cloned()
        .unwrap_or_else(|| panic!("no trust agent connection named {name} was created"));
    let mut surface = stored_surface(world).await;
    surface["signing"] = json!({
        "backend": "vta",
        "connection_id": connection_id,
        "context_id": "ctx-orders",
    });
    save_surface(world, &surface).await;
}

#[when("the operator saves the surface signing through a trust agent connection that does not exist")]
async fn operator_saves_surface_signing_through_missing_connection(world: &mut SurfaceWorld) {
    save_signing_through(world, "00000000-0000-0000-0000-000000000000").await;
}

async fn save_signing_through(
    world: &mut SurfaceWorld,
    connection_id: &str,
) {
    let mut surface = stored_surface(world).await;
    surface["signing"] = json!({
        "backend": "vta",
        "connection_id": connection_id,
        "context_id": "ctx-orders",
        "key_id": "key-orders",
    });
    save_surface(world, &surface).await;
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

#[given(expr = "the surface signs through the trust agent connection {string}")]
async fn surface_signs_through_connection(
    world: &mut SurfaceWorld,
    name: String,
) {
    let connection_id = connection_id(world, &name);
    save_signing_through(world, &connection_id).await;
    let saved = world
        .admin_response
        .take()
        .expect("the gateway must have answered the surface save");
    assert_eq!(saved.status, 200, "saving the surface signing through {name}: {}", saved.body);
}

#[when(expr = "the operator revokes the trust agent connection {string}")]
async fn operator_revokes_connection(
    world: &mut SurfaceWorld,
    name: String,
) {
    let path = format!("/v1/vta/connections/{}/revoke", connection_id(world, &name));
    world.admin_response = Some(send(world, Method::POST, &path, None).await);
}

#[when(expr = "the operator revokes the trust agent connection {string} acknowledging what stops signing")]
async fn operator_revokes_connection_acknowledged(
    world: &mut SurfaceWorld,
    name: String,
) {
    let path = format!(
        "/v1/vta/connections/{}/revoke?acknowledge_signing_users=true&acknowledge_stranded_agents=true",
        connection_id(world, &name)
    );
    world.admin_response = Some(send(world, Method::POST, &path, None).await);
}

#[when(expr = "the operator adds a trust agent connection at {string}")]
async fn operator_adds_connection_at(
    world: &mut SurfaceWorld,
    endpoint: String,
) {
    let body = json!({
        "name": "Trust agent",
        "endpoint": endpoint,
        "vta_did": "did:key:z6MkvnxZrB5vsAFb8AGaDVAqSYYNoz5y2Rgvhccn7xSvx3Aj",
        "default_context_id": "gateway",
        "control_identity": "did_key",
    });
    world.admin_response = Some(send(world, Method::POST, "/v1/vta/connections", Some(&body)).await);
}

#[when(expr = "the operator verifies the trust agent connection {string}")]
async fn operator_verifies_connection(
    world: &mut SurfaceWorld,
    name: String,
) {
    let path = format!("/v1/vta/connections/{}/verify", connection_id(world, &name));
    world.admin_response = Some(send(world, Method::POST, &path, None).await);
}

#[given(expr = "the operator has revoked the trust agent connection {string}")]
async fn operator_has_revoked_connection(
    world: &mut SurfaceWorld,
    name: String,
) {
    operator_revokes_connection(world, name.clone()).await;
    let revoked = world
        .admin_response
        .take()
        .expect("the gateway answered the revoke");
    assert_eq!(revoked.status, 200, "revoking {name}: {}", revoked.body);
}

#[when(expr = "the operator deletes the trust agent connection {string}")]
async fn operator_deletes_connection(
    world: &mut SurfaceWorld,
    name: String,
) {
    let path = format!("/v1/vta/connections/{}", connection_id(world, &name));
    world.admin_response = Some(send(world, Method::DELETE, &path, None).await);
}

#[when(expr = "the operator adds a trust agent connection for tenant {string} at {string}")]
async fn operator_adds_tenant_connection_at(
    world: &mut SurfaceWorld,
    tenant: String,
    endpoint: String,
) {
    let body = json!({
        "name": "Tenant trust agent",
        "tenant_id": tenant,
        "endpoint": endpoint,
        "vta_did": "did:key:z6MkvnxZrB5vsAFb8AGaDVAqSYYNoz5y2Rgvhccn7xSvx3Aj",
        "default_context_id": "gateway",
        "control_identity": "did_key",
    });
    world.admin_response = Some(send(world, Method::POST, "/v1/vta/connections", Some(&body)).await);
}
