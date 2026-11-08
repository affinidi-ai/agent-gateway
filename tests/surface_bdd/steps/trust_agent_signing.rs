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
    });
    save_surface(world, &surface).await;
}
