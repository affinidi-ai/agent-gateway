use cucumber::{given, when};
use serde_json::{Value, json};

use crate::bdd_support::actors::TargetActorKind;
use crate::steps::given::install_replacement_mock;
use crate::steps::when::{build_primary_target_surface_payload, configure_unseeded_route, create_surface};
use crate::world::SurfaceWorld;

fn mirror_to(endpoint: &str) -> Value {
    json!({ "endpoint": endpoint, "percentage": 100, "wait_for_response": true })
}

async fn create_mirrored_surface(
    world: &mut SurfaceWorld,
    route: &str,
    endpoint: &str,
) {
    configure_unseeded_route(world, route);
    let mut payload = build_primary_target_surface_payload(world, route).await;
    payload["target"]["networking"] = json!({ "mirror": mirror_to(endpoint) });
    create_surface(world, payload).await;
}

#[given(expr = "managed agent {string} is available as the traffic mirror")]
async fn managed_agent_available_as_traffic_mirror(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .register_secondary_managed_agent(&agent_name);
    world.register_secondary_collaborator(&agent_name, TargetActorKind::ManagedAgent);
    install_replacement_mock(world, json!({ "jsonrpc": "2.0", "id": 1, "result": "mirrored" })).await;
}

#[when(expr = "the operator attempts to create a surface for route {string} that mirrors traffic to {string}")]
async fn surface_mirroring_to_endpoint_create_request_submitted(
    world: &mut SurfaceWorld,
    route: String,
    endpoint: String,
) {
    create_mirrored_surface(world, &route, &endpoint).await;
}

#[given(expr = "a surface for route {string} mirrors every request to managed agent {string}")]
async fn surface_mirroring_to_managed_agent_exists(
    world: &mut SurfaceWorld,
    route: String,
    agent_name: String,
) {
    let endpoint = world
        .mock_for_target(&agent_name)
        .url();
    create_mirrored_surface(world, &route, &endpoint).await;
    let response = world
        .admin_response
        .as_ref()
        .expect("admin_response must be set after surface setup");
    assert_eq!(
        response.status, 201,
        "surface setup should create the surface, got status {} body {}",
        response.status, response.body
    );
}

#[when(
    expr = "the operator attempts to create a surface for route {string} with variant {string} that mirrors traffic to {string}"
)]
async fn surface_with_mirroring_variant_create_request_submitted(
    world: &mut SurfaceWorld,
    route: String,
    alias: String,
    endpoint: String,
) {
    configure_unseeded_route(world, &route);
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["variants"] = json!([{
        "id": format!("variant-{alias}"),
        "alias": alias,
        "name": alias,
        "enabled": true,
        "overrides": { "target": { "networking": { "mirror": mirror_to(&endpoint) } } }
    }]);
    create_surface(world, payload).await;
}
