use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::mock_server::MockResponse;
use crate::steps::given::install_replacement_mock;
use crate::steps::when::{
    build_primary_target_surface_payload, configure_unseeded_route, create_surface, ensure_admin_session,
    get_current_admin_surface_body, get_tracked_surface_id, record_admin_response, update_created_surface,
};
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

#[given(expr = "a mirror endpoint {string} is available")]
async fn mirror_endpoint_available(
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

#[given(expr = "a surface for route {string} mirrors every request to the mirror endpoint {string}")]
async fn surface_mirroring_to_mirror_endpoint_exists(
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

#[given(expr = "the mirror endpoint {string} answers every request with a redirect to managed agent {string}")]
async fn mirror_endpoint_answers_with_redirect(
    world: &mut SurfaceWorld,
    mirror_name: String,
    agent_name: String,
) {
    let location = world
        .mock_for_target(&agent_name)
        .url();
    let mut redirect = MockResponse::json(json!({}));
    redirect.status = 302;
    redirect
        .headers
        .insert("location".to_string(), location);
    world
        .mock_for_target(&mirror_name)
        .set_response(redirect)
        .await;
}

#[given(expr = "the surface is stored with a mirror to {string}")]
fn surface_stored_with_mirror(
    world: &mut SurfaceWorld,
    endpoint: String,
) {
    world
        .surface_config
        .mirror_endpoint = Some(endpoint);
}

#[when(expr = "the operator updates the surface to mirror traffic to {string}")]
async fn operator_updates_surface_to_mirror(
    world: &mut SurfaceWorld,
    endpoint: String,
) {
    let mut payload = get_current_admin_surface_body(world, "updating the surface mirror");
    payload["target"]["networking"] = json!({ "mirror": mirror_to(&endpoint) });
    update_created_surface(world, payload, "updating the surface mirror").await;
}

#[when(expr = "the operator patches the surface to mirror traffic to {string}")]
async fn operator_patches_surface_to_mirror(
    world: &mut SurfaceWorld,
    endpoint: String,
) {
    patch_surface(world, json!({ "target": { "networking": { "mirror": mirror_to(&endpoint) } } })).await;
}

#[when("the operator renames the stored surface")]
async fn operator_renames_stored_surface(world: &mut SurfaceWorld) {
    crate::steps::when::ensure_gateway_running(world).await;
    world.surface_under_test_id = Some("bdd-surface".to_string());
    patch_surface(world, json!({ "name": "renamed surface" })).await;
}

async fn patch_surface(
    world: &mut SurfaceWorld,
    patch: Value,
) {
    ensure_admin_session(world).await;
    let surface_id = get_tracked_surface_id(world, "patching the surface");
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .patch_surface_recorded(&surface_id, &patch)
        .await
        .unwrap_or_else(|error| panic!("patching the surface through admin API: {error}"));
    record_admin_response(world, response);
}

#[then(expr = "the mirror endpoint {string} received the forwarded request")]
async fn mirror_endpoint_received_forwarded_request(
    world: &mut SurfaceWorld,
    mirror_name: String,
) {
    let received = world
        .mock_for_target(&mirror_name)
        .request_count()
        .await;
    assert_eq!(received, 1, "mirror endpoint '{mirror_name}' should have received the copy once");
}
