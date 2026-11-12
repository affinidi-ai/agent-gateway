use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::steps::credential_save::{save_surface, stored_surface, surface_id};
use crate::steps::when::{build_primary_target_surface_payload, configure_unseeded_route, create_surface};
use crate::world::SurfaceWorld;

fn origins(list: &str) -> Value {
    json!(
        list.split(", ")
            .collect::<Vec<_>>()
    )
}

#[given(expr = "the operator has created a surface for route {string} that allows browser origins {string}")]
async fn operator_has_created_surface_with_browser_origins(
    world: &mut SurfaceWorld,
    route: String,
    allowed: String,
) {
    configure_unseeded_route(world, &route);
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["browser_origins"] = origins(&allowed);
    create_surface(world, payload).await;
    let response = world
        .admin_response
        .take()
        .expect("the admin API must answer");
    assert_eq!(response.status, 201, "creating the surface: {}", response.body);
    world.surface_under_test_id = response.body["surface_id"]
        .as_str()
        .map(str::to_string);
}

/// A PUT of the stored surface with no `browser_origins` field, as the Surface Builder sends.
#[when("the operator saves the surface without its browser origins")]
async fn operator_saves_surface_without_browser_origins(world: &mut SurfaceWorld) {
    let mut surface = stored_surface(world).await;
    assert!(surface["browser_origins"].is_array(), "the stored surface has browser origins: {surface}");
    surface
        .as_object_mut()
        .expect("the stored surface is an object")
        .remove("browser_origins");
    save_surface(world, &surface).await;
}

#[when(expr = "the operator saves the surface with browser origins {string}")]
async fn operator_saves_surface_with_browser_origins(
    world: &mut SurfaceWorld,
    allowed: String,
) {
    let mut surface = stored_surface(world).await;
    surface["browser_origins"] = origins(&allowed);
    save_surface(world, &surface).await;
}

#[when("the operator patches the surface's browser origins to an empty list")]
async fn operator_patches_browser_origins_to_empty(world: &mut SurfaceWorld) {
    crate::steps::when::ensure_admin_session(world).await;
    let id = surface_id(world);
    world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .patch_surface(&id, &json!({ "browser_origins": [] }))
        .await
        .expect("patching the surface's browser origins");
}

#[then(expr = "the stored surface allows browser origins {string}")]
async fn stored_surface_allows_browser_origins(
    world: &mut SurfaceWorld,
    allowed: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["browser_origins"], origins(&allowed), "the stored surface: {surface}");
}

#[then("the stored surface allows no browser origins")]
async fn stored_surface_allows_no_browser_origins(world: &mut SurfaceWorld) {
    let surface = stored_surface(world).await;
    assert!(
        surface
            .get("browser_origins")
            .is_none_or(|origins| origins == &json!([])),
        "the stored surface: {surface}"
    );
}
