use cucumber::{given, then, when};

use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::config::single_surface_fixture::StoredSurfaceFixture;
use crate::steps::then::gateway_log;
use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

#[given(expr = "a surface {string} is stored {word} on route {string}")]
fn surface_stored_on_route(
    world: &mut SurfaceWorld,
    id: String,
    status: String,
    route: String,
) {
    world
        .surface_config
        .keeps_gateway_log = true;
    world
        .surface_config
        .stored_surfaces_on_routes
        .push(StoredSurfaceFixture { id, route, status });
}

async fn stored_surface(
    world: &mut SurfaceWorld,
    id: &str,
) -> serde_json::Value {
    ensure_admin_session(world).await;
    let stored = world
        .admin_client
        .as_ref()
        .expect("the operator must be signed in")
        .get_surface_recorded(id)
        .await
        .unwrap_or_else(|error| panic!("read surface {id}: {error}"));
    assert_eq!(stored.status, 200, "read surface {id}: {stored:?}");
    stored.body
}

async fn save_surface(
    world: &mut SurfaceWorld,
    id: &str,
    surface: serde_json::Value,
) {
    let saved = world
        .admin_client
        .as_ref()
        .expect("the operator must be signed in")
        .update_surface_recorded(id, &surface)
        .await
        .unwrap_or_else(|error| panic!("save surface {id}: {error}"));
    world.admin_response = Some(saved);
}

#[when(expr = "the operator changes the description of surface {string}")]
async fn operator_changes_description(
    world: &mut SurfaceWorld,
    id: String,
) {
    let mut surface = stored_surface(world, &id).await;
    surface["description"] = serde_json::json!("Edited without moving its route");
    save_surface(world, &id, surface).await;
}

/// Disables the stored surface under test with a PUT of its stored record, as the operator
/// does from the dashboard.
#[given("the operator has disabled the stored surface")]
async fn operator_has_disabled_the_stored_surface(world: &mut SurfaceWorld) {
    crate::steps::when::ensure_gateway_running(world).await;
    let id = crate::steps::credential_save::surface_id(world);
    let mut surface = stored_surface(world, &id).await;
    surface["status"] = serde_json::json!("disabled");
    save_surface(world, &id, surface).await;
    let saved = world
        .admin_response
        .take()
        .expect("the operator saved the surface");
    assert_eq!(saved.status, 200, "disable surface {id}: {saved:?}");
}

#[when(expr = "the operator enables surface {string}")]
async fn operator_enables_surface(
    world: &mut SurfaceWorld,
    id: String,
) {
    let mut surface = stored_surface(world, &id).await;
    surface["status"] = serde_json::json!("active");
    save_surface(world, &id, surface).await;
}

#[then(expr = "surface {string} is {word}")]
async fn surface_has_status(
    world: &mut SurfaceWorld,
    id: String,
    status: String,
) {
    let surface = stored_surface(world, &id).await;
    assert_eq!(surface["status"], status, "surface {id}: {surface}");
}

#[then(expr = "the gateway log warns about the route of surface {string}")]
fn gateway_log_warns_about_route(
    world: &mut SurfaceWorld,
    id: String,
) {
    let log = gateway_log(world);
    assert!(
        log.lines()
            .any(|line| line.contains("breaks the rules a save now checks") && line.contains(&format!("\"{id}\""))),
        "the gateway log has no route warning for surface {id}:\n{log}"
    );
}

#[then(expr = "the admin API response stores route {string}")]
fn admin_response_stores_route(
    world: &mut SurfaceWorld,
    route: String,
) {
    let response: &RecordedResponse = world
        .admin_response
        .as_ref()
        .expect("the operator must have saved a surface");
    assert_eq!(response.body["access_point"]["route"], route, "{response:?}");
}
