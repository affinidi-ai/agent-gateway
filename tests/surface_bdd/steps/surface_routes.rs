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
        .push(StoredSurfaceFixture {
            id,
            route,
            status,
            transit_point: None,
            tenant_id: None,
        });
}

/// An active surface stored before the gateway starts, so its `listen_path`
/// passes no save gate: the way a clash the gate now refuses is held.
#[given(expr = "a surface {string} is stored on route {string} with Transit Point {string} listening on {string}")]
fn surface_stored_with_transit_point(
    world: &mut SurfaceWorld,
    id: String,
    route: String,
    alias: String,
    listen_path: String,
) {
    store_surface_with_transit_point(world, id, route, alias, listen_path, None);
}

/// [`surface_stored_with_transit_point`], owned by `tenant`.
#[given(
    expr = "a surface {string} of tenant {string} is stored on route {string} with Transit Point {string} listening on {string}"
)]
fn tenant_surface_stored_with_transit_point(
    world: &mut SurfaceWorld,
    id: String,
    tenant: String,
    route: String,
    alias: String,
    listen_path: String,
) {
    store_surface_with_transit_point(world, id, route, alias, listen_path, Some(tenant));
}

fn store_surface_with_transit_point(
    world: &mut SurfaceWorld,
    id: String,
    route: String,
    alias: String,
    listen_path: String,
    tenant_id: Option<String>,
) {
    world
        .surface_config
        .stored_surfaces_on_routes
        .push(StoredSurfaceFixture {
            id,
            route,
            status: "active".to_string(),
            transit_point: Some((alias, listen_path)),
            tenant_id,
        });
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

/// Reloads the configuration while the stored surfaces' directory cannot be read, so the
/// reload cannot load a configuration, then makes the directory readable again.
#[given("the operator has reloaded the configuration while the stored surfaces could not be read")]
async fn operator_has_reloaded_while_surfaces_unreadable(world: &mut SurfaceWorld) {
    use std::os::unix::fs::PermissionsExt as _;
    ensure_admin_session(world).await;
    let surfaces_dir = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        ._temp_dir
        .path()
        .join("_storage/agent_surfaces");
    let readable = std::fs::metadata(&surfaces_dir)
        .expect("the stored surfaces' directory")
        .permissions();
    std::fs::set_permissions(&surfaces_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let reload = world
        .admin_client
        .as_ref()
        .expect("the operator must be signed in")
        .send_recorded_json::<()>(reqwest::Method::POST, "/v1/config/reload", None)
        .await;
    std::fs::set_permissions(&surfaces_dir, readable).unwrap();
    world.admin_response = Some(reload.expect("reload the configuration"));
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

#[when(expr = "the operator saves surface {string} with status {string}")]
async fn operator_saves_surface_with_status(
    world: &mut SurfaceWorld,
    id: String,
    status: String,
) {
    let mut surface = stored_surface(world, &id).await;
    surface["status"] = serde_json::json!(status);
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
