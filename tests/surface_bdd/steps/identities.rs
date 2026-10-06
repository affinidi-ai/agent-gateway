use cucumber::{given, then, when};
use serde_json::Value;

use crate::bdd_support::caller::post_json;
use crate::bdd_support::json_rpc::build_a2a_message_send_body;
use crate::steps::when::{ensure_admin_session, ensure_gateway_running};
use crate::world::SurfaceWorld;

const DASHBOARD_STATS_PATH: &str = "/v1/dashboard/stats";

#[given("the caller has sent a request to the surface")]
async fn caller_has_sent_request_to_surface(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let infra = world
        .infra
        .as_ref()
        .expect("scenario infra must exist");
    let url = format!("http://127.0.0.1:{}{}/foo", infra.gateway_port, world.surface_config.route);
    let response = post_json(&reqwest::Client::new(), &url, &build_a2a_message_send_body("hello"), &[])
        .await
        .expect("caller request should reach the gateway");
    assert_eq!(
        response.status, 200,
        "expected the caller request to succeed before reading identities, got {}: {}",
        response.status, response.body
    );
}

#[when("the operator reads the Identities dashboard")]
async fn operator_reads_identities_dashboard(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json::<Value>(reqwest::Method::GET, DASHBOARD_STATS_PATH, None)
        .await
        .expect("dashboard stats read should return an HTTP response");
    world.admin_response = Some(response);
}

fn dashboard_identities(world: &SurfaceWorld) -> &[Value] {
    world
        .admin_response
        .as_ref()
        .expect("the Identities dashboard must have been read")
        .body
        .get("identities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("dashboard stats should list identities, got: {:?}", world.admin_response))
}

fn identities_with_origin<'a>(
    world: &'a SurfaceWorld,
    origin: &str,
) -> Vec<&'a Value> {
    dashboard_identities(world)
        .iter()
        .filter(|identity| identity.get("origin") == Some(&Value::String(origin.to_string())))
        .collect()
}

fn single_identity_with_origin<'a>(
    world: &'a SurfaceWorld,
    origin: &str,
) -> &'a Value {
    let matching = identities_with_origin(world, origin);
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one {origin} identity, observed identities: {:?}",
        dashboard_identities(world)
    );
    matching[0]
}

#[then(expr = "the Identities dashboard shows a Managed Agent identity named {string}")]
fn dashboard_shows_managed_identity_named(
    world: &mut SurfaceWorld,
    expected_name: String,
) {
    let identity = single_identity_with_origin(world, "managed");
    assert_eq!(
        identity.get("display_name"),
        Some(&Value::String(expected_name.clone())),
        "expected Managed Agent identity named {expected_name:?}, observed: {identity}"
    );
    assert_eq!(
        identity.get("display_name_source"),
        Some(&Value::String("surface_name".to_string())),
        "expected the Managed Agent name to come from its surface, observed: {identity}"
    );
    assert!(
        identity
            .get("name_conflict")
            .is_none(),
        "a uniquely named Managed Agent must not carry a name conflict, observed: {identity}"
    );
}

#[then(expr = "the Managed Agent identity belongs to surface {string}")]
fn managed_identity_belongs_to_surface(
    world: &mut SurfaceWorld,
    expected_surface_name: String,
) {
    let identity = single_identity_with_origin(world, "managed");
    assert_eq!(
        identity.get("surface_name"),
        Some(&Value::String(expected_surface_name.clone())),
        "expected surface name {expected_surface_name:?}, observed: {identity}"
    );
    let surface_id = identity
        .get("surface_id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("Managed Agent identity should carry its surface id, observed: {identity}"));
    assert_eq!(
        identity.get("group_key"),
        Some(&Value::String(format!("surface:{surface_id}"))),
        "expected the Managed Agent identity grouped by its surface, observed: {identity}"
    );
}
