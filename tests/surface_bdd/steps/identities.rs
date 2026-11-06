use cucumber::{given, then, when};
use serde_json::Value;

use crate::bdd_support::caller::post_json;
use crate::bdd_support::json_rpc::build_a2a_message_send_body;
use crate::steps::given::tracked_surface_id;
use crate::steps::when::{ensure_admin_session, ensure_gateway_running};
use crate::world::SurfaceWorld;

const DASHBOARD_STATS_PATH: &str = "/v1/dashboard/stats";
const RECORDER_STATUS_ATTEMPTS: usize = 50;
const RECORDER_STATUS_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

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

const API_KEY_HEADER: &str = "x-api-key";

fn api_key_value(api_key_id: &str) -> String {
    format!("bdd-{api_key_id}-value")
}

/// Stores the API key as a secret under `api_key_id`, so a surface can both
/// authenticate it and derive an identity from it.
async fn ensure_api_key_secret(
    world: &mut SurfaceWorld,
    api_key_id: &str,
) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(
            reqwest::Method::POST,
            "/api/v1/secrets/new",
            Some(&serde_json::json!({
                "name": format!("BDD API key {api_key_id}"),
                "secret_id": api_key_id,
                "description": "BDD API key shared by a managed agent and its calls",
                "value": api_key_value(api_key_id),
                "secret_type": "ApiKey",
                "tags": ["bdd"],
            })),
        )
        .await
        .unwrap_or_else(|error| panic!("create API key secret through admin API: {error}"));
    let already_exists = response.status == 400
        && response
            .body
            .to_string()
            .contains("already exists");
    assert!(
        response.status == 201 || already_exists,
        "API key secret setup should create or reuse the secret, got status {} body {}",
        response.status,
        response.body
    );
}

/// Reads surface `surface_name`, applies `edit`, and saves it through the admin API.
async fn edit_named_surface(
    world: &mut SurfaceWorld,
    surface_name: &str,
    action: &str,
    edit: impl FnOnce(&mut Value),
) {
    ensure_admin_session(world).await;
    let surface_id = tracked_surface_id(world, surface_name);
    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let mut surface: Value = client
        .send_json::<(), _>(reqwest::Method::GET, &format!("/v1/surfaces/{surface_id}"), None)
        .await
        .unwrap_or_else(|error| panic!("read surface {surface_name:?} before {action}: {error}"));
    edit(&mut surface);
    let response = client
        .update_surface_recorded(&surface_id, &surface)
        .await
        .unwrap_or_else(|error| panic!("{action} through admin API: {error}"));
    assert_eq!(response.status, 200, "{action} should succeed, got: {}", response.body);
}

#[given(expr = "surfaces {string} and {string} have managed identity enabled")]
async fn surfaces_have_managed_identity(
    world: &mut SurfaceWorld,
    first: String,
    second: String,
) {
    let injection = crate::bdd_support::config::managed_identity::target_identity_injection_json(
        &crate::bdd_support::config::managed_identity::default_identity_payload_schema(),
    );
    for surface_name in [first, second] {
        edit_named_surface(world, &surface_name, "enabling managed identity", |surface| {
            surface["target"]["identity_injection"] = injection.clone();
        })
        .await;
    }
}

#[given(expr = "surface {string} takes its managed identity from API key {string}")]
async fn surface_takes_managed_identity_from_api_key(
    world: &mut SurfaceWorld,
    surface_name: String,
    api_key_id: String,
) {
    ensure_api_key_secret(world, &api_key_id).await;
    edit_named_surface(world, &surface_name, "deriving managed identity from an API key", |surface| {
        surface["identity_slots"]["protected"] = serde_json::json!({
            "type": "from_api_key",
            "api_key_id": api_key_id,
        });
    })
    .await;
}

#[given(expr = "surface {string} identifies its callers by API key {string}")]
async fn surface_identifies_callers_by_api_key(
    world: &mut SurfaceWorld,
    surface_name: String,
    api_key_id: String,
) {
    ensure_api_key_secret(world, &api_key_id).await;
    edit_named_surface(world, &surface_name, "identifying callers by API key", |surface| {
        surface["access_point"]["caller_authentication"] = serde_json::json!({
            "methods": [crate::bdd_support::config::source_auth::api_key_source_auth_method_json(
                API_KEY_HEADER,
                &api_key_id,
            )],
        });
        surface["identity_slots"]["inbound"] = serde_json::json!({ "type": "from_api_key" });
    })
    .await;
}

async fn send_request_to_named_surface(
    world: &mut SurfaceWorld,
    surface_name: &str,
    headers: &[(String, String)],
) {
    ensure_gateway_running(world).await;
    let route = world
        .actors
        .surface(surface_name)
        .and_then(|surface| surface.route.clone())
        .unwrap_or_else(|| panic!("surface {surface_name:?} must have a route"));
    let gateway_port = world
        .infra
        .as_ref()
        .expect("scenario infra must exist")
        .gateway_port;
    let url = format!("http://127.0.0.1:{gateway_port}{route}/foo");
    let response = post_json(&reqwest::Client::new(), &url, &build_a2a_message_send_body("hello"), headers)
        .await
        .expect("request should reach the gateway");
    assert_eq!(
        response.status, 200,
        "expected the request to surface {surface_name:?} to succeed, got {}: {}",
        response.status, response.body
    );
}

#[given(expr = "the caller has sent a request to surface {string}")]
async fn caller_has_sent_request_to_named_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    send_request_to_named_surface(world, &surface_name, &[]).await;
}

#[given(expr = "managed agent {string} has called surface {string}")]
async fn managed_agent_has_called_surface(
    world: &mut SurfaceWorld,
    _agent_name: String,
    surface_name: String,
) {
    send_request_to_named_surface(world, &surface_name, &[]).await;
}

#[given(expr = "managed agent {string} has called surface {string} with API key {string}")]
async fn managed_agent_has_called_surface_with_api_key(
    world: &mut SurfaceWorld,
    _agent_name: String,
    surface_name: String,
    api_key_id: String,
) {
    let headers = [(API_KEY_HEADER.to_string(), api_key_value(&api_key_id))];
    send_request_to_named_surface(world, &surface_name, &headers).await;
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
    let managed_surfaces = identity
        .get("managed_surfaces")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    assert_eq!(
        managed_surfaces, 1,
        "a named Managed Agent must be the managed agent of exactly one surface, observed: {identity}"
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
    assert!(
        identity
            .get("surface_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty()),
        "Managed Agent identity should carry its surface id, observed: {identity}"
    );
}

#[then("the Identities dashboard shows one Managed Agent identity without a name")]
fn dashboard_shows_one_unnamed_managed_identity(world: &mut SurfaceWorld) {
    let identity = single_identity_with_origin(world, "managed");
    for absent in ["display_name", "surface_id", "surface_name"] {
        assert!(
            identity.get(absent).is_none(),
            "{absent} must be omitted for a Managed Agent shared by several surfaces, observed: {identity}"
        );
    }
}

#[then(expr = "the Managed Agent identity belongs to surfaces {string} and {string}")]
fn managed_identity_belongs_to_surfaces(
    world: &mut SurfaceWorld,
    first: String,
    second: String,
) {
    let identity = single_identity_with_origin(world, "managed");
    let mut observed: Vec<&str> = identity
        .get("managed_surfaces")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("expected managed surfaces, observed: {identity}"))
        .iter()
        .filter_map(|surface| {
            surface
                .get("surface_name")
                .and_then(Value::as_str)
        })
        .collect();
    observed.sort_unstable();
    let mut expected = [first.as_str(), second.as_str()];
    expected.sort_unstable();
    assert_eq!(observed, expected, "unexpected managed surfaces, observed: {identity}");
}

fn recorder_state_and_reason(status: &Value) -> (Option<&str>, Option<&str>) {
    (
        status
            .get("state")
            .and_then(Value::as_str),
        status
            .get("reason")
            .and_then(Value::as_str),
    )
}

async fn wait_for_managed_recorder_status(
    world: &mut SurfaceWorld,
    expected_state: &str,
    expected_reason: Option<&str>,
) {
    ensure_admin_session(world).await;
    let mut observed = Value::Null;
    for _ in 0..RECORDER_STATUS_ATTEMPTS {
        let response = world
            .admin_client
            .as_ref()
            .expect("admin client must exist")
            .send_recorded_json::<Value>(reqwest::Method::GET, DASHBOARD_STATS_PATH, None)
            .await
            .expect("dashboard stats read should return an HTTP response");
        world.admin_response = Some(response);
        observed = single_identity_with_origin(world, "managed")
            .get("trust_recorder")
            .cloned()
            .unwrap_or(Value::Null);
        let (state, reason) = recorder_state_and_reason(&observed);
        if state == Some(expected_state) && (expected_reason.is_none() || reason == expected_reason) {
            return;
        }
        tokio::time::sleep(RECORDER_STATUS_POLL_INTERVAL).await;
    }
    panic!("expected Trust Recorder status {expected_state:?} because {expected_reason:?}, last observed: {observed}");
}

#[given(expr = "within ten seconds the Managed Agent identity has shown Trust Recorder status {string}")]
async fn managed_identity_has_shown_recorder_status(
    world: &mut SurfaceWorld,
    expected_state: String,
) {
    wait_for_managed_recorder_status(world, &expected_state, None).await;
}

#[then(expr = "within ten seconds the Managed Agent identity shows Trust Recorder status {string} because {string}")]
async fn managed_identity_shows_recorder_status_because(
    world: &mut SurfaceWorld,
    expected_state: String,
    expected_reason: String,
) {
    wait_for_managed_recorder_status(world, &expected_state, Some(&expected_reason)).await;
}

#[then(expr = "the Managed Agent identity shows Trust Recorder status {string}")]
fn managed_identity_shows_recorder_status(
    world: &mut SurfaceWorld,
    expected_state: String,
) {
    let identity = single_identity_with_origin(world, "managed");
    let status = identity
        .get("trust_recorder")
        .unwrap_or_else(|| panic!("expected a Trust Recorder status, observed: {identity}"));
    assert_eq!(recorder_state_and_reason(status).0, Some(expected_state.as_str()), "observed: {identity}");
}

#[then("the Managed Agent identity shows no Trust Recorder status")]
fn managed_identity_shows_no_recorder_status(world: &mut SurfaceWorld) {
    let identity = single_identity_with_origin(world, "managed");
    assert!(
        identity
            .get("trust_recorder")
            .is_none(),
        "a surface without a Trust Recorder must not show a recorder status, observed: {identity}"
    );
}

#[then(expr = "within ten seconds the Trust Recorder status of surface {string} is {string}")]
async fn surface_recorder_status_is(
    world: &mut SurfaceWorld,
    surface_name: String,
    expected_state: String,
) {
    ensure_admin_session(world).await;
    let surface_id = tracked_surface_id(world, &surface_name);
    let path = format!("/v1/surfaces/{surface_id}/trust-recorder-status");
    let mut observed = Value::Null;
    for _ in 0..RECORDER_STATUS_ATTEMPTS {
        let response = world
            .admin_client
            .as_ref()
            .expect("admin client must exist")
            .send_recorded_json::<Value>(reqwest::Method::GET, &path, None)
            .await
            .expect("surface Trust Recorder status read should return an HTTP response");
        assert_eq!(response.status, 200, "unexpected response: {}", response.body);
        observed = response
            .body
            .get("status")
            .cloned()
            .unwrap_or(Value::Null);
        world.admin_response = Some(response);
        if recorder_state_and_reason(&observed).0 == Some(expected_state.as_str()) {
            return;
        }
        tokio::time::sleep(RECORDER_STATUS_POLL_INTERVAL).await;
    }
    panic!("expected surface {surface_name:?} Trust Recorder status {expected_state:?}, last observed: {observed}");
}
