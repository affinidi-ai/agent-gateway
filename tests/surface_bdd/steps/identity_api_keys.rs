use std::collections::HashMap;
use std::time::Duration;

use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{AdminApiClient, RecordedResponse};
use crate::bdd_support::config;
use crate::bdd_support::config::single_surface_fixture::{StoredApiKeyFixture, SurfaceSourceAuthConfig};
use crate::bdd_support::gateway_process::{GatewayProcess, SURFACE_TEST_AUTH_TOKEN};
use crate::steps::credential_save::{save_surface, send, stored_surface, surface_id};
use crate::steps::target_credential::before_the_gateway_starts;
use crate::steps::then::gateway_log;
use crate::steps::when::{build_primary_target_surface_payload, ensure_gateway_running};
use crate::world::SurfaceWorld;

/// The line the gateway logs when it has revoked the API keys of surfaces that no longer exist.
const SWEEP_DONE: &str = "Revoked the API keys of surfaces that no longer exist";

fn from_api_key(key_id: &str) -> Value {
    json!({"type": "from_api_key", "api_key_id": key_id})
}

fn api_key(
    world: &SurfaceWorld,
    name: &str,
) -> (String, String) {
    world
        .api_keys
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("API key {name:?} must be created first"))
}

async fn create_api_key(
    world: &mut SurfaceWorld,
    owner: &str,
    name: &str,
) {
    let path = format!("/v1/api-keys/{owner}");
    let response = send(world, Method::POST, &path, Some(&json!({"client_id": name}))).await;
    assert_eq!(response.status, 201, "creating API key {name:?}: {}", response.body);
    let key_id = response.body["key_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the created API key has an id: {}", response.body))
        .to_string();
    world
        .api_keys
        .insert(name.to_string(), (owner.to_string(), key_id));
}

async fn surface_naming_in_protected_identity(
    world: &mut SurfaceWorld,
    name: &str,
) -> Value {
    let (_, key_id) = api_key(world, name);
    let mut surface = stored_surface(world).await;
    surface["identity_slots"]["protected"] = from_api_key(&key_id);
    surface
}

#[given(expr = "the surface has an API key {string}")]
async fn surface_has_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let owner = surface_id(world);
    world.surface_under_test_id = Some(owner.clone());
    create_api_key(world, &owner, &name).await;
}

#[given(expr = "the surface for route {string} has an API key {string}")]
async fn other_surface_has_api_key(
    world: &mut SurfaceWorld,
    route: String,
    name: String,
) {
    create_surface_with_api_key(world, &route, None, &name).await;
}

#[given(expr = "the surface for route {string} of tenant {string} has an API key {string}")]
async fn other_tenants_surface_has_api_key(
    world: &mut SurfaceWorld,
    route: String,
    tenant: String,
    name: String,
) {
    create_surface_with_api_key(world, &route, Some(&tenant), &name).await;
}

async fn create_surface_with_api_key(
    world: &mut SurfaceWorld,
    route: &str,
    tenant: Option<&str>,
    name: &str,
) {
    let mut payload = build_primary_target_surface_payload(world, route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    payload["tenant_id"] = json!(tenant);
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    assert_eq!(response.status, 201, "creating surface {route}: {}", response.body);
    let owner = response.body["surface_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the created surface has an id: {}", response.body))
        .to_string();
    create_api_key(world, &owner, name).await;
}

fn store_api_key(
    world: &mut SurfaceWorld,
    owner: &str,
    name: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    loads: bool,
) {
    before_the_gateway_starts(world, "a stored API key");
    let key_id = format!("atgk_{}", uuid::Uuid::new_v4().as_simple());
    world
        .surface_config
        .stored_api_keys
        .push(StoredApiKeyFixture {
            owner: owner.to_string(),
            key_id: key_id.clone(),
            created_at,
            loads,
        });
    world
        .api_keys
        .insert(name.to_string(), (owner.to_string(), key_id));
}

fn a_day_ago() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::days(1)
}

#[given(expr = "an active API key {string}, created a day ago, belongs to surface {string}, which no longer exists")]
fn active_api_key_of_surface_that_no_longer_exists(
    world: &mut SurfaceWorld,
    name: String,
    owner: String,
) {
    store_api_key(world, &owner, &name, a_day_ago(), true);
}

#[given(expr = "surface {string} was stored with an API key {string}")]
fn surface_was_stored_with_api_key(
    world: &mut SurfaceWorld,
    owner: String,
    name: String,
) {
    store_api_key(world, &owner, &name, a_day_ago(), true);
    world
        .surface_config
        .other_stored_surfaces
        .push(owner);
}

#[given(expr = "API key {string} of surface {string} sits in a key folder that fails to load")]
fn api_key_in_folder_that_fails_to_load(
    world: &mut SurfaceWorld,
    name: String,
    owner: String,
) {
    store_api_key(world, &owner, &name, a_day_ago(), false);
}

#[given(expr = "the surface's API key {string} sits in a key folder that fails to load")]
fn surface_api_key_in_folder_that_fails_to_load(
    world: &mut SurfaceWorld,
    name: String,
) {
    let owner = surface_id(world);
    world.surface_under_test_id = Some(owner.clone());
    store_api_key(world, &owner, &name, a_day_ago(), false);
}

#[given(expr = "the surface was stored with its protected Identity taking its DID from API key {string}")]
fn surface_was_stored_naming_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    before_the_gateway_starts(world, "the stored surface's protected Identity");
    world.surface_under_test_id = Some(surface_id(world));
    let (_, key_id) = api_key(world, &name);
    world
        .surface_config
        .protected_identity_api_key_id = Some(key_id);
}

#[given(expr = "the surface's API Key Provider accepts API key {string}, created a day ago")]
fn api_key_provider_accepts_key_created_a_day_ago(
    world: &mut SurfaceWorld,
    name: String,
) {
    before_the_gateway_starts(world, "the API Key Provider's key");
    let Some(SurfaceSourceAuthConfig::ApiKeyProvider(provider)) = &world
        .surface_config
        .source_auth
    else {
        panic!("the surface must require API Key Provider source authentication first");
    };
    let key = (provider.agent_id.clone(), provider.key_id.clone());
    world
        .surface_config
        .api_key_provider_key_created_at = Some(a_day_ago());
    world
        .api_keys
        .insert(name, key);
}

#[given("the gateway runs in Standby")]
fn gateway_runs_in_standby(world: &mut SurfaceWorld) {
    before_the_gateway_starts(world, "Standby mode");
    world
        .surface_config
        .starts_standby = true;
}

#[given("another node of the gateway shares its storage")]
async fn another_node_shares_storage(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let base_dir = world
        .infra
        .as_ref()
        .expect("the gateway runs")
        ._temp_dir
        .path()
        .to_path_buf();
    let (port, mut reservation) = config::reserve_free_port("second gateway node port");
    let config_path = config::single_surface_writer::write_second_node_config(&base_dir, port);
    reservation.release_listener();
    let mut node = GatewayProcess::start_surface_with_env(&config_path, &base_dir, &HashMap::new())
        .with_port(port)
        .with_port_reservation(reservation);
    node.wait_until_ready().await;
    let client = AdminApiClient::new(port, SURFACE_TEST_AUTH_TOKEN, "surface-bdd-admin");
    client
        .bootstrap_test_session()
        .await
        .expect("test-support auth login on the other node should succeed");
    world.other_node = Some((node, client));
}

async fn send_through_other_node(
    world: &SurfaceWorld,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    let request = method.to_string();
    world
        .other_node
        .as_ref()
        .expect("another node must share the storage first")
        .1
        .send_recorded_json(method, path, body)
        .await
        .unwrap_or_else(|error| panic!("{request} request through the other node failed: {error}"))
}

#[given(expr = "the operator has revoked API key {string} through the other node")]
async fn operator_has_revoked_api_key_through_other_node(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}/revoke");
    let response = send_through_other_node(world, Method::POST, &path, Some(&json!({}))).await;
    assert_eq!(response.status, 204, "revoking API key {name:?} through the other node: {}", response.body);
}

#[when("the gateway starts")]
async fn gateway_starts(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
}

#[when("the gateway becomes Active")]
async fn gateway_becomes_active(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let pid = world
        .infra
        .as_ref()
        .expect("the gateway runs")
        .gateway
        .pid();
    let status = std::process::Command::new("kill")
        .args(["-USR1", &pid.to_string()])
        .status()
        .expect("signal the gateway");
    assert!(status.success(), "signalling the gateway to become Active: {status}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !gateway_log(world).contains(SWEEP_DONE) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the gateway did not finish becoming Active; keep its informational log to see it:\n{}",
            gateway_log(world)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[given(expr = "the surface's protected Identity takes its DID from API key {string}")]
async fn protected_identity_takes_did_from_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let surface = surface_naming_in_protected_identity(world, &name).await;
    save_surface(world, &surface).await;
    let response = world
        .admin_response
        .take()
        .expect("the save has a response");
    assert_eq!(response.status, 200, "naming API key {name:?} in the protected Identity: {}", response.body);
}

#[given(expr = "the operator has revoked API key {string}")]
async fn operator_has_revoked_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}/revoke");
    let response = send(world, Method::POST, &path, Some(&json!({}))).await;
    assert_eq!(response.status, 204, "revoking API key {name:?}: {}", response.body);
}

#[given(expr = "the operator has deleted API key {string}")]
async fn operator_has_deleted_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}");
    let response = send(world, Method::DELETE, &path, None).await;
    assert_eq!(response.status, 204, "deleting API key {name:?}: {}", response.body);
}

#[when(expr = "the operator saves the surface with its protected Identity taking its DID from API key {string}")]
async fn operator_saves_protected_identity_from_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let surface = surface_naming_in_protected_identity(world, &name).await;
    save_surface(world, &surface).await;
}

#[when("the operator deletes the surface")]
async fn operator_deletes_surface(world: &mut SurfaceWorld) {
    crate::steps::when::delete_surface(world).await;
}

#[when("the operator creates a surface with the deleted surface's id")]
async fn operator_creates_surface_with_deleted_id(world: &mut SurfaceWorld) {
    let deleted = surface_id(world);
    let mut payload = build_primary_target_surface_payload(world, "/smoke/reused").await;
    payload["surface_id"] = json!(deleted);
    payload["name"] = json!("reused");
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    world.admin_response = Some(response);
}

#[then(regex = r#"^the surface reports API key "([^"]+)" as "([a-z]+)", which (blocks|does not block) the surface$"#)]
fn surface_reports_api_key_status(
    world: &mut SurfaceWorld,
    name: String,
    status: String,
    blocking: String,
) {
    let (_, key_id) = api_key(world, &name);
    let surface = &world
        .surface_lookup_response
        .as_ref()
        .expect("the surface was read")
        .body;
    let references = surface["api_key_references"]
        .as_array()
        .unwrap_or_else(|| panic!("the surface reports no api_key_references: {surface}"));
    let expected = json!({"key_id": key_id, "status": status, "blocking": blocking == "blocks"});
    assert!(references.contains(&expected), "expected API key {name:?} reported as {expected}, got {references:?}");
}

#[then(expr = "the admin API error response does not mention {string}")]
fn admin_api_error_response_does_not_mention(
    world: &mut SurfaceWorld,
    unexpected: String,
) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("the admin API answered")
        .body;
    assert!(
        !body
            .to_string()
            .contains(&unexpected),
        "the error response mentions {unexpected:?}: {body}"
    );
}

#[then(expr = "the stored surface's protected Identity takes its DID from API key {string}")]
async fn stored_protected_identity_takes_did_from_api_key(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (_, key_id) = api_key(world, &name);
    let surface = stored_surface(world).await;
    assert_eq!(surface["identity_slots"]["protected"], from_api_key(&key_id), "{surface}");
}

#[then(expr = "the operator reads API key {string} as revoked, with its surface deleted")]
async fn operator_reads_api_key_revoked_with_surface_deleted(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}");
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 200, "reading API key {name:?}: {}", response.body);
    assert_eq!(response.body["status"], "revoked", "{}", response.body);
    assert_eq!(response.body["surface_deleted"], true, "{}", response.body);
}

#[then(expr = "the admin API response warns {string}")]
fn admin_api_response_warns(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("the admin API answered")
        .body;
    let warned = body["warnings"]
        .as_array()
        .is_some_and(|warnings| {
            warnings
                .iter()
                .any(|warning| {
                    warning["message"]
                        .as_str()
                        .is_some_and(|message| message.contains(&expected))
                })
        });
    assert!(warned, "no warning mentions {expected:?}: {body}");
}

#[then("no surface with the deleted surface's id is stored")]
async fn no_surface_with_deleted_id_is_stored(world: &mut SurfaceWorld) {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 404, "reading the deleted surface's id: {}", response.body);
}

#[then(expr = "the operator reads API key {string} as active")]
async fn operator_reads_api_key_active(
    world: &mut SurfaceWorld,
    name: String,
) {
    let (owner, key_id) = api_key(world, &name);
    let path = format!("/v1/api-keys/{owner}/{key_id}");
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 200, "reading API key {name:?}: {}", response.body);
    assert_eq!(response.body["status"], "active", "{}", response.body);
}

#[then(expr = "the gateway log records API key {string} revoked by {string}")]
fn gateway_log_records_api_key_revoked_by(
    world: &mut SurfaceWorld,
    name: String,
    actor: String,
) {
    let (_, key_id) = api_key(world, &name);
    let log = gateway_log(world);
    let actor_field = format!("actor={actor}");
    assert!(
        log.lines()
            .any(|line| line.contains("Revoked API key") && line.contains(&key_id) && line.contains(&actor_field)),
        "the gateway log does not record API key {name:?} ({key_id}) revoked by {actor:?}:\n{log}"
    );
}

#[then("a surface with the deleted surface's id is stored")]
async fn surface_with_deleted_id_is_stored(world: &mut SurfaceWorld) {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 200, "reading the reused id: {}", response.body);
    assert_eq!(response.body["name"], "reused", "{}", response.body);
}
