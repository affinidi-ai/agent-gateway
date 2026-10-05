use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};
use std::time::Duration;

use crate::bdd_support::admin_client::AdminApiClient;
use crate::bdd_support::gateway_process::SURFACE_TEST_AUTH_TOKEN;
use crate::steps::when::ensure_gateway_running;
use crate::world::SurfaceWorld;

async fn login(
    world: &mut SurfaceWorld,
    username: &str,
    role: &str,
) -> AdminApiClient {
    ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("scenario infrastructure should exist")
        .gateway_port;
    let client = AdminApiClient::new(port, SURFACE_TEST_AUTH_TOKEN, username);
    let response = client
        .bootstrap_test_session_recorded_with_role(role)
        .await
        .expect("test authentication should complete");
    world.caller_response = Some(response);
    world
        .human_clients
        .entry(username.to_string())
        .or_default()
        .push(client.clone());
    client
}

fn latest_client(
    world: &SurfaceWorld,
    username: &str,
) -> AdminApiClient {
    world
        .human_clients
        .get(username)
        .and_then(|clients| clients.last())
        .unwrap_or_else(|| panic!("human user {username:?} should have an authenticated client"))
        .clone()
}

async fn accept_current_terms(client: &AdminApiClient) {
    let status = client
        .send_recorded_json::<Value>(Method::GET, "/v1/terms/status", None)
        .await
        .expect("Terms status request should complete");
    assert_eq!(status.status, 200, "Terms status should succeed: {}", status.body);
    let accepted_terms = status
        .body
        .get("required_terms")
        .and_then(Value::as_array)
        .expect("Terms status should include required_terms")
        .iter()
        .map(|term| {
            json!({
                "terms_type": term["terms_type"],
                "version_id": term["version_id"],
                "accepted": true,
            })
        })
        .collect::<Vec<_>>();
    let response = client
        .send_recorded_json(Method::POST, "/v1/terms/acceptances", Some(&json!({ "accepted_terms": accepted_terms })))
        .await
        .expect("Terms acceptance should complete");
    assert_eq!(response.status, 200, "Terms acceptance should succeed: {}", response.body);
}

async fn save_customer_draft(
    client: &AdminApiClient,
    version: &str,
    url: &str,
    requires_reconsent: bool,
) {
    let response = client
        .send_recorded_json(
            Method::PUT,
            "/v1/terms/customer/draft",
            Some(&json!({
                "version": version,
                "title": format!("Customer Terms {version}"),
                "url": url,
                "requires_reconsent": requires_reconsent,
            })),
        )
        .await
        .expect("Customer Terms draft request should complete");
    assert_eq!(response.status, 200, "Customer Terms draft should be saved: {}", response.body);
}

async fn publish_customer_terms(client: &AdminApiClient) -> crate::world::RecordedResponse {
    client
        .send_recorded_json::<Value>(Method::POST, "/v1/terms/customer/publish", None)
        .await
        .expect("Customer Terms publication should complete")
}

async fn accepted_customer_terms(
    world: &mut SurfaceWorld,
    username: &str,
    version: &str,
) -> AdminApiClient {
    let client = login(world, username, "administrator").await;
    accept_current_terms(&client).await;
    save_customer_draft(&client, version, &format!("https://example.com/terms/{version}"), true).await;
    let publication = publish_customer_terms(&client).await;
    assert_eq!(publication.status, 201, "Customer Terms version should publish: {}", publication.body);
    accept_current_terms(&client).await;
    client
}

async fn publish_customer_terms_version(
    world: &mut SurfaceWorld,
    username: &str,
    version: &str,
) {
    let client = latest_client(world, username);
    save_customer_draft(&client, version, &format!("https://example.com/terms/{version}"), true).await;
    let publication = publish_customer_terms(&client).await;
    assert_eq!(publication.status, 201, "Customer Terms version should publish: {}", publication.body);
}

#[given("Terms consent is enabled")]
fn terms_consent_is_enabled(world: &mut SurfaceWorld) {
    world.terms_enabled = true;
    world.affinidi_cache_seeded = true;
}

#[given(expr = "Affinidi Terms version {string} is current")]
fn affinidi_terms_version_is_current(
    world: &mut SurfaceWorld,
    version: String,
) {
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
}

#[given(expr = "Affinidi Terms version {string} was received from Affinidi Well")]
fn affinidi_terms_version_was_received(
    world: &mut SurfaceWorld,
    version: String,
) {
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
    world.affinidi_cache_seeded = true;
}

#[given("Affinidi Well is unavailable before the appliance has received metadata")]
fn affinidi_well_is_unavailable_before_first_fetch(world: &mut SurfaceWorld) {
    world.affinidi_cache_seeded = false;
    world.affinidi_well_available = false;
}

#[given("Affinidi Well is unavailable")]
async fn affinidi_well_is_unavailable(world: &mut SurfaceWorld) {
    world.affinidi_well_available = false;
    if let Some(well) = world
        .infra
        .as_ref()
        .and_then(|infra| infra.affinidi_well.as_ref())
    {
        let request_count = well.request_count().await;
        well.set_status(503).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if well.request_count().await > request_count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the appliance should retry Affinidi Well");
    }
}

#[given(expr = "administrator {string} accepted all applicable Terms")]
async fn administrator_accepted_all_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login(world, &username, "administrator").await;
    accept_current_terms(&client).await;
}

#[given(expr = "human user {string} accepted Affinidi Terms version {string}")]
async fn human_user_accepted_affinidi_terms(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
) {
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
    let client = login(world, &username, "administrator").await;
    accept_current_terms(&client).await;
}

#[given(expr = "Affinidi Well publishes version {string} requiring re-consent")]
async fn affinidi_well_publishes_version(
    world: &mut SurfaceWorld,
    version: String,
) {
    let next_sequence = world.affinidi_terms_manifest["publication_sequence"]
        .as_u64()
        .expect("publication sequence should be numeric")
        + 1;
    world.affinidi_terms_manifest["publication_sequence"] = json!(next_sequence);
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
    world.affinidi_terms_manifest["requires_reconsent"] = json!(true);
    let well = world
        .infra
        .as_ref()
        .and_then(|infra| infra.affinidi_well.as_ref())
        .expect("Affinidi Well should be running");
    well.set_response(
        world
            .affinidi_terms_manifest
            .clone(),
    )
    .await;
}

async fn wait_for_affinidi_well_request(
    world: &SurfaceWorld,
    previous_request_count: usize,
) {
    let well = world
        .infra
        .as_ref()
        .and_then(|infra| infra.affinidi_well.as_ref())
        .expect("Affinidi Well should be running");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if well.request_count().await > previous_request_count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the appliance should refresh Affinidi Terms metadata");
}

#[given("the appliance has refreshed Affinidi Terms metadata")]
async fn appliance_refreshed_affinidi_terms(world: &mut SurfaceWorld) {
    let port = world
        .infra
        .as_ref()
        .expect("scenario infrastructure should exist")
        .gateway_port;
    let expected_version = world.affinidi_terms_manifest["version"].clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = reqwest::get(format!("http://127.0.0.1:{port}/api/v1/terms/applicable"))
                .await
                .expect("applicable Terms request should complete");
            if response.status().is_success() {
                let body = response
                    .json::<Value>()
                    .await
                    .expect("applicable Terms should be JSON");
                if body["terms"]
                    .as_array()
                    .is_some_and(|terms| {
                        terms
                            .iter()
                            .any(|term| term["version"] == expected_version)
                    })
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the appliance should refresh Affinidi Terms metadata");
}

#[given("Affinidi Well serves an invalid publication")]
async fn affinidi_well_serves_invalid_publication(world: &mut SurfaceWorld) {
    let well = world
        .infra
        .as_ref()
        .and_then(|infra| infra.affinidi_well.as_ref())
        .expect("Affinidi Well should be running");
    let request_count = well.request_count().await;
    let mut invalid = world
        .affinidi_terms_manifest
        .clone();
    invalid["schema_version"] = json!(999);
    well.set_response(invalid)
        .await;
    wait_for_affinidi_well_request(world, request_count).await;
}

#[given("Affinidi Well serves a rollback publication")]
async fn affinidi_well_serves_rollback_publication(world: &mut SurfaceWorld) {
    let well = world
        .infra
        .as_ref()
        .and_then(|infra| infra.affinidi_well.as_ref())
        .expect("Affinidi Well should be running");
    let request_count = well.request_count().await;
    let mut rollback = world
        .affinidi_terms_manifest
        .clone();
    rollback["publication_sequence"] = json!(1);
    rollback["version_id"] = json!("affinidi:3.2");
    rollback["version"] = json!("3.2");
    well.set_response(rollback)
        .await;
    wait_for_affinidi_well_request(world, request_count).await;
}

#[when("the caller requests Affinidi Terms provider health")]
async fn caller_requests_affinidi_terms_provider_health(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("scenario infrastructure should exist")
        .gateway_port;
    let client = AdminApiClient::new(port, SURFACE_TEST_AUTH_TOKEN, "health-probe");
    world.caller_response = Some(
        client
            .send_recorded_json::<Value>(Method::GET, "/v1/terms/provider-health", None)
            .await
            .expect("provider health request should complete"),
    );
}

#[then("the Affinidi Terms provider health state is unavailable")]
fn affinidi_terms_provider_health_is_unavailable(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("provider health response should exist");
    assert_eq!(response.body["state"], "unavailable");
}

#[when(expr = "human user {string} signs in")]
async fn human_user_signs_in(
    world: &mut SurfaceWorld,
    username: String,
) {
    login(world, &username, "administrator").await;
}

#[then("authentication succeeds")]
fn authentication_succeeds(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert_eq!(response.status, 200, "expected successful authentication, got {}", response.body);
}

#[then(expr = "a consent-pending session is issued to human user {string}")]
fn consent_pending_session_is_issued(
    world: &mut SurfaceWorld,
    username: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert_eq!(response.body["username"], username);
    assert_eq!(response.body["consent_required"], true);
}

#[given(expr = "administrator {string} has a consent-pending session")]
async fn administrator_has_consent_pending_session(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login(world, &username, "administrator").await;
    world
        .operator_clients
        .insert(username, client);
}

#[given(expr = "administrator {string} loaded the applicable Terms")]
async fn administrator_loaded_applicable_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    let status = client
        .send_recorded_json::<Value>(Method::GET, "/v1/terms/status", None)
        .await
        .expect("Terms status request should complete");
    let accepted_terms = status.body["required_terms"]
        .as_array()
        .expect("required_terms should be an array")
        .iter()
        .map(|term| {
            json!({
                "terms_type": term["terms_type"],
                "version_id": term["version_id"],
                "accepted": true,
            })
        })
        .collect::<Vec<_>>();
    world.sent_body = Some(json!({ "accepted_terms": accepted_terms }));
}

#[when(expr = "administrator {string} submits the previously loaded Terms")]
async fn administrator_submits_previously_loaded_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    world.caller_response = Some(
        client
            .send_recorded_json(Method::POST, "/v1/terms/acceptances", world.sent_body.as_ref())
            .await
            .expect("Terms acceptance request should complete"),
    );
}

#[then("the acceptance is rejected as stale")]
fn acceptance_is_rejected_as_stale(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("Terms acceptance response should exist");
    assert_eq!(response.body["code"], "TERMS_VERSION_STALE");
}

#[when(expr = "administrator {string} requests a protected Admin API resource")]
async fn administrator_requests_protected_resource(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = world
        .operator_clients
        .get(&username)
        .unwrap_or_else(|| panic!("administrator {username:?} should have a client"));
    world.caller_response = Some(
        client
            .send_recorded_json::<Value>(Method::GET, "/v1/settings", None)
            .await
            .expect("protected Admin API request should complete"),
    );
}

#[then("the request is rejected because Terms acceptance is required")]
fn request_is_rejected_for_terms(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("request response should exist");
    assert_eq!(response.body["code"], "TERMS_ACCEPTANCE_REQUIRED");
}

#[given(expr = "human user {string} has two consent-pending sessions")]
async fn human_user_has_two_pending_sessions(
    world: &mut SurfaceWorld,
    username: String,
) {
    login(world, &username, "administrator").await;
    login(world, &username, "administrator").await;
}

#[given("one session has accepted all applicable Terms")]
async fn one_session_accepts_terms(world: &mut SurfaceWorld) {
    let client = world
        .human_clients
        .values()
        .next()
        .and_then(|clients| clients.first())
        .expect("a pending human session should exist")
        .clone();
    accept_current_terms(&client).await;
}

#[when("the other session requests a protected product resource")]
async fn other_session_requests_product_resource(world: &mut SurfaceWorld) {
    let client = world
        .human_clients
        .values()
        .next()
        .and_then(|clients| clients.get(1))
        .expect("a second human session should exist")
        .clone();
    world.caller_response = Some(
        client
            .send_recorded_json::<Value>(Method::GET, "/v1/settings", None)
            .await
            .expect("protected product request should complete"),
    );
}

#[when(expr = "administrator {string} requests the T&C Manager data")]
async fn administrator_requests_terms_manager_data(
    world: &mut SurfaceWorld,
    username: String,
) {
    world.caller_response = Some(
        latest_client(world, &username)
            .send_recorded_json::<Value>(Method::GET, "/v1/terms", None)
            .await
            .expect("T&C Manager request should complete"),
    );
}

#[then("the Affinidi Terms provider status is degraded")]
fn affinidi_provider_status_is_degraded(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("T&C Manager response should exist");
    assert_eq!(response.body["affinidi_provider"]["state"], "degraded");
}

#[then(expr = "Affinidi Terms version {string} remains active")]
fn affinidi_terms_version_remains_active(
    world: &mut SurfaceWorld,
    version: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("T&C Manager response should exist");
    assert_eq!(response.body["affinidi"]["version"], version);
}

#[then("the request succeeds")]
fn request_succeeds(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("request response should exist");
    assert_eq!(response.status, 200, "expected status 200, got {}: {}", response.status, response.body);
}

#[when(expr = "human user {string} signs in and requests Terms status")]
async fn human_user_signs_in_and_requests_terms_status(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login(world, &username, "administrator").await;
    world.caller_response = Some(
        client
            .send_recorded_json::<Value>(Method::GET, "/v1/terms/status", None)
            .await
            .expect("Terms status request should complete"),
    );
}

#[then("only Affinidi Terms require acceptance")]
fn only_affinidi_terms_require_acceptance(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("Terms status response should exist");
    assert_eq!(response.status, 200, "Terms status should succeed: {}", response.body);
    let required = response.body["required_terms"]
        .as_array()
        .expect("required_terms should be an array");
    assert_eq!(required.len(), 1);
    assert_eq!(required[0]["terms_type"], "affinidi");
}

#[given(expr = "human user {string} accepted Customer Terms version {string}")]
async fn human_user_accepted_customer_terms(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
) {
    accepted_customer_terms(world, &username, &version).await;
}

#[given(expr = "current Customer Terms version {string} requires re-consent")]
async fn current_customer_terms_requires_reconsent(
    world: &mut SurfaceWorld,
    version: String,
) {
    let username = world
        .human_clients
        .keys()
        .next()
        .expect("an accepted human user should exist")
        .clone();
    publish_customer_terms_version(world, &username, &version).await;
}

#[given(expr = "human user {string} has an unrestricted session after accepting Customer Terms version {string}")]
async fn human_user_has_unrestricted_session(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
) {
    accepted_customer_terms(world, &username, &version).await;
}

#[when(expr = "human user {string} requests a protected product resource with the active session")]
async fn human_user_requests_with_active_session(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    world.caller_response = Some(
        client
            .send_recorded_json::<Value>(Method::GET, "/v1/settings", None)
            .await
            .expect("protected product request should complete"),
    );
}

#[then("authentication fails because Terms status is unavailable")]
fn authentication_fails_for_terms_status(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert_eq!(response.status, 503);
    assert_eq!(response.body["code"], "TERMS_OPERATIONAL_FAILURE");
}

#[then("no authenticated session is issued")]
fn no_authenticated_session_is_issued(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert!(
        response
            .body
            .get("session_token")
            .is_none()
    );
}

#[given(expr = "administrator {string} has saved Customer Terms draft version {string} at {string}")]
async fn administrator_saved_customer_terms_draft(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
    url: String,
) {
    let client = login(world, &username, "administrator").await;
    accept_current_terms(&client).await;
    save_customer_draft(&client, &version, &url, true).await;
    world
        .operator_clients
        .insert(username, client);
}

#[when(expr = "administrator {string} publishes the Customer Terms draft")]
async fn administrator_publishes_customer_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = world
        .operator_clients
        .get(&username)
        .unwrap_or_else(|| panic!("administrator {username:?} should have a client"));
    world.admin_response = Some(publish_customer_terms(client).await);
}

#[then(expr = "Customer Terms version {string} is published")]
fn customer_terms_version_is_published(
    world: &mut SurfaceWorld,
    version: String,
) {
    let response = world
        .admin_response
        .as_ref()
        .expect("publication response should exist");
    assert_eq!(response.status, 201, "publication should succeed: {}", response.body);
    assert_eq!(response.body["version"], version);
}

#[then("the published Customer Terms have an immutable version ID")]
fn published_customer_terms_have_version_id(world: &mut SurfaceWorld) {
    let version_id = world
        .admin_response
        .as_ref()
        .and_then(|response| response.body["version_id"].as_str())
        .unwrap_or_default();
    assert!(!version_id.is_empty(), "published Customer Terms should have a version ID");
}

#[given(expr = "human user {string} lacks permission to edit Customer Terms")]
async fn human_user_lacks_terms_edit_permission(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login(world, &username, "user").await;
    accept_current_terms(&client).await;
}

#[given("a Customer Terms draft is ready to publish")]
async fn customer_terms_draft_is_ready(world: &mut SurfaceWorld) {
    let client = login(world, "terms-admin", "administrator").await;
    accept_current_terms(&client).await;
    save_customer_draft(&client, "1", "https://example.com/terms/1", true).await;
}

#[when(expr = "human user {string} attempts to publish the Customer Terms draft")]
async fn human_user_attempts_to_publish(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    world.caller_response = Some(publish_customer_terms(&client).await);
}

#[then("publication is forbidden")]
fn publication_is_forbidden(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("publication response should exist");
    assert_eq!(response.status, 403, "expected forbidden publication, got {}", response.body);
}
