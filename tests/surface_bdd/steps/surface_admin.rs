//! Steps for what an operator reads about a surface through the admin API: the
//! report a save answers with, the declarations of a stored surface and the
//! agent card preview.

use cucumber::{given, then, when};
use reqwest::Method;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::{Value, json};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::admin_client::recorded_response;
use crate::bdd_support::assertions::assert_status_with_body;
use crate::bdd_support::config::gateway_bootstrap::declared_access_point_url;
use crate::bdd_support::config::jwt_verification_strategy::SURFACE_JWT_STRATEGY_ID;
use crate::steps::when::{ensure_admin_session, fetch_surface_by_id, record_admin_response, record_mock_observation};
use crate::world::{RecordedResponse, SurfaceWorld};

const SEEDED_SURFACE_ID: &str = "bdd-surface";
const TENANT_HEADER: &str = "x-external-account";

fn surface_id(world: &SurfaceWorld) -> String {
    world
        .surface_under_test_id
        .clone()
        .or_else(|| {
            world
                .created_surface_id
                .clone()
        })
        .unwrap_or_else(|| {
            assert!(
                world
                    .surface_config
                    .seed_surface,
                "a surface must exist before the operator reads it"
            );
            SEEDED_SURFACE_ID.to_string()
        })
}

fn gateway_port(world: &SurfaceWorld) -> u16 {
    world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port
}

fn admin_response(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .admin_response
        .as_ref()
        .expect("the operator must have received an admin API response")
}

async fn send_as_operator(
    world: &mut SurfaceWorld,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    ensure_admin_session(world).await;
    world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(method, path, body)
        .await
        .unwrap_or_else(|error| panic!("{path} through the admin API: {error:#}"))
}

fn loaded_surface(world: &SurfaceWorld) -> Value {
    world
        .surface_lookup_response
        .as_ref()
        .expect("the operator must have loaded the surface")
        .body
        .clone()
}

async fn save_surface(
    world: &mut SurfaceWorld,
    body: Value,
) {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_keeping_text(Method::PUT, &path, Some(&body))
        .await
        .unwrap_or_else(|error| panic!("{path} through the admin API: {error:#}"));
    record_admin_response(world, response);
}

#[given("the operator has loaded the surface through the admin API")]
async fn operator_has_loaded_surface(world: &mut SurfaceWorld) {
    let id = surface_id(world);
    fetch_surface_by_id(world, &id).await;
    let lookup = world
        .surface_lookup_response
        .as_ref()
        .expect("the surface lookup was just recorded");
    assert_status_with_body(lookup.status, 200, &lookup.body, "surface load");
}

#[when("the operator saves the loaded surface through the admin API")]
async fn operator_saves_loaded_surface(world: &mut SurfaceWorld) {
    let body = loaded_surface(world);
    save_surface(world, body).await;
}

#[given("the operator has saved the loaded surface through the admin API")]
async fn operator_has_saved_loaded_surface(world: &mut SurfaceWorld) {
    operator_saves_loaded_surface(world).await;
    let response = admin_response(world);
    assert_status_with_body(response.status, 200, &response.body, "surface save");
}

#[when(expr = "the operator saves the loaded surface through the admin API with unknown field {string}")]
async fn operator_saves_loaded_surface_with_unknown_field(
    world: &mut SurfaceWorld,
    field: String,
) {
    let mut body = loaded_surface(world);
    body[field.as_str()] = json!("unexpected");
    save_surface(world, body).await;
}

#[when("the operator sends the save response back through the admin API")]
async fn operator_sends_save_response_back(world: &mut SurfaceWorld) {
    let body = admin_response(world)
        .body
        .clone();
    save_surface(world, body).await;
}

#[when("the operator reads the declarations of the surface")]
async fn operator_reads_surface_declarations(world: &mut SurfaceWorld) {
    let path = format!("/v1/surfaces/{}/declarations", surface_id(world));
    let response = send_as_operator(world, Method::GET, &path, None).await;
    record_admin_response(world, response);
}

#[given("the surface's JWT verification strategy has been deleted")]
async fn surface_strategy_has_been_deleted(world: &mut SurfaceWorld) {
    let path = format!("/v1/jwt-verification-strategies/{SURFACE_JWT_STRATEGY_ID}");
    let response = send_as_operator(world, Method::DELETE, &path, None).await;
    assert_status_with_body(response.status, 204, &response.body, "JWT verification strategy deletion");
}

fn reported(
    world: &SurfaceWorld,
    key: &str,
) -> Vec<Value> {
    let body = &admin_response(world).body;
    body.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| panic!("the admin API response must report {key}, got {body}"))
}

fn base_route_declaration(world: &SurfaceWorld) -> Value {
    let declarations = reported(world, "declarations");
    declarations
        .iter()
        .find(|declaration| declaration["variant"].is_null())
        .cloned()
        .unwrap_or_else(|| panic!("the base route must be reported, got {declarations:?}"))
}

#[then(expr = "the reported warnings include {string} about {string} for the base route")]
fn reported_warnings_include(
    world: &mut SurfaceWorld,
    code: String,
    path: String,
) {
    let warnings = reported(world, "warnings");
    assert!(
        warnings
            .iter()
            .any(|warning| warning["code"] == code.as_str()
                && warning["path"] == path.as_str()
                && warning["variant"].is_null()
                && warning["message"]
                    .as_str()
                    .is_some_and(|message| !message.is_empty())),
        "expected a '{code}' warning about '{path}' for the base route, got {warnings:?}"
    );
}

#[then(expr = "the reported warnings do not include {string}")]
fn reported_warnings_exclude(
    world: &mut SurfaceWorld,
    code: String,
) {
    let warnings = reported(world, "warnings");
    assert!(
        !warnings
            .iter()
            .any(|warning| warning["code"] == code.as_str()),
        "expected no '{code}' warning, got {warnings:?}"
    );
}

#[then(expr = "the base route is reported with declaration outcome {string} for reason {string}")]
fn base_route_reported_with_outcome(
    world: &mut SurfaceWorld,
    outcome: String,
    reason: String,
) {
    let declaration = base_route_declaration(world);
    assert_eq!(declaration["outcome"], outcome.as_str(), "declaration was {declaration}");
    assert_eq!(declaration["reason"], reason.as_str(), "declaration was {declaration}");
}

#[then("the base route is reported to declare the surface Access Point URL")]
fn base_route_reported_to_declare(world: &mut SurfaceWorld) {
    let declaration = base_route_declaration(world);
    let access_point_url = declared_access_point_url(gateway_port(world), &world.surface_config.route);
    assert_eq!(declaration["outcome"], "declare", "declaration was {declaration}");
    assert!(declaration["reason"].is_null(), "a declaring route has no strip reason: {declaration}");
    assert_eq!(declaration["resource"], access_point_url.as_str(), "declaration was {declaration}");
}

#[then("the response does not name the surface's JWT verification strategy")]
fn response_does_not_name_strategy(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("the caller must have received a response");
    assert!(
        !response
            .body
            .to_string()
            .contains(SURFACE_JWT_STRATEGY_ID),
        "the response body must not name the strategy, got {}",
        response.body
    );
    assert!(
        response
            .headers
            .values()
            .all(|value| !value.contains(SURFACE_JWT_STRATEGY_ID)),
        "the response headers must not name the strategy, got {:?}",
        response.headers
    );
}

fn preview_request(
    world: &SurfaceWorld,
    action: &str,
) -> (Method, String) {
    let path = format!("/v1/surfaces/{}/agent-card", surface_id(world));
    match action {
        "reads" => (Method::GET, path),
        "refreshes" => (Method::POST, format!("{path}/refresh")),
        other => panic!("unsupported agent card preview action '{other}'"),
    }
}

#[when(regex = r"^the operator (reads|refreshes) the agent card preview of the surface$")]
async fn operator_requests_agent_card_preview(
    world: &mut SurfaceWorld,
    action: String,
) {
    let (method, path) = preview_request(world, &action);
    let response = send_as_operator(world, method, &path, None).await;
    record_admin_response(world, response);
    record_mock_observation(world).await;
}

#[given(regex = r"^the operator has (read|refreshed) the agent card preview of the surface$")]
async fn operator_has_requested_agent_card_preview(
    world: &mut SurfaceWorld,
    action: String,
) {
    let action = match action.as_str() {
        "read" => "reads",
        _ => "refreshes",
    };
    operator_requests_agent_card_preview(world, action.to_string()).await;
    let response = admin_response(world);
    assert_status_with_body(response.status, 200, &response.body, "agent card preview");
}

#[when(regex = r#"^operator "([^"]+)" (reads|refreshes) the agent card preview of the surface$"#)]
async fn named_operator_requests_agent_card_preview(
    world: &mut SurfaceWorld,
    operator: String,
    action: String,
) {
    let (method, path) = preview_request(world, &action);
    let client = world
        .operator_clients
        .get(&operator)
        .unwrap_or_else(|| panic!("operator '{operator}' must have a role before reading the agent card preview"))
        .clone();
    let response = client
        .send_recorded_json::<Value>(method, &path, None)
        .await
        .unwrap_or_else(|error| panic!("{path} as operator '{operator}': {error:#}"));
    record_admin_response(world, response);
}

#[given(expr = "the surface belongs to tenant {string}")]
async fn surface_belongs_to_tenant(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let path = format!("/v1/tenant-ownership/surfaces/{}", surface_id(world));
    let response = send_as_operator(world, Method::PUT, &path, Some(&json!({ "tenant_id": tenant }))).await;
    assert_status_with_body(response.status, 200, &response.body, "surface ownership change");
}

#[given(expr = "the operator has issued an access token for tenant {string}")]
async fn operator_has_issued_tenant_access_token(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let request = json!({
        "name": format!("{tenant} surfaces"),
        "resource_pattern": format!("TENANT:${{{TENANT_HEADER}}}:surfaces:.*"),
        "required_headers": [{ "name": TENANT_HEADER, "pattern": tenant }],
    });
    let response = send_as_operator(world, Method::POST, "/v1/access-tokens", Some(&request)).await;
    assert_eq!(response.status, 201, "issuing an access token for tenant '{tenant}' should succeed");
    let token = response
        .body
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the issued access token for tenant '{tenant}' must carry its secret"))
        .to_string();
    world
        .access_tokens
        .insert(tenant, token);
}

async fn send_as_tenant_token_holder(
    world: &mut SurfaceWorld,
    tenant: &str,
    method: Method,
    path: &str,
) {
    let token = world
        .access_tokens
        .get(tenant)
        .unwrap_or_else(|| panic!("an access token for tenant '{tenant}' must have been issued"))
        .clone();
    let url = format!("http://127.0.0.1:{}/api{path}", gateway_port(world));
    let mut authorization =
        HeaderValue::from_str(&format!("Bearer {token}")).expect("an access token forms a valid header value");
    authorization.set_sensitive(true);
    let response = reqwest::Client::new()
        .request(method, &url)
        .header(AUTHORIZATION, authorization)
        .header(TENANT_HEADER, tenant)
        .send()
        .await
        .unwrap_or_else(|error| panic!("{url} with the access token for tenant '{tenant}': {error}"));
    let recorded = recorded_response(response)
        .await
        .unwrap_or_else(|error| panic!("{url} with the access token for tenant '{tenant}': {error:#}"));
    record_admin_response(world, recorded);
}

#[when(
    regex = r#"^the holder of the access token for tenant "([^"]+)" (reads|refreshes) the agent card preview of the surface$"#
)]
async fn tenant_token_holder_requests_agent_card_preview(
    world: &mut SurfaceWorld,
    tenant: String,
    action: String,
) {
    let (method, path) = preview_request(world, &action);
    send_as_tenant_token_holder(world, &tenant, method, &path).await;
}

#[when(expr = "the holder of the access token for tenant {string} reads the declarations of the surface")]
async fn tenant_token_holder_reads_surface_declarations(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let path = format!("/v1/surfaces/{}/declarations", surface_id(world));
    send_as_tenant_token_holder(world, &tenant, Method::GET, &path).await;
}

fn preview(world: &SurfaceWorld) -> &Value {
    &admin_response(world).body
}

fn published_card(
    world: &SurfaceWorld,
    agent_name: &str,
) -> Value {
    world
        .actors
        .expect_target_kind(agent_name, TargetActorKind::ManagedAgent);
    let collaborator_key = world
        .actors
        .target_collaborator_key(agent_name);
    world
        .collaborator_target(collaborator_key)
        .configured_response
        .body
        .clone()
}

#[then("the agent card preview reports a successful fetch")]
fn preview_reports_successful_fetch(world: &mut SurfaceWorld) {
    let preview = preview(world);
    assert_eq!(preview["supported"], true, "preview was {preview}");
    assert_eq!(preview["fetch"]["status"], "ok", "preview was {preview}");
    assert!(preview["fetch"]["cause"].is_null(), "a successful fetch has no cause: {preview}");
}

fn assert_failed_fetch(
    preview: &Value,
    cause: &str,
    http_status: Value,
) {
    assert_eq!(preview["supported"], true, "preview was {preview}");
    assert_eq!(preview["fetch"]["status"], "failed", "preview was {preview}");
    assert_eq!(preview["fetch"]["cause"], cause, "preview was {preview}");
    assert_eq!(preview["fetch"]["http_status"], http_status, "preview was {preview}");
}

#[then(expr = "the agent card preview reports a failed fetch with cause {string} and HTTP status {int}")]
fn preview_reports_failed_fetch(
    world: &mut SurfaceWorld,
    cause: String,
    http_status: u16,
) {
    assert_failed_fetch(preview(world), &cause, json!(http_status));
}

#[then(expr = "the agent card preview reports a failed fetch with cause {string} and no HTTP status")]
fn preview_reports_failed_fetch_without_status(
    world: &mut SurfaceWorld,
    cause: String,
) {
    assert_failed_fetch(preview(world), &cause, Value::Null);
}

#[then(expr = "the agent card preview reports the Target credential as {string}")]
fn preview_reports_target_credential(
    world: &mut SurfaceWorld,
    result: String,
) {
    let preview = preview(world);
    assert_eq!(preview["auth"]["kind"], "static_secret", "preview was {preview}");
    assert_eq!(preview["auth"]["result"], result.as_str(), "preview was {preview}");
}

#[then(expr = "the agent card preview does not reveal the Target credential from secret {string} with value {string}")]
fn preview_reveals_no_target_credential(
    world: &mut SurfaceWorld,
    secret_id: String,
    secret_value: String,
) {
    let response = admin_response(world);
    let text = response.body.to_string();
    for (what, needle) in [("secret id", &secret_id), ("secret value", &secret_value)] {
        assert!(!text.contains(needle.as_str()), "the preview must not carry the {what}: {text}");
        assert!(
            response
                .headers
                .values()
                .all(|value| !value.contains(needle.as_str())),
            "the preview headers must not carry the {what}: {:?}",
            response.headers
        );
    }
}

#[then("the agent card preview answers from the earlier fetch")]
fn preview_answers_from_earlier_fetch(world: &mut SurfaceWorld) {
    let preview = preview(world);
    assert_eq!(preview["cached"], true, "preview was {preview}");
}

#[then(expr = "the agent card preview shows the card managed agent {string} publishes")]
fn preview_shows_published_card(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let published = published_card(world, &agent_name);
    let preview = preview(world);
    assert_eq!(preview["before"], published, "preview was {preview}");
}

#[then(expr = "the agent card preview shows no card from managed agent {string}")]
fn preview_shows_no_published_card(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let preview = preview(world);
    assert!(preview["before"].is_null(), "no card of '{agent_name}' was obtained: {preview}");
}

#[then("the agent card preview shows the card the caller was served")]
fn preview_shows_served_card(world: &mut SurfaceWorld) {
    let served = &world
        .caller_response
        .as_ref()
        .expect("the caller must have fetched the agent card")
        .body;
    assert!(served.is_object(), "the caller must have been served an agent card, got {served}");
    let preview = preview(world);
    assert_eq!(&preview["after"], served, "preview was {preview}");
}

#[then("the agent card preview shows no served card")]
fn preview_shows_no_served_card(world: &mut SurfaceWorld) {
    let preview = preview(world);
    assert!(preview["after"].is_null(), "the gateway has served no card yet: {preview}");
}

#[then(expr = "the agent card preview reports the declaration outcome {string}")]
fn preview_reports_declaration_outcome(
    world: &mut SurfaceWorld,
    outcome: String,
) {
    let preview = preview(world);
    assert_eq!(preview["outcome"]["outcome"], outcome.as_str(), "preview was {preview}");
    assert!(preview["outcome"]["variant"].is_null(), "the preview is of the base route: {preview}");
}

#[then("the admin API response reveals nothing of the agent card")]
fn admin_response_reveals_no_agent_card(world: &mut SurfaceWorld) {
    let body = &admin_response(world).body;
    for key in ["supported", "fetch", "before", "after", "outcome"] {
        assert!(body.get(key).is_none(), "the response must not carry '{key}': {body}");
    }
}

#[then("the admin API response reveals no declarations or warnings")]
fn admin_response_reveals_no_report(world: &mut SurfaceWorld) {
    let body = &admin_response(world).body;
    for key in ["declarations", "warnings"] {
        assert!(body.get(key).is_none(), "the response must not carry '{key}': {body}");
    }
}

#[then("the VP Audit Log records no caller refusal or source authentication failure")]
async fn vp_audit_log_records_no_caller_refusal(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    let (found, events) = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .wait_for_audit_event(|event| {
            event["event"]
                .get("request_rejected")
                .is_some()
                || event["event"]
                    .get("auth_failed")
                    .is_some()
        })
        .await
        .unwrap_or_else(|error| panic!("the VP Audit Log must be readable: {error:#}"));
    assert!(!found, "expected no caller refusal or source authentication failure, got {events:?}");
}
