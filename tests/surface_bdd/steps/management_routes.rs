use std::io::Write;
use std::path::PathBuf;

use cucumber::{given, then, when};
use reqwest::{Method, header};
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{AdminApiClient, RecordedResponse, recorded_response};
use crate::steps::when::{ensure_admin_session, ensure_gateway_running, gateway_is_running};
use crate::world::SurfaceWorld;

const WELCOME_TEMPLATE_PATH: &str = "/v1/notifications/user-welcome-template";
const PROBE_TOKEN_ENDPOINT: &str = "https://192.0.2.1/token";
const AGENTS_PATH: &str = "/v1/agents";
const SURFACE_ID: &str = "bdd-surface";
const TENANT_HEADER: &str = "x-external-account";
/// A personal access token resource pattern that matches every surface id.
const ALL_SURFACES: &str = ".*";

/// Who calls a management route in a scenario.
enum Caller<'a> {
    Operator(&'a str),
    PersonalAccessToken,
}

fn operator_client<'a>(
    world: &'a SurfaceWorld,
    operator: &str,
    path: &str,
) -> &'a AdminApiClient {
    world
        .operator_clients
        .get(operator)
        .unwrap_or_else(|| panic!("operator '{operator}' must have a role before calling {path}"))
}

async fn send(
    world: &SurfaceWorld,
    caller: Caller<'_>,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    match caller {
        Caller::Operator(operator) => operator_client(world, operator, path)
            .send_recorded_json(method, path, body)
            .await
            .unwrap_or_else(|error| panic!("{path} as operator '{operator}': {error}")),
        Caller::PersonalAccessToken => send_with_personal_access_token(world, method, path, body).await,
    }
}

async fn send_with_personal_access_token(
    world: &SurfaceWorld,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let mut request = world
        .personal_access_token_client
        .as_ref()
        .expect("an operator must hold a personal access token")
        .request(method, format!("http://127.0.0.1:{port}/api{path}"));
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request
        .send()
        .await
        .unwrap_or_else(|error| panic!("{path} with the personal access token: {error}"));
    recorded_response(response)
        .await
        .unwrap_or_else(|error| panic!("reading the {path} response: {error}"))
}

async fn record(
    world: &mut SurfaceWorld,
    caller: Caller<'_>,
    method: Method,
    path: &str,
    body: Option<&Value>,
) {
    let response = send(world, caller, method, path, body).await;
    world.admin_response = Some(response);
}

fn management_response(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .admin_response
        .as_ref()
        .expect("a management request must have been sent")
}

fn log_directory(world: &SurfaceWorld) -> PathBuf {
    world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        ._temp_dir
        .path()
        .join("_storage/logs")
}

async fn user_id_of(
    world: &SurfaceWorld,
    operator: &str,
) -> String {
    let profile = send(world, Caller::Operator(operator), Method::GET, "/v1/profile", None).await;
    assert_eq!(profile.status, 200, "reading the profile of operator '{operator}': {}", profile.body);
    profile.body["user_id"]
        .as_str()
        .expect("a profile carries the user id")
        .to_string()
}

async fn notification_titles(
    world: &SurfaceWorld,
    operator: &str,
) -> Vec<String> {
    let response = send(world, Caller::Operator(operator), Method::GET, "/v1/notifications", None).await;
    assert_eq!(response.status, 200, "listing the notifications of operator '{operator}': {}", response.body);
    response
        .body
        .as_array()
        .expect("notifications are a list")
        .iter()
        .filter_map(|notification| notification["title"].as_str())
        .map(str::to_string)
        .collect()
}

async fn welcome_template_title(
    world: &SurfaceWorld,
    operator: &str,
) -> String {
    let response = send(world, Caller::Operator(operator), Method::GET, WELCOME_TEMPLATE_PATH, None).await;
    assert_eq!(response.status, 200, "reading the user welcome template: {}", response.body);
    response.body["title"]
        .as_str()
        .expect("the welcome template has a title")
        .to_string()
}

async fn remove_old_log_files(
    world: &mut SurfaceWorld,
    caller: Caller<'_>,
) {
    record(world, caller, Method::POST, "/v1/logs/truncate", None).await;
}

async fn truncate_stored_metrics(
    world: &mut SurfaceWorld,
    caller: Caller<'_>,
) {
    record(world, caller, Method::POST, "/v1/metrics/truncate", None).await;
}

async fn read_welcome_template(
    world: &mut SurfaceWorld,
    caller: Caller<'_>,
) {
    record(world, caller, Method::GET, WELCOME_TEMPLATE_PATH, None).await;
}

async fn change_welcome_template_title(
    world: &mut SurfaceWorld,
    caller: Caller<'_>,
    title: &str,
) {
    let template = json!({"title": title, "message": "Changed welcome message"});
    record(world, caller, Method::PUT, WELCOME_TEMPLATE_PATH, Some(&template)).await;
}

async fn send_welcome_notification(
    world: &mut SurfaceWorld,
    caller: Caller<'_>,
    title: &str,
    recipient: &str,
) {
    let user_id = user_id_of(world, recipient).await;
    let request = json!({"user_id": user_id, "title": title, "message": "Welcome message"});
    record(world, caller, Method::POST, "/v1/notifications/send-welcome", Some(&request)).await;
}

/// Mints a personal access token of `tenant`, limited to the tenant's surfaces that
/// `surfaces` matches, for the scenario's personal access token steps.
async fn hold_tenant_token(
    world: &mut SurfaceWorld,
    tenant: &str,
    surfaces: &str,
) {
    ensure_admin_session(world).await;
    let request = json!({
        "name": "agents token",
        "scopes": [],
        "resource_pattern": format!("TENANT:${{x-external-account}}:surfaces:{surfaces}"),
        "required_headers": [{"name": TENANT_HEADER, "pattern": tenant}],
    });
    let mut headers = header::HeaderMap::new();
    headers.insert(TENANT_HEADER, header::HeaderValue::from_str(tenant).expect("a tenant header"));
    let client = world
        .admin_client
        .as_ref()
        .expect("the operator session must exist")
        .personal_access_token_client(&request, headers)
        .await;
    world.personal_access_token_client = Some(client);
}

/// `/v1/agents/{id}` of the surface's agent, followed by `suffix`.
fn surface_agent_path(
    world: &SurfaceWorld,
    suffix: &str,
) -> String {
    let id = world
        .surface_agent_id
        .as_deref()
        .expect("the operator must have looked up the surface's agent");
    format!("{AGENTS_PATH}/{id}{suffix}")
}

/// The id of the agent in an agents list that the surface under test uses.
fn agent_of_surface(body: &Value) -> Option<&str> {
    body["agents"]
        .as_array()?
        .iter()
        .find(|agent| {
            agent["surfaces"]
                .as_array()
                .is_some_and(|surfaces| {
                    surfaces
                        .iter()
                        .any(|surface| surface["surface_id"] == SURFACE_ID)
                })
        })?["id"]
        .as_str()
}

/// The id of the surface's agent, as the operator lists it.
async fn agent_id_of_surface(world: &mut SurfaceWorld) -> String {
    ensure_admin_session(world).await;
    let listed = world
        .admin_client
        .as_ref()
        .expect("the operator session must exist")
        .send_recorded_json::<Value>(Method::GET, AGENTS_PATH, None)
        .await
        .expect("listing the agents as the operator");
    assert_eq!(listed.status, 200, "listing the agents as the operator: {}", listed.body);
    agent_of_surface(&listed.body)
        .unwrap_or_else(|| panic!("the operator's agents list has no agent of {SURFACE_ID}: {}", listed.body))
        .to_string()
}

#[given(expr = "a log file {string}")]
async fn log_file(
    world: &mut SurfaceWorld,
    file_name: String,
) {
    if !world
        .surface_config
        .writes_log_directory
    {
        assert!(
            !gateway_is_running(world),
            "\"a log file\" must come before any step that starts the gateway: the running gateway \
             was started without a log directory"
        );
        world
            .surface_config
            .writes_log_directory = true;
    }
    ensure_gateway_running(world).await;
    let directory = log_directory(world);
    std::fs::create_dir_all(&directory).expect("creating the log directory");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join(&file_name))
        .and_then(|mut file| file.write_all(b"a log line\n"))
        .unwrap_or_else(|error| panic!("writing log file {file_name}: {error}"));
}

#[given(expr = "operator {string} holds a personal access token with scopes {string}")]
async fn operator_holds_personal_access_token(
    world: &mut SurfaceWorld,
    operator: String,
    scopes: String,
) {
    let scopes: Vec<&str> = scopes
        .split(',')
        .map(str::trim)
        .collect();
    let request = json!({"name": "management route token", "scopes": scopes});
    let client = operator_client(world, &operator, "/v1/access-tokens")
        .personal_access_token_client(&request, header::HeaderMap::new())
        .await;
    world.personal_access_token_client = Some(client);
}

#[given(expr = "a personal access token of tenant {string}")]
async fn tenant_personal_access_token(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    hold_tenant_token(world, &tenant, ALL_SURFACES).await;
}

#[given(expr = "a personal access token of tenant {string} limited to surface {string}")]
async fn surface_limited_tenant_personal_access_token(
    world: &mut SurfaceWorld,
    tenant: String,
    surface: String,
) {
    hold_tenant_token(world, &tenant, &regex::escape(&surface)).await;
}

#[given("the operator has looked up the surface's agent")]
async fn operator_looked_up_surface_agent(world: &mut SurfaceWorld) {
    world.surface_agent_id = Some(agent_id_of_surface(world).await);
}

#[when(expr = "operator {string} removes old log files")]
async fn operator_removes_old_log_files(
    world: &mut SurfaceWorld,
    operator: String,
) {
    remove_old_log_files(world, Caller::Operator(&operator)).await;
}

#[when("the personal access token removes old log files")]
async fn personal_access_token_removes_old_log_files(world: &mut SurfaceWorld) {
    remove_old_log_files(world, Caller::PersonalAccessToken).await;
}

#[when(expr = "operator {string} downloads the server logs")]
async fn operator_downloads_server_logs(
    world: &mut SurfaceWorld,
    operator: String,
) {
    record(world, Caller::Operator(&operator), Method::GET, "/v1/logs/download", None).await;
}

#[when(expr = "operator {string} truncates stored metrics")]
async fn operator_truncates_stored_metrics(
    world: &mut SurfaceWorld,
    operator: String,
) {
    truncate_stored_metrics(world, Caller::Operator(&operator)).await;
}

#[when("the personal access token truncates stored metrics")]
async fn personal_access_token_truncates_stored_metrics(world: &mut SurfaceWorld) {
    truncate_stored_metrics(world, Caller::PersonalAccessToken).await;
}

#[when(expr = "operator {string} reads the user welcome template")]
async fn operator_reads_welcome_template(
    world: &mut SurfaceWorld,
    operator: String,
) {
    read_welcome_template(world, Caller::Operator(&operator)).await;
}

#[when("the personal access token reads the user welcome template")]
async fn personal_access_token_reads_welcome_template(world: &mut SurfaceWorld) {
    read_welcome_template(world, Caller::PersonalAccessToken).await;
}

#[when(expr = "operator {string} changes the user welcome template title to {string}")]
async fn operator_changes_welcome_template_title(
    world: &mut SurfaceWorld,
    operator: String,
    title: String,
) {
    change_welcome_template_title(world, Caller::Operator(&operator), &title).await;
}

#[when(expr = "the personal access token changes the user welcome template title to {string}")]
async fn personal_access_token_changes_welcome_template_title(
    world: &mut SurfaceWorld,
    title: String,
) {
    change_welcome_template_title(world, Caller::PersonalAccessToken, &title).await;
}

#[when(expr = "operator {string} sends a welcome notification titled {string} to operator {string}")]
async fn operator_sends_welcome_notification(
    world: &mut SurfaceWorld,
    sender: String,
    title: String,
    recipient: String,
) {
    send_welcome_notification(world, Caller::Operator(&sender), &title, &recipient).await;
}

#[when(expr = "the personal access token sends a welcome notification titled {string} to operator {string}")]
async fn personal_access_token_sends_welcome_notification(
    world: &mut SurfaceWorld,
    title: String,
    recipient: String,
) {
    send_welcome_notification(world, Caller::PersonalAccessToken, &title, &recipient).await;
}

#[when(expr = "operator {string} validates a credential provider")]
async fn operator_validates_credential_provider(
    world: &mut SurfaceWorld,
    operator: String,
) {
    let provider = json!({
        "provider_type": "oauth2_client_credentials",
        "token_endpoint": PROBE_TOKEN_ENDPOINT,
        "client_id_secret_ref": "probe-client-id",
        "client_secret_secret_ref": "probe-client-secret",
    });
    record(world, Caller::Operator(&operator), Method::POST, "/v1/credential-providers/validate", Some(&provider))
        .await;
}

#[when("the personal access token lists the agents")]
async fn personal_access_token_lists_agents(world: &mut SurfaceWorld) {
    record(world, Caller::PersonalAccessToken, Method::GET, AGENTS_PATH, None).await;
}

#[when("the personal access token reads the surface's agent")]
async fn personal_access_token_reads_surface_agent(world: &mut SurfaceWorld) {
    let path = surface_agent_path(world, "");
    record(world, Caller::PersonalAccessToken, Method::GET, &path, None).await;
}

#[when("the personal access token reads the agent card of the surface's agent")]
async fn personal_access_token_reads_agent_card_of_surface(world: &mut SurfaceWorld) {
    let path = surface_agent_path(world, "/agent-card");
    record(world, Caller::PersonalAccessToken, Method::GET, &path, None).await;
}

#[when("the operator reads the agent card of the surface's agent")]
async fn operator_reads_agent_card_of_surface(world: &mut SurfaceWorld) {
    let path = surface_agent_path(world, "/agent-card");
    operator_reads_agent_card(world, &path).await;
}

#[when("the operator reads the agent card of the surface's agent through that surface")]
async fn operator_reads_agent_card_through_surface(world: &mut SurfaceWorld) {
    let path = surface_agent_path(world, &format!("/agent-card?surface_id={SURFACE_ID}"));
    operator_reads_agent_card(world, &path).await;
}

async fn operator_reads_agent_card(
    world: &mut SurfaceWorld,
    path: &str,
) {
    let response = world
        .admin_client
        .as_ref()
        .expect("the operator session must exist")
        .send_recorded_json::<Value>(Method::GET, path, None)
        .await
        .expect("reading the agent card as the operator");
    world.admin_response = Some(response);
}

#[then(expr = "the agent card is available with source {string}")]
fn agent_card_is_available_with_source(
    world: &mut SurfaceWorld,
    source: String,
) {
    let body = &management_response(world).body;
    assert_eq!((&body["available"], &body["source"]), (&json!(true), &json!(source)), "the agent card answer: {body}");
    assert!(body["card"]["name"].is_string(), "the agent card names the agent: {body}");
}

#[then("the agent card points at the gateway")]
fn agent_card_points_at_gateway(world: &mut SurfaceWorld) {
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let body = &management_response(world).body;
    let url = body["card"]["url"]
        .as_str()
        .unwrap_or_else(|| panic!("the agent card names a url: {body}"));
    assert!(url.contains(&format!("localhost:{port}")), "{url} does not point at the gateway");
}

#[then("the agents list names the surface")]
fn agents_list_names_surface(world: &mut SurfaceWorld) {
    let body = &management_response(world).body;
    assert!(agent_of_surface(body).is_some(), "the agents list has no agent of {SURFACE_ID}: {body}");
    assert!(body["window_minutes"].is_u64(), "the agents list names its window: {body}");
}

#[then("the agents list is empty")]
fn agents_list_is_empty(world: &mut SurfaceWorld) {
    let body = &management_response(world).body;
    assert_eq!(body["agents"], json!([]), "the agents list: {body}");
}

#[then("the agent answer names the surface")]
fn agent_answer_names_surface(world: &mut SurfaceWorld) {
    let body = &management_response(world).body;
    let surface_ids: Vec<&str> = body["surfaces"]
        .as_array()
        .expect("an agent lists its surfaces")
        .iter()
        .filter_map(|surface| surface["surface_id"].as_str())
        .collect();
    assert_eq!(surface_ids, vec![SURFACE_ID], "the agent's surfaces: {body}");
}

#[then("the agent card is unavailable because only an operator may read it")]
fn agent_card_is_operator_only(world: &mut SurfaceWorld) {
    assert_agent_card_unavailable(world, "operator_only");
}

#[then("the agent card is unavailable because none of the agent's surfaces is running")]
fn agent_card_is_not_running(world: &mut SurfaceWorld) {
    assert_agent_card_unavailable(world, "not_running");
}

#[then("the agent card can't be read through that surface")]
fn agent_card_surface_unavailable(world: &mut SurfaceWorld) {
    let body = &management_response(world).body;
    assert_eq!(
        (&body["error"], &body["code"]),
        (&json!("Not Found"), &json!("surface_unavailable")),
        "the agent card answer: {body}"
    );
}

fn assert_agent_card_unavailable(
    world: &SurfaceWorld,
    reason: &str,
) {
    let body = &management_response(world).body;
    assert_eq!(
        (&body["available"], &body["reason"], body.get("card")),
        (&json!(false), &json!(reason), None),
        "the agent card answer: {body}"
    );
}

#[then(expr = "the response reports {int} removed log file(s)")]
fn response_reports_removed_log_files(
    world: &mut SurfaceWorld,
    expected: u64,
) {
    let body = &management_response(world).body;
    assert_eq!(body["files_removed"].as_u64(), Some(expected), "removed log files: {body}");
}

#[then("the response reports the removed and retained metrics records")]
fn response_reports_metrics_records(world: &mut SurfaceWorld) {
    let body = &management_response(world).body;
    for field in ["connections_removed", "events_removed", "connections_retained", "events_retained"] {
        assert!(body[field].is_u64(), "metrics truncation reports {field}: {body}");
    }
}

#[then("the response reports the token endpoint the credential provider validation checked")]
fn response_reports_validated_token_endpoint(world: &mut SurfaceWorld) {
    let body = &management_response(world).body;
    assert_eq!(body["token_endpoint"].as_str(), Some(PROBE_TOKEN_ENDPOINT), "validated token endpoint: {body}");
    assert!(body["reachable"].is_boolean(), "the validation reports whether the token endpoint answered: {body}");
}

#[then("the answer is a ZIP archive of the server logs")]
fn answer_is_server_log_archive(world: &mut SurfaceWorld) {
    let headers = &management_response(world).headers;
    assert_eq!(
        (
            headers
                .get("content-type")
                .map(String::as_str),
            headers
                .get("content-disposition")
                .map(String::as_str)
        ),
        (Some("application/zip"), Some(r#"attachment; filename="logs.zip""#)),
        "{headers:?}"
    );
}

#[then(expr = "the log file {string} still exists")]
fn log_file_still_exists(
    world: &mut SurfaceWorld,
    file_name: String,
) {
    let path = log_directory(world).join(&file_name);
    assert!(path.is_file(), "log file {} should still exist", path.display());
}

#[then(expr = "the log file {string} is gone")]
fn log_file_is_gone(
    world: &mut SurfaceWorld,
    file_name: String,
) {
    let path = log_directory(world).join(&file_name);
    assert!(!path.exists(), "log file {} should have been removed", path.display());
}

#[then(expr = "operator {string} reads a user welcome template titled {string}")]
async fn operator_reads_welcome_template_titled(
    world: &mut SurfaceWorld,
    operator: String,
    title: String,
) {
    let stored_title = welcome_template_title(world, &operator).await;
    assert_eq!(stored_title, title, "the user welcome template title");
}

#[then(expr = "operator {string} reads a user welcome template not titled {string}")]
async fn operator_reads_welcome_template_not_titled(
    world: &mut SurfaceWorld,
    operator: String,
    title: String,
) {
    let stored_title = welcome_template_title(world, &operator).await;
    assert_ne!(stored_title, title, "the user welcome template title changed");
}

#[then(expr = "operator {string} has a notification titled {string}")]
async fn operator_has_notification_titled(
    world: &mut SurfaceWorld,
    operator: String,
    title: String,
) {
    let titles = notification_titles(world, &operator).await;
    assert!(
        titles.contains(&title),
        "operator '{operator}' should have a notification titled {title:?}, has {titles:?}"
    );
}

#[then(expr = "operator {string} has no notification titled {string}")]
async fn operator_has_no_notification_titled(
    world: &mut SurfaceWorld,
    operator: String,
    title: String,
) {
    let titles = notification_titles(world, &operator).await;
    assert!(
        !titles.contains(&title),
        "operator '{operator}' should have no notification titled {title:?}, has {titles:?}"
    );
}
