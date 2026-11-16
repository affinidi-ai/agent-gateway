use std::io::Write;
use std::path::PathBuf;

use cucumber::{given, then, when};
use reqwest::{Method, header};
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{AdminApiClient, RecordedResponse, recorded_response};
use crate::steps::when::{ensure_gateway_running, gateway_is_running};
use crate::world::SurfaceWorld;

const WELCOME_TEMPLATE_PATH: &str = "/v1/notifications/user-welcome-template";
const PROBE_TOKEN_ENDPOINT: &str = "https://192.0.2.1/token";

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
