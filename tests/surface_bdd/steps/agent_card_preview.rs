use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::agent_card_preview::{CardPreviewApi, PreviewCaller};
use crate::bdd_support::mock_server::MockResponse;
use crate::steps::when::{ensure_admin_session, ensure_gateway_running};
use crate::world::SurfaceWorld;

const SURFACE_ID: &str = "bdd-surface";
const AUDIT_EVENT: &str = "agent_card.preview_fetch";

fn caller_of(
    tenant: Option<String>,
    view_only: bool,
) -> PreviewCaller {
    match (tenant, view_only) {
        (Some(tenant), _) => PreviewCaller::Tenant(tenant),
        (None, true) => PreviewCaller::ViewOnly,
        (None, false) => PreviewCaller::Operator,
    }
}

async fn ask(
    world: &mut SurfaceWorld,
    caller: PreviewCaller,
    refresh: bool,
) {
    ensure_admin_session(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let operator = world
        .admin_client
        .clone()
        .expect("the operator session must exist");
    let api = CardPreviewApi { port, operator: &operator };
    let response = if refresh {
        api.refresh(&caller, SURFACE_ID)
            .await
    } else {
        api.read(&caller, SURFACE_ID)
            .await
    };
    world.admin_response = Some(response);
}

fn preview(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .admin_response
        .as_ref()
        .expect("the agent card preview must have been requested")
}

#[given("the gateway logs its audit events")]
fn gateway_logs_audit_events(world: &mut SurfaceWorld) {
    world
        .surface_config
        .keeps_gateway_log = true;
    world
        .surface_config
        .logs_audit_events = true;
}

#[given(expr = "managed agent {string} serves an Agent Card that names its own address")]
async fn managed_agent_serves_card_naming_its_address(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    ensure_gateway_running(world).await;
    let mock = world.mock_for_target(&agent_name);
    let address = format!("{}/a2a", mock.url());
    mock.set_response(MockResponse::json(json!({"name": "Orders agent", "url": address, "skills": []})))
        .await;
}

#[when("the operator reads the agent card preview of the surface")]
async fn operator_reads_preview(world: &mut SurfaceWorld) {
    ask(world, caller_of(None, false), false).await;
}

#[when("the operator refreshes the agent card preview of the surface")]
async fn operator_refreshes_preview(world: &mut SurfaceWorld) {
    ask(world, caller_of(None, false), true).await;
}

#[when(expr = "a token of tenant {string} reads the agent card preview of the surface")]
async fn tenant_reads_preview(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    ask(world, caller_of(Some(tenant), false), false).await;
}

#[when(expr = "a token of tenant {string} refreshes the agent card preview of the surface")]
async fn tenant_refreshes_preview(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    ask(world, caller_of(Some(tenant), false), true).await;
}

#[when("a view-only token reads the agent card preview of the surface")]
async fn view_only_reads_preview(world: &mut SurfaceWorld) {
    ask(world, caller_of(None, true), false).await;
}

#[when("a view-only token refreshes the agent card preview of the surface")]
async fn view_only_refreshes_preview(world: &mut SurfaceWorld) {
    ask(world, caller_of(None, true), true).await;
}

#[given(expr = "the operator has refreshed the agent card preview {int} times, each answered with {int}")]
async fn operator_has_refreshed_preview_repeatedly(
    world: &mut SurfaceWorld,
    times: usize,
    status: u16,
) {
    for attempt in 1..=times {
        ask(world, caller_of(None, false), true).await;
        let answered = preview(world).status;
        assert_eq!(answered, status, "refresh {attempt} of {times} was answered with {answered}");
    }
}

#[given(expr = "the operator's next refresh was refused with {int}")]
async fn operators_next_refresh_was_refused(
    world: &mut SurfaceWorld,
    status: u16,
) {
    ask(world, caller_of(None, false), true).await;
    assert_eq!(preview(world).status, status, "{}", preview(world).body);
}

#[then(expr = "the agent card preview answers {int}")]
fn preview_answers(
    world: &mut SurfaceWorld,
    status: u16,
) {
    let response = preview(world);
    assert_eq!(response.status, status, "agent card preview answer: {}", response.body);
}

fn preview_field<'a>(
    world: &'a SurfaceWorld,
    pointer: &str,
) -> &'a Value {
    let response = preview(world);
    response
        .body
        .pointer(pointer)
        .unwrap_or_else(|| panic!("the agent card preview has no {pointer}: {}", response.body))
}

#[then(expr = "the agent card preview field {string} is {string}")]
fn preview_field_is_text(
    world: &mut SurfaceWorld,
    field: String,
    expected: String,
) {
    let pointer = format!("/{}", field.replace('.', "/"));
    assert_eq!(preview_field(world, &pointer), &json!(expected), "agent card preview field {field}");
}

#[then(expr = "the agent card preview field {string} is true")]
fn preview_field_is_true(
    world: &mut SurfaceWorld,
    field: String,
) {
    let pointer = format!("/{}", field.replace('.', "/"));
    assert_eq!(preview_field(world, &pointer), &json!(true), "agent card preview field {field}");
}

#[then(expr = "the agent card preview field {string} is false")]
fn preview_field_is_false(
    world: &mut SurfaceWorld,
    field: String,
) {
    let pointer = format!("/{}", field.replace('.', "/"));
    assert_eq!(preview_field(world, &pointer), &json!(false), "agent card preview field {field}");
}

#[then(expr = "the agent card preview field {string} is empty")]
fn preview_field_is_empty(
    world: &mut SurfaceWorld,
    field: String,
) {
    let pointer = format!("/{}", field.replace('.', "/"));
    assert_eq!(preview_field(world, &pointer), &Value::Null, "agent card preview field {field}");
}

#[then(expr = "the agent card preview shows no card and no fetch result")]
fn preview_shows_nothing_fetched(world: &mut SurfaceWorld) {
    for field in ["before", "after", "auth", "fetch"] {
        assert_eq!(&preview(world).body[field], &Value::Null, "agent card preview field {field}");
    }
}

#[then(expr = "the agent card preview shows the card of managed agent {string} as the agent publishes it")]
fn preview_shows_managed_card(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let target_url = world
        .mock_for_target(&agent_name)
        .url();
    assert_eq!(preview_field(world, "/before/name"), &json!("Orders agent"));
    assert_eq!(preview_field(world, "/before/url"), &json!(format!("{target_url}/a2a")));
}

#[then("the agent card preview shows the card the gateway serves, pointing at the gateway")]
fn preview_shows_served_card(world: &mut SurfaceWorld) {
    let gateway = format!(
        "{}/",
        world
            .infra
            .as_ref()
            .expect("the gateway must be running")
            .gateway_port
    );
    let served = preview_field(world, "/after/url")
        .as_str()
        .expect("the served card names a url")
        .to_string();
    let served_card_url = preview_field(world, "/served_url")
        .as_str()
        .expect("the preview names the served card address")
        .to_string();
    assert_eq!(preview_field(world, "/after/name"), &json!("Orders agent"));
    for url in [&served, &served_card_url] {
        assert!(
            url.contains(&format!("localhost:{}", gateway.trim_end_matches('/'))),
            "{url} does not point at the gateway"
        );
    }
    assert!(
        served_card_url.ends_with("/smoke/.well-known/agent-card.json"),
        "the served card address is the surface's card route: {served_card_url}"
    );
}

#[then(expr = "managed agent {string} received {int} request(s)")]
async fn managed_agent_received_requests(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected: usize,
) {
    let requests = world
        .mock_for_target(&agent_name)
        .requests()
        .await;
    assert_eq!(requests.len(), expected, "managed agent {agent_name} received {requests:?}");
}

#[then(expr = "managed agent {string} received a request for its agent card without the operator's credentials")]
async fn managed_agent_received_card_fetch(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let requests = world
        .mock_for_target(&agent_name)
        .requests()
        .await;
    assert_eq!(requests.len(), 1, "managed agent {agent_name} received {requests:?}");
    let request = &requests[0];
    assert_eq!(request.method, "GET");
    assert!(
        request
            .path_and_query
            .ends_with("/.well-known/agent-card.json"),
        "the agent was asked for {}",
        request.path_and_query
    );
    for header in ["authorization", "cookie"] {
        assert!(
            !request
                .headers
                .contains_key(header),
            "the agent received a {header} header: {:?}",
            request.headers
        );
    }
}

#[then(expr = "the agent card preview response tells the operator to retry within {int} seconds")]
fn preview_response_retry_after(
    world: &mut SurfaceWorld,
    seconds: u64,
) {
    let header = preview(world)
        .headers
        .get("retry-after")
        .cloned();
    let wait: u64 = header
        .as_deref()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("a numeric retry-after header, got {header:?}"));
    assert!((1..=seconds).contains(&wait), "retry-after {wait} is not within 1 to {seconds} seconds");
}

fn audit_lines(world: &SurfaceWorld) -> Vec<String> {
    let path = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        ._temp_dir
        .path()
        .join("gateway.log");
    let log =
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("the gateway log {}: {error}", path.display()));
    let mut plain = String::new();
    let mut chars = log.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for skipped in chars.by_ref() {
                if skipped.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
        .lines()
        .filter(|line| line.contains(AUDIT_EVENT))
        .map(str::to_string)
        .collect()
}

#[then(expr = "the audit log holds {int} agent card preview fetch event(s)")]
fn audit_holds_fetch_events(
    world: &mut SurfaceWorld,
    expected: usize,
) {
    let lines = audit_lines(world);
    assert_eq!(lines.len(), expected, "agent card preview fetch events: {lines:?}");
}

#[then(expr = "the agent card preview fetch event records {string}")]
fn audit_event_records(
    world: &mut SurfaceWorld,
    field: String,
) {
    let lines = audit_lines(world);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&field)),
        "no agent card preview fetch event records {field}: {lines:?}"
    );
}

#[then("the agent card preview fetch event shows no target URL")]
fn audit_event_shows_no_target_url(world: &mut SurfaceWorld) {
    let target = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .mock
        .url();
    let port = target
        .rsplit(':')
        .next()
        .expect("the target url has a port")
        .to_string();
    for line in audit_lines(world) {
        assert!(
            !line.contains(&target) && !line.contains(&format!(":{port}")),
            "the audit event shows the target url: {line}"
        );
        assert!(!line.contains("http://") && !line.contains("https://"), "the audit event shows a url: {line}");
    }
}

#[then(expr = "the agent card preview fetch event does not show {string}")]
fn audit_event_does_not_show(
    world: &mut SurfaceWorld,
    text: String,
) {
    for line in audit_lines(world) {
        assert!(!line.contains(&text), "the audit event shows {text:?}: {line}");
    }
}
