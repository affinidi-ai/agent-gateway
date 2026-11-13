use std::sync::{Arc, Mutex};
use std::time::Duration;

use cucumber::{given, then, when};
use futures::StreamExt;
use reqwest::Method;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::bdd_support::admin_client::RecordedResponse;
use crate::steps::given::tracked_surface_id;
use crate::steps::policy_changes::{client, send};
use crate::world::SurfaceWorld;

const CAPTURED: &str = "policy_input_captured";
const THE_OPERATOR: &str = "";

fn capture_path(
    world: &SurfaceWorld,
    surface_name: &str,
) -> String {
    format!("/v1/surfaces/{}/policy-input-capture", tracked_surface_id(world, surface_name))
}

async fn switch_on(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
    surface_name: &str,
    minutes: i64,
) -> RecordedResponse {
    let path = capture_path(world, surface_name);
    send(world, operator, Method::PUT, &path, Some(&json!({ "minutes": minutes }))).await
}

async fn switch_off(
    world: &mut SurfaceWorld,
    surface_name: &str,
) -> RecordedResponse {
    let path = capture_path(world, surface_name);
    send(world, None, Method::DELETE, &path, None).await
}

async fn stored_surface(
    world: &mut SurfaceWorld,
    surface_name: &str,
) -> Value {
    let surface_id = tracked_surface_id(world, surface_name);
    let response = client(world, None)
        .await
        .get_surface_recorded(&surface_id)
        .await
        .unwrap_or_else(|error| panic!("read surface '{surface_name}' through admin API: {error}"));
    assert_eq!(response.status, 200, "read surface '{surface_name}': {}", response.body);
    response.body
}

fn text_of(message: Message) -> Option<Value> {
    match message {
        Message::Text(text) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

/// Open the dashboard WebSocket as `operator` and collect the policy input captures it
/// receives, from the moment the gateway confirms the connection.
async fn watch(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
) {
    let client = client(world, operator).await;
    let token = client
        .session_token()
        .expect("the operator must have a dashboard session");
    let mut request = client
        .dashboard_socket_url()
        .into_client_request()
        .expect("a dashboard WebSocket request");
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .expect("a bearer header"),
    );
    let (socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("open the dashboard WebSocket");
    let (write, mut read) = socket.split();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), read.next())
            .await
            .expect("the dashboard WebSocket confirms the connection")
            .expect("the dashboard WebSocket stays open")
            .expect("a dashboard WebSocket message");
        if text_of(message).is_some_and(|update| update["type"] == "connected") {
            break;
        }
    }
    let captures = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::clone(&captures);
    tokio::spawn(async move {
        let _keep_open = write;
        while let Some(Ok(message)) = read.next().await {
            if let Some(update) = text_of(message).filter(|update| update["type"] == CAPTURED) {
                received
                    .lock()
                    .expect("captures lock")
                    .push(update);
            }
        }
    });
    world
        .dashboard_captures
        .insert(
            operator
                .unwrap_or(THE_OPERATOR)
                .to_string(),
            captures,
        );
}

fn captures_of(
    world: &SurfaceWorld,
    operator: &str,
) -> Vec<Value> {
    world
        .dashboard_captures
        .get(operator)
        .unwrap_or_else(|| panic!("operator '{operator}' must be watching the dashboard Capture view"))
        .lock()
        .expect("captures lock")
        .clone()
}

#[given("the operator watches the dashboard Capture view")]
async fn operator_watches(world: &mut SurfaceWorld) {
    watch(world, None).await;
}

#[given(expr = "operator {string} watches the dashboard Capture view")]
async fn named_operator_watches(
    world: &mut SurfaceWorld,
    operator: String,
) {
    watch(world, Some(&operator)).await;
}

#[given(expr = "the operator has switched on policy input capture for surface {string} for {int} minutes")]
async fn operator_has_switched_on(
    world: &mut SurfaceWorld,
    surface_name: String,
    minutes: i64,
) {
    let response = switch_on(world, None, &surface_name, minutes).await;
    assert_eq!(response.status, 200, "switching on policy input capture: {}", response.body);
}

#[given(expr = "the operator has switched off policy input capture for surface {string}")]
async fn operator_has_switched_off(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let response = switch_off(world, &surface_name).await;
    assert_eq!(response.status, 200, "switching off policy input capture: {}", response.body);
}

#[when(expr = "the operator switches on policy input capture for surface {string} for {int} minutes")]
async fn operator_switches_on(
    world: &mut SurfaceWorld,
    surface_name: String,
    minutes: i64,
) {
    world.admin_response = Some(switch_on(world, None, &surface_name, minutes).await);
}

#[when(expr = "operator {string} switches on policy input capture for surface {string} for {int} minutes")]
async fn named_operator_switches_on(
    world: &mut SurfaceWorld,
    operator: String,
    surface_name: String,
    minutes: i64,
) {
    world.admin_response = Some(switch_on(world, Some(&operator), &surface_name, minutes).await);
}

#[when(expr = "the operator saves surface {string} with a policy input capture end of its own")]
async fn operator_saves_surface_with_own_end(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let mut surface = stored_surface(world, &surface_name).await;
    surface["policy_input_capture_until"] = json!("2099-01-01T00:00:00Z");
    let surface_id = tracked_surface_id(world, &surface_name);
    let response = client(world, None)
        .await
        .update_surface_recorded(&surface_id, &surface)
        .await
        .unwrap_or_else(|error| panic!("save surface '{surface_name}' through admin API: {error}"));
    world.admin_response = Some(response);
}

#[then(expr = "surface {string} captures its policy input for at most {int} minutes")]
async fn surface_captures_policy_input_for_at_most(
    world: &mut SurfaceWorld,
    surface_name: String,
    minutes: i64,
) {
    let surface = stored_surface(world, &surface_name).await;
    let until = surface["policy_input_capture_until"]
        .as_str()
        .unwrap_or_else(|| panic!("surface '{surface_name}' has no policy input capture end: {surface}"));
    let until = chrono::DateTime::parse_from_rfc3339(until)
        .unwrap_or_else(|error| panic!("policy input capture end {until:?}: {error}"))
        .with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();
    assert!(
        until > now && until <= now + chrono::Duration::minutes(minutes),
        "surface '{surface_name}' captures its policy input until {until}, expected within {minutes} minutes of {now}"
    );
}

#[then(
    expr = "the Capture view shows the {string} policy of surface {string} deciding {string} on an input showing {string}"
)]
async fn capture_view_shows(
    world: &mut SurfaceWorld,
    slot: String,
    surface_name: String,
    decision: String,
    text: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    let matches = |capture: &Value| {
        capture["config_id"] == surface_id.as_str()
            && capture["slot"] == slot.as_str()
            && capture["decision"] == decision.as_str()
            && capture["input"]
                .to_string()
                .contains(&text)
    };
    for _ in 0..100 {
        if captures_of(world, THE_OPERATOR)
            .iter()
            .any(matches)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "no {slot} policy capture of surface '{surface_name}' ({surface_id}) deciding {decision:?} on an input showing {text:?}: {:#?}",
        captures_of(world, THE_OPERATOR)
    );
}

async fn assert_no_capture(
    world: &SurfaceWorld,
    operator: &str,
) {
    tokio::time::sleep(Duration::from_millis(500)).await;
    let captures = captures_of(world, operator);
    assert!(captures.is_empty(), "expected no policy input capture, received: {captures:#?}");
}

#[then("the Capture view shows no policy input")]
async fn capture_view_shows_nothing(world: &mut SurfaceWorld) {
    assert_no_capture(world, THE_OPERATOR).await;
}

#[then(expr = "the Capture view of operator {string} shows no policy input")]
async fn named_capture_view_shows_nothing(
    world: &mut SurfaceWorld,
    operator: String,
) {
    assert_no_capture(world, &operator).await;
}
