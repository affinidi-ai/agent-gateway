use std::sync::{Arc, Mutex};
use std::time::Duration;

use cucumber::{given, then, when};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::steps::given::tracked_surface_id;
use crate::steps::policy_changes::client;
use crate::world::{DashboardSocket, SurfaceWorld};

const CAPTURED: &str = "policy_input_captured";
const LISTEN_ANSWER: &str = "policy_input_capture";
const THE_OPERATOR: &str = "";

fn text_of(message: Message) -> Option<Value> {
    match message {
        Message::Text(text) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

/// Open the dashboard WebSocket as `operator`, once, and collect the policy input
/// captures and listen answers it receives from the moment the gateway confirms the
/// connection.
async fn watch(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
) {
    let key = operator
        .unwrap_or(THE_OPERATOR)
        .to_string();
    if world
        .dashboard_sockets
        .contains_key(&key)
    {
        return;
    }
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
    let (mut write, mut read) = socket.split();
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
    let received = Arc::new(Mutex::new(Vec::new()));
    let collected = Arc::clone(&received);
    let reader = tokio::spawn(async move {
        while let Some(Ok(message)) = read.next().await {
            if let Some(update) =
                text_of(message).filter(|update| update["type"] == CAPTURED || update["type"] == LISTEN_ANSWER)
            {
                collected
                    .lock()
                    .expect("dashboard messages lock")
                    .push(update);
            }
        }
    });
    let (outgoing, mut to_send) = tokio::sync::mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(text) = to_send.recv().await {
            if write
                .send(Message::Text(text.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    world
        .dashboard_sockets
        .insert(key, DashboardSocket::new(received, outgoing, reader, writer));
}

fn socket<'a>(
    world: &'a SurfaceWorld,
    operator: &str,
) -> &'a DashboardSocket {
    world
        .dashboard_sockets
        .get(operator)
        .unwrap_or_else(|| panic!("operator '{operator}' must be watching the dashboard Capture view"))
}

fn received_of(
    world: &SurfaceWorld,
    operator: &str,
    message_type: &str,
) -> Vec<Value> {
    socket(world, operator)
        .received()
        .into_iter()
        .filter(|message| message["type"] == message_type)
        .collect()
}

/// Ask, as `operator`, to start or stop listening to the policy input of `surface_name`,
/// and return the gateway's answer.
async fn ask_to_listen(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
    surface_name: &str,
    start: bool,
) -> Value {
    watch(world, operator).await;
    let key = operator.unwrap_or(THE_OPERATOR);
    let surface_id = tracked_surface_id(world, surface_name);
    let answered = received_of(world, key, LISTEN_ANSWER).len();
    let message_type = if start {
        "capture_policy_input"
    } else {
        "stop_capturing_policy_input"
    };
    socket(world, key).send(json!({ "type": message_type, "surface_id": surface_id }).to_string());
    for _ in 0..100 {
        if let Some(answer) = received_of(world, key, LISTEN_ANSWER)
            .into_iter()
            .nth(answered)
        {
            assert_eq!(answer["surface_id"], surface_id.as_str(), "listen answer: {answer}");
            return answer;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the gateway did not answer the request to listen to the policy input of surface '{surface_name}'");
}

async fn listens(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
    surface_name: &str,
) {
    let answer = ask_to_listen(world, operator, surface_name, true).await;
    assert_eq!(answer["listening"], true, "listening to policy input: {answer}");
}

#[given(expr = "the {string} role is granted {string}")]
fn role_is_granted(
    world: &mut SurfaceWorld,
    role: String,
    feature: String,
) {
    world
        .surface_config
        .rbac_permissions
        .push((feature, role));
}

#[given(expr = "surface {string} has a request policy that denies with reason {string}")]
async fn surface_has_denying_request_policy(
    world: &mut SurfaceWorld,
    surface_name: String,
    reason: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    let policy_id = format!("bdd-capture-deny-{surface_id}");
    let rego = format!("package surface.policy\n\ndefault allow := false\n\ndeny_reason := {reason:?}\n");
    let admin = client(world, None).await;
    let created = admin
        .create_surface_policy_definition_recorded(&policy_id, "BDD denying policy", "Denies every request", &rego)
        .await
        .expect("create the denying policy definition");
    assert!(created.status < 300, "creating the denying policy definition: {}", created.body);
    let stored = admin
        .get_surface_recorded(&surface_id)
        .await
        .expect("read the surface");
    assert_eq!(stored.status, 200, "reading surface '{surface_name}': {}", stored.body);
    let updated = admin
        .update_surface_policy_reference_recorded(
            &surface_id,
            stored.body,
            crate::bdd_support::admin_client::SurfacePolicySlot::Request,
            &policy_id,
        )
        .await
        .expect("attach the denying policy");
    assert_eq!(updated.status, 200, "attaching the denying policy: {}", updated.body);
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

#[given(expr = "the operator listens to the policy input of surface {string}")]
async fn operator_listens(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    listens(world, None, &surface_name).await;
}

#[given(expr = "operator {string} listens to the policy input of surface {string}")]
async fn named_operator_listens(
    world: &mut SurfaceWorld,
    operator: String,
    surface_name: String,
) {
    listens(world, Some(&operator), &surface_name).await;
}

#[given(expr = "the operator has stopped listening to the policy input of surface {string}")]
async fn operator_has_stopped_listening(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let answer = ask_to_listen(world, None, &surface_name, false).await;
    assert_eq!(answer["listening"], false, "stopping listening to policy input: {answer}");
}

async fn asks_to_listen(
    world: &mut SurfaceWorld,
    operator: String,
    surface_name: &str,
) {
    let answer = ask_to_listen(world, Some(&operator), surface_name, true).await;
    world
        .dashboard_listen_answers
        .insert(operator, answer);
}

#[given(expr = "operator {string} has asked to listen to the policy input of surface {string}")]
async fn named_operator_has_asked_to_listen(
    world: &mut SurfaceWorld,
    operator: String,
    surface_name: String,
) {
    asks_to_listen(world, operator, &surface_name).await;
}

#[when(expr = "operator {string} asks to listen to the policy input of surface {string}")]
async fn named_operator_asks_to_listen(
    world: &mut SurfaceWorld,
    operator: String,
    surface_name: String,
) {
    asks_to_listen(world, operator, &surface_name).await;
}

#[then(expr = "operator {string} may not listen to policy input")]
async fn named_operator_may_not_listen(
    world: &mut SurfaceWorld,
    operator: String,
) {
    let answer = world
        .dashboard_listen_answers
        .get(&operator)
        .unwrap_or_else(|| panic!("operator '{operator}' must have asked to listen to policy input"));
    assert_eq!(answer["listening"], false, "{answer}");
    assert_eq!(answer["error"], "needs surfaces.edit and policies.edit", "{answer}");
}

async fn shows_capture(
    world: &SurfaceWorld,
    operator: &str,
    slot: &str,
    surface_name: &str,
    decision: &str,
    text: &str,
) {
    let surface_id = tracked_surface_id(world, surface_name);
    let matches = |capture: &Value| {
        capture["config_id"] == surface_id.as_str()
            && capture["slot"] == slot
            && capture["decision"] == decision
            && capture["input"]
                .to_string()
                .contains(text)
    };
    for _ in 0..100 {
        if received_of(world, operator, CAPTURED)
            .iter()
            .any(matches)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "no {slot} policy capture of surface '{surface_name}' ({surface_id}) deciding {decision:?} on an input showing {text:?}: {:#?}",
        received_of(world, operator, CAPTURED)
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
    shows_capture(world, THE_OPERATOR, &slot, &surface_name, &decision, &text).await;
}

#[then(
    expr = "the Capture view of operator {string} shows the {string} policy of surface {string} deciding {string} on an input showing {string}"
)]
async fn named_capture_view_shows(
    world: &mut SurfaceWorld,
    operator: String,
    slot: String,
    surface_name: String,
    decision: String,
    text: String,
) {
    shows_capture(world, &operator, &slot, &surface_name, &decision, &text).await;
}

#[then(expr = "the Capture view shows the {string} policy of surface {string} running policy {string}")]
async fn capture_view_names_policy(
    world: &mut SurfaceWorld,
    slot: String,
    surface_name: String,
    policy_name: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    let matches = |capture: &Value| {
        capture["config_id"] == surface_id.as_str()
            && capture["slot"] == slot.as_str()
            && capture["policies"]
                .as_array()
                .is_some_and(|policies| {
                    policies
                        .iter()
                        .any(|policy| policy["name"] == policy_name.as_str())
                })
    };
    for _ in 0..100 {
        if received_of(world, THE_OPERATOR, CAPTURED)
            .iter()
            .any(matches)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "no {slot} policy capture of surface '{surface_name}' running policy {policy_name:?}: {:#?}",
        received_of(world, THE_OPERATOR, CAPTURED)
    );
}

#[then(expr = "no captured policy input of surface {string} contains {string}")]
async fn no_capture_contains(
    world: &mut SurfaceWorld,
    surface_name: String,
    text: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    let captures: Vec<Value> = received_of(world, THE_OPERATOR, CAPTURED)
        .into_iter()
        .filter(|capture| capture["config_id"] == surface_id.as_str())
        .collect();
    assert!(!captures.is_empty(), "no policy input of surface '{surface_name}' was captured");
    for capture in &captures {
        assert!(
            !capture["input"]
                .to_string()
                .contains(&text),
            "a captured input contains {text:?}: {capture:#}"
        );
    }
}

#[then(expr = "the Capture view shows the {string} policy of surface {string} denying with reason {string}")]
async fn capture_view_shows_denial(
    world: &mut SurfaceWorld,
    slot: String,
    surface_name: String,
    reason: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    let matches = |capture: &Value| {
        capture["config_id"] == surface_id.as_str()
            && capture["slot"] == slot.as_str()
            && capture["decision"] == "deny"
            && capture["reason"] == reason.as_str()
    };
    for _ in 0..100 {
        if received_of(world, THE_OPERATOR, CAPTURED)
            .iter()
            .any(matches)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "no {slot} policy capture of surface '{surface_name}' denying with reason {reason:?}: {:#?}",
        received_of(world, THE_OPERATOR, CAPTURED)
    );
}

async fn assert_no_capture(
    world: &SurfaceWorld,
    operator: &str,
) {
    tokio::time::sleep(Duration::from_millis(500)).await;
    let captures = received_of(world, operator, CAPTURED);
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
