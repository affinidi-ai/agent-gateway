use std::time::Duration;

use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::bdd_support::dashboard_socket::{
    DashboardSocket, POLICY_INPUT_CAPTURED as CAPTURED, POLICY_INPUT_LISTEN_ANSWER as LISTEN_ANSWER,
};
use crate::steps::given::tracked_surface_id;
use crate::steps::policy_changes::client;
use crate::world::SurfaceWorld;

const THE_OPERATOR: &str = "";
/// Longer than the dashboard WebSocket's 30 s keep-alive interval.
const KEEP_ALIVE_WAIT: Duration = Duration::from_secs(40);
/// The system feature flag that allows policy input capture.
const CAPTURE_FLAG: &str = "policy_input_capture";
/// Why a listen is refused or stopped while policy input capture is turned off.
const TURNED_OFF: &str = "policy input capture is turned off";
/// Why a listen is stopped once the operator's dashboard session ends.
const SESSION_ENDED: &str = "your dashboard session has ended; sign in again";

const PERMISSION_MISSING: &str = "needs surfaces.edit and policies.edit";

/// Open the dashboard WebSocket as `operator`, once.
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
    let socket = DashboardSocket::connect(&client.dashboard_socket_url(), &token).await;
    world
        .dashboard_sockets
        .insert(key, socket);
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
    socket(world, operator).received_of(message_type)
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
    let surface_id = tracked_surface_id(world, surface_name);
    socket(world, operator.unwrap_or(THE_OPERATOR))
        .ask_to_listen(&surface_id, start)
        .await
}

async fn listens(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
    surface_name: &str,
) {
    let answer = ask_to_listen(world, operator, surface_name, true).await;
    assert_eq!(answer["listening"], true, "listening to policy input: {answer}");
}

/// Create the policy definition `policy_id` from `rego` and make it the request policy
/// of `surface_name`, through the admin API.
async fn attach_request_policy(
    world: &mut SurfaceWorld,
    surface_name: &str,
    policy_id: &str,
    policy_name: &str,
    rego: &str,
) {
    let surface_id = tracked_surface_id(world, surface_name);
    let admin = client(world, None).await;
    let created = admin
        .create_surface_policy_definition_recorded(policy_id, policy_name, policy_name, rego)
        .await
        .expect("create the request policy definition");
    assert!(created.status < 300, "creating the request policy definition: {}", created.body);
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
            policy_id,
        )
        .await
        .expect("attach the request policy");
    assert_eq!(updated.status, 200, "attaching the request policy: {}", updated.body);
}

#[given(expr = "surface {string} has a request policy that denies with reason {string}")]
async fn surface_has_denying_request_policy(
    world: &mut SurfaceWorld,
    surface_name: String,
    reason: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    let rego = format!("package surface.policy\n\ndefault allow := false\n\ndeny_reason := {reason:?}\n");
    attach_request_policy(world, &surface_name, &format!("bdd-capture-deny-{surface_id}"), "BDD denying policy", &rego)
        .await;
}

#[given(expr = "surface {string} has a request policy that allows every request")]
async fn surface_has_allowing_request_policy(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    attach_request_policy(
        world,
        &surface_name,
        &format!("bdd-capture-allow-{surface_id}"),
        "BDD allow-all policy",
        "package surface.policy\n\ndefault allow := true\n",
    )
    .await;
}

/// Create the surface policy definition `policy_id` from `rego` and enforce it as the
/// only appliance-wide surface policy, through the admin API.
async fn enforce_appliance_wide_policy(
    world: &mut SurfaceWorld,
    policy_id: &str,
    policy_name: &str,
    description: &str,
    rego: &str,
) {
    let admin = client(world, None).await;
    let created = admin
        .create_surface_policy_definition_recorded(policy_id, policy_name, description, rego)
        .await
        .expect("create the appliance-wide policy definition");
    assert!(created.status < 300, "creating the appliance-wide policy definition: {}", created.body);
    let assignments =
        json!({ "assignments": { "agent_surface": [{ "policy_id": policy_id, "monitor_only": false }] } });
    let assigned = admin
        .send_recorded_json(reqwest::Method::PUT, "/v1/policy-assignments", Some(&assignments))
        .await
        .expect("assign the appliance-wide policy");
    assert_eq!(assigned.status, 200, "assigning the appliance-wide policy: {}", assigned.body);
}

#[given(expr = "an appliance-wide surface policy {string} denies every request")]
async fn appliance_wide_policy_denies(
    world: &mut SurfaceWorld,
    policy_name: String,
) {
    enforce_appliance_wide_policy(
        world,
        "bdd-capture-appliance-deny",
        &policy_name,
        "Denies every request",
        "package surface.policy\n\ndefault allow := false\n",
    )
    .await;
}

#[given(expr = "an appliance-wide surface policy {string} fails to evaluate")]
async fn appliance_wide_policy_fails_to_evaluate(
    world: &mut SurfaceWorld,
    policy_name: String,
) {
    // Compiles, but the two rules give `allow` two values for every input,
    // which is an evaluation error rather than a decision.
    let rego = "package surface.policy\n\nallow := true if {\n    true\n}\n\nallow := false if {\n    true\n}\n";
    enforce_appliance_wide_policy(world, "bdd-capture-appliance-error", &policy_name, "Fails to evaluate", rego).await;
}

#[given(expr = "Transit Point {string} has a policy that allows every request")]
fn transit_point_allows_every_request(
    world: &mut SurfaceWorld,
    transit_point: String,
) {
    crate::steps::given::transit_point_config_mut(world, &transit_point).policy =
        Some(crate::bdd_support::config::config_tree::PolicyDefinitionFixture::new(
            format!("bdd-transit-allow-{transit_point}"),
            "BDD Transit Point allow-all policy",
            "package surface.policy\n\ndefault allow := true\n",
        ));
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
    let named = (operator != THE_OPERATOR).then_some(operator.as_str());
    let answer = ask_to_listen(world, named, surface_name, true).await;
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
    assert_eq!(answer["error"], PERMISSION_MISSING, "{answer}");
}

#[when(expr = "the dashboard session of operator {string} ends")]
async fn operator_session_ends(
    world: &mut SurfaceWorld,
    operator: String,
) {
    let ended = client(world, Some(&operator))
        .await
        .send_recorded_json(reqwest::Method::POST, "/auth/logout", None::<&Value>)
        .await
        .expect("sign the operator out");
    assert!(ended.status < 300, "signing operator '{operator}' out: {}", ended.body);
}

/// Wait up to one keep-alive check for `operator` to be told that listening to `surface_name`
/// stopped with `error`.
async fn wait_until_told_listening_stopped(
    world: &SurfaceWorld,
    operator: &str,
    surface_name: &str,
    error: &str,
) {
    let surface_id = tracked_surface_id(world, surface_name);
    let stopped = |answer: &Value| {
        answer["surface_id"] == surface_id.as_str() && answer["listening"] == false && answer["error"] == error
    };
    let deadline = tokio::time::Instant::now() + KEEP_ALIVE_WAIT;
    while tokio::time::Instant::now() < deadline {
        if received_of(world, operator, LISTEN_ANSWER)
            .iter()
            .any(stopped)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "operator '{operator}' was not told that listening to surface '{surface_name}' stopped with '{error}': {:#?}",
        received_of(world, operator, LISTEN_ANSWER)
    );
}

#[then(
    expr = "operator {string} is told by the next keep-alive check that listening to surface {string} stopped because the session ended"
)]
async fn operator_told_listening_stopped(
    world: &mut SurfaceWorld,
    operator: String,
    surface_name: String,
) {
    wait_until_told_listening_stopped(world, &operator, &surface_name, SESSION_ENDED).await;
}

#[when(expr = "an administrator changes the role of operator {string} to {string}")]
async fn administrator_changes_operator_role(
    world: &mut SurfaceWorld,
    operator: String,
    role: String,
) {
    let admin = client(world, None).await;
    let users = admin
        .send_recorded_json(reqwest::Method::GET, "/v1/users", None::<&Value>)
        .await
        .expect("list the users");
    assert!(users.status < 300, "listing the users: {}", users.body);
    let user_id = users
        .body
        .as_array()
        .and_then(|listed| {
            listed
                .iter()
                .find(|user| user["username"] == operator.as_str())
        })
        .and_then(|user| user["user_id"].as_str())
        .unwrap_or_else(|| panic!("operator '{operator}' must be a user: {}", users.body))
        .to_string();
    let changed = admin
        .send_recorded_json(reqwest::Method::PUT, &format!("/v1/users/{user_id}"), Some(&json!({ "role": role })))
        .await
        .expect("change the operator's role");
    assert!(changed.status < 300, "changing the role of operator '{operator}': {}", changed.body);
}

/// Turn policy input capture on or off: at once on a running gateway, or as soon as the admin
/// session opens on one that has not started, so the step never starts it early.
async fn turn_capture(
    world: &mut SurfaceWorld,
    turned_on: bool,
) {
    if world.admin_client.is_some() {
        client(world, None)
            .await
            .set_feature_flags(&[(CAPTURE_FLAG, turned_on)])
            .await
            .expect("set the policy input capture feature flag");
    } else {
        world
            .pending_feature_flags
            .push((CAPTURE_FLAG.to_string(), turned_on));
    }
}

#[given("policy input capture is turned on")]
async fn capture_is_turned_on(world: &mut SurfaceWorld) {
    turn_capture(world, true).await;
}

#[given("policy input capture is turned off")]
async fn capture_is_turned_off(world: &mut SurfaceWorld) {
    turn_capture(world, false).await;
}

#[when("an administrator turns policy input capture off")]
async fn administrator_turns_capture_off(world: &mut SurfaceWorld) {
    turn_capture(world, false).await;
}

#[when(expr = "the operator asks to listen to the policy input of surface {string}")]
async fn operator_asks_to_listen(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    asks_to_listen(world, THE_OPERATOR.to_string(), &surface_name).await;
}

#[given(expr = "the operator has asked to listen to the policy input of surface {string}")]
async fn operator_has_asked_to_listen(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    asks_to_listen(world, THE_OPERATOR.to_string(), &surface_name).await;
}

#[when(expr = "the operator listens to the policy input of surface {string}")]
async fn operator_starts_listening(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    listens(world, None, &surface_name).await;
}

#[when(expr = "the operator stops listening to the policy input of surface {string}")]
async fn operator_stops_listening(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    operator_has_stopped_listening(world, surface_name).await;
}

#[then("the operator may not listen to policy input because policy input capture is turned off")]
async fn operator_may_not_listen_while_turned_off(world: &mut SurfaceWorld) {
    let answer = world
        .dashboard_listen_answers
        .get(THE_OPERATOR)
        .expect("the operator must have asked to listen to policy input");
    assert_eq!(answer["listening"], false, "{answer}");
    assert_eq!(answer["error"], TURNED_OFF, "{answer}");
}

#[then(
    expr = "the operator is told by the next keep-alive check that listening to surface {string} stopped because policy input capture is turned off"
)]
async fn operator_told_listening_stopped_while_turned_off(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    wait_until_told_listening_stopped(world, THE_OPERATOR, &surface_name, TURNED_OFF).await;
}

/// Assert the VP Audit Log holds a `category` record of the operator on `surface_name`,
/// with `reason` when one is given.
async fn audit_log_records_capture(
    world: &mut SurfaceWorld,
    category: &str,
    surface_name: &str,
    reason: Option<&str>,
) {
    let user = crate::steps::policy_changes::user_id(world, None).await;
    let surface_id = tracked_surface_id(world, surface_name);
    let (found, events) = client(world, None)
        .await
        .wait_for_audit_event(|record| {
            let details = &record["event"][category];
            record["surface_id"] == surface_id.as_str()
                && details["actor"]["id"] == user.as_str()
                && reason.is_none_or(|reason| details["reason"] == reason)
        })
        .await
        .expect("read the VP Audit Log");
    assert!(found, "expected a {category} record for surface {surface_id}, got {events:?}");
}

#[then(expr = "the VP Audit Log records that the operator started capturing the policy input of surface {string}")]
async fn audit_log_records_capture_started(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    audit_log_records_capture(world, "policy_input_capture_started", &surface_name, None).await;
}

#[then(
    expr = "the VP Audit Log records that the operator's capture of the policy input of surface {string} ended with reason {string}"
)]
async fn audit_log_records_capture_stopped(
    world: &mut SurfaceWorld,
    surface_name: String,
    reason: String,
) {
    audit_log_records_capture(world, "policy_input_capture_stopped", &surface_name, Some(&reason)).await;
}

/// Wait until `operator`'s Capture view has received a capture `matches` accepts,
/// panicking with `missing` and everything it received when none arrives.
async fn wait_for_capture(
    world: &SurfaceWorld,
    operator: &str,
    matches: impl Fn(&Value) -> bool,
    missing: &str,
) {
    socket(world, operator)
        .wait_for_capture(matches, missing)
        .await;
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
    let missing = format!(
        "no {slot} policy capture of surface '{surface_name}' ({surface_id}) deciding {decision:?} on an input showing {text:?}"
    );
    wait_for_capture(world, operator, matches, &missing).await;
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
    let missing = format!("no {slot} policy capture of surface '{surface_name}' running policy {policy_name:?}");
    wait_for_capture(world, THE_OPERATOR, matches, &missing).await;
}

#[then(expr = "no captured policy input of surface {string} contains {string}")]
async fn no_capture_contains(
    world: &mut SurfaceWorld,
    surface_name: String,
    text: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    socket(world, THE_OPERATOR).assert_no_capture_contains(&surface_id, &text);
}

#[then(expr = "the Capture view shows the {string} policy of surface {string} decided by policy {string}")]
async fn capture_view_names_deciding_policy(
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
                    policies.iter().any(|policy| {
                        policy["name"] == policy_name.as_str()
                            && policy["id"].is_string()
                            && policy["id"] == capture["decided_by"]
                    })
                })
    };
    let missing = format!("no {slot} policy capture of surface '{surface_name}' decided by policy {policy_name:?}");
    wait_for_capture(world, THE_OPERATOR, matches, &missing).await;
}

#[given(expr = "gateway {string} has gateway-level policy {string} that allows inbound requests only to {string}")]
fn gateway_has_named_policy_to_path(
    world: &mut SurfaceWorld,
    gateway_name: String,
    policy_id: String,
    allowed_path: String,
) {
    set_gateway_policy_definition(
        world,
        &gateway_name,
        &policy_id,
        &crate::bdd_support::policies::build_gateway_request_path_policy(&allowed_path),
    );
}

#[given(expr = "gateway {string} has a gateway-level policy that allows every request")]
fn gateway_allows_every_request(
    world: &mut SurfaceWorld,
    gateway_name: String,
) {
    world
        .actors
        .gateway_instance_mut(&gateway_name)
        .expect("gateway must exist to set its policy")
        .fixture
        .as_mut()
        .expect("gateway fixture must exist to set its policy")
        .policy_opa_entry = Some("package gateway.policy\n\ndefault allow := true\n".to_string());
}

/// Make the policy definition `policy_id` holding `rego` the gateway-level policy of the
/// bootstrapped gateway `gateway_name`.
fn set_gateway_policy_definition(
    world: &mut SurfaceWorld,
    gateway_name: &str,
    policy_id: &str,
    rego: &str,
) {
    let fixture = world
        .actors
        .gateway_instance_mut(gateway_name)
        .expect("gateway must exist to set its policy")
        .fixture
        .as_mut()
        .expect("gateway fixture must exist to set its policy");
    fixture.policy_opa_entry = Some(rego.to_string());
    fixture.policy_definition_id = Some(policy_id.to_string());
    fixture.policies.insert(
        policy_id.to_string(),
        crate::bdd_support::config::config_tree::PolicyDefinitionFixture {
            id: policy_id.to_string(),
            description: policy_id.to_string(),
            rego: rego.to_string(),
        },
    );
}

async fn shows_decision_with_reason(
    world: &SurfaceWorld,
    slot: &str,
    surface_name: &str,
    decision: &str,
    reason: &str,
) {
    let surface_id = tracked_surface_id(world, surface_name);
    let matches = |capture: &Value| {
        capture["config_id"] == surface_id.as_str()
            && capture["slot"] == slot
            && capture["decision"] == decision
            && capture["reason"] == reason
    };
    let missing =
        format!("no {slot} policy capture of surface '{surface_name}' deciding {decision:?} with reason {reason:?}");
    wait_for_capture(world, THE_OPERATOR, matches, &missing).await;
}

#[then(expr = "the Capture view shows the {string} policy of surface {string} denying with reason {string}")]
async fn capture_view_shows_denial(
    world: &mut SurfaceWorld,
    slot: String,
    surface_name: String,
    reason: String,
) {
    shows_decision_with_reason(world, &slot, &surface_name, "deny", &reason).await;
}

#[then(expr = "the Capture view shows the {string} policy of surface {string} failing with error {string}")]
async fn capture_view_shows_error(
    world: &mut SurfaceWorld,
    slot: String,
    surface_name: String,
    reason: String,
) {
    shows_decision_with_reason(world, &slot, &surface_name, "error", &reason).await;
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
