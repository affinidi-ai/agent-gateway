use cucumber::{given, then, when};
use reqwest::Method;

use crate::bdd_support::config::single_surface_fixture::ControlKeyTrustAgentSetup;
use crate::bdd_support::trust_agent::{Behaviour, MockTrustAgent};
use crate::steps::credential_save::send;
use crate::world::SurfaceWorld;

async fn trust_agent(
    world: &mut SurfaceWorld,
    behaviour: Behaviour,
    control_did_method: &'static str,
) {
    let agent = MockTrustAgent::start(behaviour).await;
    world
        .surface_config
        .control_key_trust_agent = Some(ControlKeyTrustAgentSetup {
        base_url: agent.url.clone(),
        key_path: agent.control_key_path(),
        control_did_method,
    });
    world.trust_agent = Some(agent);
}

fn agent(world: &SurfaceWorld) -> &MockTrustAgent {
    world
        .trust_agent
        .as_ref()
        .expect("a trust agent")
}

#[given("a trust agent that knows the gateway by its control did:key")]
async fn trust_agent_that_knows_the_gateway(world: &mut SurfaceWorld) {
    trust_agent(world, Behaviour::Accepting, "did_key").await;
}

#[given("a trust agent that refuses to move the gateway's access entry")]
async fn trust_agent_that_refuses_the_swap(world: &mut SurfaceWorld) {
    trust_agent(world, Behaviour::RefusingSwap, "did_key").await;
}

#[given("a trust agent that knows the gateway by its published did:webvh")]
async fn trust_agent_that_knows_a_webvh_gateway(world: &mut SurfaceWorld) {
    trust_agent(world, Behaviour::Accepting, "did_webvh").await;
}

#[given(expr = "the gateway is set to rotate its control key every {int} days")]
async fn gateway_rotates_every_days(
    world: &mut SurfaceWorld,
    days: u32,
) {
    world
        .surface_config
        .control_key_rotation_days = Some(days);
}

#[given(expr = "human user {string} lacks permission to manage keys")]
async fn human_user_lacks_key_management(
    world: &mut SurfaceWorld,
    username: String,
) {
    crate::steps::terms::login(world, &username, "user").await;
}

#[when("the operator reads the trust agent status")]
async fn operator_reads_trust_agent_status(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/vta/status", None).await;
    world.admin_response = Some(response);
}

#[when("the operator lists the trust agent connections")]
async fn operator_lists_trust_agent_connections(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/vta/connections", None).await;
    world.admin_response = Some(response);
}

#[when("the operator rotates the control key")]
async fn operator_rotates_the_control_key(world: &mut SurfaceWorld) {
    let response = send(world, Method::POST, "/v1/vta/control-key/rotate", None).await;
    world.admin_response = Some(response);
}

#[given("the operator has rotated the control key")]
async fn operator_has_rotated_the_control_key(world: &mut SurfaceWorld) {
    let response = send(world, Method::POST, "/v1/vta/control-key/rotate", None).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

#[when(expr = "human user {string} tries to rotate the control key")]
async fn human_user_tries_to_rotate(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = crate::steps::terms::latest_client(world, &username);
    let response = client
        .send_recorded_json::<serde_json::Value>(Method::POST, "/v1/vta/control-key/rotate", None)
        .await
        .expect("the rotation request completes");
    world.admin_response = Some(response);
}

fn status(world: &SurfaceWorld) -> &serde_json::Value {
    &world
        .admin_response
        .as_ref()
        .expect("the trust agent status was read")
        .body
}

fn rotation(world: &SurfaceWorld) -> &serde_json::Value {
    &world
        .admin_response
        .as_ref()
        .expect("a rotation was asked for")
        .body
}

#[then("the gateway signs through the trust agent")]
async fn gateway_signs_through_the_trust_agent(world: &mut SurfaceWorld) {
    let resolution = &status(world)["default_resolution"];
    assert_eq!(resolution["backend"], "vta", "{resolution}");
}

#[then(expr = "the trust agent was asked to create {int} signing key(s)")]
async fn trust_agent_was_asked_to_create_keys(
    world: &mut SurfaceWorld,
    count: usize,
) {
    assert_eq!(agent(world).signing_keys_created(), count);
}

#[then("the trust agent knows the gateway by the new did:key")]
async fn trust_agent_knows_the_new_did(world: &mut SurfaceWorld) {
    let body = rotation(world);
    let (previous, new) = (
        body["previous_control_did"]
            .as_str()
            .expect("previous DID"),
        body["control_did"]
            .as_str()
            .expect("new DID"),
    );
    assert_ne!(previous, new, "{body}");
    let agent = agent(world);
    assert_eq!(
        agent
            .gateway_entry()
            .as_deref(),
        Some(new)
    );
    assert_eq!(agent.swaps(), vec![(previous.to_string(), new.to_string())]);
}

#[then("the trust agent refused no sign-in from the gateway")]
async fn trust_agent_refused_no_sign_in(world: &mut SurfaceWorld) {
    assert_eq!(agent(world).refused_sign_ins(), 0, "the gateway signed in as a key that no longer holds the entry");
}

#[then("the status shows the control key was rotated just now")]
async fn status_shows_rotated_just_now(world: &mut SurfaceWorld) {
    let control_key = &status(world)["control_key"];
    let rotated = control_key["rotated_at"]
        .as_str()
        .unwrap_or_else(|| panic!("no rotation time in {}", status(world)));
    let rotated = chrono::DateTime::parse_from_rfc3339(rotated).expect("an RFC 3339 time");
    let age = chrono::Utc::now().signed_duration_since(rotated);
    assert!(age < chrono::Duration::minutes(1) && age > chrono::Duration::minutes(-1), "{age}");
}

#[then(expr = "the next rotation is due in {int} days")]
async fn next_rotation_is_due_in_days(
    world: &mut SurfaceWorld,
    days: i64,
) {
    let control_key = &status(world)["control_key"];
    assert_eq!(control_key["rotation_days"], days, "{control_key}");
    let next = control_key["next_rotation_at"]
        .as_str()
        .unwrap_or_else(|| panic!("no next rotation in {control_key}"));
    let next = chrono::DateTime::parse_from_rfc3339(next).expect("an RFC 3339 time");
    let wait = next.signed_duration_since(chrono::Utc::now());
    assert!(wait > chrono::Duration::days(days - 1) && wait < chrono::Duration::days(days + 1), "{wait}");
}

#[then("the trust agent still knows the gateway by the did:key it was granted")]
async fn trust_agent_still_knows_the_first_did(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/vta/status", None).await;
    let reported = response.body["control_key"]["control_did"]
        .as_str()
        .expect("a control DID")
        .to_string();
    let agent = agent(world);
    assert_eq!(
        agent
            .gateway_entry()
            .as_deref(),
        Some(reported.as_str())
    );
    assert!(agent.swaps().is_empty(), "nothing moved");
}

#[then("the rotation is told how long to wait")]
async fn rotation_is_told_to_wait(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("a rotation was asked for");
    assert_eq!(response.status, 429, "{}", response.body);
    let wait: u64 = response
        .headers
        .get("retry-after")
        .unwrap_or_else(|| panic!("no Retry-After in {:?}", response.headers))
        .parse()
        .expect("seconds");
    assert!((1..=600).contains(&wait), "{wait}");
}
