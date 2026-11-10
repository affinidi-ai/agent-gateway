use cucumber::{given, then, when};
use reqwest::Method;

use crate::bdd_support::config::single_surface_fixture::BundledTrustAgentSetup;
use crate::bdd_support::trust_agent::{Behaviour, MockTrustAgent};
use crate::steps::credential_save::send;
use crate::world::SurfaceWorld;

async fn bundled_trust_agent(
    world: &mut SurfaceWorld,
    behaviour: Behaviour,
    publishes_identity: bool,
) {
    let agent = MockTrustAgent::start(behaviour).await;
    if publishes_identity {
        agent.publish_identity();
    }
    world
        .surface_config
        .bundled_trust_agent = Some(BundledTrustAgentSetup {
        base_url: agent.url.clone(),
        bootstrap_dir: agent.bootstrap_path(),
    });
    world.bundled_trust_agent = Some(agent);
}

#[given("a bundled trust agent that has enrolled the gateway")]
async fn bundled_trust_agent_that_enrolled_the_gateway(world: &mut SurfaceWorld) {
    bundled_trust_agent(world, Behaviour::Enrolled, true).await;
}

#[given("a bundled trust agent that has not published its identity")]
async fn bundled_trust_agent_that_has_not_published(world: &mut SurfaceWorld) {
    bundled_trust_agent(world, Behaviour::Enrolled, false).await;
}

#[given("a bundled trust agent that refuses the gateway")]
async fn bundled_trust_agent_that_refuses_the_gateway(world: &mut SurfaceWorld) {
    bundled_trust_agent(world, Behaviour::Refusing, true).await;
}

#[given("a bundled trust agent that granted the gateway more than the bundled grant")]
async fn bundled_trust_agent_that_over_granted(world: &mut SurfaceWorld) {
    bundled_trust_agent(world, Behaviour::OverPrivileged, true).await;
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

#[when("the operator verifies the bundled trust agent connection")]
async fn operator_verifies_bundled_connection(world: &mut SurfaceWorld) {
    let response = send(world, Method::POST, "/v1/vta/connections/vta-bootstrap/verify", None).await;
    world.admin_response = Some(response);
}

#[when("the operator reads the key inventory")]
async fn operator_reads_key_inventory(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/key-management/inventory", None).await;
    world.admin_response = Some(response);
}

#[then("the inventory lists the bundled trust agent as paired and usable")]
async fn inventory_lists_bundled_agent_usable(world: &mut SurfaceWorld) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("the key inventory was read")
        .body;
    let connection = body["connections"]
        .as_array()
        .and_then(|connections| {
            connections
                .iter()
                .find(|c| c["connection_id"] == "vta-bootstrap")
        })
        .unwrap_or_else(|| panic!("no bootstrap connection in {body}"));
    assert_eq!(connection["pairing_state"], "connected", "{connection}");
    assert_eq!(connection["usable"], true, "{connection}");
}

#[then("the inventory shows the bundled trust agent's signing key")]
async fn inventory_shows_bundled_key(world: &mut SurfaceWorld) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("the key inventory was read")
        .body;
    let connection = body["connections"]
        .as_array()
        .and_then(|connections| {
            connections
                .iter()
                .find(|c| c["connection_id"] == "vta-bootstrap")
        })
        .unwrap_or_else(|| panic!("no bootstrap connection in {body}"));
    assert_eq!(connection["keys"][0]["key_id"], "gateway-jwt-1", "{connection}");
    assert_eq!(connection["keys"][0]["status"], "active", "{connection}");
}

fn bootstrap_connection(world: &SurfaceWorld) -> &serde_json::Value {
    let body = &world
        .admin_response
        .as_ref()
        .expect("the trust agent connections were listed")
        .body;
    body.as_array()
        .and_then(|connections| {
            connections
                .iter()
                .find(|connection| connection["id"] == "vta-bootstrap")
        })
        .unwrap_or_else(|| panic!("no bootstrap connection in {body}"))
}

#[then("the bootstrap connection is shown as connected")]
async fn bootstrap_connection_is_connected(world: &mut SurfaceWorld) {
    let connection = bootstrap_connection(world);
    assert_eq!(connection["status"], "connected", "{connection}");
    assert_eq!(connection["pairing"]["state"], "connected", "{connection}");
}

#[then("the bootstrap connection shows the bundled grant and no error")]
async fn bootstrap_connection_shows_grant(world: &mut SurfaceWorld) {
    let pairing = &bootstrap_connection(world)["pairing"];
    assert_eq!(pairing["granted_role"], "initiator", "{pairing}");
    assert_eq!(pairing["granted_contexts"], serde_json::json!(["gateway"]), "{pairing}");
    assert!(
        pairing
            .get("last_error")
            .is_none(),
        "{pairing}"
    );
}

fn status(world: &SurfaceWorld) -> &serde_json::Value {
    &world
        .admin_response
        .as_ref()
        .expect("the trust agent status was read")
        .body
}

#[then(expr = "the bootstrap state is {string}")]
async fn bootstrap_state_is(
    world: &mut SurfaceWorld,
    state: String,
) {
    assert_eq!(status(world)["bootstrap"]["state"], state, "{}", status(world));
}

#[then("the trust agent has no owner yet")]
async fn trust_agent_has_no_owner(world: &mut SurfaceWorld) {
    assert_eq!(status(world)["bootstrap"]["owner"], "unclaimed", "{}", status(world));
}

#[then("the deployment is reported as bundled with no custody claim")]
async fn deployment_is_bundled_without_custody(world: &mut SurfaceWorld) {
    let status = status(world);
    assert_eq!(status["tier"], "bundled", "{status}");
    assert_eq!(status["custody_claim"], false, "{status}");
}

#[then("the gateway authenticates as a did:key")]
async fn gateway_authenticates_as_did_key(world: &mut SurfaceWorld) {
    assert_eq!(status(world)["control_did_method"], "did_key", "{}", status(world));
}

#[then(expr = "the gateway signs with its own local key because the bundled trust agent is {string}")]
async fn gateway_signs_locally(
    world: &mut SurfaceWorld,
    state: String,
) {
    let resolution = &status(world)["default_resolution"];
    assert_eq!(resolution["backend"], "local", "{resolution}");
    assert_eq!(resolution["fallback_from"], "bundled", "{resolution}");
    assert_eq!(status(world)["bootstrap"]["state"], state, "{}", status(world));
}

#[then("the gateway wrote its own did:key for the trust agent to enrol")]
async fn gateway_wrote_its_did_key(world: &mut SurfaceWorld) {
    let path = world
        .bundled_trust_agent
        .as_ref()
        .expect("a bundled trust agent")
        .bootstrap_path()
        .join("gateway-enrolment.env");
    let note = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    assert!(note.contains("GATEWAY_CONTROL_DID=did:key:"), "{note}");
    assert!(
        !note
            .to_lowercase()
            .contains("seed"),
        "nothing secret may be written to the shared folder: {note}"
    );
}

#[then("the trust agent gave the gateway context an identity to issue as")]
async fn trust_agent_gave_context_an_identity(world: &mut SurfaceWorld) {
    let agent = world
        .bundled_trust_agent
        .as_ref()
        .expect("a bundled trust agent");
    assert_eq!(
        agent
            .context_identity()
            .as_deref(),
        Some("did:key:z6MkBddMintedPublicKey")
    );
}

#[then(expr = "the trust agent was asked to create {int} signing key(s)")]
async fn trust_agent_was_asked_to_create_keys(
    world: &mut SurfaceWorld,
    count: usize,
) {
    let created = world
        .bundled_trust_agent
        .as_ref()
        .expect("a bundled trust agent")
        .signing_keys_created();
    assert_eq!(created, count);
}

#[given("a bundled trust agent that refuses to move the gateway's access entry")]
async fn bundled_trust_agent_that_refuses_the_swap(world: &mut SurfaceWorld) {
    bundled_trust_agent(world, Behaviour::RefusingSwap, true).await;
}

#[given(expr = "human user {string} lacks permission to manage keys")]
async fn human_user_lacks_key_management(
    world: &mut SurfaceWorld,
    username: String,
) {
    crate::steps::terms::login(world, &username, "user").await;
}

#[when("the operator rotates the bundled control key")]
async fn operator_rotates_the_control_key(world: &mut SurfaceWorld) {
    let response = send(world, Method::POST, "/v1/vta/control-key/rotate", None).await;
    world.admin_response = Some(response);
}

#[given("the operator has rotated the bundled control key")]
async fn operator_has_rotated_the_control_key(world: &mut SurfaceWorld) {
    let response = send(world, Method::POST, "/v1/vta/control-key/rotate", None).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

#[when(expr = "human user {string} tries to rotate the bundled control key")]
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

fn rotation(world: &SurfaceWorld) -> &serde_json::Value {
    &world
        .admin_response
        .as_ref()
        .expect("a rotation was asked for")
        .body
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
    let agent = world
        .bundled_trust_agent
        .as_ref()
        .expect("a bundled trust agent");
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
    let refused = world
        .bundled_trust_agent
        .as_ref()
        .expect("a bundled trust agent")
        .refused_sign_ins();
    assert_eq!(refused, 0, "the gateway signed in as a key that no longer holds the entry");
}

#[then(expr = "the bootstrap signing key is still {string}")]
async fn bootstrap_signing_key_is(
    world: &mut SurfaceWorld,
    key_id: String,
) {
    assert_eq!(status(world)["bootstrap"]["signing_key_id"], key_id, "{}", status(world));
}

#[then("the status shows the control key was rotated just now")]
async fn status_shows_rotated_just_now(world: &mut SurfaceWorld) {
    let rotated = status(world)["bootstrap"]["control_key_rotated_at"]
        .as_str()
        .unwrap_or_else(|| panic!("no rotation time in {}", status(world)));
    let rotated = chrono::DateTime::parse_from_rfc3339(rotated).expect("an RFC 3339 time");
    let age = chrono::Utc::now().signed_duration_since(rotated);
    assert!(age < chrono::Duration::minutes(1) && age > chrono::Duration::minutes(-1), "{age}");
}

#[then("the next rotation is due in 90 days")]
async fn next_rotation_is_due_in_ninety_days(world: &mut SurfaceWorld) {
    let bootstrap = &status(world)["bootstrap"];
    assert_eq!(bootstrap["control_key_rotation_days"], 90, "{bootstrap}");
    let next = bootstrap["control_key_next_rotation_at"]
        .as_str()
        .unwrap_or_else(|| panic!("no next rotation in {bootstrap}"));
    let next = chrono::DateTime::parse_from_rfc3339(next).expect("an RFC 3339 time");
    let wait = next.signed_duration_since(chrono::Utc::now());
    assert!(wait > chrono::Duration::days(89) && wait < chrono::Duration::days(91), "{wait}");
}

#[then("the trust agent still knows the gateway by the did:key it enrolled")]
async fn trust_agent_still_knows_the_first_did(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/vta/status", None).await;
    let reported = response.body["bootstrap"]["control_did"]
        .as_str()
        .expect("a control DID")
        .to_string();
    let agent = world
        .bundled_trust_agent
        .as_ref()
        .expect("a bundled trust agent");
    assert_eq!(
        agent
            .gateway_entry()
            .as_deref(),
        Some(reported.as_str())
    );
    assert!(agent.swaps().is_empty(), "nothing moved");
    assert_eq!(response.body["bootstrap"]["state"], "connected", "the gateway is still connected: {}", response.body);
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
