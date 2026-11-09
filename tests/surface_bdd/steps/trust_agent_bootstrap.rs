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
