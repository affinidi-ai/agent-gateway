use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::custom_trust_agent::{CUSTOM_TRUST_AGENT_DID, CustomTrustAgent};
use crate::steps::credential_save::send;
use crate::world::SurfaceWorld;

const NAME: &str = "Custom VTA";
const DID_KEY: &str = "Custom VTA control DID";

fn connection_id(world: &SurfaceWorld) -> String {
    world
        .trust_agent_connections
        .get(NAME)
        .cloned()
        .expect("a custom trust agent connection was made")
}

async fn connect(
    world: &mut SurfaceWorld,
    control_identity: &str,
) {
    let agent = CustomTrustAgent::start().await;
    let body = json!({
        "name": NAME,
        "enabled": true,
        "transport": "https",
        "endpoint": agent.url,
        "vta_did": CUSTOM_TRUST_AGENT_DID,
        "default_context_id": "custom",
        "control_identity": control_identity,
    });
    let created = send(world, Method::POST, "/v1/vta/connections", Some(&body)).await;
    assert_eq!(created.status, 201, "creating the connection: {}", created.body);
    let id = created.body["id"]
        .as_str()
        .expect("an id")
        .to_string();
    let control_did = created.body["control_did"]
        .as_str()
        .map(str::to_string);
    world
        .trust_agent_connections
        .insert(NAME.to_string(), id.clone());
    if control_identity == "did_key" {
        world.custom_trust_agent = Some(agent);
        return;
    }
    let control_did = control_did
        .unwrap_or_else(|| panic!("the gateway published no did:webvh for the connection: {}", created.body));
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .gateway_port;
    agent.read_dids_from(&format!("http://127.0.0.1:{port}"));
    agent.grant(&control_did);
    let paired = send(world, Method::POST, &format!("/v1/vta/connections/{id}/pair"), None).await;
    assert_eq!(paired.status, 200, "pairing: {}", paired.body);
    let verified = send(world, Method::POST, &format!("/v1/vta/connections/{id}/verify"), None).await;
    assert_eq!(verified.status, 200, "verifying: {}", verified.body);
    assert_eq!(verified.body["pairing"]["state"], "connected", "{}", verified.body);
    world
        .trust_agent_connections
        .insert(DID_KEY.to_string(), control_did);
    world.custom_trust_agent = Some(agent);
}

fn agent(world: &SurfaceWorld) -> &CustomTrustAgent {
    world
        .custom_trust_agent
        .as_ref()
        .expect("a custom trust agent")
}

#[given("the operator has connected a custom trust agent that reads the gateway's published DID")]
async fn connected_custom_agent(world: &mut SurfaceWorld) {
    connect(world, "webvh").await;
}

#[given("the operator has connected a custom trust agent as a did:key")]
async fn connected_custom_agent_as_did_key(world: &mut SurfaceWorld) {
    connect(world, "did_key").await;
}

#[given("the custom trust agent does not take a new key")]
async fn custom_agent_does_not_take_a_new_key(world: &mut SurfaceWorld) {
    agent(world).only_accept("key-1");
}

#[given("the gateway rolls a refused rotation back after ten seconds")]
async fn rolls_back_after_ten_seconds(world: &mut SurfaceWorld) {
    world
        .surface_config
        .connection_key_switch_timeout_secs = Some(10);
}

#[given("the operator has rotated the custom connection's control key")]
async fn operator_has_rotated(world: &mut SurfaceWorld) {
    let id = connection_id(world);
    let response = send(world, Method::POST, &format!("/v1/vta/connections/{id}/control-key/rotate"), None).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

#[given(expr = "human user {string} lacks permission to manage keys on the custom connection")]
async fn human_user_lacks_permission(
    world: &mut SurfaceWorld,
    username: String,
) {
    crate::steps::terms::login(world, &username, "user").await;
}

#[when("the operator rotates the custom connection's control key")]
async fn operator_rotates(world: &mut SurfaceWorld) {
    let id = connection_id(world);
    let response = send(world, Method::POST, &format!("/v1/vta/connections/{id}/control-key/rotate"), None).await;
    world.admin_response = Some(response);
}

#[when(expr = "human user {string} tries to rotate the custom connection's control key")]
async fn human_user_tries(
    world: &mut SurfaceWorld,
    username: String,
) {
    let id = connection_id(world);
    let client = crate::steps::terms::latest_client(world, &username);
    let response = client
        .send_recorded_json::<Value>(Method::POST, &format!("/v1/vta/connections/{id}/control-key/rotate"), None)
        .await
        .expect("the request completes");
    world.admin_response = Some(response);
}

#[when("the operator verifies the custom connection")]
async fn operator_verifies(world: &mut SurfaceWorld) {
    let id = connection_id(world);
    let response = send(world, Method::POST, &format!("/v1/vta/connections/{id}/verify"), None).await;
    world.admin_response = Some(response);
}

#[when("the operator renames the custom connection")]
async fn operator_renames(world: &mut SurfaceWorld) {
    let id = connection_id(world);
    let current = send(world, Method::GET, &format!("/v1/vta/connections/{id}"), None).await;
    assert_eq!(current.status, 200, "{}", current.body);
    let c = &current.body;
    let body = json!({
        "name": "Renamed custom VTA",
        "enabled": c["enabled"],
        "transport": c["transport"],
        "endpoint": c["endpoint"],
        "vta_did": c["vta_did"],
        "default_context_id": c["default_context_id"],
        "control_key_ref": c["control_key_ref"],
    });
    let response = send(world, Method::PUT, &format!("/v1/vta/connections/{id}"), Some(&body)).await;
    world.admin_response = Some(response);
}

fn body(world: &SurfaceWorld) -> &Value {
    &world
        .admin_response
        .as_ref()
        .expect("a response")
        .body
}

#[then("the connection keeps the DID that was granted")]
async fn keeps_the_did(world: &mut SurfaceWorld) {
    let granted = world
        .trust_agent_connections
        .get(DID_KEY)
        .cloned()
        .expect("the granted DID");
    assert_eq!(body(world)["control_did"], granted, "{}", body(world));
}

#[then("the trust agent finds only the new key published for that DID")]
async fn only_the_new_key(world: &mut SurfaceWorld) {
    let did = world
        .trust_agent_connections
        .get(DID_KEY)
        .cloned()
        .expect("the granted DID");
    assert_eq!(
        agent(world)
            .published_fragments(&did)
            .await,
        vec!["key-2".to_string()]
    );
}

#[then("the trust agent finds only the original key published for that DID")]
async fn only_the_original_key(world: &mut SurfaceWorld) {
    let did = world
        .trust_agent_connections
        .get(DID_KEY)
        .cloned()
        .expect("the granted DID");
    assert_eq!(
        agent(world)
            .published_fragments(&did)
            .await,
        vec!["key-1".to_string()]
    );
}

#[then("the trust agent accepted the gateway signing in with the new key")]
async fn accepted_new_key(world: &mut SurfaceWorld) {
    assert_eq!(body(world)["pairing"]["state"], "connected", "{}", body(world));
    assert_eq!(
        agent(world)
            .last_signed_in_as()
            .as_deref(),
        Some("key-2")
    );
}

#[then("the trust agent saw the gateway sign in with the original key last")]
async fn original_key_last(world: &mut SurfaceWorld) {
    assert_eq!(
        agent(world)
            .last_signed_in_as()
            .as_deref(),
        Some("key-1")
    );
    assert!(
        agent(world)
            .refused_fragments()
            .contains(&"key-2".to_string()),
        "the new key was tried and refused"
    );
}

#[then("the connection still names the rotated key after the edit")]
async fn names_rotated_key(world: &mut SurfaceWorld) {
    assert_eq!(body(world)["name"], "Renamed custom VTA", "{}", body(world));
    assert_eq!(body(world)["control_key_state"]["verification_method"], "#key-2", "{}", body(world));
    assert_eq!(
        body(world)["control_key_ref"],
        "vta-control-key-".to_string() + &connection_id_of(body(world)) + "-key-2"
    );
}

fn connection_id_of(body: &Value) -> String {
    body["id"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[then("the custom connection shows when its control key was rotated and no rotation under way")]
async fn shows_rotation_time(world: &mut SurfaceWorld) {
    let list = body(world)
        .as_array()
        .expect("a list");
    let custom = list
        .iter()
        .find(|c| c["name"] == NAME)
        .expect("the custom connection");
    assert!(custom["control_key_state"]["rotated_at"].is_string(), "{custom}");
    assert_eq!(custom["control_key_state"]["verification_method"], "#key-2", "{custom}");
    assert!(
        custom["control_key_state"]
            .get("rotation")
            .is_none(),
        "{custom}"
    );
}
