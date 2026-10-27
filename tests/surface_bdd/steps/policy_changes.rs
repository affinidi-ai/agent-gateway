use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{AdminApiClient, RecordedResponse};
use crate::steps::given::{current_surface_body, tracked_surface_id, update_named_surface};
use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

const ALLOW_ALL: &str = "package surface.policy\n\ndefault allow := true\n";
const DENY_ALL: &str = "package surface.policy\n\ndefault allow := false\n";

/// The policy definition this scenario changes: one per surface, so scenarios never share it.
fn policy_id(world: &SurfaceWorld) -> String {
    format!("bdd-policy-change-{}", tracked_surface_id(world, "alpha"))
}

fn definition(
    id: &str,
    rego: &str,
) -> Value {
    json!({
        "id": id,
        "name": "BDD audited policy",
        "description": "A policy definition whose changes are audited",
        "policy_type": "agent_surface",
        "policy": rego,
        "enabled": true,
        "created_at": chrono::Utc::now().to_rfc3339(),
    })
}

/// The client of `operator`, or of the default operator when `None`.
async fn client(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
) -> AdminApiClient {
    match operator {
        Some(operator) => world
            .operator_clients
            .get(operator)
            .unwrap_or_else(|| panic!("operator '{operator}' must have signed in"))
            .clone(),
        None => {
            ensure_admin_session(world).await;
            world
                .admin_client
                .clone()
                .expect("admin client must exist")
        }
    }
}

async fn send(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    client(world, operator)
        .await
        .send_recorded_json(method.clone(), path, body)
        .await
        .unwrap_or_else(|error| panic!("{method} {path} through admin API: {error}"))
}

async fn create_policy(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
) -> RecordedResponse {
    let id = policy_id(world);
    send(world, operator, Method::POST, "/v1/policy-definitions", Some(&definition(&id, ALLOW_ALL))).await
}

async fn add_policy_to_surface(
    world: &mut SurfaceWorld,
    surface_name: &str,
) {
    let mut surface = current_surface_body(world, "adding the policy definition");
    surface["target"]["policy"] = json!({ "policy_definition_id": policy_id(world) });
    update_named_surface(world, surface_name, surface, "adding the policy definition").await;
}

fn require_success(
    response: &RecordedResponse,
    setup: &str,
) {
    assert!((200..300).contains(&response.status), "{setup}: status {} body {}", response.status, response.body);
}

#[given("the operator has created a surface policy definition")]
async fn operator_has_created_policy(world: &mut SurfaceWorld) {
    let response = create_policy(world, None).await;
    require_success(&response, "creating the policy definition");
}

#[given(expr = "the operator has added the policy definition to surface {string} as its request policy")]
async fn operator_has_added_policy_to_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    add_policy_to_surface(world, &surface_name).await;
    let response = world
        .admin_response
        .as_ref()
        .expect("the surface update has a response");
    require_success(response, "adding the policy definition to the surface");
}

#[when("the operator creates a surface policy definition")]
async fn operator_creates_policy(world: &mut SurfaceWorld) {
    world.admin_response = Some(create_policy(world, None).await);
}

#[when(expr = "operator {string} creates a surface policy definition")]
async fn named_operator_creates_policy(
    world: &mut SurfaceWorld,
    operator: String,
) {
    world.admin_response = Some(create_policy(world, Some(&operator)).await);
}

#[when(expr = "the operator adds the policy definition to surface {string} as its request policy")]
async fn operator_adds_policy_to_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    add_policy_to_surface(world, &surface_name).await;
}

#[when("the operator changes the policy definition's Rego")]
async fn operator_changes_policy_rego(world: &mut SurfaceWorld) {
    let id = policy_id(world);
    let path = format!("/v1/policy-definitions/{id}");
    world.admin_response = Some(send(world, None, Method::PUT, &path, Some(&definition(&id, DENY_ALL))).await);
}

#[when(expr = "the operator removes the request policy from surface {string}")]
async fn operator_removes_policy_from_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let mut surface = current_surface_body(world, "removing the policy definition");
    surface["target"]
        .as_object_mut()
        .expect("surface target is an object")
        .remove("policy");
    update_named_surface(world, &surface_name, surface, "removing the policy definition").await;
}

#[when("the operator deletes the policy definition")]
async fn operator_deletes_policy(world: &mut SurfaceWorld) {
    let path = format!("/v1/policy-definitions/{}", policy_id(world));
    world.admin_response = Some(send(world, None, Method::DELETE, &path, None).await);
}

/// The user id of `operator` (the default operator when `None`), as the gateway records it.
async fn user_id(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
) -> String {
    let profile = send(world, operator, Method::GET, "/v1/profile", None).await;
    profile.body["user_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the profile names its user id, got {}", profile.body))
        .to_string()
}

/// Waits for a VP Audit Log record of `event` made by `operator` that `matches`.
async fn expect_change(
    world: &mut SurfaceWorld,
    operator: Option<&str>,
    event: &str,
    matches: impl Fn(&Value) -> bool,
) {
    let actor = json!({ "kind": "user", "id": user_id(world, operator).await });
    let (found, events) = client(world, None)
        .await
        .wait_for_audit_event(|record| {
            let change = &record["event"][event];
            change["actor"] == actor && change["source"] == "api" && matches(change)
        })
        .await
        .expect("read the VP Audit Log");
    assert!(found, "expected a {event} record by {actor}, got {events:?}");
}

#[then("the VP Audit Log records that the operator created the policy definition")]
async fn audit_log_records_policy_created(world: &mut SurfaceWorld) {
    let id = policy_id(world);
    expect_change(world, None, "policy_created", |change| {
        change["policy_definition_id"] == id.as_str() && change["policy_version"] == 1
    })
    .await;
}

#[then(
    expr = "the VP Audit Log records that the operator attached the policy definition to surface {string} as its request policy"
)]
async fn audit_log_records_policy_attached(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let id = policy_id(world);
    let surface_id = tracked_surface_id(world, &surface_name);
    expect_change(world, None, "policy_attached", |change| {
        change["policy_definition_id"] == id.as_str()
            && change["target"]["kind"] == "surface"
            && change["target"]["id"] == surface_id.as_str()
            && change["slot"] == "target"
            && change["scope"] == "surface"
    })
    .await;
}

#[then("the VP Audit Log records that the operator changed the policy definition's Rego")]
async fn audit_log_records_policy_rego_changed(world: &mut SurfaceWorld) {
    let id = policy_id(world);
    expect_change(world, None, "policy_updated", |change| {
        change["policy_definition_id"] == id.as_str()
            && change["changed"] == json!(["rego"])
            && change["previous_policy_version"] == 1
            && change["policy_version"] == 2
    })
    .await;
}

#[then(expr = "the VP Audit Log records that the operator detached the policy definition from surface {string}")]
async fn audit_log_records_policy_detached(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let id = policy_id(world);
    let surface_id = tracked_surface_id(world, &surface_name);
    expect_change(world, None, "policy_detached", |change| {
        change["policy_definition_id"] == id.as_str()
            && change["target"]["id"] == surface_id.as_str()
            && change["slot"] == "target"
    })
    .await;
}

#[then("the VP Audit Log records that the operator deleted the policy definition")]
async fn audit_log_records_policy_deleted(world: &mut SurfaceWorld) {
    let id = policy_id(world);
    expect_change(world, None, "policy_deleted", |change| change["policy_definition_id"] == id.as_str()).await;
}

#[then(expr = "the VP Audit Log records that operator {string} was refused creating a policy definition")]
async fn audit_log_records_policy_creation_refused(
    world: &mut SurfaceWorld,
    operator: String,
) {
    expect_change(world, Some(&operator), "policy_change_refused", |change| {
        change["action"] == "policy_created" && change["status"] == 403 && change["reason"] == "forbidden"
    })
    .await;
}

#[then("the VP Audit Log has no record that the policy definition was created")]
async fn audit_log_has_no_policy_created(world: &mut SurfaceWorld) {
    let events = client(world, None)
        .await
        .read_audit_events()
        .await
        .expect("read the VP Audit Log");
    let created: Vec<_> = events
        .iter()
        .filter(|record| record["event"].get("policy_created").is_some())
        .collect();
    assert!(created.is_empty(), "expected no policy_created record, got {created:?}");
}
