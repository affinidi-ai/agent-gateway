use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::steps::given::{current_surface_body, tracked_surface_id, update_named_surface};
use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

const ALLOW_ALL: &str = "package surface.policy\n\ndefault allow := true\n";
const DENY_ALL: &str = "package surface.policy\n\ndefault allow := false\n";

/// The policy this scenario changes: one per surface, so scenarios never share it.
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
        "description": "A policy whose changes are audited",
        "policy_type": "agent_surface",
        "policy": rego,
        "enabled": true,
        "created_at": chrono::Utc::now().to_rfc3339(),
    })
}

async fn send(
    world: &mut SurfaceWorld,
    method: Method,
    path: &str,
    body: Option<&Value>,
    expected: u16,
) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(method.clone(), path, body)
        .await
        .unwrap_or_else(|error| panic!("{method} {path} through admin API: {error}"));
    assert_eq!(response.status, expected, "{method} {path}: {}", response.body);
}

#[when("the operator creates a surface policy definition")]
async fn operator_creates_policy(world: &mut SurfaceWorld) {
    let id = policy_id(world);
    send(world, Method::POST, "/v1/policy-definitions", Some(&definition(&id, ALLOW_ALL)), 201).await;
}

#[when(expr = "the operator adds the policy to surface {string} as its request policy")]
async fn operator_adds_policy_to_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let mut surface = current_surface_body(world, "adding the audited policy");
    surface["target"]["policy"] = json!({ "policy_definition_id": policy_id(world) });
    update_named_surface(world, &surface_name, surface, "adding the audited policy").await;
    let status = world
        .admin_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(status, Some(200), "adding the audited policy to the surface");
}

#[given(expr = "the operator has added a surface policy definition to surface {string} as its request policy")]
async fn operator_has_added_policy_to_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    operator_creates_policy(world).await;
    operator_adds_policy_to_surface(world, surface_name).await;
}

#[when("the operator changes the policy's Rego")]
async fn operator_changes_policy_rego(world: &mut SurfaceWorld) {
    let id = policy_id(world);
    send(world, Method::PUT, &format!("/v1/policy-definitions/{id}"), Some(&definition(&id, DENY_ALL)), 200).await;
}

#[when(expr = "the operator removes the request policy from surface {string}")]
async fn operator_removes_policy_from_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let mut surface = current_surface_body(world, "removing the audited policy");
    surface["target"]
        .as_object_mut()
        .expect("surface target is an object")
        .remove("policy");
    update_named_surface(world, &surface_name, surface, "removing the audited policy").await;
}

#[when("the operator deletes the policy")]
async fn operator_deletes_policy(world: &mut SurfaceWorld) {
    let id = policy_id(world);
    send(world, Method::DELETE, &format!("/v1/policy-definitions/{id}"), None, 204).await;
}

/// Waits for a VP Audit Log record of `event` for this scenario's policy that
/// `matches`, made by a signed-in operator.
async fn expect_policy_change(
    world: &mut SurfaceWorld,
    event: &str,
    matches: impl Fn(&Value) -> bool,
) {
    let id = policy_id(world);
    ensure_admin_session(world).await;
    let (found, events) = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .wait_for_audit_event(|record| {
            let change = &record["event"][event];
            change["policy_definition_id"] == id.as_str()
                && change["actor"]["kind"] == "user"
                && change["actor"]["id"]
                    .as_str()
                    .is_some_and(|actor| !actor.is_empty())
                && change["source"] == "api"
                && matches(change)
        })
        .await
        .expect("read the VP Audit Log");
    assert!(found, "expected a {event} record for policy {id}, got {events:?}");
}

#[then("the VP Audit Log records that the operator created the policy")]
async fn audit_log_records_policy_created(world: &mut SurfaceWorld) {
    expect_policy_change(world, "policy_created", |change| change["policy_version"] == 1).await;
}

#[then(expr = "the VP Audit Log records that the operator attached the policy to surface {string} as its request policy")]
async fn audit_log_records_policy_attached(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    expect_policy_change(world, "policy_attached", |change| {
        change["target"]["kind"] == "surface"
            && change["target"]["id"] == surface_id.as_str()
            && change["slot"] == "target"
            && change["scope"] == "surface"
    })
    .await;
}

#[then("the VP Audit Log records that the operator changed the policy's Rego")]
async fn audit_log_records_policy_rego_changed(world: &mut SurfaceWorld) {
    expect_policy_change(world, "policy_updated", |change| {
        change["changed"] == json!(["rego"]) && change["previous_policy_version"] == 1 && change["policy_version"] == 2
    })
    .await;
}

#[then(expr = "the VP Audit Log records that the operator detached the policy from surface {string}")]
async fn audit_log_records_policy_detached(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface_id = tracked_surface_id(world, &surface_name);
    expect_policy_change(world, "policy_detached", |change| {
        change["target"]["id"] == surface_id.as_str() && change["slot"] == "target"
    })
    .await;
}

#[then("the VP Audit Log records that the operator deleted the policy")]
async fn audit_log_records_policy_deleted(world: &mut SurfaceWorld) {
    expect_policy_change(world, "policy_deleted", |_| true).await;
}
