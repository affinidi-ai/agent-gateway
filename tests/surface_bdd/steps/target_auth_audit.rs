use cucumber::then;
use serde_json::json;

use crate::steps::credential_save::surface_id;
use crate::steps::policy_changes::{client, user_id};
use crate::world::SurfaceWorld;

#[then(expr = "the VP Audit Log records that the operator replaced the secret the surface's Target authenticates with")]
async fn audit_log_records_target_secret_replaced(world: &mut SurfaceWorld) {
    let actor = json!({ "kind": "user", "id": user_id(world, None).await });
    let surface_id = surface_id(world);
    let (found, events) = client(world, None)
        .await
        .wait_for_audit_event(|record| {
            let change = &record["event"]["target_auth_changed"];
            record["surface_id"] == surface_id.as_str()
                && change["actor"] == actor
                && change["leg"] == "target"
                && change["surface_variant"] == "_base_"
                && change["previous_method"] == "static_secret"
                && change["method"] == "static_secret"
                && change["changed"] == json!(["secret_id"])
        })
        .await
        .expect("read the VP Audit Log");
    assert!(found, "expected a target_auth_changed record by {actor}, got {events:?}");
}

#[then(expr = "no VP Audit Log record names the secret {string}")]
async fn no_audit_record_names_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let events = client(world, None)
        .await
        .read_audit_events()
        .await
        .expect("read the VP Audit Log");
    let naming: Vec<_> = events
        .iter()
        .filter(|record| {
            record
                .to_string()
                .contains(&format!("\"{secret_id}\""))
        })
        .collect();
    assert!(naming.is_empty(), "expected no record naming secret {secret_id}, got {naming:?}");
}
