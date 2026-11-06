use cucumber::then;
use serde_json::json;

use crate::steps::credential_save::{SECRET_VALUE, surface_id};
use crate::steps::policy_changes::{client, user_id};
use crate::world::SurfaceWorld;

#[then(expr = "the VP Audit Log records that the operator force-deleted the secret {string} the surface still used")]
async fn audit_log_records_secret_force_deleted(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let actor = json!({ "kind": "user", "id": user_id(world, None).await });
    let referrers = json!([{ "kind": "surface", "id": surface_id(world) }]);
    let (found, events) = client(world, None)
        .await
        .wait_for_audit_event(|record| {
            let deleted = &record["event"]["secret_force_deleted"];
            deleted["actor"] == actor
                && deleted["secret_id"] == secret_id.as_str()
                && deleted["force"] == true
                && deleted["referrers"] == referrers
        })
        .await
        .expect("read the VP Audit Log");
    assert!(found, "expected a secret_force_deleted record by {actor}, got {events:?}");
}

#[then("no VP Audit Log record carries a secret value")]
async fn no_audit_record_carries_secret_value(world: &mut SurfaceWorld) {
    let events = client(world, None)
        .await
        .read_audit_events()
        .await
        .expect("read the VP Audit Log");
    let carrying: Vec<_> = events
        .iter()
        .filter(|record| {
            record
                .to_string()
                .contains(SECRET_VALUE)
        })
        .collect();
    assert!(carrying.is_empty(), "expected no record carrying a secret value, got {carrying:?}");
}
