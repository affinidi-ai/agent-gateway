//! The `request_forwarded` record an Access Point writes for each request it
//! hands to its Target.

use cucumber::then;
use serde_json::Value;

use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

fn is_forwarded(event: &Value) -> bool {
    event["event"]["request_forwarded"].is_object()
}

/// Whether the VP Audit Log came to hold a `request_forwarded` record, read
/// for up to five seconds, and the `request_forwarded` records last read.
async fn forwarded_records(world: &mut SurfaceWorld) -> (bool, Vec<Value>) {
    ensure_admin_session(world).await;
    let (found, events) = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .wait_for_audit_event(is_forwarded)
        .await
        .unwrap_or_else(|error| panic!("the VP Audit Log must be readable: {error:#}"));
    (
        found,
        events
            .into_iter()
            .filter(is_forwarded)
            .collect(),
    )
}

/// The one `request_forwarded` record of the scenario's request.
async fn the_forwarded_record(world: &mut SurfaceWorld) -> Value {
    let (found, records) = forwarded_records(world).await;
    assert!(found, "expected a request_forwarded record, the VP Audit Log holds none");
    assert_eq!(records.len(), 1, "expected one request_forwarded record, got {records:?}");
    records[0].clone()
}

#[then("the VP Audit Log records the forwarded request once")]
async fn vp_audit_log_records_the_forwarded_request_once(world: &mut SurfaceWorld) {
    the_forwarded_record(world).await;
}
