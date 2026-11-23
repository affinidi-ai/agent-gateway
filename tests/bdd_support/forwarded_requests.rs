//! The `request_forwarded` record a scenario's request leaves in the VP Audit
//! Log, and the trace headers a scenario's caller sends.

use serde_json::Value;

use super::admin_client::AdminApiClient;

/// A valid `traceparent` with a fresh trace id and span id, sampled.
pub fn generated_traceparent() -> (String, String) {
    let span_id = uuid::Uuid::new_v4()
        .simple()
        .to_string()[..16]
        .to_string();
    ("traceparent".to_string(), format!("00-{}-{span_id}-01", uuid::Uuid::new_v4().simple()))
}

/// The value of header `name` among the headers a request `sent`.
pub fn sent_header<'a>(
    sent: &'a [(String, String)],
    name: &str,
) -> Option<&'a str> {
    sent.iter()
        .find(|(sent, _)| sent.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn is_forwarded(event: &Value) -> bool {
    event["event"]["request_forwarded"].is_object()
}

/// Whether the VP Audit Log came to hold a `request_forwarded` record, read
/// for up to five seconds, and the `request_forwarded` records last read.
pub async fn forwarded_records(admin: &AdminApiClient) -> (bool, Vec<Value>) {
    let (found, events) = admin
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
pub async fn the_forwarded_record(admin: &AdminApiClient) -> Value {
    let (found, records) = forwarded_records(admin).await;
    assert!(found, "expected a request_forwarded record, the VP Audit Log holds none");
    assert_eq!(records.len(), 1, "expected one request_forwarded record, got {records:?}");
    records[0].clone()
}
