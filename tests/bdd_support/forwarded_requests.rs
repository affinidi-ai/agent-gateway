//! The `request_forwarded` and `transit_request_forwarded` records a
//! scenario's requests leave in the VP Audit Log, the trace headers a
//! scenario's caller sends, and the requests the Access Point forwards to the
//! managed agent.

use serde_json::Value;

use super::admin_client::AdminApiClient;
use super::mock_server::ReceivedRequest;

const REQUEST_FORWARDED: &str = "request_forwarded";
const TRANSIT_REQUEST_FORWARDED: &str = "transit_request_forwarded";

/// The header the Access Point hands the managed agent its transit token in.
const TRANSIT_TOKEN: &str = "x-transit-token";

/// The trace headers the gateway writes itself.
const TRACE_HEADERS: [&str; 3] = ["traceparent", "tracestate", "x-gateway-trace-id"];

/// Every value of every trace header `request` carried, by header name.
pub fn trace_headers_of(request: &ReceivedRequest) -> Vec<(String, String)> {
    TRACE_HEADERS
        .iter()
        .flat_map(|name| {
            request
                .values_of_header(name)
                .iter()
                .map(|value| (name.to_string(), value.clone()))
        })
        .collect()
}

/// The last of the `requests` a managed agent received that the Access Point
/// forwarded to it, which carries the transit token the Access Point gave it.
pub fn the_last_access_point_request(requests: &[ReceivedRequest]) -> Option<&ReceivedRequest> {
    requests
        .iter()
        .rev()
        .find(|request| {
            request
                .headers
                .contains_key(TRANSIT_TOKEN)
        })
}

/// The transit token the Access Point gave the managed agent with `request`.
pub fn transit_token_of(request: &ReceivedRequest) -> String {
    request.headers[TRANSIT_TOKEN].clone()
}

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

/// Whether the VP Audit Log came to hold a record of audit event `name`, read
/// for up to five seconds, and the records of that event last read.
async fn records_of(
    admin: &AdminApiClient,
    name: &str,
) -> (bool, Vec<Value>) {
    let is_of_event = |event: &Value| event["event"][name].is_object();
    let (found, events) = admin
        .wait_for_audit_event(is_of_event)
        .await
        .unwrap_or_else(|error| panic!("the VP Audit Log must be readable: {error:#}"));
    (
        found,
        events
            .into_iter()
            .filter(is_of_event)
            .collect(),
    )
}

/// The one record of audit event `name` in the VP Audit Log.
async fn the_record_of(
    admin: &AdminApiClient,
    name: &str,
) -> Value {
    let (found, records) = records_of(admin, name).await;
    assert!(found, "expected a {name} record, the VP Audit Log holds none");
    assert_eq!(records.len(), 1, "expected one {name} record, got {records:?}");
    records[0].clone()
}

/// Whether the VP Audit Log came to hold a `request_forwarded` record, read
/// for up to five seconds, and the `request_forwarded` records last read.
pub async fn forwarded_records(admin: &AdminApiClient) -> (bool, Vec<Value>) {
    records_of(admin, REQUEST_FORWARDED).await
}

/// The one `request_forwarded` record of the scenario's request.
pub async fn the_forwarded_record(admin: &AdminApiClient) -> Value {
    the_record_of(admin, REQUEST_FORWARDED).await
}

/// The one `transit_request_forwarded` record of the scenario's Transit Point
/// request.
pub async fn the_transit_forwarded_record(admin: &AdminApiClient) -> Value {
    the_record_of(admin, TRANSIT_REQUEST_FORWARDED).await
}
