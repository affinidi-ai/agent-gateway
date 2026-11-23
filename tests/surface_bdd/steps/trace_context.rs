//! The trace an Access Point continues or starts: what the caller sends, what
//! the target receives, and what the `request_forwarded` record carries.

use cucumber::{then, when};
use serde_json::Value;

use crate::steps::request_forwarded::{generated_traceparent, sent_header, the_forwarded_record};
use crate::steps::then::{gateway_log, get_mcp_request_for_actor};
use crate::steps::when::send_request_and_record;
use crate::world::SurfaceWorld;

const TRACEPARENT: &str = "traceparent";
const X_GATEWAY_TRACE_ID: &str = "X-Gateway-Trace-Id";

/// The written form of a trace id: 32 lowercase hex digits, no hyphens.
fn written_form(trace_id: &str) -> String {
    trace_id
        .replace('-', "")
        .to_ascii_lowercase()
}

/// The trace id a `traceparent` names, as it was written.
fn trace_id_of(traceparent: &str) -> &str {
    traceparent
        .get(3..35)
        .unwrap_or_else(|| panic!("a traceparent names a trace id: {traceparent}"))
}

/// The span a `traceparent` names.
fn span_id_of(traceparent: &str) -> &str {
    traceparent
        .get(36..52)
        .unwrap_or_else(|| panic!("a traceparent names a span: {traceparent}"))
}

/// The value of header `name` the scenario's request sent; the request must have sent it.
fn sent(
    world: &SurfaceWorld,
    name: &str,
) -> String {
    sent_header(world, name)
        .unwrap_or_else(|| panic!("the scenario's request must carry {name}"))
        .to_string()
}

/// The trace ids, in their written form, that the scenario's request named in
/// any trace header.
fn sent_trace_ids(world: &SurfaceWorld) -> Vec<String> {
    world
        .sent_headers
        .iter()
        .filter_map(|(name, value)| {
            if name.eq_ignore_ascii_case(TRACEPARENT) {
                Some(written_form(trace_id_of(value)))
            } else if name.eq_ignore_ascii_case(X_GATEWAY_TRACE_ID) {
                Some(written_form(value))
            } else {
                None
            }
        })
        .collect()
}

#[when("the caller sends a request to the surface with a hyphenated X-Gateway-Trace-Id")]
async fn request_with_hyphenated_x_gateway_trace_id(world: &mut SurfaceWorld) {
    let trace_id = uuid::Uuid::new_v4()
        .hyphenated()
        .to_string()
        .to_uppercase();
    send_request_and_record(world, vec![(X_GATEWAY_TRACE_ID.to_string(), trace_id)]).await;
}

#[when("the caller sends a request to the surface with an invalid traceparent")]
async fn request_with_invalid_traceparent(world: &mut SurfaceWorld) {
    // A traceparent is read only in lowercase; the leading "A" makes sure the
    // trace id holds a capital.
    let (name, valid) = generated_traceparent();
    let invalid = format!("00-A{}-{}-01", trace_id_of(&valid)[1..].to_uppercase(), span_id_of(&valid));
    send_request_and_record(world, vec![(name, invalid)]).await;
}

#[when("the caller sends a request to the surface with duplicate traceparent headers")]
async fn request_with_duplicate_traceparents(world: &mut SurfaceWorld) {
    send_request_and_record(world, vec![generated_traceparent(), generated_traceparent()]).await;
}

#[when("the caller sends a request to the surface with traceparent and X-Gateway-Trace-Id naming different traces")]
async fn request_with_disagreeing_trace_headers(world: &mut SurfaceWorld) {
    let x_gateway_trace_id = uuid::Uuid::new_v4()
        .simple()
        .to_string();
    send_request_and_record(
        world,
        vec![generated_traceparent(), (X_GATEWAY_TRACE_ID.to_string(), x_gateway_trace_id)],
    )
    .await;
}

#[then(expr = "MCP server {string} received a traceparent that continues the caller's trace")]
fn mcp_server_received_a_traceparent_continuing_the_callers_trace(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let who = format!("MCP server '{server_name}'");
    let caller = sent(world, TRACEPARENT);
    let request = get_mcp_request_for_actor(world, &server_name);
    let [received] = request.values_of_header(TRACEPARENT) else {
        panic!("{who} expected exactly one traceparent, received {:?}", request.values_of_header(TRACEPARENT));
    };
    assert_eq!(
        trace_id_of(received),
        trace_id_of(&caller),
        "{who} received a traceparent of another trace: the caller sent {caller}, {who} received {received}"
    );
    assert_ne!(
        span_id_of(received),
        span_id_of(&caller),
        "{who} received the caller's own span, not the gateway's: the caller sent {caller}, {who} received {received}"
    );
}

#[then("the VP Audit Log records the forwarded request under the caller's trace in its written form")]
async fn vp_audit_log_records_the_forwarded_request_under_the_callers_trace_in_its_written_form(
    world: &mut SurfaceWorld,
) {
    let caller = sent(world, X_GATEWAY_TRACE_ID);
    let record = the_forwarded_record(world).await;
    assert_eq!(
        record["trace_id"],
        written_form(&caller),
        "expected the record under the caller's trace {caller} in its written form; record: {record}"
    );
}

#[then("the VP Audit Log records the forwarded request under the X-Gateway-Trace-Id trace")]
async fn vp_audit_log_records_the_forwarded_request_under_the_x_gateway_trace_id_trace(world: &mut SurfaceWorld) {
    let named = sent(world, X_GATEWAY_TRACE_ID);
    let record = the_forwarded_record(world).await;
    assert_eq!(
        record["trace_id"],
        written_form(&named),
        "expected the record under the X-Gateway-Trace-Id trace {named}; record: {record}"
    );
}

#[then("the VP Audit Log records the forwarded request under a newly minted trace")]
async fn vp_audit_log_records_the_forwarded_request_under_a_newly_minted_trace(world: &mut SurfaceWorld) {
    let sent_ids = sent_trace_ids(world);
    let record = the_forwarded_record(world).await;
    let trace_id = record["trace_id"]
        .as_str()
        .unwrap_or_default();
    assert!(
        !sent_ids
            .iter()
            .any(|sent| sent == trace_id),
        "expected a newly minted trace, observed {trace_id}, a trace the caller sent ({sent_ids:?}); record: {record}"
    );
    assert_eq!(
        record["trace_source"], "minted",
        "expected trace source minted, observed {}; record: {record}",
        record["trace_source"]
    );
}

#[then("the VP Audit Log records the forwarded request with no parent span")]
async fn vp_audit_log_records_the_forwarded_request_with_no_parent_span(world: &mut SurfaceWorld) {
    let record = the_forwarded_record(world).await;
    assert!(
        record
            .get("parent_span_id")
            .is_none_or(Value::is_null),
        "expected no parent span, observed {}; record: {record}",
        record["parent_span_id"]
    );
}

#[then(expr = "the VP Audit Log records the forwarded request with trace source {string}")]
async fn vp_audit_log_records_the_forwarded_request_with_trace_source(
    world: &mut SurfaceWorld,
    trace_source: String,
) {
    let record = the_forwarded_record(world).await;
    assert_eq!(
        record["trace_source"],
        trace_source.as_str(),
        "expected trace source {trace_source}, observed {}; record: {record}",
        record["trace_source"]
    );
}

#[then("the gateway log does not contain the caller's invalid trace")]
fn gateway_log_does_not_contain_the_callers_invalid_trace(world: &mut SurfaceWorld) {
    let caller = sent(world, TRACEPARENT);
    let invalid = trace_id_of(&caller);
    let log = gateway_log(world);
    for form in [invalid.to_string(), invalid.to_ascii_lowercase()] {
        assert!(!log.contains(&form), "the gateway log contains the caller's invalid trace {form}");
    }
}

#[then("the gateway log warns that the trace headers named different traces")]
fn gateway_log_warns_that_the_trace_headers_named_different_traces(world: &mut SurfaceWorld) {
    let traceparent_trace = written_form(trace_id_of(&sent(world, TRACEPARENT)));
    let named_trace = written_form(&sent(world, X_GATEWAY_TRACE_ID));
    let log = gateway_log(world);
    assert!(
        log.lines()
            .any(|line| {
                line.contains("WARN")
                    && line.contains("name different traces")
                    && line.contains(&traceparent_trace)
                    && line.contains(&named_trace)
            }),
        "expected a warning that traceparent {traceparent_trace} and X-Gateway-Trace-Id {named_trace} name different traces:\n{log}"
    );
}
