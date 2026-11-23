//! The `request_forwarded` record an Access Point writes for each request it
//! hands to its Target, and the requests that carry a `traceparent`.

use cucumber::{then, when};
use serde_json::Value;

use crate::steps::when::{build_valid_api_key_source_auth_header, ensure_admin_session, send_request_and_record};
use crate::world::{SurfaceSourceAuthConfig, SurfaceWorld};

/// A valid `traceparent` with a fresh trace id and span id, sampled.
fn generated_traceparent() -> (String, String) {
    let span_id = uuid::Uuid::new_v4()
        .simple()
        .to_string()[..16]
        .to_string();
    (
        "traceparent".to_string(),
        format!(
            "00-{}-{span_id}-01",
            uuid::Uuid::new_v4().simple()
        ),
    )
}

#[when("the caller sends a request to the surface with a valid API key and a traceparent set")]
async fn request_with_valid_api_key_and_traceparent(world: &mut SurfaceWorld) {
    let api_key = build_valid_api_key_source_auth_header(world);
    send_request_and_record(world, vec![api_key, generated_traceparent()]).await;
}

#[when("the caller sends a request to the surface with a traceparent set")]
async fn request_with_traceparent(world: &mut SurfaceWorld) {
    send_request_and_record(world, vec![generated_traceparent()]).await;
}

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

#[then("the VP Audit Log records no forwarded request")]
async fn vp_audit_log_records_no_forwarded_request(world: &mut SurfaceWorld) {
    let (found, records) = forwarded_records(world).await;
    assert!(!found, "expected no request_forwarded record, got {records:?}");
}

/// The value of header `name` the scenario's request sent.
fn sent_header<'a>(
    world: &'a SurfaceWorld,
    name: &str,
) -> Option<&'a str> {
    world
        .sent_headers
        .iter()
        .find(|(sent, _)| sent.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// What the record must say about the request the scenario sent: its trace
/// id and parent span, from the `traceparent` it carried, a trace source of
/// `header`, and the API key caller when the request carried a valid key.
fn expected_for_the_request(world: &SurfaceWorld) -> Vec<(&'static str, Value)> {
    let traceparent = sent_header(world, "traceparent").expect("the scenario's request must carry a traceparent");
    let mut expected = vec![
        ("trace_id", Value::from(&traceparent[3..35])),
        ("parent_span_id", Value::from(&traceparent[36..52])),
        ("trace_source", Value::from("header")),
    ];
    if let Some(SurfaceSourceAuthConfig::ApiKey(config)) = &world
        .surface_config
        .source_auth
        && sent_header(world, &config.header_name) == Some(config.valid_key.as_str())
    {
        expected.push(("caller.auth_method", Value::from("api_key")));
        expected.push(("caller.sub", Value::from(config.secret_id.as_str())));
    }
    expected
}

#[then("the VP Audit Log record matches the request")]
async fn vp_audit_log_record_matches_the_request(world: &mut SurfaceWorld) {
    let expected = expected_for_the_request(world);
    let record = the_forwarded_record(world).await;
    let mismatches: Vec<String> = expected
        .iter()
        .filter_map(|(path, expected)| {
            let observed = path
                .split('.')
                .fold(&record, |value, key| &value[key]);
            (observed != expected).then(|| format!("{path}: expected {expected}, observed {observed}"))
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "the request_forwarded record does not match the request: {}\nrecord: {record}",
        mismatches.join("; ")
    );
}
