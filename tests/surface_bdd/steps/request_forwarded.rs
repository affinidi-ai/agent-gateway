//! The `request_forwarded` record an Access Point writes for each request it
//! hands to its Target, and the requests that carry a `traceparent`.

use cucumber::{given, then, when};
use serde_json::Value;

use crate::bdd_support::forwarded_requests::{
    forwarded_records, generated_traceparent, sent_header, the_forwarded_record,
};
use crate::steps::when::{build_valid_api_key_source_auth_header, ensure_admin_session, send_request_and_record};
use crate::world::{SurfaceSourceAuthConfig, SurfaceWorld};

#[when("the caller sends a request to the surface with a valid API key and a traceparent set")]
async fn request_with_valid_api_key_and_traceparent(world: &mut SurfaceWorld) {
    let api_key = build_valid_api_key_source_auth_header(world);
    send_request_and_record(world, vec![api_key, generated_traceparent()]).await;
}

#[when("the caller sends a request to the surface with a traceparent set")]
async fn request_with_traceparent(world: &mut SurfaceWorld) {
    send_request_with_traceparent(world).await;
}

#[given("the caller has sent a request to the surface with a traceparent set")]
async fn caller_has_sent_a_request_with_traceparent(world: &mut SurfaceWorld) {
    send_request_with_traceparent(world).await;
}

/// The caller sends a request to the surface with a fresh `traceparent`.
async fn send_request_with_traceparent(world: &mut SurfaceWorld) {
    send_request_and_record(world, vec![generated_traceparent()]).await;
}

#[then("the VP Audit Log records the forwarded request once")]
async fn vp_audit_log_records_the_forwarded_request_once(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    the_forwarded_record(
        world
            .admin_client
            .as_ref()
            .expect("admin client must exist"),
    )
    .await;
}

#[then("the VP Audit Log records no forwarded request")]
async fn vp_audit_log_records_no_forwarded_request(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    let (found, records) = forwarded_records(
        world
            .admin_client
            .as_ref()
            .expect("admin client must exist"),
    )
    .await;
    assert!(!found, "expected no request_forwarded record, got {records:?}");
}

/// What the record must say about the request the scenario sent: its trace
/// id and parent span, from the `traceparent` it carried, a trace source of
/// `header`, and the API key caller when the request carried a valid key.
fn expected_for_the_request(world: &SurfaceWorld) -> Vec<(&'static str, Value)> {
    let traceparent =
        sent_header(&world.sent_headers, "traceparent").expect("the scenario's request must carry a traceparent");
    let mut expected = vec![
        ("trace_id", Value::from(&traceparent[3..35])),
        ("parent_span_id", Value::from(&traceparent[36..52])),
        ("trace_source", Value::from("header")),
    ];
    if let Some(SurfaceSourceAuthConfig::ApiKey(config)) = &world
        .surface_config
        .source_auth
        && sent_header(&world.sent_headers, &config.header_name) == Some(config.valid_key.as_str())
    {
        expected.push(("caller.auth_method", Value::from("api_key")));
        expected.push(("caller.sub", Value::from(config.secret_id.as_str())));
    }
    expected
}

#[then("the VP Audit Log record matches the request")]
async fn vp_audit_log_record_matches_the_request(world: &mut SurfaceWorld) {
    let expected = expected_for_the_request(world);
    ensure_admin_session(world).await;
    let record = the_forwarded_record(
        world
            .admin_client
            .as_ref()
            .expect("admin client must exist"),
    )
    .await;
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
