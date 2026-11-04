//! A Transit Point credential stays under the Transit Point's base path: a
//! request whose path climbs out of it is refused with a 502 before anything
//! reaches the destination, and a request under it carries the credential.

use super::helpers::{self, GatewayHarness, MockServer};
use super::target_auth_base_path_e2e::{RPC_BODY, raw_post};
use super::target_auth_provider_e2e::write_secret;
use serde_json::json;
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_path_outside_its_base_path_is_refused_before_the_destination() {
    let mock = MockServer::start().await;
    let destination = format!("{}/base", mock.url());
    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, bootstrap| {
        write_secret(bootstrap, "transit-key", "transit-value");
        let mut surface = helpers::build_minimal_outbound_channel();
        let point = &mut surface
            .transit
            .as_mut()
            .unwrap()
            .points[0];
        point.target_endpoint = destination;
        point.target_auth = Some(
            serde_json::from_value(json!({
                "method": {"static_secret": {
                    "secret_id": "transit-key", "header_name": "X-Api-Key", "header_format": "{value}"
                }}
            }))
            .unwrap(),
        );
        gw_config.surfaces = vec![surface];
    })
    .await;
    let outbound = h
        .outbound_url
        .clone()
        .expect("the outbound listener is configured");

    for path in [
        "/outbound/smoke/target/%2e%2e/admin",
        "/outbound/smoke/target/%2E%2E/%2e%2e/admin",
        "/outbound/smoke/target/../admin",
    ] {
        let (status, response) = raw_post(&outbound, path).await;
        assert_eq!(status, 502, "{path}");
        assert!(response.contains("Target authentication"), "{path}: {response}");
    }
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{outbound}/outbound/smoke/target/rpc"))
        .header("content-type", "application/json")
        .body(RPC_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the destination received the request");
    assert_eq!(received.path, "/base/rpc");
    let credential = received
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-api-key"))
        .map(|(_, value)| value.as_str());
    assert_eq!(credential, Some("transit-value"));
}
