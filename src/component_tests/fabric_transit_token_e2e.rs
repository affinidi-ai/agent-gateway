//! A transit token issued for a request that arrived over Fabric opens the
//! receiving surface's Transit Points as an Access Point's does, with the
//! Transit Point's static credential, and a Transit Point to a peer gateway
//! refuses a call that would pass the Fabric hop limit before forwarding it.

use super::helpers::{self, GatewayHarness, MockServer};
use base64::Engine as _;
use serde_json::json;
use std::sync::atomic::Ordering;

const TARGET_SECRET_ID: &str = "fabric-transit-target-key";
const TARGET_SECRET: &str = "fabric-transit-static-secret";

fn surface() -> crate::config::agent_surface::AgentSurface {
    let mut surface = helpers::build_minimal_outbound_channel();
    surface.surface_id = "fabric-transit-surface".to_string();
    surface.name = "fabric-transit-surface".to_string();
    let transit = surface
        .transit
        .as_mut()
        .unwrap();
    transit.points[0].require_transit_token = true;
    transit.points[0].allow_unauthenticated_callers = false;
    transit.points[0].target_auth = Some(
        serde_json::from_value(json!({
            "method": { "static_secret": {
                "secret_id": TARGET_SECRET_ID,
                "header_name": "Authorization",
                "header_format": "Bearer {value}"
            } }
        }))
        .unwrap(),
    );
    transit.points.push(
        serde_json::from_value(json!({
            "alias": "partner",
            "target_endpoint": "fabric://partner-gateway/partner-surface",
            "require_transit_token": true
        }))
        .unwrap(),
    );
    surface
}

async fn start_gateway() -> GatewayHarness {
    GatewayHarness::start_with_outbound_mock(MockServer::start().await, |_, gw_config, bootstrap| {
        use crate::secrets::SecretsStore;
        let store = crate::secrets::FilesystemSecretsStore::new(
            &bootstrap
                .storage_paths
                .secrets,
        )
        .unwrap();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                store
                    .create(crate::secrets::CreateSecretRequest {
                        tenant_id: None,
                        name: "Transit Point target key".to_string(),
                        secret_id: TARGET_SECRET_ID.to_string(),
                        description: None,
                        value: TARGET_SECRET.to_string(),
                        secret_type: "ApiKey".to_string(),
                        tags: vec![],
                    })
                    .await
                    .unwrap();
            })
        });
        helpers::configure_gateway_route_prefixes(bootstrap, &[("smoke", "smoke", "/smoke")]);
        gw_config.surfaces = vec![surface()];
    })
    .await
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

/// The transit token the Access Point gave the managed agent.
async fn access_point_token(h: &GatewayHarness) -> String {
    let response = client()
        .post(format!("{}/smoke/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    h.mock
        .last_request_rx
        .borrow()
        .as_ref()
        .and_then(|request| {
            request
                .headers
                .get("x-transit-token")
                .cloned()
        })
        .expect("the managed agent receives a transit token")
}

/// `token` as the gateway issues it for a request a peer sent over Fabric that
/// had made `hops` crossings: no principal, the peer in its `fabric` claim.
fn fabric_issued(
    token: &str,
    hops: u8,
) -> String {
    let payload = token
        .split('.')
        .nth(1)
        .unwrap();
    let mut claims: crate::proxy::transit_token::TransitTokenClaims = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    claims.user_identity_hash = None;
    claims
        .caller_context_fields
        .clear();
    claims.identity_source = Some("fabric-asserted".to_string());
    claims.fabric = Some(crate::proxy::transit_token::FabricTransitClaims {
        peer_gateway_id: "partner-record".to_string(),
        peer_issuer_did: Some("did:web:partner.example".to_string()),
        hops,
    });
    crate::proxy::server::get_transit_token_issuer()
        .expect("the gateway's transit token issuer")
        .sign(&claims)
        .unwrap()
}

async fn call_transit_point(
    h: &GatewayHarness,
    alias: &str,
    token: &str,
) -> reqwest::Response {
    let url = format!(
        "{}/outbound/smoke/{alias}",
        h.outbound_url
            .as_ref()
            .unwrap()
    );
    for _ in 0..100 {
        match client()
            .post(&url)
            .header("content-type", "application/json")
            .header("x-transit-token", token)
            .header("x-gateway-fabric-hops", "1")
            .body(r#"{"jsonrpc":"2.0","method":"test","id":2}"#)
            .send()
            .await
        {
            Ok(response) => return response,
            Err(error) if error.is_connect() => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            Err(error) => panic!("{url}: {error}"),
        }
    }
    panic!("the outbound listener must accept a connection to {url}");
}

/// The agent serving a partner's request calls its own Transit Point with the
/// token this gateway issued for that request: the call reaches the target
/// with the Transit Point's static credential, without the token or the hop
/// count the agent sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_fabric_issued_token_opens_a_transit_point_with_its_static_credential() {
    let h = start_gateway().await;
    let token = fabric_issued(&access_point_token(&h).await, 2);
    let before = h
        .mock
        .request_count
        .load(Ordering::SeqCst);

    let response = call_transit_point(&h, "target", &token).await;

    assert_eq!(response.status(), 200);
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        before + 1
    );
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    assert_eq!(
        received
            .headers
            .get("authorization")
            .map(String::as_str),
        Some(format!("Bearer {TARGET_SECRET}").as_str())
    );
    for header in ["x-transit-token", "x-gateway-fabric-hops"] {
        assert!(
            !received
                .headers
                .contains_key(header),
            "{header}: {:?}",
            received.headers
        );
    }
}

/// A Transit Point to a peer gateway refuses with `508`, before forwarding, a
/// call whose Fabric-issued token already records the most crossings a request
/// may make. A call one crossing short is forwarded, and fails here only
/// because this gateway has no connection to the peer.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_to_a_peer_gateway_refuses_a_call_past_the_hop_limit() {
    let h = start_gateway().await;
    let access_point = access_point_token(&h).await;

    let refused = call_transit_point(&h, "partner", &fabric_issued(&access_point, 8)).await;
    assert_eq!(refused.status(), 508);
    let body: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(body["detail"], "The request passed through too many gateways");

    let forwarded = call_transit_point(&h, "partner", &fabric_issued(&access_point, 7)).await;
    assert_eq!(
        forwarded.status(),
        502,
        "{}",
        forwarded
            .text()
            .await
            .unwrap()
    );
}
