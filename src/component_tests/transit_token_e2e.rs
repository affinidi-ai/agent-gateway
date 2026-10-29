//! Transit token E2E: the token the Access Point hands the managed agent opens
//! that surface's Transit Points, call after call, for its lifetime, and a token
//! the gateway did not sign opens nothing.
//!
//! The Transit Point injects a static target credential, so a call that reaches
//! the mock target shows whether the credential went with it.

use super::helpers::{self, GatewayHarness, MockServer};
use crate::config::agent_surface::AgentSurface;
use base64::Engine as _;
use serde_json::json;
use std::sync::atomic::Ordering;

const TARGET_SECRET_ID: &str = "transit-point-target-key";
const TARGET_SECRET: &str = "transit-point-static-secret";

fn surface_with_static_target_credential(
    surface_id: &str,
    route: &str,
) -> AgentSurface {
    let mut surface = helpers::build_minimal_outbound_channel();
    surface.surface_id = surface_id.to_string();
    surface.name = surface_id.to_string();
    surface.access_point.route = route.to_string();
    let point = &mut surface
        .transit
        .as_mut()
        .unwrap()
        .points[0];
    point.require_transit_token = true;
    point.target_auth = Some(
        serde_json::from_value(json!({
            "method": { "static_secret": {
                "secret_id": TARGET_SECRET_ID,
                "header_name": "Authorization",
                "header_format": "Bearer {value}"
            } }
        }))
        .unwrap(),
    );
    surface
}

fn write_target_secret(storage_path: &str) {
    use crate::secrets::SecretsStore;

    let store = crate::secrets::FilesystemSecretsStore::new(storage_path).expect("create secrets store");
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
                .expect("create target secret");
        })
    });
}

async fn start_gateway() -> GatewayHarness {
    GatewayHarness::start_with_outbound_mock(MockServer::start().await, |_, gw_config, bootstrap| {
        write_target_secret(
            &bootstrap
                .storage_paths
                .secrets,
        );
        helpers::configure_gateway_route_prefixes(
            bootstrap,
            &[("smoke", "smoke", "/smoke"), ("other", "other", "/other")],
        );
        gw_config.surfaces = vec![
            surface_with_static_target_credential("transit-token-surface", "/smoke"),
            surface_with_static_target_credential("transit-token-other-surface", "/other"),
        ];
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

/// The transit token the Access Point attached to the request it forwarded to
/// the managed agent.
async fn transit_token_from_access_point(
    h: &GatewayHarness,
    route: &str,
) -> String {
    let response = client()
        .post(format!("{}{route}/rpc", h.gateway_base))
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
        .expect("the managed agent must receive a transit token")
}

async fn call_transit_point(
    h: &GatewayHarness,
    route: &str,
    token: &str,
) -> reqwest::StatusCode {
    client()
        .post(format!(
            "{}/outbound{route}/target",
            h.outbound_url
                .as_ref()
                .unwrap()
        ))
        .header("content-type", "application/json")
        .header("x-transit-token", token)
        .body(r#"{"jsonrpc":"2.0","method":"test","id":2}"#)
        .send()
        .await
        .unwrap()
        .status()
}

fn token_part(
    token: &str,
    index: usize,
) -> serde_json::Value {
    let segment = token
        .split('.')
        .nth(index)
        .unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .unwrap(),
    )
    .unwrap()
}

/// The managed agent replays the one token it was given on several calls of the
/// same turn, and each call reaches the target with the Transit Point's
/// credential and without the token.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_token_opens_its_surfaces_transit_point_for_several_calls() {
    let h = start_gateway().await;
    let token = transit_token_from_access_point(&h, "/smoke").await;

    for call in 1..=3 {
        let before = h
            .mock
            .request_count
            .load(Ordering::SeqCst);
        assert_eq!(call_transit_point(&h, "/smoke", &token).await, 200, "call {call}");
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
            Some(format!("Bearer {TARGET_SECRET}").as_str()),
            "call {call}"
        );
        assert!(
            !received
                .headers
                .contains_key("x-transit-token"),
            "call {call}"
        );
    }
}

/// A token signed with a key other than the gateway's stored transit token key
/// is refused before the target is called.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_token_signed_with_another_key_is_refused() {
    use sha2::{Digest, Sha256};

    let h = start_gateway().await;
    let token = transit_token_from_access_point(&h, "/smoke").await;
    let header = token_part(&token, 0);
    let mut claims = token_part(&token, 1);
    claims["user_identity_hash"] = json!("another-users-hash");
    let derived = Sha256::new()
        .chain_update(b"transit-token-signing-key:")
        .chain_update(
            claims["iss"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .finalize();
    let mut with_real_kid = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    with_real_kid.kid = header["kid"]
        .as_str()
        .map(str::to_string);
    let before = h
        .mock
        .request_count
        .load(Ordering::SeqCst);

    for forged_header in [jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256), with_real_kid] {
        let forged =
            jsonwebtoken::encode(&forged_header, &claims, &jsonwebtoken::EncodingKey::from_secret(&derived)).unwrap();
        assert_eq!(call_transit_point(&h, "/smoke", &forged).await, 401);
    }
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        before,
        "a refused call must not reach the target"
    );
}

/// A token one surface's Access Point issued does not open another surface's
/// Transit Point, even one with the same alias.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_token_does_not_open_another_surfaces_transit_point() {
    let h = start_gateway().await;
    let token = transit_token_from_access_point(&h, "/smoke").await;
    let before = h
        .mock
        .request_count
        .load(Ordering::SeqCst);

    assert_eq!(call_transit_point(&h, "/other", &token).await, 401);

    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        before,
        "a refused call must not reach the target"
    );
    assert_eq!(call_transit_point(&h, "/smoke", &token).await, 200);
}

/// A surface whose Transit Point speaks MCP and injects a static target
/// credential, as a linked agent's surface is set up.
fn surface_with_an_mcp_transit_point() -> AgentSurface {
    let mut surface = surface_with_static_target_credential("transit-token-mcp-surface", "/links");
    surface
        .transit
        .as_mut()
        .unwrap()
        .points[0]
        .protocol = crate::config::agent_surface::TransitProtocol::Mcp;
    surface
}

/// A managed agent linked to another agent over an MCP Transit Point replays
/// the one transit token its turn was given through the whole `2024-11-05`
/// exchange: `initialize`, `tools/list` and `tools/call` each reach the linked
/// agent with the Transit Point's credential and without the token.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_token_opens_an_mcp_transit_point_for_a_whole_mcp_exchange() {
    let mock = MockServer::start_with_response(
        json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {},
            "serverInfo": {"name": "linked-agent", "version": "1"}, "tools": [], "content": []}})
        .to_string(),
    )
    .await;
    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, bootstrap| {
        write_target_secret(
            &bootstrap
                .storage_paths
                .secrets,
        );
        helpers::configure_gateway_route_prefixes(bootstrap, &[("links", "links", "/links")]);
        gw_config.surfaces = vec![surface_with_an_mcp_transit_point()];
    })
    .await;
    let token = transit_token_from_access_point(&h, "/links").await;

    for (id, method, params) in [
        (
            1,
            "initialize",
            json!({"protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "managed-agent", "version": "1"}}),
        ),
        (2, "tools/list", json!({})),
        (3, "tools/call", json!({"name": "ask", "arguments": {"question": "status?"}})),
    ] {
        let before = h
            .mock
            .request_count
            .load(Ordering::SeqCst);
        let mut request = client()
            .post(format!(
                "{}/outbound/links/target",
                h.outbound_url
                    .as_ref()
                    .unwrap()
            ))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("x-transit-token", &token);
        if method != "initialize" {
            request = request.header("mcp-protocol-version", "2024-11-05");
        }
        let response = request
            .body(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "{method}");
        assert_eq!(
            h.mock
                .request_count
                .load(Ordering::SeqCst),
            before + 1,
            "{method}"
        );
        let received = h
            .mock
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&received.body).unwrap()["method"], method, "{method}");
        assert_eq!(
            received
                .headers
                .get("authorization")
                .map(String::as_str),
            Some(format!("Bearer {TARGET_SECRET}").as_str()),
            "{method}"
        );
        assert!(
            !received
                .headers
                .contains_key("x-transit-token"),
            "{method}"
        );
    }
}
