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
    start_gateway_with_transit_token_lifetime(None).await
}

/// A gateway whose `/smoke` surface sets `lifetime_secs` as its transit token
/// lifetime, beside a second surface on `/other`.
async fn start_gateway_with_transit_token_lifetime(lifetime_secs: Option<u64>) -> GatewayHarness {
    start_gateway_with_transit_token_limits(lifetime_secs, None).await
}

/// Like [`start_gateway_with_transit_token_lifetime`], on an appliance whose
/// `gateway.json` sets `transit_token_min_lifetime_secs` to `min_secs`.
async fn start_gateway_with_transit_token_limits(
    lifetime_secs: Option<u64>,
    min_secs: Option<u64>,
) -> GatewayHarness {
    GatewayHarness::start_with_outbound_mock(MockServer::start().await, |_, gw_config, bootstrap| {
        if let Some(min_secs) = min_secs {
            helpers::configure_gateway_setting(bootstrap, "transit_token_min_lifetime_secs", json!(min_secs));
        }
        write_target_secret(
            &bootstrap
                .storage_paths
                .secrets,
        );
        helpers::configure_gateway_route_prefixes(
            bootstrap,
            &[("smoke", "smoke", "/smoke"), ("other", "other", "/other")],
        );
        let mut surface = surface_with_static_target_credential("transit-token-surface", "/smoke");
        surface
            .transit
            .as_mut()
            .unwrap()
            .shared
            .transit_token_lifetime_secs = lifetime_secs;
        gw_config.surfaces =
            vec![surface, surface_with_static_target_credential("transit-token-other-surface", "/other")];
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

/// The status a call to the surface's Transit Point is answered with, once the
/// outbound listener, which a surface save rebinds, accepts the connection.
async fn call_transit_point(
    h: &GatewayHarness,
    route: &str,
    token: &str,
) -> reqwest::StatusCode {
    let url = format!(
        "{}/outbound{route}/target",
        h.outbound_url
            .as_ref()
            .unwrap()
    );
    for _ in 0..100 {
        match client()
            .post(&url)
            .header("content-type", "application/json")
            .header("x-transit-token", token)
            .body(r#"{"jsonrpc":"2.0","method":"test","id":2}"#)
            .send()
            .await
        {
            Ok(response) => return response.status(),
            Err(error) if error.is_connect() => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            Err(error) => panic!("{url}: {error}"),
        }
    }
    panic!("the outbound listener must accept a connection to {url}");
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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// How long `token` was issued to live, in seconds.
fn lifetime_of(token: &str) -> u64 {
    let claims = token_part(token, 1);
    claims["exp"]
        .as_u64()
        .unwrap()
        - claims["iat"]
            .as_u64()
            .unwrap()
}

/// `token` issued at `iat` to expire at `exp`, signed with the key the gateway
/// signs its transit tokens with.
fn reissued(
    token: &str,
    iat: u64,
    exp: u64,
) -> String {
    let mut claims: crate::proxy::transit_token::TransitTokenClaims =
        serde_json::from_value(token_part(token, 1)).unwrap();
    claims.iat = iat;
    claims.exp = exp;
    crate::proxy::server::get_transit_token_issuer()
        .expect("the gateway's transit token issuer")
        .sign(&claims)
        .unwrap()
}

/// The Access Point hands the managed agent a token living the lifetime its
/// surface sets, and the Transit Point accepts a token for that whole lifetime:
/// 400 seconds into 600 it reaches the target with the Transit Point's
/// credential, while one past its lifetime, or living longer than the surface
/// allows, is refused before the target.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_token_opens_its_transit_point_for_the_lifetime_its_surface_sets() {
    let h = start_gateway_with_transit_token_lifetime(Some(600)).await;
    let token = transit_token_from_access_point(&h, "/smoke").await;
    assert_eq!(lifetime_of(&token), 600);
    let now = unix_now();
    let before = h
        .mock
        .request_count
        .load(Ordering::SeqCst);

    assert_eq!(call_transit_point(&h, "/smoke", &reissued(&token, now - 400, now + 200)).await, 200);
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
    for (case, iat, exp) in
        [("past its lifetime", now - 610, now - 10), ("living longer than its surface allows", now, now + 601)]
    {
        assert_eq!(call_transit_point(&h, "/smoke", &reissued(&token, iat, exp)).await, 401, "{case}");
    }
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        before + 1,
        "a refused call must not reach the target"
    );
}

/// An appliance whose `gateway.json` lowers `transit_token_min_lifetime_secs` to
/// 10 admits a surface lifetime of 10 seconds through the admin API and has its
/// Access Point issue 10 second tokens that its Transit Point accepts, while 5 is
/// refused naming the new minimum; one that sets nothing still refuses 10.
#[tokio::test(flavor = "multi_thread")]
async fn the_appliance_sets_the_shortest_transit_token_lifetime_a_surface_may_have() {
    let h = start_gateway_with_transit_token_limits(Some(10), Some(10)).await;
    let token = transit_token_from_access_point(&h, "/smoke").await;
    assert_eq!(lifetime_of(&token), 10);
    assert_eq!(call_transit_point(&h, "/smoke", &token).await, 200);

    for (min_secs, secs, accepted) in [(Some(10), 10, true), (Some(10), 5, false), (None, 10, false), (None, 30, true)]
    {
        let mut admin = None;
        let h = GatewayHarness::start_with_outbound(|_, _, bootstrap| {
            admin = Some(helpers::configure_admin_api(bootstrap));
            helpers::configure_gateway_route_prefixes(bootstrap, &[("lifetime", "lifetime", "/lifetime")]);
            if let Some(min_secs) = min_secs {
                helpers::configure_gateway_setting(bootstrap, "transit_token_min_lifetime_secs", json!(min_secs));
            }
        })
        .await;
        let local = |url: &str| {
            format!(
                "http://localhost:{}",
                url.rsplit(':')
                    .next()
                    .unwrap()
            )
        };
        let response = admin
            .unwrap()
            .post(format!("{}/api/v1/surfaces", h.gateway_base))
            .json(&json!({
                "name": "lifetime",
                "access_point": { "listen_address": local(&h.gateway_base), "route": "/lifetime", "protocol": "a2a" },
                "target": { "endpoint": h.mock.url() },
                "transit": {
                    "transit_token_lifetime_secs": secs,
                    "outbound_listen_address": local(h.outbound_url.as_deref().unwrap()),
                    "points": [{ "alias": "target", "target_endpoint": h.mock.url() }]
                }
            }))
            .send()
            .await
            .unwrap();
        if accepted {
            assert_eq!(response.status(), 201, "{min_secs:?} {secs}");
        } else {
            assert_eq!(response.status(), 400, "{min_secs:?} {secs}");
            assert!(
                response
                    .text()
                    .await
                    .unwrap()
                    .contains(&format!(
                        "transit.transit_token_lifetime_secs must be from {} to 900 seconds, not {secs}",
                        min_secs.unwrap_or(30)
                    )),
                "{min_secs:?} {secs}"
            );
        }
    }
}

/// The admin API refuses a transit token lifetime outside 30 to 900 seconds,
/// and one set in a variant. Lengthening a surface's lifetime keeps the
/// shorter tokens already issued; shortening it refuses the tokens issued for
/// longer at once, while the Access Point issues tokens for the new lifetime.
#[tokio::test(flavor = "multi_thread")]
async fn changing_a_surfaces_transit_token_lifetime_applies_to_the_tokens_already_issued() {
    let mut admin = None;
    let h = GatewayHarness::start_with_outbound(|_, _, bootstrap| {
        admin = Some(helpers::configure_admin_api(bootstrap));
        helpers::configure_gateway_route_prefixes(bootstrap, &[("lifetime", "lifetime", "/lifetime")]);
    })
    .await;
    let admin = admin.unwrap();
    let listener = |url: &str| {
        format!(
            "http://localhost:{}",
            url.rsplit(':')
                .next()
                .unwrap()
        )
    };
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let payload = json!({
        "name": "lifetime",
        "access_point": { "listen_address": listener(&h.gateway_base), "route": "/lifetime", "protocol": "a2a" },
        "target": { "endpoint": h.mock.url() },
        "transit": {
            "outbound_listen_address": listener(h.outbound_url.as_deref().unwrap()),
            "points": [{ "alias": "target", "target_endpoint": h.mock.url(), "require_transit_token": true }]
        }
    });

    for secs in [29, 901] {
        let mut refused = payload.clone();
        refused["transit"]["transit_token_lifetime_secs"] = json!(secs);
        let response = admin
            .post(&collection)
            .json(&refused)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "{secs}");
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains(&format!("transit.transit_token_lifetime_secs must be from 30 to 900 seconds, not {secs}")),
            "{secs}"
        );
    }
    let mut in_a_variant = payload.clone();
    in_a_variant["variants"] = json!([{
        "id": "longer", "alias": "longer", "name": "Longer",
        "overrides": { "transit": { "shared": { "transit_token_lifetime_secs": 900 } } }
    }]);
    let response = admin
        .post(&collection)
        .json(&in_a_variant)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("unknown field `transit_token_lifetime_secs`")
    );

    let created = admin
        .post(&collection)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let stored: serde_json::Value = created.json().await.unwrap();
    assert!(
        stored["transit"]
            .get("transit_token_lifetime_secs")
            .is_none(),
        "{stored}"
    );
    let surface_url = format!(
        "{collection}/{}",
        stored["surface_id"]
            .as_str()
            .unwrap()
    );
    let set_lifetime = |secs: u64| {
        admin
            .patch(&surface_url)
            .header("content-type", "application/merge-patch+json")
            .body(json!({ "transit": { "transit_token_lifetime_secs": secs } }).to_string())
            .send()
    };

    let issued_for_300 = transit_token_from_access_point(&h, "/lifetime").await;
    assert_eq!(lifetime_of(&issued_for_300), 300);
    assert_eq!(call_transit_point(&h, "/lifetime", &issued_for_300).await, 200);

    let lengthened = set_lifetime(600)
        .await
        .unwrap();
    assert_eq!(lengthened.status(), 200);
    assert_eq!(
        lengthened
            .json::<serde_json::Value>()
            .await
            .unwrap()["transit"]["transit_token_lifetime_secs"],
        600
    );
    let issued_for_600 = transit_token_from_access_point(&h, "/lifetime").await;
    assert_eq!(lifetime_of(&issued_for_600), 600);
    assert_eq!(call_transit_point(&h, "/lifetime", &issued_for_600).await, 200);
    assert_eq!(call_transit_point(&h, "/lifetime", &issued_for_300).await, 200, "a shorter token is kept");

    let refused = set_lifetime(901)
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    assert_eq!(call_transit_point(&h, "/lifetime", &issued_for_600).await, 200, "a refused change changes nothing");

    assert_eq!(
        set_lifetime(300)
            .await
            .unwrap()
            .status(),
        200
    );
    let before = h
        .mock
        .request_count
        .load(Ordering::SeqCst);
    assert_eq!(call_transit_point(&h, "/lifetime", &issued_for_600).await, 401, "a longer token is refused");
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        before,
        "a refused call must not reach the target"
    );
    assert_eq!(call_transit_point(&h, "/lifetime", &issued_for_300).await, 200);
    assert_eq!(lifetime_of(&transit_token_from_access_point(&h, "/lifetime").await), 300);
}
