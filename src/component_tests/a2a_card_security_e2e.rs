//! Agent card security E2E tests
//!
//! A declaring Access Point replaces the security an upstream card declares with the
//! gateway's own `agent_gateway` OAuth scheme, in the shape of the card's A2A era, drops
//! the card's signatures, and refuses a card it cannot process rather than serve it as
//! received. A Transit Point of a declaring Access Point serves its partner's card with
//! no security at all. An Access Point that does not declare serves the upstream security
//! and signatures unchanged. A declaring Access Point also publishes RFC 9728 protected
//! resource metadata at its own URL, for its base route and for each Surface Variant
//! whose URL its audiences name.

use serde_json::{Value, json};

use super::helpers;
use helpers::card_security::{
    ISSUER, REQUIRED_SCOPE, SMOKE_RESOURCE, STRATEGY_ID, UPSTREAM_MARKER, add_upstream_security,
    advertise_public_origin, assert_declares, assert_keeps_upstream_security, assert_strips,
    jwt_bearer_caller_authentication, write_strategy,
};
use helpers::jwt::{JwksFixture, now_secs, sign_jwt};
use helpers::{GatewayHarness, MockServer};

const BACKEND: &str = "https://backend.internal";
const DEV_RESOURCE: &str = "https://gw.example/smoke$dev";
const OTHER_AUDIENCE: &str = "api://agent";

#[derive(Clone, Copy, Debug)]
enum Era {
    V1,
    V0_3,
    Dual,
}

impl Era {
    const ALL: [Era; 3] = [Era::V1, Era::V0_3, Era::Dual];

    fn has_v1(self) -> bool {
        matches!(self, Era::V1 | Era::Dual)
    }

    fn has_v0_3(self) -> bool {
        matches!(self, Era::V0_3 | Era::Dual)
    }
}

fn upstream_card(era: Era) -> Value {
    let mut card = json!({ "name": "secured-agent", "version": "1.0.0" });
    if era.has_v1() {
        card["supportedInterfaces"] =
            json!([{ "url": format!("{BACKEND}/a2a"), "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }]);
    }
    if era.has_v0_3() {
        card["protocolVersion"] = json!("0.3.0");
        card["url"] = json!(format!("{BACKEND}/a2a"));
        card["preferredTransport"] = json!("JSONRPC");
    }
    add_upstream_security(&mut card);
    card
}

fn extended_card_envelope(era: Era) -> String {
    json!({ "jsonrpc": "2.0", "id": 1, "result": upstream_card(era) }).to_string()
}

enum CallerAuth {
    None,
    Jwt { issuer: String, pinned: bool, audiences: Vec<&'static str> },
}

fn jwt(
    pinned: bool,
    audiences: &[&'static str],
) -> CallerAuth {
    CallerAuth::Jwt {
        issuer: ISSUER.to_string(),
        pinned,
        audiences: audiences.to_vec(),
    }
}

/// One pinned `jwt_bearer` method whose audiences name the base route's Access Point
/// URL, so the base route declares and its `dev` variant does not.
fn declaring() -> CallerAuth {
    jwt(true, &[SMOKE_RESOURCE])
}

/// The same method trusting the keys of `fixture`, so a caller can present a token.
fn declaring_with_keys(fixture: &JwksFixture) -> CallerAuth {
    CallerAuth::Jwt {
        issuer: fixture.issuer.clone(),
        pinned: true,
        audiences: vec![SMOKE_RESOURCE],
    }
}

async fn start_gateway(
    upstream_body: String,
    caller_auth: CallerAuth,
) -> GatewayHarness {
    let mock = MockServer::start_with_response(upstream_body).await;
    GatewayHarness::start_with_outbound_mock(mock, move |temp_dir, gw_config, bootstrap| {
        advertise_public_origin(bootstrap);
        let mut surface = helpers::build_minimal_outbound_channel();
        surface.variants = vec![
            serde_json::from_value(json!({
                "id": "vc-dev", "alias": "dev", "name": "dev", "description": "", "enabled": true, "overrides": {}
            }))
            .expect("variant"),
        ];
        if let CallerAuth::Jwt { issuer, pinned, audiences } = caller_auth {
            write_strategy(temp_dir, &issuer, pinned);
            surface
                .access_point
                .caller_authentication =
                Some(serde_json::from_value(jwt_bearer_caller_authentication(&audiences)).expect("caller auth"));
        }
        gw_config.surfaces = vec![surface];
    })
    .await
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("HTTP client")
}

async fn get(url: &str) -> (reqwest::StatusCode, reqwest::header::HeaderMap, String) {
    let response = client()
        .get(url)
        .send()
        .await
        .expect("GET through gateway");
    let status = response.status();
    let headers = response.headers().clone();
    (
        status,
        headers,
        response
            .text()
            .await
            .expect("body"),
    )
}

fn public_card_url(
    h: &GatewayHarness,
    route: &str,
) -> String {
    format!("{}{route}/.well-known/agent-card.json", h.gateway_base)
}

fn transit_card_url(h: &GatewayHarness) -> String {
    format!(
        "{}/outbound/smoke/target/.well-known/agent-card.json",
        h.outbound_url
            .as_ref()
            .expect("outbound url")
    )
}

async fn card_at(url: &str) -> Value {
    let (status, _, body) = get(url).await;
    assert_eq!(status, 200, "{url}: {body}");
    serde_json::from_str(&body).expect("card JSON")
}

async fn public_card(
    h: &GatewayHarness,
    route: &str,
) -> Value {
    card_at(&public_card_url(h, route)).await
}

fn token(
    fixture: &JwksFixture,
    audience: &str,
) -> String {
    sign_jwt(
        json!({
            "iss": fixture.issuer, "sub": "client", "aud": audience, "scope": REQUIRED_SCOPE,
            "exp": now_secs() + 300, "iat": now_secs(),
        }),
        &fixture.kid,
    )
}

async fn request_extended_card(
    h: &GatewayHarness,
    method: &str,
    token: Option<&str>,
) -> reqwest::Response {
    let mut request = client()
        .post(format!("{}/smoke/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .body(json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": {} }).to_string());
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request
        .send()
        .await
        .expect("extended card request")
}

async fn extended_card(
    h: &GatewayHarness,
    method: &str,
    token: &str,
) -> Value {
    let response = request_extended_card(h, method, Some(token)).await;
    assert_eq!(response.status(), 200);
    let envelope: Value = response
        .json()
        .await
        .expect("envelope JSON");
    envelope["result"].clone()
}

fn endpoint(card: &Value) -> Option<&str> {
    crate::a2a::url_rewriter::primary_endpoint_url(card)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_access_point_replaces_upstream_security_on_its_public_card_in_every_era() {
    for era in Era::ALL {
        let h = start_gateway(upstream_card(era).to_string(), declaring()).await;
        let card = public_card(&h, "/smoke").await;
        assert_declares(&card, ISSUER, era.has_v1(), era.has_v0_3());
        assert_eq!(endpoint(&card), Some(SMOKE_RESOURCE), "{era:?}: the card names the Access Point URL it declares");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_access_point_declares_on_its_extended_card_in_both_eras() {
    let fixture = JwksFixture::start().await;
    for (era, method) in [(Era::V1, "GetExtendedAgentCard"), (Era::V0_3, "agent/getAuthenticatedExtendedCard")] {
        let h = start_gateway(extended_card_envelope(era), declaring_with_keys(&fixture)).await;
        let unauthenticated = request_extended_card(&h, method, None).await;
        assert_eq!(unauthenticated.status(), 401, "{era:?}: a caller without a token is challenged");

        let card = extended_card(&h, method, &token(&fixture, SMOKE_RESOURCE)).await;
        assert_declares(&card, &fixture.issuer, era.has_v1(), era.has_v0_3());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_access_point_that_does_not_declare_serves_upstream_security_unchanged() {
    for caller_auth in [CallerAuth::None, jwt(false, &[SMOKE_RESOURCE]), jwt(true, &[OTHER_AUDIENCE])] {
        let h = start_gateway(upstream_card(Era::Dual).to_string(), caller_auth).await;
        let card = public_card(&h, "/smoke").await;
        assert_keeps_upstream_security(&card);
        assert!(
            card["securitySchemes"]
                .get("agent_gateway")
                .is_none(),
            "{card}"
        );
    }

    let fixture = JwksFixture::start().await;
    let other_audience = CallerAuth::Jwt {
        issuer: fixture.issuer.clone(),
        pinned: true,
        audiences: vec![OTHER_AUDIENCE],
    };
    let h = start_gateway(extended_card_envelope(Era::V1), other_audience).await;
    let card = extended_card(&h, "GetExtendedAgentCard", &token(&fixture, OTHER_AUDIENCE)).await;
    assert_keeps_upstream_security(&card);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_variant_declares_only_when_the_audiences_name_its_url() {
    let h = start_gateway(upstream_card(Era::V1).to_string(), declaring()).await;
    assert_keeps_upstream_security(&public_card(&h, "/smoke$dev").await);
    assert_declares(&public_card(&h, "/smoke").await, ISSUER, true, false);

    let h = start_gateway(upstream_card(Era::V1).to_string(), jwt(true, &[SMOKE_RESOURCE, DEV_RESOURCE])).await;
    let variant = public_card(&h, "/smoke$dev").await;
    assert_declares(&variant, ISSUER, true, false);
    assert_eq!(endpoint(&variant), Some(DEV_RESOURCE), "the variant's card names the variant URL it declares");
    let base = public_card(&h, "/smoke").await;
    assert_declares(&base, ISSUER, true, false);
    assert_eq!(endpoint(&base), Some(SMOKE_RESOURCE));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_access_points_cards_must_be_revalidated_against_their_digest() {
    let h = start_gateway(upstream_card(Era::V1).to_string(), declaring()).await;
    for url in [public_card_url(&h, "/smoke"), transit_card_url(&h)] {
        let (status, headers, body) = get(&url).await;
        assert_eq!(status, 200, "{url}: {body}");
        assert_eq!(
            headers
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-cache"),
            "{url}: {headers:?}"
        );
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(body.as_bytes()));
        assert_eq!(
            headers
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok()),
            Some(format!("W/\"{digest}\"").as_str()),
            "{url}: the ETag is the digest of the card served: {headers:?}"
        );
        assert!(
            headers
                .get(reqwest::header::LAST_MODIFIED)
                .is_none(),
            "{url}: {headers:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_of_a_declaring_access_point_strips_its_partners_card() {
    for era in Era::ALL {
        let h = start_gateway(upstream_card(era).to_string(), declaring()).await;
        assert_strips(&card_at(&transit_card_url(&h)).await);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_of_an_access_point_without_caller_authentication_serves_its_partners_card_unchanged() {
    let h = start_gateway(upstream_card(Era::Dual).to_string(), CallerAuth::None).await;
    assert_keeps_upstream_security(&card_at(&transit_card_url(&h)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_the_gateway_cannot_process_is_refused_without_its_body() {
    let unparseable = format!("not a card {UPSTREAM_MARKER}");

    let h = start_gateway(unparseable.clone(), declaring()).await;
    for url in [public_card_url(&h, "/smoke"), transit_card_url(&h)] {
        let (status, _, body) = get(&url).await;
        assert_eq!(status, 502, "{url}: {body}");
        assert!(!body.contains(UPSTREAM_MARKER), "{url}: the upstream body was served: {body}");
    }

    let h = start_gateway(unparseable, CallerAuth::None).await;
    let (status, _, body) = get(&public_card_url(&h, "/smoke")).await;
    assert_eq!(status, 502, "{body}");
    assert!(!body.contains(UPSTREAM_MARKER), "the upstream body was served: {body}");
}

/// A public card served through the card route is counted once with its outcome and
/// reason. No other test serves a card whose strategy pin mismatches, so the count
/// rises by exactly one.
#[tokio::test(flavor = "multi_thread")]
async fn a_served_public_card_is_counted_once_with_its_strip_reason() {
    let mock = MockServer::start_with_response(upstream_card(Era::V1).to_string()).await;
    let h = GatewayHarness::start_with_outbound_mock(mock, |temp_dir, gw_config, bootstrap| {
        advertise_public_origin(bootstrap);
        write_strategy(temp_dir, ISSUER, true);
        let path = temp_dir
            .join("jwt_verification_strategies")
            .join(format!("{STRATEGY_ID}.json"));
        let mut strategy: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read strategy")).expect("strategy JSON");
        strategy["authorization_server"]["issuer"] = json!("https://other-issuer.example");
        std::fs::write(&path, strategy.to_string()).expect("write strategy");
        let mut surface = helpers::build_minimal_outbound_channel();
        surface
            .access_point
            .caller_authentication =
            Some(serde_json::from_value(jwt_bearer_caller_authentication(&[SMOKE_RESOURCE])).expect("caller auth"));
        gw_config.surfaces = vec![surface];
    })
    .await;
    let count = || {
        crate::metrics::backends::prometheus::CARD_SECURITY
            .with_label_values(&["strip", "pin_mismatch"])
            .get()
    };

    let before = count();
    assert_keeps_upstream_security(&public_card(&h, "/smoke").await);
    assert_eq!(count() - before, 1, "one served card is counted once");
}

fn protected_resource_url(
    h: &GatewayHarness,
    path: &str,
) -> String {
    format!("{}/.well-known/oauth-protected-resource{path}", h.gateway_base)
}

fn expected_metadata(resource: &str) -> Value {
    json!({
        "resource": resource,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [REQUIRED_SCOPE],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_access_point_publishes_protected_resource_metadata_at_its_own_url_only() {
    let h = start_gateway(upstream_card(Era::V1).to_string(), declaring()).await;
    let (status, headers, body) = get(&protected_resource_url(&h, "/smoke")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        headers
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(serde_json::from_str::<Value>(&body).expect("metadata JSON"), expected_metadata(SMOKE_RESOURCE));
    for path in ["", "/unknown", "/smoke$dev", "/smoke%24dev", "/smoke/rpc"] {
        let (status, _, body) = get(&protected_resource_url(&h, path)).await;
        assert_eq!(status, 404, "{path}: {body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_variant_whose_url_the_audiences_name_publishes_metadata_at_both_spellings() {
    let h = start_gateway(upstream_card(Era::V1).to_string(), jwt(true, &[SMOKE_RESOURCE, DEV_RESOURCE])).await;
    for path in ["/smoke$dev", "/smoke%24dev"] {
        let (status, _, body) = get(&protected_resource_url(&h, path)).await;
        assert_eq!(status, 200, "{path}: {body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("metadata JSON"),
            expected_metadata(DEV_RESOURCE),
            "{path}"
        );
    }
    let (status, _, body) = get(&protected_resource_url(&h, "/smoke")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).expect("metadata JSON"), expected_metadata(SMOKE_RESOURCE));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_reads_a_declaring_access_points_metadata_from_any_origin() {
    let h = start_gateway(upstream_card(Era::V1).to_string(), declaring()).await;
    let origin = "https://a2a-client.example";
    let url = protected_resource_url(&h, "/smoke");

    let read = client()
        .get(&url)
        .header("origin", origin)
        .send()
        .await
        .expect("metadata read");
    assert_eq!(read.status(), 200);
    assert_eq!(read.headers()["access-control-allow-origin"], origin);

    let preflight = |method: &'static str| {
        client()
            .request(reqwest::Method::OPTIONS, &url)
            .header("origin", origin)
            .header("access-control-request-method", method)
            .send()
    };
    let allowed = preflight("GET")
        .await
        .expect("GET preflight");
    assert!(allowed.status().is_success(), "{}", allowed.status());
    assert_eq!(allowed.headers()["access-control-allow-origin"], origin);
    let refused = preflight("POST")
        .await
        .expect("POST preflight");
    assert!(
        !refused
            .headers()
            .contains_key("access-control-allow-origin"),
        "{:?}",
        refused.headers()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_access_point_that_does_not_declare_publishes_no_protected_resource_metadata() {
    for caller_auth in [jwt(false, &[SMOKE_RESOURCE]), jwt(true, &[OTHER_AUDIENCE]), CallerAuth::None] {
        let h = start_gateway(upstream_card(Era::V1).to_string(), caller_auth).await;
        let (status, _, body) = get(&protected_resource_url(&h, "/smoke")).await;
        assert_eq!(status, 404, "{body}");
    }
}
