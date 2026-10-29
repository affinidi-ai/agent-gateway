//! Transit Point caller authentication E2E: a Transit Point authenticates its
//! caller with its own `source_auth` before anything is forwarded, so a refused
//! caller never reaches the target and an admitted caller's credential is never
//! sent on; the verified caller reaches the Transit Point's policy input; a
//! Transit Point that authenticates no caller is refused unless it is marked
//! open, and an open one other hosts can reach is reported.

use super::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
use super::helpers::{GatewayHarness, MockServer, configure_admin_api};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;

const CALLER_KEY: &str = "copilot-studio-key";
const CALLER_KEY_SECRET: &str = "transit-caller-keys";
const STRATEGY_ID: &str = "transit-caller-jwt";
const POLICY_ID: &str = "only-alice-through-the-transit-point";
const PUBLIC_OUTBOUND_URL: &str = "https://transit.example.com";

fn surface(transit_point: serde_json::Value) -> crate::config::agent_surface::AgentSurface {
    let mut point = json!({
        "alias": "target",
        "target_endpoint": "outbound_target_placeholder",
        "gateway_url": "outbound_gateway_url_placeholder",
        "require_transit_token": false
    });
    point
        .as_object_mut()
        .unwrap()
        .extend(
            transit_point
                .as_object()
                .unwrap()
                .clone(),
        );
    serde_json::from_value(json!({
        "surface_id": "transit-caller-auth",
        "name": "transit-caller-auth",
        "access_point": { "listen_address": "inbound_port_placeholder", "route": "/smoke", "protocol": "a2a" },
        "target": { "endpoint": "inbound_target_placeholder" },
        "transit": { "outbound_listen_address": "outbound_port_placeholder", "points": [point] }
    }))
    .expect("transit caller auth surface")
}

fn write_caller_key(temp_dir: &std::path::Path) {
    write_api_key_secret(temp_dir, CALLER_KEY_SECRET, None);
}

fn write_api_key_secret(
    temp_dir: &std::path::Path,
    secret_id: &str,
    tenant_id: Option<&str>,
) {
    let dir = temp_dir.join("secrets");
    std::fs::create_dir_all(&dir).expect("create secrets dir");
    let now = chrono::Utc::now().to_rfc3339();
    std::fs::write(
        dir.join(format!("{secret_id}-record.json")),
        json!({
            "id": format!("{secret_id}-record"),
            "tenant_id": tenant_id,
            "name": "Transit Point caller key",
            "secret_id": secret_id,
            "description": null,
            "value": CALLER_KEY,
            "secret_type": "ApiKey",
            "tags": [],
            "created_at": now,
            "updated_at": now
        })
        .to_string(),
    )
    .expect("write caller key");
}

fn write_jwt_strategy(
    temp_dir: &std::path::Path,
    fixture: &JwksFixture,
) {
    let dir = temp_dir.join("jwt_verification_strategies");
    std::fs::create_dir_all(&dir).expect("create strategy dir");
    let strategy = json!({
        "id": STRATEGY_ID,
        "name": "Transit Point caller strategy",
        "expected_issuer": fixture.issuer,
        "jwks_source": { "type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer) },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(dir.join(format!("{STRATEGY_ID}.json")), strategy.to_string()).expect("write strategy");
}

fn write_policy_definition(
    temp_dir: &std::path::Path,
    rego: &str,
) {
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    let definition = json!({
        "id": POLICY_ID,
        "name": "Transit Point caller policy",
        "description": "Admits a Transit Point call by the caller its source_auth verified.",
        "policy_type": "agent_surface",
        "policy": rego,
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(dir.join(format!("{POLICY_ID}.json")), definition.to_string()).expect("write policy definition");
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

async fn call_transit_point(
    h: &GatewayHarness,
    path: &str,
    header: Option<(&str, &str)>,
) -> reqwest::Response {
    let mut request = client()
        .post(format!(
            "{}{path}",
            h.outbound_url
                .as_ref()
                .unwrap()
        ))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":7}"#);
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    request.send().await.unwrap()
}

fn requests_seen(h: &GatewayHarness) -> usize {
    h.mock
        .request_count
        .load(Ordering::SeqCst)
}

fn last_forwarded_headers(h: &GatewayHarness) -> std::collections::HashMap<String, String> {
    h.mock
        .last_request_rx
        .borrow()
        .as_ref()
        .expect("the target received a request")
        .headers
        .clone()
}

async fn assert_refused_before_the_target(
    h: &GatewayHarness,
    header: Option<(&str, &str)>,
    case: &str,
) {
    let before = requests_seen(h);
    let response = call_transit_point(h, "/outbound/smoke/target", header).await;
    assert_eq!(response.status(), 401, "{case}");
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["detail"], "Caller credential missing or invalid", "{case}: {body}");
    for detail in ["api_key", "jwt", "secret", "expired", "not found"] {
        assert!(
            !body
                .to_string()
                .to_lowercase()
                .contains(detail),
            "{case}: the caller is not told why: {body}"
        );
    }
    assert_eq!(requests_seen(h), before, "{case}: a refused caller must not reach the target");
}

/// A Transit Point that authenticates its callers with an API key admits the
/// key it holds and forwards the call without it, and refuses a missing or
/// wrong key, discovery reads included, before the target is reached.
#[tokio::test(flavor = "multi_thread")]
async fn an_api_key_caller_is_admitted_and_a_missing_or_wrong_key_never_reaches_the_target() {
    let h = GatewayHarness::start_with_outbound(|temp_dir, gw_config, _| {
        write_caller_key(temp_dir);
        gw_config.surfaces = vec![surface(json!({
            "source_auth": {
                "type": "api_key",
                "extraction": { "source": "http_header", "field": "X-API-Key" },
                "secret_id": CALLER_KEY_SECRET
            }
        }))];
    })
    .await;

    assert_refused_before_the_target(&h, None, "no key").await;
    assert_refused_before_the_target(&h, Some(("x-api-key", "guessed-key")), "wrong key").await;
    let before = requests_seen(&h);
    let discovery = client()
        .get(format!(
            "{}/outbound/smoke/target/.well-known/agent-card.json",
            h.outbound_url
                .as_ref()
                .unwrap()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(discovery.status(), 401, "a discovery read needs the caller's key too");
    assert_eq!(requests_seen(&h), before);

    let before = requests_seen(&h);
    let admitted = call_transit_point(&h, "/outbound/smoke/target", Some(("x-api-key", CALLER_KEY))).await;
    assert_eq!(admitted.status(), 200);
    assert_eq!(requests_seen(&h), before + 1, "the admitted call reaches the target");
    let forwarded = last_forwarded_headers(&h);
    assert!(!forwarded.contains_key("x-api-key"), "the caller's key must never reach the target: {forwarded:?}");
}

/// A Transit Point sends its target none of the caller-info or DID identity
/// headers, in any case, whoever its caller is; the caller's other headers
/// pass.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_sends_its_target_no_caller_info_or_did_identity_header() {
    let h = GatewayHarness::start_with_outbound(|temp_dir, gw_config, _| {
        write_caller_key(temp_dir);
        gw_config.surfaces = vec![surface(json!({
            "source_auth": {
                "type": "api_key",
                "extraction": { "source": "http_header", "field": "X-API-Key" },
                "secret_id": CALLER_KEY_SECRET
            }
        }))];
    })
    .await;

    let response = client()
        .post(format!(
            "{}/outbound/smoke/target",
            h.outbound_url
                .as_ref()
                .unwrap()
        ))
        .header("content-type", "application/json")
        .header("x-api-key", CALLER_KEY)
        .header("X-Caller-DID", "did:web:caller-sent.example")
        .header("x-caller-identity-source", "verified-presentation")
        .header("x-caller-dna-uai", "uai:caller-sent")
        .header("X-Gateway-DID", "did:web:caller-sent-gateway.example")
        .header("x-did-identity", "did:web:caller-sent-surface.example")
        .header("X-DID-Signed-Identity", r#"{"id":"did:web:caller-sent-surface.example"}"#)
        .header("x-partner-context", "kept")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":7}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let forwarded = last_forwarded_headers(&h);
    for name in [
        "x-caller-did",
        "x-caller-identity-source",
        "x-caller-dna-uai",
        "x-gateway-did",
        "x-did-identity",
        "x-did-signed-identity",
    ] {
        assert!(!forwarded.contains_key(name), "{name} reached the target: {forwarded:?}");
    }
    assert_eq!(
        forwarded
            .get("x-partner-context")
            .map(String::as_str),
        Some("kept"),
        "{forwarded:?}"
    );
}

/// A Transit Point that authenticates its callers with a JWT puts the verified
/// caller in its policy input with `verification: source_auth`, so a policy can
/// admit Alice and refuse Bob; the target sees only Alice's call and never her
/// token.
#[tokio::test(flavor = "multi_thread")]
async fn a_jwt_caller_reaches_the_policy_input_so_a_policy_can_admit_one_caller_and_refuse_another() {
    let fixture = JwksFixture::start().await;
    let rego = format!(
        r#"package surface.policy

default allow := false

allow if {{
    input.transit.caller.verified
    input.transit.caller.verification == "source_auth"
    input.transit.caller.identity_source == "jwt_bearer"
    input.transit.caller.user_identity_hash == "{:x}"
    input.source_auth.claims.tid == "contoso"
}}
"#,
        Sha256::digest(format!(r#"["jwt_bearer","{}",null,"alice"]"#, fixture.issuer).as_bytes())
    );
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |temp_dir, gw_config, _| {
        write_jwt_strategy(temp_dir, &fixture);
        write_policy_definition(temp_dir, &rego);
        gw_config.surfaces = vec![surface(json!({
            "source_auth": {
                "type": "jwt_bearer",
                "jwt_verification_strategy_id": STRATEGY_ID,
                "audiences": ["api://transit-point"]
            },
            "policy": { "policy_definition_id": POLICY_ID }
        }))];
    })
    .await;
    let token_for = |subject: &str| {
        format!(
            "Bearer {}",
            sign_jwt(
                json!({
                    "iss": fixture.issuer, "sub": subject, "aud": "api://transit-point", "tid": "contoso",
                    "exp": now_secs() + 300, "iat": now_secs(),
                }),
                &fixture.kid,
            )
        )
    };

    let alice = token_for("alice");
    let before = requests_seen(&h);
    let admitted = call_transit_point(&h, "/outbound/smoke/target", Some(("authorization", &alice))).await;
    assert_eq!(admitted.status(), 200);
    assert_eq!(requests_seen(&h), before + 1, "Alice's call reaches the target");
    let forwarded = last_forwarded_headers(&h);
    assert!(
        !forwarded
            .values()
            .any(|value| value.contains(alice.trim_start_matches("Bearer "))),
        "the caller's token must never reach the target: {forwarded:?}"
    );

    let before = requests_seen(&h);
    let refused = call_transit_point(&h, "/outbound/smoke/target", Some(("authorization", &token_for("bob")))).await;
    assert_eq!(refused.status(), 403, "the policy admits only Alice");
    assert_eq!(requests_seen(&h), before, "Bob's call must not reach the target");

    let other_audience = format!(
        "Bearer {}",
        sign_jwt(
            json!({
                "iss": fixture.issuer, "sub": "alice", "aud": "api://another-resource", "tid": "contoso",
                "exp": now_secs() + 300, "iat": now_secs(),
            }),
            &fixture.kid,
        )
    );
    assert_refused_before_the_target(&h, Some(("authorization", &other_audience)), "another audience").await;
    assert_refused_before_the_target(&h, None, "no token").await;
}

/// A Transit Point a variant defines authenticates its callers with its own
/// `source_auth`, here a JWT in a header of its own, on the variant's `$alias`
/// route; the header never reaches the target, and the surface's own Transit
/// Point keeps its own check.
#[tokio::test(flavor = "multi_thread")]
async fn a_variants_transit_point_checks_a_jwt_in_its_own_header_on_the_variant_route() {
    let fixture = JwksFixture::start().await;
    let mock = MockServer::start().await;
    let target = mock.url();
    let h = GatewayHarness::start_with_outbound_mock(mock, |temp_dir, gw_config, _| {
        write_caller_key(temp_dir);
        write_jwt_strategy(temp_dir, &fixture);
        let mut surface = surface(json!({
            "source_auth": { "type": "api_key", "secret_id": CALLER_KEY_SECRET,
                             "extraction": { "source": "http_header", "field": "x-api-key" } }
        }));
        surface.variants = vec![
            serde_json::from_value(json!({
                "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": { "transit": { "points": [{
                    "alias": "target", "target_endpoint": target, "require_transit_token": false,
                    "source_auth": { "type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID,
                                     "audiences": ["api://transit-point"], "token_header": "x-caller-token" }
                }] } }
            }))
            .unwrap(),
        ];
        gw_config.surfaces = vec![surface];
    })
    .await;
    let token = format!(
        "Bearer {}",
        sign_jwt(
            json!({
                "iss": fixture.issuer, "sub": "alice", "aud": "api://transit-point",
                "exp": now_secs() + 300, "iat": now_secs(),
            }),
            &fixture.kid,
        )
    );

    let before = requests_seen(&h);
    let admitted = call_transit_point(&h, "/outbound/smoke$dev/target", Some(("x-caller-token", &token))).await;
    assert_eq!(admitted.status(), 200);
    assert_eq!(requests_seen(&h), before + 1);
    assert!(!last_forwarded_headers(&h).contains_key("x-caller-token"), "the caller's token never reaches the target");

    let before = requests_seen(&h);
    for (path, header, case) in [
        ("/outbound/smoke$dev/target", None, "the variant's Transit Point without a token"),
        ("/outbound/smoke/target", Some(("x-caller-token", token.as_str())), "the surface's own Transit Point"),
    ] {
        let refused = call_transit_point(&h, path, header).await;
        assert_eq!(refused.status(), 401, "{case}");
    }
    assert_eq!(requests_seen(&h), before, "a refused call must not reach the target");
}

/// A Transit Point that authenticates its callers by client certificate admits
/// a certificate a trusted proxy forwarded, and refuses a call without one.
#[tokio::test(flavor = "multi_thread")]
async fn an_mtls_caller_whose_certificate_a_trusted_proxy_forwarded_is_admitted() {
    let key_pair = rcgen::KeyPair::generate().expect("client key pair");
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "copilot-connector");
    let certificate_pem = params
        .self_signed(&key_pair)
        .expect("self-signed client certificate")
        .pem();
    let mut certificate_id = None;
    let h = GatewayHarness::start_with_outbound(|_, gw_config, bootstrap| {
        use crate::certificates::CertificateStore as _;

        let store_path = std::path::PathBuf::from(
            &bootstrap
                .storage_paths
                .certificates,
        );
        let created = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::certificates::FilesystemCertificateStore::new(store_path)
                    .await
                    .expect("certificate store")
                    .create(crate::certificates::CreateCertificateRequest {
                        tenant_id: None,
                        name: "Copilot connector".to_string(),
                        description: None,
                        tags: None,
                        kind: crate::certificates::CertificateKind::ClientLeaf,
                        certificate_pem: certificate_pem.clone(),
                        private_key_pem: None,
                        expires_at: None,
                        active: Some(true),
                        identity_did: None,
                    })
                    .await
                    .expect("store the client certificate")
            })
        });
        gw_config
            .tls
            .client_auth
            .trusted_proxies = vec![
            "127.0.0.1/32"
                .parse()
                .unwrap(),
        ];
        gw_config
            .tls
            .client_auth
            .forwarded_header
            .format = crate::config::types::ForwardedHeaderFormat::UrlEncodedPem;
        gw_config.surfaces = vec![surface(json!({
            "source_auth": {
                "type": "mtls",
                "trust": { "type": "pinned", "certificate_ids": [created.id] },
                "identity_binding": { "type": "subject_cn" }
            }
        }))];
        certificate_id = Some(created.id);
    })
    .await;
    assert!(certificate_id.is_some());
    let forwarded_certificate = urlencoding::encode(&certificate_pem).into_owned();
    let header_name = crate::config::types::ForwardedHeaderConfig::default().header_name;

    let before = requests_seen(&h);
    let missing = call_transit_point(&h, "/outbound/smoke/target", None).await;
    assert_eq!(missing.status(), 401);
    assert_eq!(requests_seen(&h), before, "a caller without a certificate must not reach the target");

    let admitted =
        call_transit_point(&h, "/outbound/smoke/target", Some((header_name.as_str(), &forwarded_certificate))).await;
    assert_eq!(admitted.status(), 200);
    assert_eq!(requests_seen(&h), before + 1);
    assert!(
        !last_forwarded_headers(&h).contains_key(&header_name.to_ascii_lowercase()),
        "the forwarded certificate must not reach the target"
    );

    // The inbound listener shares the outbound listener's host, so it passes
    // `/outbound` requests on from loopback, a trusted proxy; it must not pass
    // on a forwarded certificate nobody verified.
    let through_inbound = client()
        .post(format!("{}/outbound/smoke/target", h.gateway_base))
        .header("content-type", "application/json")
        .header(header_name.as_str(), &forwarded_certificate)
        .body(r#"{"jsonrpc":"2.0","method":"test","id":7}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(through_inbound.status(), 401, "a certificate sent to the inbound listener is never forwarded");
    assert_eq!(requests_seen(&h), before + 1, "the refused call must not reach the target");
}

/// A Transit Point that authenticates no caller: the admin API refuses it
/// unless it is marked open; one stored that way refuses every request without
/// reaching its target; an open one serves its callers, and the admin API warns
/// when other hosts can reach it.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_that_authenticates_no_caller_must_be_marked_open_and_an_open_public_one_is_reported() {
    let mut admin = None;
    let h = GatewayHarness::start_with_outbound(|_, gw_config, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        let gateway_path = &bootstrap.config_files.gateway;
        let mut gateway: serde_json::Value = serde_json::from_slice(&std::fs::read(gateway_path).unwrap()).unwrap();
        for listener in gateway["listeners"]
            .as_array_mut()
            .unwrap()
        {
            if listener["listener_type"] == "outbound" {
                listener["external_urls"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(PUBLIC_OUTBOUND_URL));
            }
        }
        std::fs::write(gateway_path, serde_json::to_vec(&gateway).unwrap()).unwrap();
        gw_config.surfaces = vec![surface(json!({}))];
    })
    .await;
    let admin = admin.unwrap();

    let before = requests_seen(&h);
    let stored = call_transit_point(&h, "/outbound/smoke/target", None).await;
    assert_eq!(stored.status(), 503, "a stored Transit Point that authenticates no caller refuses every request");
    let body: serde_json::Value = stored.json().await.unwrap();
    assert_eq!(body["detail"], "This Transit Point is unavailable", "{body}");
    assert_eq!(requests_seen(&h), before);

    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let payload = |open: bool| {
        let mut point = json!({ "alias": "open", "target_endpoint": h.mock.url(), "require_transit_token": false });
        if open {
            point["allow_unauthenticated_callers"] = json!(true);
        }
        json!({
            "name": "open-transit",
            "access_point": { "listen_address": h.gateway_base, "route": "/open-transit", "protocol": "a2a" },
            "target": { "endpoint": h.mock.url() },
            "transit": { "outbound_listen_address": PUBLIC_OUTBOUND_URL, "points": [point] }
        })
    };

    let refused = admin
        .post(&collection)
        .json(&payload(false))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    let body = refused.text().await.unwrap();
    assert!(body.contains("transit.points[0]: Transit Point 'open' authenticates no caller"), "{body}");

    let created = admin
        .post(&collection)
        .json(&payload(true))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let warnings: Vec<String> = created
        .headers()
        .get_all("warning")
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let inbound_port = h
        .gateway_base
        .rsplit(':')
        .next()
        .unwrap();
    assert_eq!(
        warnings,
        vec![format!(
            "299 - \"Transit Point 'open' serves callers it does not authenticate and is reachable from other \
             hosts: 0.0.0.0:{inbound_port}, {PUBLIC_OUTBOUND_URL}\""
        )],
        "the outbound listener's public URL, and the inbound listener that binds every address and passes \
         /outbound on because it shares the outbound listener's host"
    );

    let before = requests_seen(&h);
    let open_point = format!(
        "{}/outbound/open-transit/open",
        h.outbound_url
            .as_ref()
            .unwrap()
    );
    let mut status = None;
    for _ in 0..100 {
        status = client()
            .post(&open_point)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","method":"test","id":7}"#)
            .send()
            .await
            .ok()
            .map(|response| response.status());
        if status == Some(reqwest::StatusCode::OK) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(status, Some(reqwest::StatusCode::OK), "an open Transit Point serves a caller it does not authenticate");
    assert_eq!(requests_seen(&h), before + 1);

    let mut saved: serde_json::Value = created.json().await.unwrap();
    let surface_url = format!(
        "{collection}/{}",
        saved["surface_id"]
            .as_str()
            .unwrap()
    );
    saved["transit"]["points"][0]
        .as_object_mut()
        .unwrap()
        .remove("allow_unauthenticated_callers");
    let rewritten = admin
        .put(&surface_url)
        .json(&saved)
        .send()
        .await
        .unwrap();
    assert_eq!(rewritten.status(), 200, "a PUT that does not show the open marking keeps it");
    let stored: serde_json::Value = rewritten
        .json()
        .await
        .unwrap();
    assert_eq!(stored["transit"]["points"][0]["allow_unauthenticated_callers"], true, "{stored}");
}

/// A save answers with a `Warning` header when a Transit Point accepts JWTs
/// from an issuer through one JWT verification strategy and the surface
/// accepts that issuer through another: the identity hash keys a JWT caller by
/// issuer and subject, so callers verified through either share delegated
/// credentials. One strategy for the issuer, or another issuer, gets none.
#[tokio::test(flavor = "multi_thread")]
async fn a_save_warns_of_a_transit_point_strategy_that_shares_an_issuer_with_another() {
    const ISSUER: &str = "https://login.example.com";
    let mut admin = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        let dir = temp_dir.join("jwt_verification_strategies");
        std::fs::create_dir_all(&dir).expect("create strategy dir");
        for (id, issuer, jwks_uri) in [
            ("workforce", ISSUER, "https://login.example.com/keys"),
            ("partner-keys", ISSUER, "https://partner.example/keys"),
            ("partner-issuer", "https://partner.example", "https://partner.example/keys"),
        ] {
            let strategy = json!({
                "id": id, "name": id, "expected_issuer": issuer,
                "jwks_source": { "type": "remote", "jwks_uri": jwks_uri },
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            });
            std::fs::write(dir.join(format!("{id}.json")), strategy.to_string()).expect("write strategy");
        }
    })
    .await;
    let admin = admin.unwrap();
    let save = |id: &str, transit_point_strategy: &str| {
        admin
            .post(format!("{}/api/v1/surfaces", h.gateway_base))
            .json(&json!({
                "surface_id": id, "name": id, "status": "disabled",
                "access_point": { "listen_address": h.gateway_base, "route": format!("/{id}"), "protocol": "a2a",
                    "caller_authentication": { "methods": [{ "type": "jwt_bearer",
                        "jwt_verification_strategy_id": "workforce", "audiences": ["api://agent"] }] } },
                "target": { "endpoint": h.mock.url() },
                "transit": { "points": [{ "alias": "crm", "target_endpoint": "https://crm.example/a2a",
                    "protocol": "a2a", "require_transit_token": false,
                    "source_auth": { "type": "jwt_bearer", "jwt_verification_strategy_id": transit_point_strategy,
                        "audiences": ["api://crm-transit"] } }] }
            }))
            .send()
    };
    let warnings = |response: &reqwest::Response| -> Vec<String> {
        response
            .headers()
            .get_all("warning")
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    };

    let shared = save("shared-issuer", "partner-keys")
        .await
        .unwrap();
    assert_eq!(shared.status(), 201);
    assert_eq!(
        warnings(&shared),
        [format!(
            "299 - \"Transit Point 'crm' accepts tokens from issuer '{ISSUER}' through JWT verification strategy \
             'partner-keys', and this surface accepts that issuer through 'workforce' too: a caller with the same \
             subject through either is one caller, with the same delegated credentials; use one strategy per issuer\""
        )]
    );
    for (id, strategy) in [("one-strategy", "workforce"), ("another-issuer", "partner-issuer")] {
        let response = save(id, strategy)
            .await
            .unwrap();
        assert_eq!(response.status(), 201, "{id}");
        assert!(warnings(&response).is_empty(), "{id}: {:?}", warnings(&response));
    }
}

/// A tenant access token can point a Transit Point's `source_auth` only at its
/// own or appliance-wide secrets, on the base and in a variant, as it can on an
/// Access Point.
#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_token_names_only_its_own_secrets_in_a_transit_points_source_auth() {
    let mut tenant = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        for (secret_id, tenant_id) in
            [("tenant-a-key", Some("tenant-a")), ("tenant-b-key", Some("tenant-b")), ("appliance-key", None)]
        {
            write_api_key_secret(temp_dir, secret_id, tenant_id);
        }
        configure_admin_api(bootstrap);
        tenant = Some(super::a2a_flow_e2e::seed_scoped_access_token(
            bootstrap,
            Some("TENANT:${x-external-account}:(?:surfaces:.*|secrets:.*)"),
        ));
    })
    .await;
    let tenant = tenant.expect("tenant client");
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let surface = |id: &str, base_secret: &str, variant_secret: &str| {
        let point = |alias: &str, secret_id: &str| {
            json!({
                "alias": alias, "target_endpoint": "https://partner.example/a2a", "protocol": "a2a",
                "require_transit_token": false,
                "source_auth": { "type": "api_key", "secret_id": secret_id,
                                 "extraction": { "source": "http_header", "field": "x-api-key" } }
            })
        };
        json!({
            "surface_id": id, "name": id, "status": "disabled",
            "access_point": { "listen_address": h.gateway_base, "route": format!("/{id}"), "protocol": "a2a" },
            "target": { "endpoint": h.mock.url() },
            "transit": { "points": [point("base-partner", base_secret)] },
            "variants": [{ "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": { "transit": { "points": [point("dev-partner", variant_secret)] } } }]
        })
    };

    for (id, base, variant) in
        [("tp-key-base-b", "tenant-b-key", "tenant-a-key"), ("tp-key-variant-b", "tenant-a-key", "tenant-b-key")]
    {
        let response = tenant
            .post(&collection)
            .json(&surface(id, base, variant))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, 400, "{id}: another tenant's secret must be refused: {body}");
        assert!(body.contains("Secret reference is not accessible"), "{id}: {body}");
    }

    for (id, secret) in [("tp-key-own", "tenant-a-key"), ("tp-key-appliance", "appliance-key")] {
        let response = tenant
            .post(&collection)
            .json(&surface(id, secret, secret))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(status, 201, "{id}: {body}");
        assert_eq!(body["tenant_id"], "tenant-a", "{id}: {body}");
    }
}

/// A surface whose Transit Point authenticates its callers with `source_auth`
/// is stored with `transit_point_source_auth: true`, so a release that predates
/// Transit Point `source_auth` refuses the whole surface instead of serving that
/// Transit Point without it; the marker follows the Transit Points on every
/// save, whatever the write sends.
#[tokio::test(flavor = "multi_thread")]
async fn a_surface_whose_transit_point_uses_source_auth_is_stored_so_older_releases_refuse_it() {
    let mut paths = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_caller_key(temp_dir);
        paths = Some((
            configure_admin_api(bootstrap),
            std::path::PathBuf::from(
                &bootstrap
                    .storage_paths
                    .agent_surfaces,
            ),
        ));
    })
    .await;
    let (admin, surfaces_dir) = paths.unwrap();
    let stored = |surface_id: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(surfaces_dir.join(format!("{surface_id}.json"))).unwrap()).unwrap()
    };
    let key_point = json!({
        "alias": "partner", "target_endpoint": "https://partner.example/a2a", "protocol": "a2a",
        "require_transit_token": false,
        "source_auth": { "type": "api_key", "secret_id": CALLER_KEY_SECRET,
                         "extraction": { "source": "http_header", "field": "x-api-key" } }
    });
    let token_point =
        json!({ "alias": "partner", "target_endpoint": "https://partner.example/a2a", "protocol": "a2a" });
    let surface = |id: &str, base: &serde_json::Value, variant: Option<&serde_json::Value>, marker: bool| {
        let mut body = json!({
            "surface_id": id, "name": id, "status": "disabled",
            "access_point": { "listen_address": h.gateway_base, "route": format!("/{id}"), "protocol": "a2a" },
            "target": { "endpoint": h.mock.url() },
            "transit": { "points": [base] },
            "transit_point_source_auth": marker
        });
        if let Some(point) = variant {
            body["variants"] = json!([{ "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": { "transit": { "points": [point] } } }]);
        }
        body
    };
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);

    for (id, base, variant) in [("tp-auth-base", &key_point, None), ("tp-auth-variant", &token_point, Some(&key_point))]
    {
        let created = admin
            .post(&collection)
            .json(&surface(id, base, variant, false))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201, "{id}: {}", created.text().await.unwrap());
        assert_eq!(stored(id)["transit_point_source_auth"], true, "{id}: {}", stored(id));
    }

    let replaced = admin
        .put(format!("{collection}/tp-auth-base"))
        .json(&surface("tp-auth-base", &token_point, None, true))
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), 200, "{}", replaced.text().await.unwrap());
    assert!(
        stored("tp-auth-base")
            .get("transit_point_source_auth")
            .is_none(),
        "with no Transit Point on source_auth left, an older release may load it again: {}",
        stored("tp-auth-base")
    );
}

/// A `PUT` of one variant whose Transit Points leave out `source_auth` and
/// `allow_unauthenticated_callers` keeps the stored values, as a `PUT` of the
/// whole surface does; a merge `PATCH` whose Transit Points leave
/// `source_auth` out removes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_variant_put_that_omits_a_transit_points_caller_authentication_keeps_it() {
    let mut admin = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_caller_key(temp_dir);
        admin = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = admin.unwrap();
    let key = json!({ "type": "api_key", "secret_id": CALLER_KEY_SECRET,
                      "extraction": { "source": "http_header", "field": "x-api-key" } });
    let point = |id: &str, extra: serde_json::Value| {
        let mut point = json!({ "id": id, "alias": id, "target_endpoint": format!("https://{id}.example/a2a"),
            "protocol": "a2a", "require_transit_token": false });
        point
            .as_object_mut()
            .unwrap()
            .extend(
                extra
                    .as_object()
                    .unwrap()
                    .clone(),
            );
        point
    };
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let created = admin
        .post(&collection)
        .json(&json!({
            "surface_id": "tp-variant-put", "name": "tp-variant-put", "status": "disabled",
            "access_point": { "listen_address": h.gateway_base, "route": "/tp-variant-put", "protocol": "a2a" },
            "target": { "endpoint": h.mock.url() },
            "variants": [{ "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": { "transit": { "points": [
                    point("keyed", json!({ "source_auth": key })),
                    point("open", json!({ "allow_unauthenticated_callers": true }))
                ] } } }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "{}", created.text().await.unwrap());
    let variant_url = format!("{collection}/tp-variant-put/variants/variant-dev");
    let saved_points = |variant: &serde_json::Value| variant["overrides"]["transit"]["points"].clone();

    let kept = admin
        .put(&variant_url)
        .json(&json!({ "name": "dev, renamed", "overrides": { "transit": { "points": [
            point("keyed", json!({})),
            point("open", json!({}))
        ] } } }))
        .send()
        .await
        .unwrap();
    let status = kept.status();
    let kept: serde_json::Value = kept.json().await.unwrap();
    assert_eq!(status, 200, "{kept}");
    assert_eq!(kept["name"], "dev, renamed");
    assert_eq!(saved_points(&kept)[0]["source_auth"], key, "{kept}");
    assert_eq!(saved_points(&kept)[1]["allow_unauthenticated_callers"], true, "{kept}");

    let removed = admin
        .patch(&variant_url)
        .header("content-type", "application/merge-patch+json")
        .body(
            json!({ "overrides": { "transit": { "points": [
                point("keyed", json!({ "require_transit_token": true })),
                point("open", json!({ "allow_unauthenticated_callers": true }))
            ] } } })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let status = removed.status();
    let removed: serde_json::Value = removed.json().await.unwrap();
    assert_eq!(status, 200, "{removed}");
    let variant = removed["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["id"] == "variant-dev")
        .unwrap()
        .clone();
    assert!(
        saved_points(&variant)[0]
            .get("source_auth")
            .is_none(),
        "{variant}"
    );
}

/// In a `PUT` of the surface or of one variant, `"source_auth": null` removes a
/// Transit Point's stored `source_auth` and an omitted one keeps it. The save
/// rules then apply, so a removal that leaves a Transit Point authenticating no
/// caller is refused and the stored one is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn a_put_that_sends_a_null_source_auth_removes_it_unless_no_caller_would_be_authenticated() {
    let mut admin = None;
    let h = GatewayHarness::start(|temp_dir, _, bootstrap| {
        write_caller_key(temp_dir);
        admin = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = admin.unwrap();
    let key = json!({ "type": "api_key", "secret_id": CALLER_KEY_SECRET,
                      "extraction": { "source": "http_header", "field": "x-api-key" } });
    let point = |id: &str, require_transit_token: bool, source_auth: Option<serde_json::Value>| {
        let mut point = json!({ "id": id, "alias": id, "target_endpoint": format!("https://{id}.example/a2a"),
            "protocol": "a2a", "require_transit_token": require_transit_token });
        if let Some(source_auth) = source_auth {
            point["source_auth"] = source_auth;
        }
        point
    };
    let stored_points = json!([point("kept", false, Some(key.clone())), point("tokened", true, Some(key.clone()))]);
    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let surface_url = format!("{collection}/tp-null-put");
    let variant_url = format!("{surface_url}/variants/variant-dev");
    let surface = |points: &serde_json::Value, variant_points: &serde_json::Value| {
        json!({
            "surface_id": "tp-null-put", "name": "tp-null-put", "status": "disabled",
            "access_point": { "listen_address": h.gateway_base, "route": "/tp-null-put", "protocol": "a2a" },
            "target": { "endpoint": h.mock.url() },
            "transit": { "points": points },
            "variants": [{ "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": { "transit": { "points": variant_points } } }]
        })
    };
    let created = admin
        .post(&collection)
        .json(&surface(&stored_points, &stored_points))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "{}", created.text().await.unwrap());
    let stored = || async {
        admin
            .get(&surface_url)
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
    };
    let base_points = |surface: &serde_json::Value| surface["transit"]["points"].clone();
    let dev_points = |surface: &serde_json::Value| surface["variants"][0]["overrides"]["transit"]["points"].clone();

    let refused_points = json!([point("kept", false, Some(json!(null))), point("tokened", true, None)]);
    for (endpoint, url, body) in [
        ("surface", &surface_url, surface(&refused_points, &stored_points)),
        ("variant", &variant_url, json!({ "overrides": { "transit": { "points": refused_points } } })),
    ] {
        let response = admin
            .put(url)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert_eq!(status, 400, "{endpoint}: {text}");
        assert!(text.contains("Transit Point 'kept' authenticates no caller"), "{endpoint}: {text}");
        let unchanged = stored().await;
        for points in [base_points(&unchanged), dev_points(&unchanged)] {
            assert_eq!(points[0]["source_auth"], key, "{endpoint}: {unchanged}");
        }
    }

    let removed_points = json!([point("kept", false, None), point("tokened", true, Some(json!(null)))]);
    let removed = admin
        .put(&surface_url)
        .json(&surface(&removed_points, &stored_points))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 200, "{}", removed.text().await.unwrap());
    let saved = stored().await;
    assert_eq!(base_points(&saved)[0]["source_auth"], key, "omitted keeps it: {saved}");
    assert!(
        base_points(&saved)[1]
            .get("source_auth")
            .is_none(),
        "null removes it: {saved}"
    );
    assert_eq!(dev_points(&saved)[1]["source_auth"], key, "the variant is untouched: {saved}");

    let removed = admin
        .put(&variant_url)
        .json(&json!({ "overrides": { "transit": { "points": removed_points } } }))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 200, "{}", removed.text().await.unwrap());
    let saved = stored().await;
    assert_eq!(dev_points(&saved)[0]["source_auth"], key, "omitted keeps it: {saved}");
    assert!(
        dev_points(&saved)[1]
            .get("source_auth")
            .is_none(),
        "null removes it: {saved}"
    );
}
