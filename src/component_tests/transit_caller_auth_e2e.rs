//! Transit Point caller authentication E2E: a Transit Point authenticates its
//! caller with its own `source_auth` before anything is forwarded, so a refused
//! caller never reaches the target and an admitted caller's credential is never
//! sent on; the verified caller reaches the Transit Point's policy input; a
//! Transit Point that authenticates no caller is refused unless it is marked
//! open, and an open one reachable on a public address is reported.

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
}

/// A Transit Point that authenticates no caller: the admin API refuses it
/// unless it is marked open; one stored that way refuses every request without
/// reaching its target; an open one serves its callers, and the admin API warns
/// when it is reachable on a public address.
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
    assert_eq!(
        warnings,
        vec![format!(
            "299 - \"Transit Point 'open' serves callers it does not authenticate and is reachable on a public \
             address: {PUBLIC_OUTBOUND_URL}\""
        )]
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
