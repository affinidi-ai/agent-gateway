//! Inbound `from_api_key` caller identity on a running gateway: every API key a
//! caller presents is its own External Caller, keyed as the configured key was.

use super::helpers::{self, GatewayHarness, MockServer, write_api_key_secret};
use super::identity_e2e::{a2a_request, decode_jwt_payload, forwarded_binding_did};
use crate::api_keys::store::ApiKeyStore as _;
use crate::config::agent_surface::AgentSurface;
use crate::identity::IdentityStore as _;
use crate::identity::filesystem::{AgentIdentityRecord, IdentityOrigin};
use serde_json::json;
use std::sync::atomic::Ordering;

const PROVIDER_AGENT_ID: &str = "per-key-provider-agent";

struct ProviderKey {
    key_id: String,
    secret: String,
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
}

fn api_keys_dir(bootstrap: &crate::config::BootstrapConfig) -> String {
    std::path::Path::new(
        &bootstrap
            .storage_paths
            .secrets,
    )
    .parent()
    .expect("secrets path has a parent")
    .join("api_keys")
    .to_string_lossy()
    .to_string()
}

/// Issue one API Key Provider key per client for [`PROVIDER_AGENT_ID`], then
/// revoke the keys at the `revoked` indexes.
fn create_provider_keys(
    bootstrap: &crate::config::BootstrapConfig,
    clients: &[&str],
    revoked: &[usize],
) -> Vec<ProviderKey> {
    let dir = api_keys_dir(bootstrap);
    block_on(async {
        let store = crate::api_keys::FileSystemApiKeyStore::new(&dir)
            .await
            .expect("create API key store");
        let mut keys = Vec::new();
        for client in clients {
            let created = store
                .create(PROVIDER_AGENT_ID, client, None, "component-test")
                .await
                .expect("create provider key");
            keys.push(ProviderKey {
                key_id: created.key_id,
                secret: created.secret,
            });
        }
        for index in revoked {
            store
                .revoke(PROVIDER_AGENT_ID, &keys[*index].key_id, "component-test")
                .await
                .expect("revoke provider key");
        }
        keys
    })
}

fn seed_identity(
    identities_dir: &str,
    record: AgentIdentityRecord,
) {
    block_on(async {
        crate::identity::FilesystemIdentityStore::new(identities_dir)
            .await
            .expect("open identity store")
            .create(record)
            .await
            .expect("seed identity record");
    });
}

fn identity_records(identities_dir: &str) -> Vec<AgentIdentityRecord> {
    block_on(async {
        crate::identity::FilesystemIdentityStore::new(identities_dir)
            .await
            .expect("open identity store")
            .list_all()
            .await
            .expect("list identity records")
    })
}

fn records_with_origin(
    identities_dir: &str,
    origin: IdentityOrigin,
) -> Vec<AgentIdentityRecord> {
    identity_records(identities_dir)
        .into_iter()
        .filter(|record| record.origin == Some(origin))
        .collect()
}

fn api_key_identity_hash(key_id: &str) -> String {
    crate::identity::credential_identity::hash_credential(&[("credential_type", "api_key"), ("api_key_id", key_id)])
}

fn record_for_hash<'a>(
    records: &'a [AgentIdentityRecord],
    hash: &str,
) -> Option<&'a AgentIdentityRecord> {
    records
        .iter()
        .find(|record| record.identity_hash == hash)
}

/// The identity fields and hash the configured-key `from_api_key` path derives
/// for `key_id`.
async fn configured_key_identity(key_id: &str) -> (std::collections::HashMap<String, serde_json::Value>, String) {
    let derived = crate::identity::credential_identity::derive_credential_identity(
        &crate::source_auth::ManagedIdentityConfig::FromApiKey {
            api_key_id: Some(key_id.to_string()),
        },
        None,
        None,
    )
    .await
    .expect("derive configured key identity")
    .expect("configured key identity");
    let crate::identity::credential_identity::CredentialIdentity::Derived {
        identity_fields, identity_hash, ..
    } = derived
    else {
        panic!("an API key identity is derived");
    };
    (identity_fields, identity_hash)
}

fn write_policy(
    temp_dir: &std::path::Path,
    id: &str,
    rego: &str,
) {
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{id}.json")),
        serde_json::to_string_pretty(&json!({
            "id": id,
            "name": id,
            "description": "API key caller identity policy",
            "policy_type": "agent_surface",
            "policy": rego,
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize policy definition"),
    )
    .expect("write policy definition fixture");
}

fn provider_caller_authentication() -> serde_json::Value {
    json!({ "methods": [{
        "type": "api_key_provider",
        "extraction": { "source": "http_header", "field": "X-API-Key" },
        "agent_id": PROVIDER_AGENT_ID
    }] })
}

fn transit_with_one_point() -> serde_json::Value {
    json!({
        "outbound_listen_address": "outbound_port_placeholder",
        "points": [{
            "alias": "target",
            "target_endpoint": "outbound_target_placeholder",
            "gateway_url": "outbound_gateway_url_placeholder",
            "require_transit_token": true
        }]
    })
}

/// A surface on `route` whose callers present a key of [`PROVIDER_AGENT_ID`]
/// and are identified by it, with `policy_id` as its target policy.
fn provider_caller_surface(
    surface_id: &str,
    route: &str,
    policy_id: &str,
    transit: Option<serde_json::Value>,
) -> AgentSurface {
    let mut surface = json!({
        "surface_id": surface_id,
        "name": surface_id,
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": route,
            "protocol": "a2a",
            "caller_authentication": provider_caller_authentication()
        },
        "target": { "endpoint": "inbound_target_placeholder" },
        "identity_slots": { "inbound": { "type": "from_api_key" } }
    });
    if let Some(transit) = transit {
        surface["transit"] = transit;
    }
    with_policy(serde_json::from_value(surface).expect("provider caller surface JSON"), policy_id)
}

fn with_policy(
    mut surface: AgentSurface,
    policy_id: &str,
) -> AgentSurface {
    surface.target.policy = Some(crate::config::agent_surface::PolicyRef {
        policy_definition_id: policy_id.to_string(),
        require_agent_context: false,
    });
    surface
}

async fn send_with_key(
    url: &str,
    key: &str,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(url)
        .header("x-api-key", key)
        .json(&a2a_request())
        .send()
        .await
        .expect("inbound request failed")
}

fn forwarded(h: &GatewayHarness) -> usize {
    h.mock
        .request_count
        .load(Ordering::SeqCst)
}

/// The transit token the Access Point attached to the last request it forwarded.
fn forwarded_transit_token(h: &GatewayHarness) -> String {
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
        .expect("the forwarded request must carry a transit token")
}

fn transit_token_sub(token: &str) -> String {
    decode_jwt_payload(token).expect("transit token payload")["sub"]
        .as_str()
        .expect("transit token must name the caller in sub")
        .to_string()
}

fn resolve_count(
    surface_name: &str,
    outcome: &str,
) -> u64 {
    crate::metrics::backends::prometheus::MANAGED_IDENTITY_RESOLVE
        .with_label_values(&[surface_name, "from_api_key", outcome])
        .get()
}

/// The surface policy for two provider keys: `first_key` must reach policy as
/// `first_did`, `second_key` as some other `did:webvh` DID, each as the
/// source-auth-verified `input.agent.did`.
fn per_key_policy(
    first_key: &str,
    first_did: &str,
    second_key: &str,
) -> String {
    format!(
        r#"package surface.policy

default allow := false

key_caller if {{
    input.source_auth.method == "api_key"
    input.agent.did == input.extension_identity.did
    input.agent.did_verification == "source_auth"
    input.extension_identity.verification == "source_auth"
}}

allow if {{
    key_caller
    input.source_auth.key_name == "{first_key}"
    input.extension_identity.did == "{first_did}"
}}

allow if {{
    key_caller
    input.source_auth.key_name == "{second_key}"
    startswith(input.extension_identity.did, "did:webvh:")
    input.extension_identity.did != "{first_did}"
}}
"#
    )
}

/// Two provider keys reach policy, the transit token and the identity store
/// as two External Callers, and the first keeps the DID its record held when
/// the surface named that key.
#[tokio::test(flavor = "multi_thread")]
async fn each_provider_key_is_its_own_external_caller() {
    const SURFACE: &str = "per-key-provider-callers";
    const POLICY: &str = "per-key-provider-policy";
    const LEGACY_DID: &str = "did:web:client-1.legacy.example";

    let mut keys = Vec::new();
    let mut identities_dir = String::new();
    let mut legacy_hash = String::new();
    let mut admin = None;
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |dir, gw_config, bootstrap| {
        keys = create_provider_keys(bootstrap, &["client-1", "client-2"], &[]);
        identities_dir = bootstrap
            .storage_paths
            .identities
            .clone();
        admin = Some(helpers::configure_admin_api(bootstrap));
        let (fields, hash) = block_on(configured_key_identity(&keys[0].key_id));
        legacy_hash = hash.clone();
        let mut legacy = crate::identity::test_helpers::test_surface_identity_record(LEGACY_DID, SURFACE);
        legacy.identity_hash = hash;
        legacy.identity_fields = fields;
        legacy.origin = Some(IdentityOrigin::ExternalCaller);
        seed_identity(&identities_dir, legacy);
        write_policy(dir, POLICY, &per_key_policy(&keys[0].key_id, LEGACY_DID, &keys[1].key_id));
        gw_config.surfaces = vec![provider_caller_surface(SURFACE, "/smoke", POLICY, Some(transit_with_one_point()))];
    })
    .await;

    let mut subs = Vec::new();
    for key in [&keys[0], &keys[1], &keys[0]] {
        let response = send_with_key(&h.gateway_url, &key.secret).await;
        assert_eq!(response.status(), 200, "policy must see the DID of key {}", key.key_id);
        subs.push(transit_token_sub(&forwarded_transit_token(&h)));
    }
    assert_eq!(forwarded(&h), 3);
    assert_eq!(subs[0], LEGACY_DID, "client-1 keeps the DID of its configured-key record");
    assert_eq!(subs[2], subs[0]);
    assert_ne!(subs[1], subs[0]);
    assert!(subs[1].starts_with("did:webvh:"), "{}", subs[1]);

    let callers = records_with_origin(&identities_dir, IdentityOrigin::ExternalCaller);
    assert_eq!(callers.len(), 2, "{callers:?}");
    assert_eq!(legacy_hash, api_key_identity_hash(&keys[0].key_id));
    for (key, did) in [(&keys[0], &subs[0]), (&keys[1], &subs[1])] {
        let record = record_for_hash(&callers, &api_key_identity_hash(&key.key_id))
            .unwrap_or_else(|| panic!("no External Caller record for key {}", key.key_id));
        assert_eq!(&record.did, did);
        assert_eq!(record.identity_fields["api_key_id"], key.key_id.as_str());
    }

    let stats: serde_json::Value = admin
        .unwrap()
        .get(format!("{}/api/v1/dashboard/stats", h.gateway_base))
        .send()
        .await
        .expect("dashboard stats request failed")
        .json()
        .await
        .expect("dashboard stats JSON");
    let external_callers: Vec<&serde_json::Value> = stats["identities"]
        .as_array()
        .unwrap_or_else(|| panic!("dashboard stats must list identities, got {stats}"))
        .iter()
        .filter(|identity| identity["origin"] == "external_caller")
        .collect();
    for identity in &external_callers {
        assert_eq!(identity["channel_name"], SURFACE, "{identity}");
    }
    let mut listed: Vec<&str> = external_callers
        .iter()
        .filter_map(|identity| identity["did"].as_str())
        .collect();
    listed.sort_unstable();
    let mut expected = vec![subs[0].as_str(), subs[1].as_str()];
    expected.sort_unstable();
    assert_eq!(listed, expected);
}

/// Each provider key reaches a caller Trust Check on `{{ input.agent.did }}`
/// and the Access Point target's identity VP as the DID its transit token names.
#[tokio::test(flavor = "multi_thread")]
async fn each_provider_key_names_its_own_did_to_trust_check_and_target() {
    const SURFACE: &str = "per-key-trust-check-and-vp";
    const POLICY: &str = "per-key-trust-check-entity-policy";

    let mut keys = Vec::new();
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |dir, gw_config, bootstrap| {
        keys = create_provider_keys(bootstrap, &["tc-client-1", "tc-client-2"], &[]);
        write_policy(
            dir,
            POLICY,
            r#"package surface.policy

default allow := false

allow if {
    input.source_auth.method == "api_key"
    input.agent.did == input.extension_identity.did
    count(input.trust_check_results.caller) == 1
    input.trust_check_results.caller[0].id == "caller-entity"
    input.trust_check_results.caller[0].entity_id == input.agent.did
}
"#,
        );
        let mut surface = provider_caller_surface(SURFACE, "/smoke", POLICY, Some(transit_with_one_point()));
        surface
            .access_point
            .trust_check_list = serde_json::from_value(json!([{
            "id": "caller-entity",
            "trust_registry_id": "tr-unreachable",
            "query_type": "recognition",
            "query": { "authority_id": "did:example:authority", "entity_id": "{{ input.agent.did }}" }
        }]))
        .expect("caller Trust Check JSON");
        surface
            .target
            .identity_injection
            .inject_vp = true;
        gw_config.surfaces = vec![surface];
    })
    .await;

    let mut subs = Vec::new();
    for key in &keys {
        let response = send_with_key(&h.gateway_url, &key.secret).await;
        assert_eq!(response.status(), 200, "the Trust Check entity must be the DID of key {}", key.key_id);
        let sub = transit_token_sub(&forwarded_transit_token(&h));
        assert_eq!(forwarded_binding_did(&h), sub, "the target VP holder of key {}", key.key_id);
        subs.push(sub);
    }
    assert_eq!(forwarded(&h), 2);
    assert_ne!(subs[0], subs[1]);
}

/// The first value under `key` anywhere in `value`, looking inside strings
/// that hold JSON or a JWT.
fn find_field(
    value: &serde_json::Value,
    key: &str,
) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => map
            .get(key)
            .cloned()
            .or_else(|| {
                map.values()
                    .find_map(|value| find_field(value, key))
            }),
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_field(value, key)),
        serde_json::Value::String(text) => serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .filter(|parsed| parsed.is_object() || parsed.is_array())
            .or_else(|| decode_jwt_payload(text))
            .and_then(|parsed| find_field(&parsed, key)),
        _ => None,
    }
}

/// A Transit Point with Workload Binding binds the caller the transit token
/// names, so each provider key reaches the Transit Point's target as its own
/// `userIdentity.id`.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_workload_binding_names_each_provider_key() {
    const SURFACE: &str = "per-key-workload-binding";
    const POLICY: &str = "per-key-workload-binding-policy";

    let mut keys = Vec::new();
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |dir, gw_config, bootstrap| {
        keys = create_provider_keys(bootstrap, &["wb-client-1", "wb-client-2"], &[]);
        write_policy(dir, POLICY, "package surface.policy\n\ndefault allow := true\n");
        let mut transit = transit_with_one_point();
        transit["points"][0]["workload_binding"] = json!({ "enabled": true });
        transit["points"][0]["identity_injection"] = json!({ "inject_vp": true });
        let mut surface = provider_caller_surface(SURFACE, "/smoke", POLICY, Some(transit));
        surface
            .identity_slots
            .protected = Some(crate::source_auth::ManagedIdentityConfig::FromApiKey {
            api_key_id: Some("atgk_e2e0000000000000000000000000078".to_string()),
        });
        gw_config.surfaces = vec![surface];
    })
    .await;
    let transit_point = format!(
        "{}/outbound/smoke/target",
        h.outbound_url
            .as_ref()
            .expect("outbound listener")
    );

    let mut bound = Vec::new();
    for key in &keys {
        assert_eq!(
            send_with_key(&h.gateway_url, &key.secret)
                .await
                .status(),
            200
        );
        let token = forwarded_transit_token(&h);
        let sub = transit_token_sub(&token);
        let response = reqwest::Client::new()
            .post(&transit_point)
            .header("x-transit-token", &token)
            .json(&a2a_request())
            .send()
            .await
            .expect("Transit Point request failed");
        assert_eq!(
            response.status(),
            200,
            "{}",
            response
                .text()
                .await
                .unwrap_or_default()
        );
        let received = h
            .mock
            .last_request_rx
            .borrow()
            .clone()
            .expect("the Transit Point target must receive the call");
        let body: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body JSON");
        let user_identity =
            find_field(&body, "userIdentity").unwrap_or_else(|| panic!("no userIdentity in the forwarded VP: {body}"));
        assert_eq!(user_identity["id"], sub.as_str());
        bound.push(sub);
    }
    assert_ne!(bound[0], bound[1]);
}

/// A revoked provider key identifies no caller: policy sees a failed source
/// auth with no caller DID, and a policy wanting a caller denies the request.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_provider_key_identifies_no_caller() {
    const POLICY: &str = "revoked-key-policy";
    let cases = [
        (
            "revoked-key-needs-caller",
            r#"package surface.policy

default allow := false

allow if {
    input.source_auth.method == "api_key"
    startswith(input.extension_identity.did, "did:webvh:")
    input.agent.did == input.extension_identity.did
}
"#,
            [403, 200],
        ),
        (
            "revoked-key-sees-failure",
            r#"package surface.policy

default allow := false

allow if {
    input.source_auth.method == "failed"
    input.source_auth.attempted_method == "api_key_provider"
    not input.agent.did
    not input.extension_identity
}
"#,
            [200, 403],
        ),
    ];
    for (surface_id, rego, [revoked_status, active_status]) in cases {
        let mut keys = Vec::new();
        let mut identities_dir = String::new();
        let h = GatewayHarness::start(|dir, gw_config, bootstrap| {
            keys = create_provider_keys(bootstrap, &["revoked-client", "active-client"], &[0]);
            identities_dir = bootstrap
                .storage_paths
                .identities
                .clone();
            write_policy(dir, POLICY, rego);
            gw_config.surfaces = vec![provider_caller_surface(surface_id, "/smoke", POLICY, None)];
        })
        .await;

        let revoked = send_with_key(&h.gateway_url, &keys[0].secret).await;
        assert_eq!(revoked.status(), revoked_status, "{surface_id}: revoked key");
        let active = send_with_key(&h.gateway_url, &keys[1].secret).await;
        assert_eq!(active.status(), active_status, "{surface_id}: active key");

        let records = identity_records(&identities_dir);
        assert!(
            record_for_hash(&records, &api_key_identity_hash(&keys[0].key_id)).is_none(),
            "{surface_id}: a revoked key must not get a DID"
        );
        assert!(record_for_hash(&records, &api_key_identity_hash(&keys[1].key_id)).is_some(), "{surface_id}");
    }
}

/// A stored surface with a JWT Bearer caller method, which a save refuses,
/// refuses an authenticated JWT caller with a fixed body instead of resolving a
/// caller DID.
#[tokio::test(flavor = "multi_thread")]
async fn a_stored_surface_with_a_jwt_method_refuses_the_jwt_caller() {
    use helpers::jwt::{JwksFixture, now_secs, setup_jwt_claim_inbound_identity, sign_jwt};
    const SURFACE: &str = "jwt-method-api-key-identity";

    let fixture = JwksFixture::start().await;
    let issuer = fixture.issuer.clone();
    let h = GatewayHarness::start_with_outbound(|dir, gw_config, _| {
        setup_jwt_claim_inbound_identity(&fixture, dir, gw_config);
        let surface = &mut gw_config.surfaces[0];
        surface.surface_id = SURFACE.to_string();
        surface.name = SURFACE.to_string();
        surface.identity_slots.inbound =
            Some(crate::source_auth::ManagedIdentityConfig::FromApiKey { api_key_id: None });
        surface
            .access_point
            .caller_authentication
            .as_mut()
            .expect("JWT caller authentication")
            .methods
            .push(serde_json::from_value(provider_caller_authentication()["methods"][0].clone()).unwrap());
    })
    .await;
    let token = sign_jwt(
        json!({
            "iss": issuer,
            "sub": "app-registration-123",
            "oid": "11111111-2222-3333-4444-555555555555",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        "e2e-test-key",
    );
    let before = resolve_count(SURFACE, "api_key_unavailable");

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("authorization", format!("Bearer {token}"))
        .json(&a2a_request())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(response.status(), 500);
    let body = response.text().await.unwrap();
    assert!(body.contains("Caller identity requires API key authentication"), "{body}");
    assert_eq!(resolve_count(SURFACE, "api_key_unavailable") - before, 1);
    assert_eq!(forwarded(&h), 0);
}

/// Every value of a plain API Key secret is one caller: the secret's DID,
/// unverified.
#[tokio::test(flavor = "multi_thread")]
async fn every_value_of_a_plain_api_key_secret_is_one_unverified_caller() {
    const SECRET_ID: &str = "plain-caller-keys";
    const POLICY: &str = "plain-key-unverified-policy";

    let mut identities_dir = String::new();
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |dir, gw_config, bootstrap| {
        identities_dir = bootstrap
            .storage_paths
            .identities
            .clone();
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            SECRET_ID,
            "value-a,value-b",
        );
        write_policy(
            dir,
            POLICY,
            r#"package surface.policy

default allow := false

allow if {
    input.source_auth.method == "api_key"
    startswith(input.agent.did, "did:webvh:")
    input.agent.did == input.extension_identity.did
    input.agent.did_verification == "unverified"
    input.extension_identity.verification == "unverified"
}
"#,
        );
        let mut surface =
            provider_caller_surface("plain-key-callers", "/smoke", POLICY, Some(transit_with_one_point()));
        surface
            .access_point
            .caller_authentication = Some(
            serde_json::from_value(json!({ "methods": [{
                "type": "api_key",
                "extraction": { "source": "http_header", "field": "X-API-Key" },
                "secret_id": SECRET_ID
            }] }))
            .unwrap(),
        );
        gw_config.surfaces = vec![surface];
    })
    .await;

    let mut subs = Vec::new();
    for value in ["value-a", "value-b"] {
        assert_eq!(
            send_with_key(&h.gateway_url, value)
                .await
                .status(),
            200,
            "{value}"
        );
        subs.push(transit_token_sub(&forwarded_transit_token(&h)));
    }

    assert_eq!(subs[0], subs[1]);
    let callers = records_with_origin(&identities_dir, IdentityOrigin::ExternalCaller);
    assert_eq!(callers.len(), 1, "{callers:?}");
    assert_eq!(callers[0].identity_hash, api_key_identity_hash(SECRET_ID));
    assert_eq!(callers[0].did, subs[0]);
}

fn managed_api_key_surface(
    surface_id: &str,
    route: &str,
    api_key_id: &str,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": surface_id,
        "name": surface_id,
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": route,
            "protocol": "a2a",
            "caller_authentication": provider_caller_authentication()
        },
        "target": { "endpoint": "inbound_target_placeholder" },
        "identity_slots": { "protected": { "type": "from_api_key", "api_key_id": api_key_id } }
    }))
    .expect("managed API key surface JSON")
}

/// With no inbound slot, a surface whose Managed Agent is a `from_api_key`
/// identity keeps resolving that key on inbound requests, whatever key the
/// caller presented.
#[tokio::test(flavor = "multi_thread")]
async fn a_managed_agent_fallback_ignores_the_presented_key() {
    const MANAGED_KEY_ID: &str = "atgk_e2e0000000000000000000000000077";

    let mut keys = Vec::new();
    let mut identities_dir = String::new();
    let h = GatewayHarness::start(|_, gw_config, bootstrap| {
        keys = create_provider_keys(bootstrap, &["fallback-client"], &[]);
        identities_dir = bootstrap
            .storage_paths
            .identities
            .clone();
        gw_config.surfaces = vec![managed_api_key_surface("managed-key-fallback", "/smoke", MANAGED_KEY_ID)];
    })
    .await;

    assert_eq!(
        send_with_key(&h.gateway_url, &keys[0].secret)
            .await
            .status(),
        200
    );

    let records = identity_records(&identities_dir);
    assert_eq!(records.len(), 1, "identity record count");
    assert_eq!(records[0].identity_hash, api_key_identity_hash(MANAGED_KEY_ID));
    assert_eq!(records[0].origin, Some(IdentityOrigin::Managed));
}

const SHARED_KEY_DID: &str = "did:web:shared-key.example";

/// Seed a [`SHARED_KEY_DID`] record for `key_id` with `origin`, on `surface_id`
/// and keyed as the configured key is.
fn seed_api_key_record(
    identities_dir: &str,
    surface_id: &str,
    key_id: &str,
    origin: IdentityOrigin,
) {
    let (fields, hash) = block_on(configured_key_identity(key_id));
    let mut record = crate::identity::test_helpers::test_surface_identity_record(SHARED_KEY_DID, surface_id);
    record.identity_hash = hash;
    record.identity_fields = fields;
    record.origin = Some(origin);
    record.private_key = Some(serde_json::to_value(ssi::jwk::JWK::generate_ed25519().unwrap()).unwrap());
    seed_identity(identities_dir, record);
}

/// Seed the record the inbound slot of an older build gave `key_id`: an External
/// Caller of `surface_id`, keyed as the configured key was.
fn seed_legacy_caller_record(
    identities_dir: &str,
    surface_id: &str,
    key_id: &str,
) {
    seed_api_key_record(identities_dir, surface_id, key_id, IdentityOrigin::ExternalCaller);
}

/// A surface whose callers are identified by the key they present and whose
/// Managed Agent and Transit Point are identified by `managed_key`.
fn shared_key_surface(
    surface_id: &str,
    policy_id: &str,
    managed_key: &str,
) -> AgentSurface {
    let managed = json!({ "type": "from_api_key", "api_key_id": managed_key });
    let mut transit = transit_with_one_point();
    transit["points"][0]["managed_identity"] = managed.clone();
    let mut surface = provider_caller_surface(surface_id, "/smoke", policy_id, Some(transit));
    surface
        .identity_slots
        .protected = Some(serde_json::from_value(managed).unwrap());
    surface
}

/// A Managed Agent key that an older build recorded as a caller keeps that
/// record: an unknown caller key adds no identity record, another caller key
/// adds only its own, the Managed Agent and the Transit Point reuse the record,
/// and a caller presenting the Managed Agent key on the same surface is served
/// with the record's DID. The record keeps its DID and role throughout.
#[tokio::test(flavor = "multi_thread")]
async fn a_managed_agent_key_recorded_as_a_caller_keeps_its_record() {
    const SURFACE: &str = "legacy-dual-role";
    const POLICY: &str = "legacy-dual-role-allow";
    let mut keys = Vec::new();
    let mut identities_dir = String::new();
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |dir, gw_config, bootstrap| {
        keys = create_provider_keys(bootstrap, &["legacy-managed", "legacy-caller"], &[]);
        identities_dir = bootstrap
            .storage_paths
            .identities
            .clone();
        seed_legacy_caller_record(&identities_dir, SURFACE, &keys[0].key_id);
        write_policy(dir, POLICY, "package surface.policy\n\ndefault allow := true\n");
        gw_config.surfaces = vec![shared_key_surface(SURFACE, POLICY, &keys[0].key_id)];
    })
    .await;
    let managed_hash = api_key_identity_hash(&keys[0].key_id);

    let unknown = send_with_key(&h.gateway_url, "atgk_unknown_caller_key").await;

    assert_eq!(unknown.status(), 200, "{}", unknown.text().await.unwrap());
    let records = identity_records(&identities_dir);
    assert_eq!(records.len(), 1, "identity record count");
    assert_eq!(records[0].identity_hash, managed_hash);

    assert_eq!(
        send_with_key(&h.gateway_url, &keys[1].secret)
            .await
            .status(),
        200
    );
    let transit_point_status = reqwest::Client::new()
        .post(format!(
            "{}/outbound/smoke/target",
            h.outbound_url
                .as_ref()
                .expect("outbound listener")
        ))
        .header("x-transit-token", forwarded_transit_token(&h))
        .json(&a2a_request())
        .send()
        .await
        .expect("Transit Point request failed")
        .status();
    assert_eq!(transit_point_status, 200);

    let records = identity_records(&identities_dir);
    assert_eq!(records.len(), 2, "the seeded record and the second caller key's record");
    let record = record_for_hash(&records, &managed_hash).expect("the Managed Agent key record");
    assert_eq!(record.origin, Some(IdentityOrigin::ExternalCaller));
    assert_eq!(record.did, SHARED_KEY_DID);

    let same_key = send_with_key(&h.gateway_url, &keys[0].secret).await;

    assert_eq!(same_key.status(), 200, "{}", same_key.text().await.unwrap());
    assert_eq!(transit_token_sub(&forwarded_transit_token(&h)), SHARED_KEY_DID);
    let records = identity_records(&identities_dir);
    assert_eq!(records.len(), 2, "identity record count");
    let record = record_for_hash(&records, &managed_hash).expect("the Managed Agent key record");
    assert_eq!(record.origin, Some(IdentityOrigin::ExternalCaller));
    assert_eq!(record.did, SHARED_KEY_DID);
}

/// A surface policy denying the Managed Agent's key id refuses a caller that
/// presents that key before the target is called, and leaves the Managed
/// Agent's record as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_surface_policy_on_key_name_refuses_a_caller_with_the_managed_agent_key() {
    const SURFACE: &str = "shared-key-refused";
    const POLICY: &str = "shared-key-refuse-managed-key";
    let mut keys = Vec::new();
    let mut identities_dir = String::new();
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |dir, gw_config, bootstrap| {
        keys = create_provider_keys(bootstrap, &["refused-managed", "refused-caller"], &[]);
        identities_dir = bootstrap
            .storage_paths
            .identities
            .clone();
        seed_api_key_record(&identities_dir, SURFACE, &keys[0].key_id, IdentityOrigin::Managed);
        write_policy(
            dir,
            POLICY,
            &format!(
                r#"package surface.policy

default allow := false

managed_agent_key if {{
    input.source_auth.key_name == "{}"
}}

allow if {{
    not managed_agent_key
}}

deny_reason := "The Managed Agent's API key cannot be used by a caller" if managed_agent_key
"#,
                keys[0].key_id
            ),
        );
        gw_config.surfaces = vec![shared_key_surface(SURFACE, POLICY, &keys[0].key_id)];
    })
    .await;
    let managed_hash = api_key_identity_hash(&keys[0].key_id);
    assert_eq!(
        send_with_key(&h.gateway_url, &keys[1].secret)
            .await
            .status(),
        200
    );
    let records = identity_records(&identities_dir);
    let forwarded_before = forwarded(&h);

    let refused = send_with_key(&h.gateway_url, &keys[0].secret).await;

    assert_eq!(refused.status(), 403, "{}", refused.text().await.unwrap());
    assert_eq!(forwarded(&h), forwarded_before, "the target is not called");
    let after = identity_records(&identities_dir);
    assert_eq!(after.len(), records.len(), "identity record count");
    let record = record_for_hash(&after, &managed_hash).expect("the Managed Agent key record");
    assert_eq!(record.origin, Some(IdentityOrigin::Managed));
    assert_eq!(record.did, SHARED_KEY_DID);
}

const LEGACY_SAVED_KEY_ID: &str = "atgk_e2e0000000000000000000000000079";

/// A gateway with surface `surface_id` stored as an older build saved it, its
/// inbound slot naming its Managed Agent key, and that key's legacy caller
/// record.
async fn start_with_stored_shared_key_surface(surface_id: &'static str) -> (GatewayHarness, reqwest::Client, String) {
    let mock = MockServer::start().await;
    let target = mock.url();
    let mut admin = None;
    let mut identities_dir = String::new();
    let h = GatewayHarness::start_with_mock(mock, |_, _, bootstrap| {
        admin = Some(helpers::configure_admin_api(bootstrap));
        identities_dir = bootstrap
            .storage_paths
            .identities
            .clone();
        seed_legacy_caller_record(&identities_dir, surface_id, LEGACY_SAVED_KEY_ID);
        let api_keys = api_keys_dir(bootstrap);
        block_on(async {
            crate::api_keys::FileSystemApiKeyStore::new(&api_keys)
                .await
                .expect("create API key store")
                .create_with_material(
                    surface_id,
                    LEGACY_SAVED_KEY_ID.to_string(),
                    "atgs_legacy_saved_key".to_string(),
                    "legacy",
                    None,
                    "component-test",
                )
                .await
                .expect("seed the legacy key");
        });
        let gateway: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
        let stored = json!({
            "surface_id": surface_id,
            "name": surface_id,
            "access_point": {
                "listen_address": gateway["listeners"][0]["external_urls"][0],
                "route": "/legacy",
                "protocol": "a2a",
                "caller_authentication": { "methods": [{
                    "type": "api_key_provider",
                    "extraction": { "source": "http_header", "field": "X-API-Key" },
                    "agent_id": surface_id
                }] }
            },
            "target": { "endpoint": target },
            "identity_slots": {
                "inbound": { "type": "from_api_key", "api_key_id": LEGACY_SAVED_KEY_ID },
                "protected": { "type": "from_api_key", "api_key_id": LEGACY_SAVED_KEY_ID }
            }
        });
        let directory = std::path::Path::new(
            &bootstrap
                .storage_paths
                .agent_surfaces,
        );
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join(format!("{surface_id}.json")), stored.to_string()).unwrap();
    })
    .await;
    (h, admin.unwrap(), identities_dir)
}

/// Saving a stored surface whose Managed Agent key is also its external
/// Identity key succeeds without a warning and drops only the stored inbound
/// id; a tenant reassignment succeeds too, and the key's caller record keeps
/// its DID and role.
#[tokio::test(flavor = "multi_thread")]
async fn saving_one_key_as_managed_agent_and_caller_identity_is_accepted() {
    const SURFACE: &str = "legacy-dual-role-save";
    let (h, admin, identities_dir) = start_with_stored_shared_key_surface(SURFACE).await;
    let surface_url = format!("{}/api/v1/surfaces/{SURFACE}", h.gateway_base);
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
    let mut body = stored().await;
    body["identity_slots"]["external"] = body["identity_slots"]["protected"].clone();

    let saved = admin
        .put(&surface_url)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert!(
        saved
            .headers()
            .get(reqwest::header::WARNING)
            .is_none()
    );
    assert_eq!(saved.status(), 200, "{}", saved.text().await.unwrap());
    let after = stored().await;
    assert_eq!(after["identity_slots"]["inbound"], json!({ "type": "from_api_key" }));
    assert_eq!(after["identity_slots"]["external"], after["identity_slots"]["protected"]);

    let reassigned = admin
        .put(format!("{}/api/v1/tenant-ownership/surfaces/{SURFACE}", h.gateway_base))
        .json(&json!({ "tenant_id": "tenant-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reassigned.status(),
        200,
        "{}",
        reassigned
            .text()
            .await
            .unwrap()
    );

    let records = identity_records(&identities_dir);
    let record = record_for_hash(&records, &api_key_identity_hash(LEGACY_SAVED_KEY_ID)).expect("the caller record");
    assert_eq!(record.origin, Some(IdentityOrigin::ExternalCaller));
    assert_eq!(record.did, SHARED_KEY_DID);
}

/// A gateway with a caller surface on `/smoke` whose callers are identified by
/// the key they present, and a surface on `/managed` whose Managed Agent is
/// identified by the first of two provider keys.
async fn start_shared_key_gateway(
    caller_surface: &'static str,
    managed_surface: &'static str,
) -> (GatewayHarness, Vec<ProviderKey>, String) {
    const POLICY: &str = "shared-key-allow-callers";
    let mut keys = Vec::new();
    let mut identities_dir = String::new();
    let h = GatewayHarness::start(|dir, gw_config, bootstrap| {
        keys = create_provider_keys(bootstrap, &["shared-client", "other-client"], &[]);
        identities_dir = bootstrap
            .storage_paths
            .identities
            .clone();
        helpers::configure_gateway_route_prefixes(
            bootstrap,
            &[("smoke", "smoke", "/smoke"), ("managed", "managed", "/managed")],
        );
        write_policy(dir, POLICY, "package surface.policy\n\ndefault allow := true\n");
        gw_config.surfaces = vec![
            provider_caller_surface(caller_surface, "/smoke", POLICY, None),
            managed_api_key_surface(managed_surface, "/managed", &keys[0].key_id),
        ];
    })
    .await;
    (h, keys, identities_dir)
}

/// A provider key that already identifies a Managed Agent on another surface
/// is served when a caller presents it, with the Managed Agent's DID, and its
/// record stays the Managed Agent's.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_already_identifying_a_managed_agent_is_served_as_a_caller() {
    let (h, keys, identities_dir) = start_shared_key_gateway("shared-key-callers", "shared-key-managed").await;
    let shared_hash = api_key_identity_hash(&keys[0].key_id);

    let managed = send_with_key(&format!("{}/managed/rpc", h.gateway_base), &keys[1].secret).await;
    assert_eq!(managed.status(), 200);
    let records = identity_records(&identities_dir);
    let managed_record = record_for_hash(&records, &shared_hash).expect("the Managed Agent record");
    assert_eq!(managed_record.origin, Some(IdentityOrigin::Managed));
    let managed_did = managed_record.did.clone();
    let forwarded_before = forwarded(&h);

    let caller = send_with_key(&h.gateway_url, &keys[0].secret).await;

    assert_eq!(caller.status(), 200, "{}", caller.text().await.unwrap());
    assert_eq!(forwarded(&h), forwarded_before + 1);
    let after = identity_records(&identities_dir);
    assert_eq!(after.len(), records.len(), "identity record count");
    let kept = record_for_hash(&after, &shared_hash).expect("the Managed Agent record");
    assert_eq!(kept.origin, Some(IdentityOrigin::Managed));
    assert_eq!(kept.did, managed_did);
}

/// A provider key that a caller presented first is served as another
/// surface's Managed Agent key with the caller's DID, and its record stays the
/// caller's.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_already_identifying_a_caller_is_served_as_a_managed_agent() {
    let (h, keys, identities_dir) =
        start_shared_key_gateway("shared-key-callers-first", "shared-key-managed-second").await;
    let shared_hash = api_key_identity_hash(&keys[0].key_id);

    let caller = send_with_key(&h.gateway_url, &keys[0].secret).await;
    assert_eq!(caller.status(), 200);
    let records = identity_records(&identities_dir);
    let caller_record = record_for_hash(&records, &shared_hash).expect("the caller record");
    assert_eq!(caller_record.origin, Some(IdentityOrigin::ExternalCaller));
    let caller_did = caller_record.did.clone();

    let managed = send_with_key(&format!("{}/managed/rpc", h.gateway_base), &keys[1].secret).await;

    assert_eq!(managed.status(), 200, "{}", managed.text().await.unwrap());
    let after = identity_records(&identities_dir);
    assert_eq!(after.len(), records.len(), "identity record count");
    let kept = record_for_hash(&after, &shared_hash).expect("the caller record");
    assert_eq!(kept.origin, Some(IdentityOrigin::ExternalCaller));
    assert_eq!(kept.did, caller_did);
}
