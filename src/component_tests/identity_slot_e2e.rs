//! The managed slot and credential `updated_at` recorded by the request-path call sites.
//!
//! The Identities page groups versions by `slot`, and the slot is kept once set, so these
//! drive real requests and check what each call site stored.

use super::helpers;
use crate::identity::IdentityStore as _;
use crate::identity::filesystem::{AgentIdentityRecord, FilesystemIdentityStore, ManagedSlot};
use helpers::{GatewayHarness, MockServer};
use serde_json::json;

const AGENT_IDENTITY_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";

async fn stored_record_with_field(
    identities_path: &std::path::Path,
    value: &str,
) -> AgentIdentityRecord {
    let records = FilesystemIdentityStore::new(identities_path)
        .await
        .expect("open identity store")
        .list_all()
        .await
        .expect("list identity records");
    let matching: Vec<_> = records
        .into_iter()
        .filter(|record| {
            record
                .identity_fields
                .values()
                .any(|field| field == value)
        })
        .collect();
    assert_eq!(matching.len(), 1, "expected one identity record with field {value}, got {matching:?}");
    matching
        .into_iter()
        .next()
        .expect("one matching record")
}

async fn send_outbound(
    h: &GatewayHarness,
    metadata: serde_json::Value,
) {
    let outbound_url = h
        .outbound_url
        .as_ref()
        .expect("outbound_url must be set");
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-1",
                "parts": [{ "kind": "text", "text": "hi" }],
                "extensions": [AGENT_IDENTITY_URI],
                "metadata": { AGENT_IDENTITY_URI: metadata }
            }
        }
    });
    let resp = reqwest::Client::new()
        .post(format!("{outbound_url}/outbound/smoke/target/rpc"))
        .json(&body)
        .send()
        .await
        .expect("outbound request failed");
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text()
            .await
            .unwrap_or_default()
    );
}

/// A Transit Point with its own `managed_identity` records its DID under that Transit Point's slot.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_through_transit_point_with_own_identity_records_its_slot() {
    let mut identities_path = std::path::PathBuf::new();
    let h = GatewayHarness::start_with_outbound(|_, gw_config, bootstrap| {
        identities_path = bootstrap
            .storage_paths
            .identities
            .clone()
            .into();
        gw_config.surfaces = vec![helpers::build_per_tp_identity_channel()];
    })
    .await;

    send_outbound(&h, json!({ "agentIdentity": { "fish": "trout" } })).await;

    let record = stored_record_with_field(&identities_path, "trout").await;
    assert_eq!(record.slot, Some(ManagedSlot::TransitPoint { alias: "target".into() }));
}

/// A Transit Point that inherits the surface identity records its DID under the protected slot.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_through_transit_point_inheriting_surface_identity_records_protected_slot() {
    let mut identities_path = std::path::PathBuf::new();
    let h = GatewayHarness::start_with_outbound(|_, gw_config, bootstrap| {
        identities_path = bootstrap
            .storage_paths
            .identities
            .clone()
            .into();
        gw_config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    send_outbound(
        &h,
        json!({ "softwareInfo": { "name": "inheriting-agent", "version": "1.0" }, "cloudProvider": "local" }),
    )
    .await;

    let record = stored_record_with_field(&identities_path, "inheriting-agent").await;
    assert_eq!(record.slot, Some(ManagedSlot::Protected));
}

/// An inbound request on a protected `from_mtls` slot stores the certificate's `updated_at`
/// as the record's baseline.
///
/// Ignored in the shared test run: the request path reads the certificate store from a
/// process-wide global (`proxy::server::get_certificates_store`) that the first gateway to boot
/// sets, so any earlier harness leaves it pointing at a deleted temp dir. Run it on its own.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs its own process: the proxy's certificate store is a process-wide global"]
async fn inbound_protected_from_mtls_records_the_certificate_updated_at() {
    let key_pair = rcgen::KeyPair::generate().expect("client key pair");
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "managed-agent");
    let certificate_pem = params
        .self_signed(&key_pair)
        .expect("self-signed client certificate")
        .pem();
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{ "kind": "text", "text": "response" }],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": { AGENT_IDENTITY_URI: { "softwareInfo": { "name": "backend-agent", "version": "2.0" } } }
        }
    });
    let mock = MockServer::start_with_response(agent_response.to_string()).await;
    let mut identities_path = std::path::PathBuf::new();
    let mut certificate = None;
    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, bootstrap| {
        use crate::certificates::CertificateStore as _;

        identities_path = bootstrap
            .storage_paths
            .identities
            .clone()
            .into();
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
                        name: "Managed agent".to_string(),
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
                    .expect("store the managed agent's certificate")
            })
        });
        gw_config.surfaces = vec![
            serde_json::from_value(json!({
                "name": "smoke-mtls-identity",
                "access_point": {
                    "listen_address": "inbound_port_placeholder",
                    "route": "/smoke",
                    "protocol": "a2a"
                },
                "target": { "endpoint": "inbound_target_placeholder" },
                "identity_slots": {
                    "protected": { "type": "from_mtls", "certificate_id": created.id }
                }
            }))
            .expect("from_mtls identity surface JSON"),
        ];
        certificate = Some(created);
    })
    .await;
    let certificate = certificate.expect("certificate created during setup");

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "message/send",
            "id": 1,
            "params": { "message": { "role": "user", "messageId": "msg-1", "parts": [{ "kind": "text", "text": "hi" }] } }
        }))
        .send()
        .await
        .expect("inbound request failed");
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text()
            .await
            .unwrap_or_default()
    );

    let record = stored_record_with_field(&identities_path, &certificate.id).await;
    assert_eq!(record.slot, Some(ManagedSlot::Protected));
    assert_eq!(record.credential_updated_at, Some(certificate.updated_at));
}
