//! A transit token issued for a request that arrived over Fabric opens the
//! receiving surface's Transit Points as an Access Point's does, with the
//! Transit Point's static credential, and a Transit Point to a peer gateway
//! refuses a call that would pass the Fabric hop limit before forwarding it.
//! Delegated per-user credentials reach a Transit Point's target only for the
//! caller the receiving surface verified, on a Transit Point that opts in.

use super::helpers::{self, GatewayHarness, MockServer};
use base64::Engine as _;
use serde_json::json;
use std::sync::atomic::Ordering;

const TARGET_SECRET_ID: &str = "fabric-transit-target-key";
const TARGET_SECRET: &str = "fabric-transit-static-secret";
const AGENT_DID: &str = "did:web:agent.example";
const DELEGATED_HEADER: &str = "x-delegated-credential";

/// A token-requiring Transit Point to the mock target whose managed identity
/// is `AGENT_DID` and whose delegated credential, from provider `provider`,
/// travels in `DELEGATED_HEADER`.
fn delegating_transit_point(
    alias: &str,
    for_fabric_callers: bool,
) -> crate::config::agent_surface::TransitPoint {
    serde_json::from_value(json!({
        "alias": alias,
        "target_endpoint": "outbound_target_placeholder",
        "require_transit_token": true,
        "managed_identity": { "type": "static", "did": AGENT_DID },
        "transit_credentials": { "credential_provider_id": "provider", "scopes": ["read"],
            "inject_as": { "type": "custom_header", "name": DELEGATED_HEADER, "format": "{value}" } },
        "delegated_credentials_for_fabric_callers": for_fabric_callers
    }))
    .unwrap()
}

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
    transit
        .points
        .push(delegating_transit_point("delegated", true));
    transit
        .points
        .push(delegating_transit_point("withheld", false));
    surface
}

async fn start_gateway() -> GatewayHarness {
    start_gateway_with_vault()
        .await
        .0
}

/// The gateway, and the directory its delegation vault keeps grants in.
async fn start_gateway_with_vault() -> (GatewayHarness, std::path::PathBuf) {
    let mut vault = None;
    let h = GatewayHarness::start_with_outbound_mock(MockServer::start().await, |_, gw_config, bootstrap| {
        use crate::credential_providers::storage::CredentialProviderStorage;
        use crate::secrets::SecretsStore;
        vault = Some(std::path::PathBuf::from(
            &bootstrap
                .storage_paths
                .delegation_vault,
        ));
        let store = crate::secrets::FilesystemSecretsStore::new(
            &bootstrap
                .storage_paths
                .secrets,
        )
        .unwrap();
        let providers_path = std::path::PathBuf::from(
            &bootstrap
                .storage_paths
                .credential_providers,
        );
        let identities_path = std::path::PathBuf::from(
            &bootstrap
                .storage_paths
                .identities,
        );
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
                crate::credential_providers::storage::FileSystemCredentialProviderStore::new(providers_path)
                    .await
                    .unwrap()
                    .create(
                        serde_json::from_value(json!({
                            "id": "provider", "name": "provider", "provider_id": "provider",
                            "resource": "https://provider.example/api",
                            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                        }))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                // The Transit Points' managed agent, whose presentation they
                // sign into each call.
                let mut agent =
                    crate::identity::test_helpers::test_surface_identity_record(AGENT_DID, "fabric-transit-surface");
                agent.private_key = Some(serde_json::to_value(ssi::jwk::JWK::generate_ed25519().unwrap()).unwrap());
                crate::identity::IdentityStore::create(
                    &crate::identity::FilesystemIdentityStore::new(identities_path)
                        .await
                        .unwrap(),
                    agent,
                )
                .await
                .unwrap();
            })
        });
        helpers::configure_gateway_route_prefixes(bootstrap, &[("smoke", "smoke", "/smoke")]);
        gw_config.surfaces = vec![surface()];
    })
    .await;
    (h, vault.unwrap())
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
    fabric_issued_with(token, hops, |_| {})
}

/// [`fabric_issued`], with `change` applied to the claims before they are
/// signed.
fn fabric_issued_with(
    token: &str,
    hops: u8,
    change: impl FnOnce(&mut crate::proxy::transit_token::TransitTokenClaims),
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
        principal_hash: None,
    });
    change(&mut claims);
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
    call_transit_point_with_body(h, alias, token, r#"{"jsonrpc":"2.0","method":"test","id":2}"#).await
}

async fn call_transit_point_with_body(
    h: &GatewayHarness,
    alias: &str,
    token: &str,
    body: &'static str,
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
            .body(body)
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

/// Stores `access_token` in the gateway's delegation vault as the grant of the
/// caller whose identity hash is `user_identity_hash`, for `AGENT_DID` and
/// provider `provider`.
async fn store_grant(
    vault: &std::path::Path,
    id: &str,
    user_identity_hash: &str,
    access_token: &str,
) {
    use crate::delegation_vault::storage::DelegationVaultStorage;
    crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(vault.to_path_buf())
        .await
        .unwrap()
        .store(
            serde_json::from_value(json!({
                "id": id, "agent_did": AGENT_DID, "user_identity_hash": user_identity_hash,
                "credential_provider_id": "provider", "provider_id": "provider", "access_token": access_token,
                "refresh_token": format!("{id}-refresh"), "scopes": ["read"],
                "expires_at": chrono::Utc::now() + chrono::Duration::hours(1),
                "consent_granted_at": "2026-09-01T00:00:00Z",
                "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
}

const A2A_MESSAGE: &str = r#"{"jsonrpc":"2.0","id":2,"method":"message/send","params":{"message":{"role":"user","messageId":"m-1","parts":[{"kind":"text","text":"hi"}]}}}"#;

/// A Transit Point with `delegated_credentials_for_fabric_callers` sends its
/// target the grant of the caller the receiving surface verified on a Fabric
/// request. One without it refuses that call with `403`, and so does one with
/// it when the receiving surface verified no caller, whatever the peer said
/// its caller was; the target is not called either time. The credential
/// delegation stores are process-global, so the gateway runs in a child
/// process of its own.
#[test]
fn a_fabric_callers_delegated_credential_reaches_the_target_only_through_a_transit_point_that_opts_in() {
    const CHILD: &str = "ATG_FABRIC_CALLER_DELEGATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated Fabric caller delegation test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(Box::pin(fabric_caller_delegation_flow()));
}

async fn fabric_caller_delegation_flow() {
    let (h, vault) = start_gateway_with_vault().await;
    let alice = crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "alice".to_string(),
        provider_agent_id: None,
    }
    .principal_hash(None)
    .unwrap();
    let peer_did = "did:web:asserted-user.example";
    let peer_did_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(peer_did.as_bytes()));
    store_grant(&vault, "alice-token", &alice, "alice-access").await;
    store_grant(&vault, "did-token", &peer_did_hash, "asserted-did-access").await;
    let access_point = access_point_token(&h).await;
    let verified = fabric_issued_with(&access_point, 1, |claims| {
        claims.sub = Some(peer_did.to_string());
        claims
            .fabric
            .as_mut()
            .unwrap()
            .principal_hash = Some(alice.clone());
    });
    let forwarded = || {
        h.mock
            .request_count
            .load(Ordering::SeqCst)
    };

    let before = forwarded();
    let response = call_transit_point_with_body(&h, "delegated", &verified, A2A_MESSAGE).await;
    let status = response.status();
    assert_eq!(status, 200, "{}", response.text().await.unwrap());
    assert_eq!(forwarded(), before + 1);
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    assert_eq!(
        received
            .headers
            .get(DELEGATED_HEADER)
            .map(String::as_str),
        Some("alice-access")
    );

    let before = forwarded();
    let withheld = call_transit_point_with_body(&h, "withheld", &verified, A2A_MESSAGE).await;
    assert_eq!(withheld.status(), 403, "{}", withheld.text().await.unwrap());

    for asserted in [
        fabric_issued_with(&access_point, 1, |claims| claims.sub = Some(peer_did.to_string())),
        fabric_issued_with(&access_point, 1, |claims| {
            claims.sub = Some(peer_did.to_string());
            claims.user_identity_hash = Some(peer_did_hash.clone());
        }),
    ] {
        let refused = call_transit_point_with_body(&h, "delegated", &asserted, A2A_MESSAGE).await;
        assert_eq!(refused.status(), 403, "{}", refused.text().await.unwrap());
    }
    assert_eq!(forwarded(), before, "a refused call never reaches the target");
}
