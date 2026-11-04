//! The VP Audit Log record of a Target credential the direct path did not send: one
//! `request_rejected` record with reason `target_auth_failed`, whatever the fallback did, and
//! never a secret, token or token endpoint body.

use std::sync::Arc;

use serde_json::{Value, json};

use super::variant_routing_tests::{router, send};
use crate::audit::events::TargetAuthRejection;
use crate::audit::request_events::{RejectionReason, RejectionStage, TargetAuthOutcome};
use crate::component_tests::helpers::MockServer;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};

const DESCRIPTION_MARKER: &str = "description-secret-marker";
const CLIENT_SECRET: &str = "client-secret-marker";

fn surface(
    endpoint: &str,
    target_auth: Value,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "orders", "name": "Orders",
        "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
        "target": {"endpoint": endpoint, "auth": target_auth}
    }))
    .unwrap()
}

type Record = (RejectionStage, Option<u16>, Option<String>, Option<String>, Option<TargetAuthRejection>);

/// Each `target_auth_failed` record: its stage, HTTP status, provider, trace id and detail.
fn target_auth_records(events: &[DelegationAuditEvent]) -> Vec<Record> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                stage,
                reason: RejectionReason::TargetAuthFailed,
                http_status,
                target_auth,
                ..
            } => Some((
                *stage,
                *http_status,
                event.provider_id.clone(),
                event
                    .trace_id
                    .as_ref()
                    .map(|_| "trace".to_string()),
                target_auth.clone(),
            )),
            _ => None,
        })
        .collect()
}

fn detail(
    outcome: TargetAuthOutcome,
    oauth_error: Option<&str>,
) -> Option<TargetAuthRejection> {
    Some(TargetAuthRejection {
        outcome,
        transit_point: None,
        oauth_error: oauth_error.map(str::to_string),
    })
}

async fn agent() -> MockServer {
    MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string()).await
}

#[tokio::test]
async fn a_target_secret_that_cannot_be_read_is_recorded_once_with_what_the_fallback_did() {
    let target = agent().await;
    for (fallback, status, outcome, http_status) in [
        ("reject", 502, TargetAuthOutcome::Rejected, Some(502)),
        ("passthrough", 200, TargetAuthOutcome::Passthrough, None),
    ] {
        let surface = surface(
            &target.url(),
            json!({"method": {"static_secret": {"secret_id": "absent", "header_name": "x-key"}}, "fallback": fallback}),
        );
        let (answered, events) = send(router(surface), "/a2a").await;
        assert_eq!(answered.as_u16(), status, "{fallback}");
        assert_eq!(
            target_auth_records(&events),
            vec![(RejectionStage::Forward, http_status, None, Some("trace".to_string()), detail(outcome, None))],
            "{fallback}"
        );
    }
}

#[tokio::test]
async fn a_credential_withheld_by_an_enforced_rule_is_recorded() {
    use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode, TEST_CREDENTIAL_POLICY};
    let target = agent().await;
    let policy: &'static CredentialPolicyConfig = Box::leak(Box::new(CredentialPolicyConfig {
        target_https: RuleMode::Enforce,
        ..CredentialPolicyConfig::default()
    }));
    let surface = surface(
        &target.url(),
        json!({"method": {"credential_provider": {"provider_id": "machine"}}, "fallback": "reject"}),
    );
    let (answered, events) = TEST_CREDENTIAL_POLICY
        .scope(policy, send(router(surface), "/a2a"))
        .await;
    assert_eq!(answered.as_u16(), 502);
    assert_eq!(
        target_auth_records(&events),
        vec![(
            RejectionStage::Forward,
            Some(502),
            Some("machine".to_string()),
            Some("trace".to_string()),
            detail(TargetAuthOutcome::Rejected, None)
        )]
    );
}

/// A token endpoint that refuses every request with an OAuth error whose description and echo
/// carry secret text.
async fn refusing_token_endpoint() -> (String, tokio::task::JoinSet<()>) {
    let app = axum::Router::new().fallback(axum::routing::post(|| async {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "error": "invalid_client",
                "error_description": DESCRIPTION_MARKER,
                "client_secret": CLIENT_SECRET
            })),
        )
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let mut server = tokio::task::JoinSet::new();
    server.spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap();
    });
    (endpoint, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_token_request_is_recorded_with_its_oauth_error_code_and_no_secret_text() {
    use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
    use crate::secrets::SecretsStore;

    let target = agent().await;
    let (token_endpoint, _server) = refusing_token_endpoint().await;
    let directory = tempfile::tempdir().unwrap();
    let secrets: Arc<dyn SecretsStore> = Arc::new(
        crate::secrets::FilesystemSecretsStore::new(
            directory
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .unwrap(),
    );
    for (secret_id, value) in [("CLIENT_ID", "client"), ("CLIENT_SECRET", CLIENT_SECRET)] {
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: value.into(),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
    }
    let providers = FileSystemCredentialProviderStore::new(
        directory
            .path()
            .join("providers"),
    )
    .await
    .unwrap();
    providers
        .create(
            serde_json::from_value(json!({
                "id": "machine", "name": "machine", "provider_id": "machine",
                "provider_type": "oauth2_client_credentials", "token_endpoint": token_endpoint,
                "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET",
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let mut router = router(surface(
        &target.url(),
        json!({"method": {"credential_provider": {"provider_id": "machine"}}, "fallback": "reject"}),
    ));
    router.secrets_store = Some(secrets);
    router.credential_provider_store = Some(Arc::new(providers) as Arc<dyn CredentialProviderStorage>);
    router.delegation_vault_store = Some(Arc::new(
        crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap(),
    ) as Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>);
    let egress = crate::delegation_vault::oauth::TokenEgress {
        timeout: std::time::Duration::from_secs(5),
        exact_allowlist: Some(token_endpoint),
        policy: Default::default(),
    };

    let (answered, events) = egress
        .scope(send(router, "/a2a"))
        .await;

    assert_eq!(answered.as_u16(), 502);
    assert_eq!(
        target_auth_records(&events),
        vec![(
            RejectionStage::Forward,
            Some(502),
            Some("machine".to_string()),
            Some("trace".to_string()),
            detail(TargetAuthOutcome::Rejected, Some("invalid_client"))
        )]
    );
    let stored = serde_json::to_string(&events).unwrap();
    for secret in [DESCRIPTION_MARKER, CLIENT_SECRET] {
        assert!(!stored.contains(secret), "the audit records carry secret text");
    }
}
