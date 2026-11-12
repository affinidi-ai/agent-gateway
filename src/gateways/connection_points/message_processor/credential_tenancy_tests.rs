//! How Fabric receive holds a tenant surface to its own tenant's credentials on
//! the Target leg, under each `tenant_credential_isolation` mode.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::variant_routing_tests::isolated;
use super::{ProcessingResult, process_forward_request};
use crate::component_tests::helpers::RecordingTarget;
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode, TEST_CREDENTIAL_POLICY};
use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};
use crate::delegation_vault::storage::FileSystemDelegationVaultStore;
use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
use crate::gateways::types::{ExposureMode, Gateway, GatewayType};
use crate::messages::MessageType;
use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore, SecretsStore};
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

const SENDER_DID: &str = "did:web:sender.example";
const CALLER_KEY: &str = "tenant-a-caller-key";

struct Receiver {
    target: RecordingTarget,
    surfaces_path: std::path::PathBuf,
    secrets_path: std::path::PathBuf,
    _root: tempfile::TempDir,
    _issuer_dir: tempfile::TempDir,
}

impl Receiver {
    /// A receiving gateway with one appliance-wide paired sender and a
    /// `tenant-a` surface per credential: one sending each secret as Target
    /// Authentication, one delegating each API key provider. Each surface
    /// verifies its callers by an API key header, which a delegated credential
    /// needs over Fabric.
    async fn new() -> Self {
        let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
        let root = tempfile::tempdir().unwrap();
        let mut sender =
            Gateway::new(SENDER_DID.to_string(), String::new(), SENDER_DID.to_string(), GatewayType::Remote);
        sender.exposure_mode = Some(ExposureMode::All);
        sender.issuer_did = Some("did:web:sender-gateway.example".to_string());
        let issuer_dir =
            crate::gateways::test_helpers::install_listener_manager_with_peers(root.path(), &[sender]).await;

        let secrets_path = root.path().join("secrets");
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            FilesystemSecretsStore::new_async(secrets_path.to_str().unwrap())
                .await
                .unwrap(),
        );
        let providers = FileSystemCredentialProviderStore::new(root.path().join("providers"))
            .await
            .unwrap();
        for (credential, tenant) in [("own", Some("tenant-a")), ("wide", None), ("other", Some("tenant-b"))] {
            secrets
                .create(CreateSecretRequest {
                    tenant_id: tenant.map(String::from),
                    name: credential.into(),
                    secret_id: credential.into(),
                    description: None,
                    value: format!("{credential}-value"),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
            providers
                .create(
                    serde_json::from_value(json!({
                        "id": credential, "name": credential, "provider_id": credential, "tenant_id": tenant,
                        "provider_type": "api_key", "api_key_secret_ref": credential,
                        "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        secrets
            .create(CreateSecretRequest {
                tenant_id: Some("tenant-a".into()),
                name: "callers".into(),
                secret_id: "callers".into(),
                description: None,
                value: CALLER_KEY.into(),
                secret_type: "ApiKey".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        super::init_source_auth_middleware(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
            Arc::new(crate::didauth::DidAuthSessionStore::new()),
            Arc::new(
                crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.path().join("strategies"))
                    .await
                    .unwrap(),
            ),
            Arc::new(crate::jwt_bearer::JwksClient::new()),
            Some(secrets.clone()),
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        )))
        .await;
        super::init_secrets_store(secrets).await;
        super::init_credential_provider_store(Arc::new(providers) as Arc<dyn CredentialProviderStorage>).await;
        super::init_delegation_vault_store(Arc::new(
            FileSystemDelegationVaultStore::new(root.path().join("vault"))
                .await
                .unwrap(),
        ))
        .await;
        super::init_gateway_base_url("https://receiver.example".to_string()).await;

        let surfaces_path = root.path().join("surfaces");
        let store = FileSystemAgentSurfaceStore::new(surfaces_path.clone())
            .await
            .unwrap();
        for credential in ["own", "wide", "other"] {
            for (surface_id, target_auth, outbound_credentials) in [
                (
                    format!("auth-{credential}"),
                    json!({"method": {"static_secret": {"secret_id": credential, "header_name": "x-target-key"}}}),
                    json!([]),
                ),
                (format!("delegated-{credential}"), Value::Null, json!([{"credential_provider_id": credential}])),
            ] {
                let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                    "surface_id": surface_id, "name": surface_id, "tenant_id": "tenant-a",
                    "access_point": {"listen_address": "127.0.0.1:8080", "route": format!("/{surface_id}"), "protocol": "a2a",
                        "public": false,
                        "caller_authentication": {"methods": [{"type": "api_key", "secret_id": "callers",
                            "extraction": {"source": "http_header", "field": "x-api-key"}}]}},
                    "target": {"endpoint": target.url, "auth": target_auth},
                    "outbound_credentials": outbound_credentials
                }))
                .unwrap();
                store
                    .save(&surface)
                    .await
                    .unwrap();
            }
        }
        Self {
            target,
            surfaces_path,
            secrets_path,
            _root: root,
            _issuer_dir: issuer_dir,
        }
    }

    /// A legacy `ForwardRequest` for `surface_id`. With a `caller_key` the
    /// surface verifies the caller, which keys a delegated credential.
    fn forward_request(
        &self,
        surface_id: &str,
        caller_key: Option<&str>,
    ) -> ReceivedMessage {
        self.forward_request_to(surface_id, caller_key, "/", &[])
    }

    /// [`Self::forward_request`] for `path`, carrying `extra_headers` from the peer.
    fn forward_request_to(
        &self,
        surface_id: &str,
        caller_key: Option<&str>,
        path: &str,
        extra_headers: &[(&str, &str)],
    ) -> ReceivedMessage {
        let mut headers = json!({"content-type": "application/json"});
        if let Some(key) = caller_key {
            headers["x-api-key"] = json!(key);
        }
        for (name, value) in extra_headers {
            headers[*name] = json!(value);
        }
        ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(super::super::envelope_replay::now_secs() + 60),
            json!({
                "channel_id": surface_id, "method": "POST", "path": path,
                "headers": headers,
                "body": {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
                    "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hello"}]
                }}}
            }),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(self.surfaces_path))
        .with_context("secrets_storage_path", json!(self.secrets_path))
    }

    /// Receives a request for `surface_id` under `mode`, and returns the
    /// `ForwardResponse` status, the credential headers the Target received
    /// (none when it was not called), and the credential audit records.
    async fn receive(
        &self,
        surface_id: &str,
        mode: RuleMode,
    ) -> (u64, Option<(Option<String>, Option<String>)>, Vec<String>) {
        self.receive_from(surface_id, mode, Some(CALLER_KEY))
            .await
    }

    /// [`Self::receive`] from a peer that presents `caller_key`, if any.
    async fn receive_from(
        &self,
        surface_id: &str,
        mode: RuleMode,
        caller_key: Option<&str>,
    ) -> (u64, Option<(Option<String>, Option<String>)>, Vec<String>) {
        let policy: &'static CredentialPolicyConfig = Box::leak(Box::new(CredentialPolicyConfig {
            tenant_credential_isolation: mode,
            ..CredentialPolicyConfig::default()
        }));
        let called_before = self.target.received().len();
        let message = self.forward_request(surface_id, caller_key);
        let (result, events) = TEST_CREDENTIAL_POLICY
            .scope(
                policy,
                crate::audit::producer::capture(async {
                    tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&message)))
                        .await
                        .expect("Fabric receive handler timed out")
                }),
            )
            .await;
        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected a ForwardResponse, got {result:?}");
        };
        let status = response_body["status"]
            .as_u64()
            .unwrap_or_else(|| panic!("no status in {response_body}"));
        let received = self.target.received();
        assert!(received.len() <= called_before + 1, "{surface_id}: the Target was called more than once");
        let header = |headers: &axum::http::HeaderMap, name: &str| {
            headers
                .get(name)
                .map(|value| {
                    value
                        .to_str()
                        .unwrap()
                        .to_string()
                })
        };
        let credentials = received
            .get(called_before)
            .map(|headers| (header(headers, "x-target-key"), header(headers, "authorization")));
        (status, credentials, credential_records(&events))
    }
}

/// The detail of each injected delegated credential, and `target_auth_failed (<outcome>)` for
/// each Target credential the receiving gateway did not send.
fn credential_records(events: &[DelegationAuditEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::TokenInjected => event.detail.clone(),
            DelegationAuditAction::RequestRejected {
                reason: crate::audit::request_events::RejectionReason::TargetAuthFailed,
                http_status,
                target_auth: Some(target_auth),
                ..
            } => {
                assert!(event.via_fabric, "a Fabric receive record is marked as such");
                assert_eq!(*http_status, None, "a Fabric receive record has no HTTP status");
                Some(format!("target_auth_failed ({:?})", target_auth.outcome))
            }
            _ => None,
        })
        .collect()
}

fn sent(
    target_key: Option<&str>,
    authorization: Option<&str>,
) -> Option<(Option<String>, Option<String>)> {
    Some((target_key.map(String::from), authorization.map(String::from)))
}

#[test]
fn fabric_receive_sends_a_tenant_surface_only_credentials_the_isolation_mode_allows() {
    isolated("AG_FABRIC_CREDENTIAL_TENANCY_CHILD", async {
        let receiver = Receiver::new().await;
        let api_key = vec!["api_key".to_string()];
        let none = Vec::<String>::new();
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(
                receiver
                    .receive("auth-own", mode)
                    .await,
                (200, sent(Some("own-value"), None), none.clone()),
                "{mode:?}"
            );
            assert_eq!(
                receiver
                    .receive("auth-other", mode)
                    .await,
                (502, None, vec!["target_auth_failed (Rejected)".to_string()]),
                "{mode:?}"
            );
            assert_eq!(
                receiver
                    .receive("delegated-own", mode)
                    .await,
                (200, sent(None, Some("Bearer own-value")), api_key.clone()),
                "{mode:?}"
            );
            assert_eq!(
                receiver
                    .receive("delegated-other", mode)
                    .await,
                (503, None, none.clone()),
                "{mode:?}"
            );
            assert_eq!(
                receiver
                    .receive_from("delegated-own", mode, None)
                    .await,
                (401, None, none.clone()),
                "{mode:?}: no verified caller"
            );
            assert_eq!(
                receiver
                    .receive_from("delegated-own", mode, Some("a-key-the-surface-refuses"))
                    .await,
                (401, None, none.clone()),
                "{mode:?}: a caller the surface did not verify"
            );
        }

        assert_eq!(
            receiver
                .receive("auth-wide", RuleMode::Warn)
                .await,
            (200, sent(Some("wide-value"), None), none.clone())
        );
        assert_eq!(
            receiver
                .receive("delegated-wide", RuleMode::Warn)
                .await,
            (200, sent(None, Some("Bearer wide-value")), vec!["api_key (appliance_wide_credential)".to_string()])
        );

        assert_eq!(
            receiver
                .receive("auth-wide", RuleMode::Enforce)
                .await,
            (502, None, vec!["target_auth_failed (Rejected)".to_string()])
        );
        assert_eq!(
            receiver
                .receive("delegated-wide", RuleMode::Enforce)
                .await,
            (503, None, none)
        );
    });
}

#[test]
fn fabric_receive_keeps_the_target_credential_under_its_base_path_and_drops_a_caller_copy() {
    isolated("AG_FABRIC_TARGET_SCOPE_CHILD", async {
        let receiver = Receiver::new().await;
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "scoped", "name": "scoped", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "127.0.0.1:8080", "route": "/scoped", "protocol": "a2a",
                "caller_authentication": {"methods": [{"type": "api_key", "secret_id": "callers",
                    "extraction": {"source": "http_header", "field": "x-api-key"}}]}},
            "target": {"endpoint": format!("{}/base", receiver.target.url),
                "auth": {"method": {"static_secret": {"secret_id": "own", "header_name": "x-target-key"}}}}
        }))
        .unwrap();
        FileSystemAgentSurfaceStore::new(receiver.surfaces_path.clone())
            .await
            .unwrap()
            .save(&surface)
            .await
            .unwrap();
        let receive = |path: &'static str| {
            let message = receiver.forward_request_to(
                "scoped",
                Some(CALLER_KEY),
                path,
                &[("X-TARGET-KEY", "caller-chosen"), ("x_target_key", "caller-chosen")],
            );
            async move {
                let policy: &'static CredentialPolicyConfig = Box::leak(Box::default());
                let (result, events) = TEST_CREDENTIAL_POLICY
                    .scope(
                        policy,
                        crate::audit::producer::capture(async {
                            tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&message)))
                                .await
                                .expect("Fabric receive handler timed out")
                        }),
                    )
                    .await;
                let ProcessingResult::RequiresResponse { response_body, .. } = result else {
                    panic!("expected a ForwardResponse, got {result:?}");
                };
                let status = response_body["status"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("no status in {response_body}"));
                (status, credential_records(&events))
            }
        };

        assert_eq!(receive("/x").await, (200, Vec::new()));
        let received = receiver.target.received();
        assert_eq!(received.len(), 1);
        assert_eq!(
            received[0]
                .get_all("x-target-key")
                .iter()
                .collect::<Vec<_>>(),
            ["own-value"]
        );
        assert!(
            received[0]
                .get("x_target_key")
                .is_none(),
            "{:?}",
            received[0]
        );

        for path in ["/%2e%2e/admin", "/x/../../admin", "/..;/admin", "/..%252Fadmin"] {
            assert_eq!(receive(path).await, (502, vec!["target_auth_failed (Rejected)".to_string()]), "{path}");
        }
        assert_eq!(
            receiver
                .target
                .received()
                .len(),
            1,
            "a path outside the base path never reaches the Target"
        );
    });
}
