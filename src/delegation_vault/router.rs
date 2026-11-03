//! Delegation vault API router

use super::handlers::{self, DelegationVaultState};
use crate::{
    auth_manager::middleware::{RbacGuard, maybe_gate},
    rbac::Feature,
};
use axum::{
    Router,
    routing::{delete, get, post},
};

/// Create the delegation vault management API router.
/// Management routes only — must be mounted inside the session-auth boundary.
///
/// Every route is RBAC-gated when `gate` is `Some`: the reads (list/get, which
/// enumerate every user's/agent's tokens) require `DelegationVaultView`; the
/// revokes (single + mass by-user) and the removals of grants by binding (one
/// grant, or one binding's) require `DelegationVaultDelete`; starting and
/// completing an external consent connect, and the report of a surface's
/// grants by binding, require `DelegationVaultConnect`, so a token provisioned
/// for the connect API never needs `DelegationVaultView`, whose reads are not
/// filtered by tenant; all are admin-only by default. The connect API and the
/// grants by binding also admit a tenant's token, for its own tenant's
/// surfaces only. When `gate` is `None` (auth backend not configured) every
/// route refuses.
pub fn create_delegation_vault_router(
    state: DelegationVaultState,
    gate: Option<RbacGuard>,
) -> Router {
    use super::connect_api;
    let g = gate.as_ref();
    let router = Router::new()
        .route("/api/v1/delegation-vault", maybe_gate(g, get(handlers::list_tokens), Feature::DelegationVaultView))
        .route("/api/v1/delegation-vault/{id}", maybe_gate(g, get(handlers::get_token), Feature::DelegationVaultView))
        .route(
            "/api/v1/delegation-vault/{id}",
            maybe_gate(g, delete(handlers::revoke_token), Feature::DelegationVaultDelete),
        )
        .route(
            "/api/v1/delegation-vault/by-user/{user_hash}",
            maybe_gate(g, delete(handlers::revoke_user_tokens), Feature::DelegationVaultDelete),
        )
        .route(
            "/api/v1/delegation-vault/connects",
            maybe_gate(g, post(connect_api::start_connect), Feature::DelegationVaultConnect),
        )
        .route(
            "/api/v1/delegation-vault/connects/{connect_id}/complete",
            maybe_gate(g, post(connect_api::complete_connect), Feature::DelegationVaultConnect),
        )
        .route(
            "/api/v1/delegation-vault/grants",
            maybe_gate(g, get(connect_api::list_grants), Feature::DelegationVaultConnect),
        )
        .route(
            "/api/v1/delegation-vault/grants",
            maybe_gate(g, delete(connect_api::delete_binding_grants), Feature::DelegationVaultDelete),
        )
        .route(
            "/api/v1/delegation-vault/grants/{grant_id}",
            maybe_gate(g, delete(connect_api::delete_grant), Feature::DelegationVaultDelete),
        );

    let router = if let Some(gate) = gate {
        router.route("/api/v1/delegation-audit", gate.gate(get(handlers::list_audit_events), Feature::AuditView))
    } else {
        router
    };

    router.with_state(state)
}

/// Create the OAuth callback router.
/// This is the only delegation-vault route that must remain public, because
/// the user's browser is redirected here from the OAuth provider.
pub fn create_delegation_vault_oauth_router(state: DelegationVaultState) -> Router {
    let callback_route = format!("{}/{{provider_id}}", state.oauth_callback_route);
    Router::new()
        .route(&callback_route, get(handlers::oauth_callback))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::producer::capture;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::AuthGuardOk;
    use crate::auth_manager::pat::{PatContext, PatDelegationContext};
    use crate::credential_providers::CredentialProvider;
    use crate::delegation_vault::audit::DelegationAuditAction;
    use crate::delegation_vault::storage::DelegationVaultStorage;
    use crate::delegation_vault::{DelegationToken, VaultLookupResult};
    use crate::rbac::RbacConfig;
    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, SecretsStore, UpdateSecretRequest};
    use axum::Extension;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    /// Minimal in-memory delegation vault backing the handler under test.
    /// Only the reads/deletes exercised by the management routes are real.
    struct InMemoryVault {
        tokens: Mutex<Vec<DelegationToken>>,
    }

    #[async_trait::async_trait]
    impl DelegationVaultStorage for InMemoryVault {
        async fn store(
            &self,
            token: DelegationToken,
        ) -> anyhow::Result<DelegationToken> {
            self.tokens
                .lock()
                .unwrap()
                .push(token.clone());
            Ok(token)
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<DelegationToken>> {
            Ok(self
                .tokens
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.id == id)
                .cloned())
        }

        async fn lookup(
            &self,
            _agent_did: &str,
            _user_identity_hash: &str,
            _provider_id: &str,
        ) -> anyhow::Result<VaultLookupResult> {
            Ok(VaultLookupResult::NotFound)
        }

        async fn list_all(&self) -> anyhow::Result<Vec<DelegationToken>> {
            Ok(self
                .tokens
                .lock()
                .unwrap()
                .clone())
        }

        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<bool> {
            let mut guard = self.tokens.lock().unwrap();
            let before = guard.len();
            guard.retain(|t| t.id != id);
            Ok(guard.len() != before)
        }

        async fn delete_by_user(
            &self,
            user_identity_hash: &str,
        ) -> anyhow::Result<usize> {
            let mut guard = self.tokens.lock().unwrap();
            let before = guard.len();
            guard.retain(|t| t.user_identity_hash != user_identity_hash);
            Ok(before - guard.len())
        }

        async fn update(
            &self,
            token: DelegationToken,
        ) -> anyhow::Result<DelegationToken> {
            Ok(token)
        }

        async fn mark_used(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Provider/secrets stores are never reached by the management routes under
    /// test (the gate denies before the handler, and revoke only touches the
    /// vault), so these panic if invoked — a guard against silent coupling.
    struct StubProviderStore;

    #[async_trait::async_trait]
    impl crate::credential_providers::storage::CredentialProviderStorage for StubProviderStore {
        async fn create(
            &self,
            _provider: CredentialProvider,
        ) -> anyhow::Result<CredentialProvider> {
            unimplemented!("provider store not used by delegation-vault management routes")
        }
        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<CredentialProvider>> {
            Ok(None)
        }
        async fn list(&self) -> anyhow::Result<Vec<CredentialProvider>> {
            unimplemented!()
        }
        async fn update(
            &self,
            _provider: CredentialProvider,
        ) -> anyhow::Result<CredentialProvider> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn find_by_provider_id(
            &self,
            _tenant_id: Option<&str>,
            _provider_id: &str,
        ) -> anyhow::Result<Option<CredentialProvider>> {
            unimplemented!()
        }
    }

    struct StubSecretsStore;

    #[async_trait::async_trait]
    impl SecretsStore for StubSecretsStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!("secrets store not used by delegation-vault management routes")
        }
        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            unimplemented!()
        }
        async fn list_all(&self) -> anyhow::Result<Vec<SecretListItem>> {
            unimplemented!()
        }
        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> anyhow::Result<Vec<SecretListItem>> {
            unimplemented!()
        }
    }

    fn seed_token(id: &str) -> DelegationToken {
        let now = Utc::now();
        DelegationToken {
            id: id.to_string(),
            agent_did: "did:web:agent.example".to_string(),
            user_identity_hash: "sha256:user-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            access_token: "secret-access".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            scopes: vec!["repo".to_string()],
            expires_at: None,
            delegation_vc: None,
            consent_granted_at: now,
            last_used_at: None,
            created_at: now,
            updated_at: now,
            consent_identity: None,
        }
    }

    fn state_with(tokens: Vec<DelegationToken>) -> DelegationVaultState {
        DelegationVaultState {
            vault_store: Arc::new(InMemoryVault { tokens: Mutex::new(tokens) }),
            provider_store: Arc::new(StubProviderStore),
            secrets_store: Arc::new(StubSecretsStore),
            gateway_base_url: "https://gw.example".to_string(),
            agent_surface_store: None,
            oauth_callback_route: "/v1/identity/oauth/callback".to_string(),
            vc_signer: None,
            vc_issuer: None,
            vault_population_notifier: None,
            egress_allowlist: None,
            resource_origins: Default::default(),
            issuers: Default::default(),
        }
    }

    async fn storage_with_user(
        user_id: &str,
        role: UserRole,
    ) -> (Arc<PasskeyStorage>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = PasskeyStorage::new(
            dir.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            dir.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let now = Utc::now();
        storage
            .save_user(&UserData {
                user_id: user_id.to_string(),
                username: user_id.to_string(),
                passkeys: Vec::new(),
                role,
                status: UserStatus::Approved,
                is_primary: false,
                first_name: None,
                last_name: None,
                email: None,
                department: None,
                job_title: None,
                avatar_path: None,
                created_at: now,
                updated_at: now,
                last_logged_in: None,
                saml_id: None,
            })
            .await
            .unwrap();
        (Arc::new(storage), dir)
    }

    fn gate_for(storage: Arc<PasskeyStorage>) -> RbacGuard {
        RbacGuard::new(storage, Arc::new(RbacConfig::default()))
    }

    async fn status_of(
        app: Router,
        method: &str,
        uri: &str,
    ) -> u16 {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        app.oneshot(req)
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    /// A callback that fails before the credential is stored leaves its state
    /// unused, so the user can retry the same callback instead of starting over.
    #[tokio::test]
    async fn a_callback_that_fails_before_storing_does_not_use_up_its_state() {
        let state = crate::delegation_vault::OAuthState {
            agent_did: "did:web:agent.example".to_string(),
            user_identity_hash: "sha256:user".to_string(),
            surface_id: "surface".to_string(),
            credential_provider_id: "deleted-provider".to_string(),
            provider_id: "github".to_string(),
            nonce: uuid::Uuid::new_v4().to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            code_verifier: None,
        };
        let encoded = crate::delegation_vault::oauth::encode_oauth_state(&state).unwrap();
        let app = create_delegation_vault_oauth_router(state_with(Vec::new()));
        for attempt in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/identity/oauth/callback/github?code=code&state={encoded}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body = String::from_utf8_lossy(&body);
            assert!(body.contains("Credential provider configuration not found"), "attempt {attempt}: {body}");
            assert!(!body.contains("already used"), "attempt {attempt}: {body}");
        }
        assert!(
            crate::delegation_vault::oauth::claim_oauth_state(&state).await,
            "the failed callbacks left the state unused"
        );
    }

    #[tokio::test]
    async fn a_provider_error_on_the_callback_logs_only_the_oauth_error_code() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let app = create_delegation_vault_oauth_router(state_with(Vec::new()));
        for query in [
            "error=access_denied&error_description=description-marker",
            "error=bad%22quote&error_description=description-marker",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/identity/oauth/callback/github?{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let lines: Vec<_> = logs
            .text()
            .lines()
            .filter(|line| line.contains("OAuth provider returned an error"))
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("oauth_error=access_denied"), "{}", lines[0]);
        assert!(lines[1].contains("oauth_error=unrecognized_error"), "{}", lines[1]);
        assert!(
            !logs
                .text()
                .contains("description-marker"),
            "{}",
            logs.text()
        );
        assert!(!logs.text().contains("quote"), "{}", logs.text());
    }

    #[tokio::test]
    async fn a_callbacks_provider_id_is_logged_escaped_and_bounded() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let app = create_delegation_vault_oauth_router(state_with(Vec::new()));
        let padding = "a".repeat(400);
        for query in ["error=access_denied", "code=c&state=not-a-state"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/identity/oauth/callback/github%0D%0AINFO%20forged{padding}?{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let text = logs.text();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("provider_id="))
            .collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert!(
            lines
                .iter()
                .all(|line| line.contains(r#"provider_id="github\r\nINFO forgedaaa"#)),
            "{text}"
        );
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("INFO forged")),
            "{text}"
        );
        assert!(!text.contains(&padding), "{text}");
    }

    // ── a non-admin principal is denied on every management route ──

    #[tokio::test]
    async fn non_admin_is_forbidden_on_all_management_routes() {
        let (storage, _dir) = storage_with_user("user-1", UserRole::User).await;
        let gate = gate_for(storage);

        for (method, uri) in [
            ("GET", "/api/v1/delegation-vault"),
            ("GET", "/api/v1/delegation-vault/t1"),
            ("DELETE", "/api/v1/delegation-vault/t1"),
            ("DELETE", "/api/v1/delegation-vault/by-user/sha256:user-1"),
            ("DELETE", "/api/v1/delegation-vault/grants/grant-1"),
            ("DELETE", "/api/v1/delegation-vault/grants?surface_id=s&transit_point_id=tp&credential_provider_id=p"),
            ("GET", "/api/v1/delegation-vault/grants?surface_id=s"),
            ("POST", "/api/v1/delegation-vault/connects"),
            ("POST", "/api/v1/delegation-vault/connects/connect-1/complete"),
        ] {
            let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), Some(gate.clone()))
                .layer(Extension(AuthGuardOk("user-1".to_string())));
            let status = status_of(app, method, uri).await;
            assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "{method} {uri} must be 403 for a non-admin");
        }
    }

    /// A binding's grants are removed by binding or one by one. A readable one
    /// is deleted and revoked; one that cannot be read is purged, unrevoked,
    /// only for an operator, and the audit says so with its binding. A tenant's
    /// token removes only its own tenant's grants, and none while one of them
    /// cannot be read.
    #[tokio::test]
    async fn grants_are_removed_by_id_or_binding_and_unreadable_ones_only_by_an_operator() {
        use crate::delegation_vault::grants::GrantKey;
        use crate::delegation_vault::grants::tests::grant;
        let directory = tempfile::tempdir().unwrap();
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let owner = GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "provider");
        let readable = GrantKey::caller(Some("tenant-a"), "surface", "tp-1", "provider", &"c".repeat(64)).unwrap();
        let unreadable = GrantKey::caller(Some("tenant-a"), "surface", "tp-1", "provider", &"d".repeat(64)).unwrap();
        for key in [&owner, &readable, &unreadable] {
            vault
                .store_grant(grant(key, "access"))
                .await
                .unwrap();
        }
        for key in [&owner, &unreadable] {
            std::fs::write(
                directory
                    .path()
                    .join("vault/delegated_grants")
                    .join(format!("{}.json.enc", key.record_id())),
                "not a grant",
            )
            .unwrap();
        }
        let mut state = state_with(Vec::new());
        state.vault_store = vault.clone();
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = || {
            create_delegation_vault_router(state.clone(), Some(gate_for(storage.clone())))
                .layer(Extension(AuthGuardOk("admin-1".to_string())))
        };
        let tenant = |tenant_id: &str| {
            app().layer(Extension(crate::tenancy::PatTenantContext {
                token_id: "pat-t".to_string(),
                tenant_id: tenant_id.to_string(),
            }))
        };

        let by_id = format!("/api/v1/delegation-vault/grants/{}", owner.record_id());
        assert_eq!(status_of(tenant("tenant-a"), "DELETE", &by_id).await, StatusCode::CONFLICT.as_u16());
        let (status, events) = capture(async { status_of(app(), "DELETE", &by_id).await }).await;
        assert_eq!(status, StatusCode::NO_CONTENT.as_u16());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].token_id.as_deref(), Some(owner.record_id().as_str()));
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:skipped,reason:purged"));
        assert_eq!(
            events[0]
                .caller
                .as_ref()
                .and_then(|caller| caller.sub.as_deref()),
            Some("admin-1")
        );
        assert_eq!(status_of(app(), "DELETE", &by_id).await, StatusCode::NOT_FOUND.as_u16());
        assert_eq!(
            status_of(app(), "DELETE", "/api/v1/delegation-vault/grants/pepper-fingerprint").await,
            StatusCode::BAD_REQUEST.as_u16()
        );

        let by_binding = "/api/v1/delegation-vault/grants?surface_id=surface&transit_point_id=tp-1\
                          &credential_provider_id=provider";
        assert_eq!(
            status_of(tenant("tenant-b"), "DELETE", &format!("{by_binding}&tenant_id=tenant-a")).await,
            StatusCode::NOT_FOUND.as_u16(),
            "another tenant's token never names this tenant"
        );
        let (status, body) = response_of(tenant("tenant-a"), "DELETE", by_binding).await;
        assert_eq!(status, StatusCode::CONFLICT.as_u16(), "{body}");
        assert_eq!(
            vault
                .binding_grant_ids(&owner.binding())
                .await
                .unwrap()
                .len(),
            2,
            "a tenant's request deletes nothing while one of the grants cannot be read"
        );
        let ((status, body), events) =
            capture(async { response_of(app(), "DELETE", &format!("{by_binding}&tenant_id=tenant-a")).await }).await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["removed"], 1);
        assert_eq!(body["grant_ids"], serde_json::json!([readable.record_id()]));
        assert_eq!(body["purged"], serde_json::json!([unreadable.record_id()]));
        let purge = events
            .iter()
            .find(|event| {
                event.token_id.as_deref()
                    == Some(
                        unreadable
                            .record_id()
                            .as_str(),
                    )
            })
            .expect("the purge is audited");
        assert_eq!(purge.surface_id.as_deref(), Some("surface"), "the audit names the binding's surface");
        assert_eq!(purge.provider_id.as_deref(), Some("provider"), "and its provider");
        assert_eq!(
            purge.detail.as_deref(),
            Some(r#"vendor_revocation:skipped,reason:purged,tenant:"tenant-a",transit_point:"tp-1""#),
            "and its tenant and Transit Point"
        );
        assert!(
            vault
                .binding_grant_ids(&owner.binding())
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// After the identity hash pepper changed, a binding's grants are filed
    /// under ids the gateway can no longer derive: the purge by binding says
    /// so with `409` and purges nothing, rather than answering that there was
    /// nothing to purge.
    #[tokio::test]
    async fn a_binding_purge_under_another_pepper_answers_409_and_purges_nothing() {
        use crate::delegation_vault::grants::GrantKey;
        use crate::delegation_vault::grants::tests::grant;
        use crate::identity::credential_identity::configure_pepper_bytes_for_tests;
        let directory = tempfile::tempdir().unwrap();
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        configure_pepper_bytes_for_tests(&[1; 32]);
        let owner = GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "provider");
        crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap()
            .store_grant(grant(&owner, "access"))
            .await
            .unwrap();
        let stored = directory
            .path()
            .join("vault/delegated_grants")
            .join(format!("{}.json.enc", owner.record_id()));
        assert!(stored.exists());

        configure_pepper_bytes_for_tests(&[2; 32]);
        let mut state = state_with(Vec::new());
        state.vault_store = Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = create_delegation_vault_router(state, Some(gate_for(storage)))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));
        let by_binding = "/api/v1/delegation-vault/grants?tenant_id=tenant-a&surface_id=surface&transit_point_id=tp-1\
                          &credential_provider_id=provider";
        let ((status, body), events) = capture(async { response_of(app, "DELETE", by_binding).await }).await;
        assert_eq!(status, StatusCode::CONFLICT.as_u16(), "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["code"], "identity_hash_pepper_mismatch", "{body}");
        let error = body["error"]
            .as_str()
            .unwrap();
        assert!(error.contains("another identity hash pepper"), "{error}");
        assert!(error.contains("delegated_grants"), "the answer says where the ids are: {error}");
        assert!(stored.exists(), "nothing is purged");
        assert!(events.is_empty(), "nothing is audited as purged");
    }

    /// The report of grants by binding needs `delegation_vault.connect`, which
    /// a token provisioned for the connect API holds, not
    /// `delegation_vault.view`, which also opens the legacy reads of every
    /// tenant's agent-keyed tokens.
    #[tokio::test]
    async fn the_grants_report_needs_the_connect_permission_not_the_legacy_view() {
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = |scope: &str| {
            create_delegation_vault_router(state_with(Vec::new()), Some(gate_for(storage.clone())))
                .layer(Extension(PatContext(Some(vec![scope.to_string()]))))
                .layer(Extension(AuthGuardOk("admin-1".to_string())))
        };
        let report = "/api/v1/delegation-vault/grants?surface_id=surface";
        assert_eq!(status_of(app("delegation_vault.view"), "GET", report).await, StatusCode::FORBIDDEN.as_u16());
        assert_ne!(status_of(app("delegation_vault.connect"), "GET", report).await, StatusCode::FORBIDDEN.as_u16());
    }

    // ── A PAT whose scopes exclude the feature is denied even for an admin ──

    #[tokio::test]
    async fn admin_pat_without_delete_scope_is_forbidden() {
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), Some(gate_for(storage)))
            .layer(Extension(PatContext(Some(vec!["delegation_vault.view".to_string()]))))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));
        let status = status_of(app, "DELETE", "/api/v1/delegation-vault/t1").await;
        assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "PAT lacking delegation_vault.delete must be 403");
    }

    // ── An authorized admin revoke succeeds and attributes the actor ──

    #[tokio::test]
    async fn admin_session_revoke_records_actor() {
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), Some(gate_for(storage)))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));

        let (status, events) = capture(async { status_of(app, "DELETE", "/api/v1/delegation-vault/t1").await }).await;
        assert_eq!(status, StatusCode::NO_CONTENT.as_u16());

        assert_eq!(events.len(), 1, "revoke must emit exactly one audit event");
        let evt = &events[0];
        assert!(matches!(evt.event, DelegationAuditAction::TokenRevoked));
        assert_eq!(evt.token_id.as_deref(), Some("t1"));
        let caller = evt
            .caller
            .as_ref()
            .expect("revoke event must attribute a caller");
        assert_eq!(caller.auth_method, "session");
        assert_eq!(caller.sub.as_deref(), Some("admin-1"));
        assert_eq!(caller.token_id, None, "session caller has no PAT token id");
    }

    #[tokio::test]
    async fn admin_pat_revoke_records_token_id() {
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), Some(gate_for(storage)))
            .layer(Extension(PatContext(Some(vec!["delegation_vault.delete".to_string()]))))
            .layer(Extension(PatDelegationContext {
                token_id: "pat-9".to_string(),
                delegation_depth: 0,
                resource_scoped: false,
            }))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));

        let (status, events) =
            capture(async { status_of(app, "DELETE", "/api/v1/delegation-vault/by-user/sha256:user-1").await }).await;
        assert_eq!(status, StatusCode::OK.as_u16());

        assert_eq!(events.len(), 1);
        let caller = events[0]
            .caller
            .as_ref()
            .expect("mass-revoke must attribute a caller");
        assert_eq!(caller.auth_method, "access_token");
        assert_eq!(caller.sub.as_deref(), Some("admin-1"));
        assert_eq!(caller.token_id.as_deref(), Some("pat-9"));
    }

    // ── Fail closed: an ungated build still rejects a revoke with no caller ──

    #[tokio::test]
    async fn revoke_without_caller_fails_closed() {
        // gate = None mirrors an auth-disabled build. `maybe_gate` now refuses the
        // route outright in that case, so the request is denied before the handler
        // runs; the handler's own fail-closed check remains as defence in depth.
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), None);
        let status = status_of(app, "DELETE", "/api/v1/delegation-vault/t1").await;
        assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "revoke with no authenticated caller must be refused");
    }

    #[tokio::test]
    async fn mass_revoke_without_caller_fails_closed() {
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), None);
        let status = status_of(app, "DELETE", "/api/v1/delegation-vault/by-user/sha256:user-1").await;
        assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "mass-revoke with no authenticated caller must be refused");
    }

    // ── Fail closed: an ungated build rejects the reads with no caller, and
    //    serialises no token metadata ──

    async fn response_of(
        app: Router,
        method: &str,
        uri: &str,
    ) -> (u16, String) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app
            .oneshot(req)
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn list_without_caller_fails_closed() {
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), None);
        let (status, body) = response_of(app, "GET", "/api/v1/delegation-vault").await;
        assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "list with no authenticated caller must be refused");
        assert!(!body.contains("did:web:agent.example"), "unauthenticated list must not serialise token metadata");
    }

    #[tokio::test]
    async fn get_without_caller_fails_closed() {
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), None);
        let (status, body) = response_of(app, "GET", "/api/v1/delegation-vault/t1").await;
        assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "get with no authenticated caller must be refused");
        assert!(!body.contains("did:web:agent.example"), "unauthenticated get must not serialise token metadata");
    }

    // ── Authorized admin reads are unchanged: 200 + metadata ──

    #[tokio::test]
    async fn admin_session_list_returns_metadata() {
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), Some(gate_for(storage)))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));
        let (status, body) = response_of(app, "GET", "/api/v1/delegation-vault").await;
        assert_eq!(status, StatusCode::OK.as_u16(), "authorized admin list must be 200");
        assert!(body.contains("\"id\":\"t1\""), "authorized list must serialise the token id");
    }

    #[tokio::test]
    async fn admin_session_get_returns_metadata() {
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), Some(gate_for(storage)))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));
        let (status, body) = response_of(app, "GET", "/api/v1/delegation-vault/t1").await;
        assert_eq!(status, StatusCode::OK.as_u16(), "authorized admin get must be 200");
        assert!(body.contains("\"id\":\"t1\""), "authorized get must serialise the token id");
        assert!(!body.contains("secret-access"), "get must never expose the access token");
    }
}
