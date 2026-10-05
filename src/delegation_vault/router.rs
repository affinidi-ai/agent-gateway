//! Delegation vault API router

use super::handlers::{self, DelegationVaultState};
use crate::{
    auth_manager::middleware::{RbacGuard, maybe_gate},
    rbac::Feature,
};
use axum::{
    Router,
    routing::{delete, get},
};

/// Create the delegation vault management API router.
/// Management routes only — must be mounted inside the session-auth boundary.
///
/// Every route is RBAC-gated when `gate` is `Some`: the two reads (list/get,
/// which enumerate every user's/agent's grants) require `DelegationVaultView`
/// and the two revokes (single + mass by-user) require `DelegationVaultDelete`
/// — both admin-only by default. When `gate` is `None` (auth backend not
/// configured) routes are returned ungated, matching the other management
/// routers' pre-RBAC behaviour.
pub fn create_delegation_vault_router(
    state: DelegationVaultState,
    gate: Option<RbacGuard>,
) -> Router {
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
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::AuthGuardOk;
    use crate::auth_manager::pat::{PatContext, PatDelegationContext};
    use crate::credential_providers::CredentialProvider;
    use crate::delegation_vault::audit::{AUDIT_DEFER_QUEUE, DelegationAuditAction, DelegationAuditEvent};
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
        ] {
            let app = create_delegation_vault_router(state_with(vec![seed_token("t1")]), Some(gate.clone()))
                .layer(Extension(AuthGuardOk("user-1".to_string())));
            let status = status_of(app, method, uri).await;
            assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "{method} {uri} must be 403 for a non-admin");
        }
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

        let queue: Arc<Mutex<Vec<DelegationAuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let status = AUDIT_DEFER_QUEUE
            .scope(queue.clone(), async { status_of(app, "DELETE", "/api/v1/delegation-vault/t1").await })
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT.as_u16());

        let events = queue.lock().unwrap();
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

        let queue: Arc<Mutex<Vec<DelegationAuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let status = AUDIT_DEFER_QUEUE
            .scope(queue.clone(), async {
                status_of(app, "DELETE", "/api/v1/delegation-vault/by-user/sha256:user-1").await
            })
            .await;
        assert_eq!(status, StatusCode::OK.as_u16());

        let events = queue.lock().unwrap();
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
