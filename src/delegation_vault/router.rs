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
/// Every route is RBAC-gated when `gate` is `Some`: the reads (list/get of the
/// agent-keyed tokens) require `DelegationVaultView`; the
/// revokes (single + mass by-user) and the removals of grants by binding (one
/// grant, or one binding's) require `DelegationVaultDelete`; starting and
/// completing an external consent connect, and the report of a surface's
/// grants by binding, require `DelegationVaultConnect`, so a token provisioned
/// for the connect API never needs `DelegationVaultView`; all are admin-only by
/// default. The reads show a tenant's token only the tokens of its own
/// tenant's credential providers. The connect API and the grants by binding
/// also admit a tenant's token, for its own tenant's surfaces only. When
/// `gate` is `None` (auth backend not configured) every route refuses.
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

/// Create the OAuth consent router: the consent start page and its POST, the
/// consent confirmation callback and the vendor callback. These
/// delegation-vault routes must remain public, because the person's browser
/// opens the start page and the identity provider and the OAuth provider
/// redirect it to the callbacks.
pub fn create_delegation_vault_oauth_router(state: DelegationVaultState) -> Router {
    let callback_route = format!("{}/{{callback_segment}}", state.oauth_callback_route);
    Router::new()
        .route(&callback_route, get(handlers::oauth_callback))
        .route(&format!("{callback_route}/start"), get(handlers::consent_start_page).post(handlers::consent_start))
        .route(
            &format!("{callback_route}{}", crate::credential_providers::CONSENT_CONFIRMATION_PATH),
            get(handlers::consent_confirmation_callback),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::DelegationFailureReason;
    use crate::audit::producer::capture;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::AuthGuardOk;
    use crate::auth_manager::pat::{PatContext, PatDelegationContext};
    use crate::credential_providers::CredentialProvider;
    use crate::credential_providers::storage::CredentialProviderStorage as _;
    use crate::delegation_vault::audit::{DelegationAuditAction, reading_audit_log_from, without_an_audit_log};
    use crate::delegation_vault::storage::DelegationVaultStorage;
    use crate::delegation_vault::test_support::{InMemoryProviders, audit_log_of_two_tenants};
    use crate::delegation_vault::{DelegationToken, VaultLookupResult};
    use crate::jwt_bearer::JwtVerificationStrategyStorage as _;
    use crate::jwt_bearer::models::JwtVerificationStrategy;
    use crate::rbac::RbacConfig;
    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, SecretsStore, UpdateSecretRequest};
    use crate::tenancy::PatTenantContext;
    use axum::Extension;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    /// Minimal in-memory delegation vault backing the handler under test.
    /// Only the reads/deletes exercised by the management routes are real.
    /// An `unreadable` vault fails every read and delete with
    /// [`VAULT_READ_FAILURE`].
    struct InMemoryVault {
        tokens: Mutex<Vec<DelegationToken>>,
        unreadable: bool,
    }

    /// The detail of a failed read or delete of an `unreadable`
    /// [`InMemoryVault`].
    const VAULT_READ_FAILURE: &str = "vault entry /srv/gateway/_storage/delegation_vault/t1.json unreadable";

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
            if self.unreadable {
                anyhow::bail!(VAULT_READ_FAILURE);
            }
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
            if self.unreadable {
                anyhow::bail!(VAULT_READ_FAILURE);
            }
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
            if self.unreadable {
                anyhow::bail!(VAULT_READ_FAILURE);
            }
            let mut guard = self.tokens.lock().unwrap();
            let before = guard.len();
            guard.retain(|t| t.id != id);
            Ok(guard.len() != before)
        }

        async fn delete_by_user(
            &self,
            user_identity_hash: &str,
        ) -> anyhow::Result<usize> {
            if self.unreadable {
                anyhow::bail!(VAULT_READ_FAILURE);
            }
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

    struct StubStrategyStore;

    #[async_trait::async_trait]
    impl crate::jwt_bearer::JwtVerificationStrategyStorage for StubStrategyStore {
        async fn create(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            unimplemented!("strategy store not used by delegation-vault management routes")
        }
        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            unimplemented!()
        }
        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            unimplemented!()
        }
        async fn update(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
    }

    /// The secrets store is never reached by the management routes under test,
    /// so it panics if invoked — a guard against silent coupling.
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

    /// A token of the credential provider `credential_provider_id`.
    fn seed_token_of(
        id: &str,
        credential_provider_id: &str,
    ) -> DelegationToken {
        DelegationToken {
            credential_provider_id: credential_provider_id.to_string(),
            ..seed_token(id)
        }
    }

    /// A token of each provider of [`InMemoryProviders::of_two_tenants`], and
    /// `t-deleted` of a provider that no longer exists.
    fn tokens_of_two_tenants() -> Vec<DelegationToken> {
        vec![
            seed_token_of("t-a", "cp-a"),
            seed_token_of("t-b", "cp-b"),
            seed_token_of("t-global", "cp-global"),
            seed_token_of("t-deleted", "cp-deleted"),
        ]
    }

    fn state_with(tokens: Vec<DelegationToken>) -> DelegationVaultState {
        state_with_providers(tokens, InMemoryProviders::of_two_tenants())
    }

    fn state_with_providers(
        tokens: Vec<DelegationToken>,
        providers: InMemoryProviders,
    ) -> DelegationVaultState {
        DelegationVaultState {
            vault_store: Arc::new(InMemoryVault {
                tokens: Mutex::new(tokens),
                unreadable: false,
            }),
            provider_store: Arc::new(providers),
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
            mcp_proxy_store: None,
            identity_strategies: Arc::new(StubStrategyStore),
            verifier: Arc::new(crate::jwt_bearer::JwtBearerVerifier::new(Arc::new(
                crate::jwt_bearer::JwksClient::new(),
            ))),
            provider_egress: crate::delegation_vault::oauth::TokenEgress::from_environment(),
            gateway_mcp_issuer: None,
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

    /// A callback that is refused before the code is exchanged leaves its state
    /// unused, though the refusal clears the browser's binding cookie.
    #[tokio::test]
    async fn a_callback_refused_before_the_exchange_does_not_use_up_its_state() {
        let fixture = consent::Fixture::new().await;
        let (callback_state, cookie) = fixture.begin().await;
        fixture
            .providers
            .delete(consent::PROVIDER_ID)
            .await
            .unwrap();
        for attempt in 0..2 {
            let refused = fixture
                .callback("github", &format!("code=code&state={callback_state}"), Some(&cookie))
                .await;
            consent::assert_refused(&refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&cookie)));
            assert_eq!(fixture.token_calls(), 0, "attempt {attempt}");
            assert_eq!(fixture.vault_records(), 0, "attempt {attempt}");
        }
        let decoded = crate::delegation_vault::oauth::decode_callback_state(&callback_state).unwrap();
        assert!(
            crate::delegation_vault::oauth::claim_oauth_state(&decoded).await,
            "the refused callbacks left the state unused"
        );
    }

    /// A vendor error shows the fixed page: `error` is logged only when it is
    /// `[A-Za-z0-9_]{1,128}`, `error_description` never.
    #[tokio::test]
    async fn a_provider_error_on_the_callback_shows_the_fixed_page_and_logs_only_a_valid_code() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let fixture = consent::Fixture::new().await;
        let (results, events) = capture(async {
            let mut results = Vec::new();
            for query in [
                "error=access_denied&error_description=description-marker",
                "error=bad%22quote&error_description=%3Cscript%3Edescription-marker",
                &format!("error={}", "a".repeat(129)),
            ] {
                results.push(
                    fixture
                        .callback("github", query, None)
                        .await,
                );
            }
            results
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, None);
            assert!(
                !refused
                    .body
                    .contains("description-marker"),
                "{}",
                refused.body
            );
            assert!(
                !refused
                    .body
                    .contains("access_denied"),
                "{}",
                refused.body
            );
        }
        assert!(events.is_empty(), "a callback without a state is not audited: {events:?}");
        let refusals: Vec<_> = logs
            .text()
            .lines()
            .filter(|line| line.contains("OAuth consent refused"))
            .map(|line| {
                ["ConsentDenied", "ConsentResponseInvalid"]
                    .into_iter()
                    .find(|reason| line.contains(&format!("reason={reason}")))
                    .unwrap_or("none")
            })
            .collect();
        assert_eq!(refusals, ["ConsentDenied", "ConsentResponseInvalid", "ConsentResponseInvalid"]);
        let lines: Vec<_> = logs
            .text()
            .lines()
            .filter(|line| line.contains("OAuth provider returned an error"))
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].contains("oauth_error=access_denied"), "{}", lines[0]);
        assert!(lines[1].contains("oauth_error=unrecognized_error"), "{}", lines[1]);
        assert!(lines[2].contains("oauth_error=unrecognized_error"), "{}", lines[2]);
        assert!(
            !logs
                .text()
                .contains("description-marker"),
            "{}",
            logs.text()
        );
        assert!(!logs.text().contains("quote"), "{}", logs.text());
        assert_eq!(fixture.token_calls(), 0);
        assert_eq!(fixture.vault_records(), 0);
    }

    /// Start page, start POST, vendor and callback in one browser store one
    /// credential keyed by agent, user and provider, and clear the cookie. An
    /// `iss` from a provider without a recorded issuer changes nothing.
    #[tokio::test]
    async fn consent_in_one_browser_stores_one_credential_and_clears_the_binding_cookie() {
        let fixture = consent::Fixture::new().await;
        let start_url = fixture.start_url();
        let start = url::Url::parse(&start_url).unwrap();
        assert_eq!(start.path(), "/v1/identity/oauth/callback/github/start");
        assert_eq!(
            start
                .origin()
                .ascii_serialization(),
            "https://198.51.100.7"
        );
        let page = fixture
            .get(&consent::local(&start_url), &[])
            .await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);

        let started = fixture
            .start_post(&consent::start_state(&start_url), &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
        assert_eq!(started.header("cache-control"), Some("no-store"));
        assert_eq!(started.header("referrer-policy"), Some("no-referrer"));
        let vendor = url::Url::parse(
            started
                .header("location")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            vendor
                .origin()
                .ascii_serialization(),
            "https://vendor.example"
        );
        let fields: std::collections::HashMap<_, _> = vendor
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(fields["client_id"], "github-client");
        assert_eq!(fields["redirect_uri"], consent::REDIRECT_URI);
        assert_eq!(fields["scope"], "repo read:user");
        assert_eq!(fields["code_challenge_method"], "S256");
        let set_cookie = started
            .header("set-cookie")
            .unwrap();
        let (cookie, attributes) = set_cookie
            .split_once(';')
            .unwrap();
        let name = consent::cookie_name(cookie);
        assert!(name.starts_with("__Host-ag_consent_") && name.len() > "__Host-ag_consent_".len(), "{set_cookie}");
        let max_age: i64 = attributes
            .split(';')
            .find_map(|attribute| {
                attribute
                    .trim()
                    .strip_prefix("Max-Age=")
            })
            .unwrap()
            .parse()
            .unwrap();
        assert!((590..=600).contains(&max_age), "{set_cookie}");
        assert_eq!(
            attributes.replace(&format!(" Max-Age={max_age};"), ""),
            " Path=/; Secure; HttpOnly; SameSite=Lax",
            "a __Host- cookie on / with no Domain"
        );
        let start_state =
            crate::delegation_vault::oauth::decode_start_state(&consent::start_state(&start_url)).unwrap();
        let callback_state = crate::delegation_vault::oauth::decode_callback_state(&fields["state"]).unwrap();
        assert!(callback_state.expires_at <= start_state.expires_at);
        assert_ne!(callback_state.nonce, start_state.nonce);

        let done = fixture
            .callback(
                "github",
                &format!("code=vendor-code&state={}&iss=https%3A%2F%2Fattacker.example", fields["state"]),
                Some(cookie),
            )
            .await;
        assert_eq!(done.status, StatusCode::OK, "{}", done.body);
        assert_eq!(done.header("cache-control"), Some("no-store"));
        assert_eq!(done.header("set-cookie"), Some(consent::cleared(&name).as_str()));
        assert_eq!(fixture.token_calls(), 1);
        let stored = fixture
            .vault
            .list_all()
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            (
                stored[0].agent_did.as_str(),
                stored[0]
                    .user_identity_hash
                    .as_str(),
                stored[0].provider_id.as_str()
            ),
            ("did:web:agent.example", "sha256:user", "github")
        );
    }

    /// A forwarded or leaked callback URL, opened in a browser without the
    /// binding cookie or with another one, is refused with 403 before the code
    /// is exchanged.
    #[tokio::test]
    async fn a_callback_without_the_browsers_binding_cookie_is_refused() {
        let fixture = consent::Fixture::new().await;
        let (callback_state, own) = fixture.begin().await;
        let (_, other_state) = fixture.begin().await;
        let name = consent::cookie_name(&own);
        let planted = format!("{}={}", consent::cookie_name(&other_state), own.split_once('=').unwrap().1);
        let wrong_value = format!("{name}=not-a-binding");
        let wrong_under_own_name = format!(
            "{name}={}",
            other_state
                .split_once('=')
                .unwrap()
                .1
        );
        let query = format!("code=vendor-code&state={callback_state}");
        let (results, events) = capture(async {
            vec![
                fixture
                    .callback("github", &query, None)
                    .await,
                fixture
                    .callback("github", &query, Some(&other_state))
                    .await,
                fixture
                    .callback("github", &query, Some(&planted))
                    .await,
                fixture
                    .callback("github", &query, Some(&wrong_value))
                    .await,
                fixture
                    .callback("github", &query, Some(&wrong_under_own_name))
                    .await,
                fixture
                    .callback("github", &query, Some(&format!("{wrong_value}; {own}")))
                    .await,
            ]
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::FORBIDDEN, Some(&name));
        }
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::BrowserBindingMismatch; 6]);
        assert_eq!(fixture.token_calls(), 0);
        assert_eq!(fixture.vault_records(), 0);
    }

    /// A refusal is audited only when the request carried a state this gateway
    /// sealed for that stage; any other is logged as a WARN only, so a loop of
    /// requests without a valid state writes no audit records.
    #[tokio::test]
    async fn only_a_refusal_of_a_gateway_sealed_state_is_audited() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let fixture = consent::Fixture::new().await;
        let (callback_state, cookie) = fixture.begin().await;
        let (results, events) = capture(async {
            let mut results = Vec::new();
            for query in ["code=c", "code=c&state=bogus", "error=access_denied", "error=access_denied&state=bogus"] {
                results.push(
                    fixture
                        .callback("github", query, None)
                        .await,
                );
            }
            results.push(
                fixture
                    .get("/v1/identity/oauth/callback/github/start?state=bogus", &[])
                    .await,
            );
            results.push(
                fixture
                    .start_post("bogus", &[("origin", "https://198.51.100.7")])
                    .await,
            );
            results.push(
                fixture
                    .callback("github", &format!("error=access_denied&state={callback_state}"), Some(&cookie))
                    .await,
            );
            results
        })
        .await;
        for refused in &results[..6] {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, None);
        }
        consent::assert_refused(&results[6], StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentDenied]);
        let text = logs.text();
        let warnings = text
            .lines()
            .filter(|line| line.contains("WARN") && line.contains("OAuth consent refused"))
            .count();
        assert_eq!(warnings, 7, "every refusal is logged: {text}");
    }

    /// Only a callback state, sealed by the start POST with a binding, reaches
    /// the exchange: a start state and an older state without a binding are
    /// refused at the callback, and a callback state at the start POST.
    #[tokio::test]
    async fn the_callback_and_the_start_post_each_take_only_their_own_stage_of_state() {
        let fixture = consent::Fixture::new().await;
        let start_state = consent::start_state(&fixture.start_url());
        let older = crate::delegation_vault::oauth::encode_oauth_state(&crate::delegation_vault::OAuthState {
            code_verifier: Some("verifier".to_string()),
            ..crate::delegation_vault::oauth::decode_start_state(&start_state).unwrap()
        })
        .unwrap();
        let (callback_state, cookie) = fixture.begin().await;
        let (results, events) = capture(async {
            vec![
                fixture
                    .callback("github", &format!("code=c&state={start_state}"), Some(&cookie))
                    .await,
                fixture
                    .callback("github", &format!("code=c&state={older}"), Some(&cookie))
                    .await,
                fixture
                    .callback("github", "code=c", Some(&cookie))
                    .await,
                fixture
                    .start_post(&callback_state, &[("origin", "https://198.51.100.7")])
                    .await,
            ]
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, None);
        }
        assert!(events.is_empty(), "a state of the other stage is not audited: {events:?}");
        assert_eq!(fixture.token_calls(), 0);
        assert_eq!(fixture.vault_records(), 0);
    }

    /// The start page shows a start state that confirms its caller. A
    /// confirmation or vendor state is refused at the start page and its POST,
    /// and a confirmation state at the vendor callback.
    #[tokio::test]
    async fn only_a_start_state_opens_the_start_page_and_a_confirmation_state_never_reaches_the_vendor() {
        use crate::delegation_vault::ConsentStage;
        use crate::delegation_vault::oauth::{decode_callback_state, encode_oauth_state};
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let confirm_start_url = fixture.confirm_start_url(&strategy);
        let page = fixture
            .get(&consent::local(&confirm_start_url), &[])
            .await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        assert!(
            page.body
                .contains("<button type=\"submit\">Sign in, then continue to GitHub</button>"),
            "{}",
            page.body
        );
        assert!(
            page.body
                .contains("You sign in to your identity provider first"),
            "{}",
            page.body
        );
        let plain = fixture
            .get(&consent::local(&fixture.start_url()), &[])
            .await;
        assert!(
            plain
                .body
                .contains("<button type=\"submit\">Continue to GitHub</button>"),
            "{}",
            plain.body
        );
        assert!(
            !plain
                .body
                .contains("identity provider"),
            "{}",
            plain.body
        );

        let signed_in = fixture
            .start_post(&consent::start_state(&confirm_start_url), &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(signed_in.status, StatusCode::FOUND, "{}", signed_in.body);
        let confirmation = consent::start_state(
            signed_in
                .header("location")
                .unwrap(),
        );
        let (cookie, ..) = consent::set_cookie(&signed_in);
        let (callback_state, _) = fixture.begin().await;
        let vendor = encode_oauth_state(&crate::delegation_vault::OAuthState {
            stage: Some(ConsentStage::Vendor(consent::confirm_binding(&strategy))),
            ..decode_callback_state(&callback_state).unwrap()
        })
        .unwrap();
        let (results, events) = capture(async {
            let mut results = Vec::new();
            for state in [&confirmation, &vendor] {
                results.push(
                    fixture
                        .get(&format!("/v1/identity/oauth/callback/github/start?state={state}"), &[])
                        .await,
                );
                results.push(
                    fixture
                        .start_post(state, &[("origin", "https://198.51.100.7")])
                        .await,
                );
            }
            results.push(
                fixture
                    .callback("github", &format!("code=c&state={confirmation}"), Some(&cookie))
                    .await,
            );
            results
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, None);
        }
        assert!(events.is_empty(), "a state of another stage is not audited: {events:?}");
        assert_eq!(fixture.token_calls(), 0);
        assert_eq!(fixture.vault_records(), 0);
    }

    /// The vendor callback takes only a vendor state: a confirm start state,
    /// whose caller was never confirmed, and a staged state sealed under the
    /// legacy label, as a gateway that predates consent stages would seal it,
    /// are refused although the browser holds the cookie, so no code is
    /// exchanged and nothing is stored.
    #[tokio::test]
    async fn the_vendor_callback_refuses_an_unconfirmed_or_an_old_label_staged_state() {
        use crate::delegation_vault::ConsentStage;
        use crate::delegation_vault::oauth::{decode_callback_state, seal_under_legacy_label};
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let confirm_start = consent::start_state(&fixture.confirm_start_url(&strategy));
        let (callback_state, cookie) = fixture.begin().await;
        let old_label = seal_under_legacy_label(&crate::delegation_vault::OAuthState {
            stage: Some(ConsentStage::Vendor(consent::confirm_binding(&strategy))),
            ..decode_callback_state(&callback_state).unwrap()
        });
        let (results, events) = capture(async {
            let mut results = Vec::new();
            for state in [&confirm_start, &old_label] {
                results.push(
                    fixture
                        .callback("github", &format!("code=c&state={state}"), Some(&cookie))
                        .await,
                );
            }
            results
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, None);
        }
        assert!(events.is_empty(), "a state of another stage is not audited: {events:?}");
        assert_eq!(fixture.token_calls(), 0);
        assert_eq!(fixture.vault_records(), 0);
    }

    /// A start state that confirms its caller sends the browser to the
    /// caller's identity provider, never the vendor: the login client, the
    /// confirmation redirect URI, `openid`, `response_mode=query`, PKCE S256
    /// and a nonce, with no vendor parameter and no `prompt`. Its state is a
    /// confirmation state that keeps the start state's consent, the verifier,
    /// the nonce and when the sign-in began, and the browser gets the binding
    /// cookie the vendor leg sets.
    #[tokio::test]
    async fn a_confirm_start_goes_to_the_identity_provider_with_a_sealed_confirmation_state() {
        use crate::delegation_vault::ConsentStage;
        use crate::delegation_vault::oauth::{
            binding_cookie_name, browser_binding_matches, decode_callback_state, decode_confirmation_state,
            decode_start_state, generate_pkce_challenge, is_claimed,
        };
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let encoded_start = consent::start_state(&fixture.confirm_start_url(&strategy));
        let start = decode_start_state(&encoded_start).unwrap();
        let before = Utc::now();
        let started = fixture
            .start_post(&encoded_start, &[("origin", "https://198.51.100.7")])
            .await;
        let after = Utc::now();
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
        assert_eq!(started.header("cache-control"), Some("no-store"));
        assert_eq!(started.header("referrer-policy"), Some("no-referrer"));
        let idp = url::Url::parse(
            started
                .header("location")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(&idp[..url::Position::AfterPath], consent::IDP_AUTHORIZE);
        let encoded = consent::query_value(&idp, "state");
        let sealed = decode_confirmation_state(&encoded).unwrap();
        let Some(ConsentStage::Confirmation(sign_in)) = &sealed.stage else {
            panic!("not a confirmation state: {sealed:?}");
        };
        let verifier = sealed
            .code_verifier
            .clone()
            .unwrap();
        let pairs: Vec<(String, String)> = idp
            .query_pairs()
            .into_owned()
            .collect();
        let expected: Vec<(String, String)> = [
            ("response_type", "code"),
            ("client_id", "login-client"),
            ("redirect_uri", "https://198.51.100.7/v1/identity/oauth/callback/github/confirm"),
            ("scope", "openid"),
            ("state", encoded.as_str()),
            ("nonce", sign_in.nonce.as_str()),
            ("code_challenge", generate_pkce_challenge(&verifier).as_str()),
            ("code_challenge_method", "S256"),
            ("response_mode", "query"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
        assert_eq!(pairs, expected);

        assert_eq!(sign_in.binding, consent::confirm_binding(&strategy));
        assert_eq!(start.stage, Some(ConsentStage::ConfirmStart(sign_in.binding.clone())));
        assert!(sign_in.nonce.len() >= 32, "{}", sign_in.nonce.len());
        assert_ne!(sign_in.nonce, sealed.nonce, "the ID token nonce is not the state's claim nonce");
        assert_ne!(sign_in.nonce, start.nonce);
        assert_ne!(sealed.nonce, start.nonce, "the confirmation state is claimed apart from the start state");
        assert!(before <= sign_in.issued_at && sign_in.issued_at <= after, "{:?}", sign_in.issued_at);
        assert!(sealed.expires_at <= start.expires_at);
        assert_eq!(
            (
                &sealed.agent_did,
                &sealed.user_identity_hash,
                &sealed.surface_id,
                &sealed.credential_provider_id,
                &sealed.provider_id,
                &sealed.scopes
            ),
            (
                &start.agent_did,
                &start.user_identity_hash,
                &start.surface_id,
                &start.credential_provider_id,
                &start.provider_id,
                &start.scopes
            ),
            "the vendor's consent is kept for after the sign-in"
        );
        assert!(decode_start_state(&encoded).is_err());
        assert!(decode_callback_state(&encoded).is_err());

        let (cookie, max_age, attributes) = consent::set_cookie(&started);
        let (name, value) = cookie
            .split_once('=')
            .unwrap();
        assert_eq!(Some(name.to_string()), binding_cookie_name(&sealed));
        assert!(browser_binding_matches(&sealed, Some(value)));
        assert!((590..=600).contains(&max_age), "{max_age}");
        assert_eq!(attributes, " Path=/; Secure; HttpOnly; SameSite=Lax");
        assert!(is_claimed(&start).await, "the start state is used up");
        assert!(!is_claimed(&sealed).await, "the confirmation state is not");
    }

    /// `openid` gives only `sub`: the sign-in asks for `profile` too when the
    /// ID token names the caller by another claim.
    #[tokio::test]
    async fn the_sign_in_asks_for_profile_only_when_the_id_token_names_the_caller_by_another_claim() {
        for (strategy_claim, id_token_claim, scope) in [
            (None, None, "openid"),
            (None, Some("sub"), "openid"),
            (Some("oid"), None, "openid profile"),
            (Some("preferred_username"), None, "openid profile"),
            (None, Some("oid"), "openid profile"),
            (Some("oid"), Some("sub"), "openid"),
        ] {
            let fixture = consent::Fixture::new().await;
            let strategy = fixture
                .confirming(strategy_claim)
                .await;
            let mut provider = fixture
                .providers
                .get(consent::PROVIDER_ID)
                .await
                .unwrap()
                .unwrap();
            provider
                .consent_confirmation
                .as_mut()
                .unwrap()
                .id_token_principal_claim = id_token_claim.map(String::from);
            fixture
                .providers
                .update(provider)
                .await
                .unwrap();
            let started = fixture
                .start_post(
                    &consent::start_state(&fixture.confirm_start_url(&strategy)),
                    &[("origin", "https://198.51.100.7")],
                )
                .await;
            assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
            let idp = url::Url::parse(
                started
                    .header("location")
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(consent::query_value(&idp, "scope"), scope, "{strategy_claim:?}, {id_token_claim:?}");
        }
    }

    /// A start state that confirms its caller is refused, audited and left
    /// unused, never sent to the vendor, while its provider no longer confirms
    /// through the sealed strategy, no longer uses legacy consent or has an
    /// authorization endpoint the save rules refuse; once the provider is
    /// restored the same state goes to the identity provider.
    #[tokio::test]
    async fn a_confirm_start_the_provider_no_longer_confirms_is_refused_and_left_unused() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let state = consent::start_state(&fixture.confirm_start_url(&strategy));
        let start = crate::delegation_vault::oauth::decode_start_state(&state).unwrap();
        let confirming = fixture
            .providers
            .get(consent::PROVIDER_ID)
            .await
            .unwrap()
            .unwrap();
        let other = fixture.confirming(None).await;
        let changed = |change: &dyn Fn(&mut CredentialProvider)| {
            let mut provider = confirming.clone();
            change(&mut provider);
            provider
        };
        let endpoint = |endpoint: &'static str| {
            changed(&move |provider| {
                provider
                    .consent_confirmation
                    .as_mut()
                    .unwrap()
                    .authorization_endpoint = endpoint.to_string()
            })
        };
        let cases = [
            (
                "setting removed",
                changed(&|provider| provider.consent_confirmation = None),
                DelegationFailureReason::ConsentStateInvalid,
            ),
            (
                "strategy changed",
                changed(&|provider| {
                    provider
                        .consent_confirmation
                        .as_mut()
                        .unwrap()
                        .jwt_verification_strategy_id = other.id.clone()
                }),
                DelegationFailureReason::ConsentStateInvalid,
            ),
            (
                "no longer legacy",
                changed(&|provider| provider.issuer = Some("https://vendor.example".to_string())),
                DelegationFailureReason::ConsentProviderMismatch,
            ),
            (
                "http endpoint",
                endpoint("http://203.0.113.20/authorize"),
                DelegationFailureReason::AuthorizationUrlInvalid,
            ),
            (
                "endpoint query",
                endpoint("https://203.0.113.20/authorize?a=1"),
                DelegationFailureReason::AuthorizationUrlInvalid,
            ),
            (
                "endpoint fragment",
                endpoint("https://203.0.113.20/authorize#f"),
                DelegationFailureReason::AuthorizationUrlInvalid,
            ),
            (
                "loopback endpoint",
                endpoint("https://127.0.0.1/authorize"),
                DelegationFailureReason::AuthorizationUrlInvalid,
            ),
            (
                "metadata endpoint",
                endpoint("https://169.254.169.254/authorize"),
                DelegationFailureReason::AuthorizationUrlInvalid,
            ),
        ];
        for (name, provider, reason) in cases {
            fixture
                .providers
                .update(provider)
                .await
                .unwrap();
            let (refused, events) = capture(async {
                fixture
                    .start_post(&state, &[("origin", "https://198.51.100.7")])
                    .await
            })
            .await;
            consent::assert_refused(&refused, StatusCode::BAD_REQUEST, None);
            assert_eq!(consent::reasons(&events), [reason], "{name}");
            assert_eq!(audited_providers(&events), [Some("github".to_string())], "{name}");
            assert!(!crate::delegation_vault::oauth::is_claimed(&start).await, "{name} claimed the start state");
        }

        let deleted = fixture.confirming(None).await;
        let deleted_state = consent::start_state(&fixture.confirm_start_url(&deleted));
        fixture
            .strategies
            .delete(&deleted.id)
            .await
            .unwrap();
        let (refused, events) = capture(async {
            fixture
                .start_post(&deleted_state, &[("origin", "https://198.51.100.7")])
                .await
        })
        .await;
        consent::assert_refused(&refused, StatusCode::BAD_REQUEST, None);
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateInvalid], "strategy deleted");
        let deleted_start = crate::delegation_vault::oauth::decode_start_state(&deleted_state).unwrap();
        assert!(
            !crate::delegation_vault::oauth::is_claimed(&deleted_start).await,
            "strategy deleted claimed its state"
        );

        fixture
            .providers
            .update(confirming)
            .await
            .unwrap();
        let started = fixture
            .start_post(&state, &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
        assert!(
            started
                .header("location")
                .unwrap()
                .starts_with(consent::IDP_AUTHORIZE)
        );
    }

    /// A start state without a stage goes to the vendor exactly as before
    /// consent confirmation, whether or not its provider has the setting.
    #[tokio::test]
    async fn a_start_state_without_a_stage_goes_to_the_vendor_unchanged() {
        for confirming in [false, true] {
            let fixture = consent::Fixture::new().await;
            if confirming {
                fixture.confirming(None).await;
            }
            let started = fixture
                .start_post(&consent::start_state(&fixture.start_url()), &[("origin", "https://198.51.100.7")])
                .await;
            assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
            let vendor = url::Url::parse(
                started
                    .header("location")
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(&vendor[..url::Position::AfterPath], "https://vendor.example/authorize");
            let masked: Vec<(String, String)> = vendor
                .query_pairs()
                .into_owned()
                .map(|(name, value)| match name.as_str() {
                    "state" | "code_challenge" => (name, "*".to_string()),
                    _ => (name, value),
                })
                .collect();
            let mut expected: Vec<(String, String)> = [
                ("response_type", "code"),
                ("client_id", "github-client"),
                ("redirect_uri", consent::REDIRECT_URI),
                ("scope", "repo read:user"),
                ("state", "*"),
                ("code_challenge", "*"),
                ("code_challenge_method", "S256"),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
            if confirming {
                expected.push(("prompt".to_string(), "consent".to_string()));
            }
            assert_eq!(masked, expected, "confirming {confirming}");
            let callback =
                crate::delegation_vault::oauth::decode_callback_state(&consent::query_value(&vendor, "state")).unwrap();
            assert_eq!(callback.stage, None, "confirming {confirming}");
            let (cookie, max_age, attributes) = consent::set_cookie(&started);
            assert_eq!(
                Some(consent::cookie_name(&cookie)),
                crate::delegation_vault::oauth::binding_cookie_name(&callback)
            );
            assert!((590..=600).contains(&max_age), "{max_age}");
            assert_eq!(attributes, " Path=/; Secure; HttpOnly; SameSite=Lax");
        }
    }

    /// A start link that confirms its caller is used once: a second POST of
    /// it, after the first or racing it, is refused as reused, with no
    /// redirect and no cookie.
    #[tokio::test]
    async fn a_confirm_start_link_is_used_once() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let state = consent::start_state(&fixture.confirm_start_url(&strategy));
        let first = fixture
            .start_post(&state, &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(first.status, StatusCode::FOUND, "{}", first.body);
        let (replayed, events) = capture(async {
            fixture
                .start_post(&state, &[("origin", "https://198.51.100.7")])
                .await
        })
        .await;
        consent::assert_refused(&replayed, StatusCode::BAD_REQUEST, None);
        assert_eq!(replayed.header("location"), None);
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateReused]);

        let raced = consent::start_state(&fixture.confirm_start_url(&strategy));
        let (one, other) = tokio::join!(
            fixture.start_post(&raced, &[("origin", "https://198.51.100.7")]),
            fixture.start_post(&raced, &[("origin", "https://198.51.100.7")])
        );
        let (won, lost) = if one.status == StatusCode::FOUND {
            (one, other)
        } else {
            (other, one)
        };
        assert_eq!(won.status, StatusCode::FOUND, "{}", won.body);
        assert!(
            won.header("location")
                .unwrap()
                .starts_with(consent::IDP_AUTHORIZE)
        );
        consent::assert_refused(&lost, StatusCode::BAD_REQUEST, None);
        assert_eq!(lost.header("location"), None);
    }

    /// Every confirm start POST draws its own ID token nonce, PKCE verifier
    /// and binding cookie.
    #[tokio::test]
    async fn each_confirm_start_draws_its_own_nonce_verifier_and_cookie() {
        use crate::delegation_vault::ConsentStage;
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let mut drawn = Vec::new();
        for _ in 0..2 {
            let started = fixture
                .start_post(
                    &consent::start_state(&fixture.confirm_start_url(&strategy)),
                    &[("origin", "https://198.51.100.7")],
                )
                .await;
            assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
            let idp = url::Url::parse(
                started
                    .header("location")
                    .unwrap(),
            )
            .unwrap();
            let sealed =
                crate::delegation_vault::oauth::decode_confirmation_state(&consent::query_value(&idp, "state"))
                    .unwrap();
            let Some(ConsentStage::Confirmation(sign_in)) = sealed.stage else {
                panic!("not a confirmation state");
            };
            drawn.push((sign_in.nonce, sealed.code_verifier.unwrap(), consent::set_cookie(&started).0));
        }
        assert_ne!(drawn[0].0, drawn[1].0, "the ID token nonce is drawn again");
        assert_ne!(drawn[0].1, drawn[1].1, "the PKCE verifier is drawn again");
        assert_ne!(drawn[0].2, drawn[1].2, "the binding cookie is drawn again");
    }

    /// A start state that confirms its caller is refused and left unused
    /// when its strategy became another tenant's, or was edited after mint so
    /// that its verification digest is no longer the sealed one.
    #[tokio::test]
    async fn a_confirm_start_through_a_strategy_it_cannot_use_is_refused_and_left_unused() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let state = consent::start_state(&fixture.confirm_start_url(&strategy));
        let start = crate::delegation_vault::oauth::decode_start_state(&state).unwrap();
        for (name, edited) in [
            (
                "another tenant's",
                JwtVerificationStrategy {
                    tenant_id: Some("tenant-b".to_string()),
                    ..strategy.clone()
                },
            ),
            (
                "edited after mint",
                JwtVerificationStrategy {
                    expected_issuer: "https://other-idp.example".to_string(),
                    ..strategy.clone()
                },
            ),
        ] {
            fixture
                .strategies
                .update(edited)
                .await
                .unwrap();
            let (refused, events) = capture(async {
                fixture
                    .start_post(&state, &[("origin", "https://198.51.100.7")])
                    .await
            })
            .await;
            consent::assert_refused(&refused, StatusCode::BAD_REQUEST, None);
            assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateInvalid], "{name}");
            assert!(!crate::delegation_vault::oauth::is_claimed(&start).await, "{name} claimed the start state");
        }
        fixture
            .strategies
            .update(strategy)
            .await
            .unwrap();
        let started = fixture
            .start_post(&state, &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    }

    /// The start POST checks the identity provider's authorization endpoint
    /// without resolving its host, so a host no DNS answers for still sends
    /// the browser there.
    #[tokio::test]
    async fn the_start_post_does_not_resolve_the_authorization_endpoint() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture.confirming(None).await;
        let mut provider = fixture
            .providers
            .get(consent::PROVIDER_ID)
            .await
            .unwrap()
            .unwrap();
        provider
            .consent_confirmation
            .as_mut()
            .unwrap()
            .authorization_endpoint = "https://login.idp.invalid/authorize".to_string();
        fixture
            .providers
            .update(provider)
            .await
            .unwrap();
        let started = fixture
            .start_post(
                &consent::start_state(&fixture.confirm_start_url(&strategy)),
                &[("origin", "https://198.51.100.7")],
            )
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
        assert!(
            started
                .header("location")
                .unwrap()
                .starts_with("https://login.idp.invalid/authorize?")
        );
    }

    /// A start state that confirms its caller is refused as unavailable,
    /// audited and left unused while the strategy store fails.
    #[tokio::test]
    async fn a_confirm_start_is_refused_and_left_unused_while_the_strategy_store_fails() {
        struct FailingStrategyStore;

        #[async_trait::async_trait]
        impl crate::jwt_bearer::JwtVerificationStrategyStorage for FailingStrategyStore {
            async fn create(
                &self,
                _strategy: JwtVerificationStrategy,
            ) -> anyhow::Result<JwtVerificationStrategy> {
                anyhow::bail!("strategy store unavailable")
            }
            async fn get(
                &self,
                _id: &str,
            ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
                anyhow::bail!("strategy store unavailable")
            }
            async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
                anyhow::bail!("strategy store unavailable")
            }
            async fn update(
                &self,
                _strategy: JwtVerificationStrategy,
            ) -> anyhow::Result<JwtVerificationStrategy> {
                anyhow::bail!("strategy store unavailable")
            }
            async fn delete(
                &self,
                _id: &str,
            ) -> anyhow::Result<()> {
                anyhow::bail!("strategy store unavailable")
            }
        }

        let fixture = consent::Fixture::with_identity_strategies(Some(Arc::new(FailingStrategyStore))).await;
        let strategy = fixture.confirming(None).await;
        let state = consent::start_state(&fixture.confirm_start_url(&strategy));
        let (refused, events) = capture(async {
            fixture
                .start_post(&state, &[("origin", "https://198.51.100.7")])
                .await
        })
        .await;
        consent::assert_refused(&refused, StatusCode::BAD_REQUEST, None);
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::CredentialsUnavailable]);
        assert_eq!(audited_providers(&events), [Some("github".to_string())]);
        let start = crate::delegation_vault::oauth::decode_start_state(&state).unwrap();
        assert!(!crate::delegation_vault::oauth::is_claimed(&start).await);
    }

    /// The callback's path must name the state's provider, and the provider the
    /// state names must still have its id and slug and no `issuer`.
    #[tokio::test]
    async fn a_callback_for_another_or_a_changed_provider_is_refused() {
        let fixture = consent::Fixture::new().await;
        let (callback_state, cookie) = fixture.begin().await;
        let query = format!("code=vendor-code&state={callback_state}");
        let ((swapped, unplain), events) = capture(async {
            (
                fixture
                    .callback("gitlab", &query, Some(&cookie))
                    .await,
                fixture
                    .callback("git%3Bhub%0A", &query, Some(&cookie))
                    .await,
            )
        })
        .await;
        let name = consent::cookie_name(&cookie);
        consent::assert_refused(&swapped, StatusCode::BAD_REQUEST, Some(&name));
        consent::assert_refused(&unplain, StatusCode::BAD_REQUEST, Some(&name));
        assert_eq!(
            audited_providers(&events),
            [Some("gitlab".to_string()), None],
            "only a plain slug from the path is recorded"
        );

        let mut external = fixture.provider();
        external.issuer = Some("https://vendor.example".to_string());
        let mut renamed = fixture.provider();
        renamed.provider_id = "github-renamed".to_string();
        let mut retyped = fixture.provider();
        retyped.provider_type = crate::credential_providers::CredentialProviderType::OAuth2ClientCredentials;
        for changed in [external, renamed, retyped] {
            fixture
                .providers
                .update(changed)
                .await
                .unwrap();
            let (refused, events) = capture(async {
                fixture
                    .callback("github", &query, Some(&cookie))
                    .await
            })
            .await;
            consent::assert_refused(&refused, StatusCode::BAD_REQUEST, Some(&name));
            assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentProviderMismatch]);
            assert_eq!(fixture.token_calls(), 0);
            assert_eq!(fixture.vault_records(), 0);
        }

        fixture
            .providers
            .update(fixture.provider())
            .await
            .unwrap();
        let accepted = fixture
            .callback("github", &query, Some(&cookie))
            .await;
        assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    }

    /// The provider each `delegation_failed` record in `events` names.
    fn audited_providers(events: &[crate::delegation_vault::audit::DelegationAuditEvent]) -> Vec<Option<String>> {
        events
            .iter()
            .map(|event| match &event.event {
                DelegationAuditAction::DelegationFailed { provider_id, .. } => provider_id.clone(),
                _ => panic!("{event:?}"),
            })
            .collect()
    }

    /// A provider whose callback path ends in its id, as a new provider's does,
    /// takes its start POST and callback at that path, and not at its slug.
    #[tokio::test]
    async fn a_provider_with_an_id_callback_path_consents_only_at_that_path() {
        let fixture = consent::Fixture::new().await;
        let id_path = format!("/v1/identity/oauth/callback/{}", consent::PROVIDER_ID);
        let mut provider = fixture.provider();
        provider.callback_path = id_path.clone();
        provider.callback_url = Some(format!("https://198.51.100.7{id_path}"));
        fixture
            .providers
            .update(provider.clone())
            .await
            .unwrap();
        let start_url = crate::delegation_vault::oauth::build_authorization_url(
            &provider,
            "did:web:agent.example",
            "sha256:user",
            "surface",
            &["repo".to_string()],
            "https://198.51.100.7",
            None,
        )
        .unwrap();
        assert_eq!(
            url::Url::parse(&start_url)
                .unwrap()
                .path(),
            format!("{id_path}/start")
        );
        let start_state = consent::start_state(&start_url);
        let origin = [("origin", "https://198.51.100.7")];

        let (at_slug, events) = capture(async {
            fixture
                .start_post_at("github", &start_state, &origin)
                .await
        })
        .await;
        consent::assert_refused(&at_slug, StatusCode::BAD_REQUEST, None);
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentProviderMismatch]);
        let (cross_site, events) = capture(async {
            fixture
                .start_post_at(consent::PROVIDER_ID, &start_state, &[("origin", "https://other.example")])
                .await
        })
        .await;
        consent::assert_refused(&cross_site, StatusCode::FORBIDDEN, None);
        assert_eq!(audited_providers(&events), [Some("github".to_string())], "a start refusal names the slug");
        let started = fixture
            .start_post_at(consent::PROVIDER_ID, &start_state, &origin)
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
        let callback_state = consent::start_state(
            started
                .header("location")
                .unwrap(),
        );
        let cookie = started
            .header("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let query = format!("code=vendor-code&state={callback_state}");

        let (at_slug, events) = capture(async {
            fixture
                .callback("github", &query, Some(&cookie))
                .await
        })
        .await;
        consent::assert_refused(&at_slug, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentProviderMismatch]);
        assert_eq!(fixture.token_calls(), 0);

        let (in_another_browser, events) = capture(async {
            fixture
                .callback(consent::PROVIDER_ID, &query, None)
                .await
        })
        .await;
        consent::assert_refused(&in_another_browser, StatusCode::FORBIDDEN, Some(&consent::cookie_name(&cookie)));
        assert_eq!(
            audited_providers(&events),
            [Some("github".to_string())],
            "a refusal at the id path names the provider by its slug, as its grant does"
        );

        let accepted = fixture
            .callback(consent::PROVIDER_ID, &query, Some(&cookie))
            .await;
        assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
        assert_eq!(fixture.vault_records(), 1);
    }

    /// The start page claims nothing and sets no cookie, so it may be fetched
    /// any number of times; the start POST then succeeds once, and a second
    /// POST of the same start state is refused.
    #[tokio::test]
    async fn the_start_page_has_no_side_effects_and_a_start_state_is_posted_once() {
        let fixture = consent::Fixture::new().await;
        let start_url = fixture.start_url();
        for _ in 0..3 {
            let page = fixture
                .get(&consent::local(&start_url), &[])
                .await;
            assert_eq!(page.status, StatusCode::OK, "{}", page.body);
            assert_eq!(page.header("set-cookie"), None);
            assert_eq!(page.header("cache-control"), Some("no-store"));
            assert_eq!(page.header("referrer-policy"), Some("same-origin"));
            assert_eq!(page.header("x-frame-options"), Some("DENY"));
            assert!(
                page.header("content-security-policy")
                    .unwrap()
                    .contains("frame-ancestors 'none'")
            );
            for shown in ["did:web:agent.example", "Agent Surface", "GitHub", "repo, read:user", "method=\"post\""] {
                assert!(page.body.contains(shown), "{shown}: {}", page.body);
            }
        }
        let state = consent::start_state(&start_url);
        let first = fixture
            .start_post(
                &state,
                &[("sec-fetch-site", "same-origin"), ("sec-fetch-user", "?1"), ("sec-fetch-dest", "document")],
            )
            .await;
        assert_eq!(first.status, StatusCode::FOUND, "{}", first.body);
        let (second, events) = capture(async {
            fixture
                .start_post(
                    &state,
                    &[("sec-fetch-site", "same-origin"), ("sec-fetch-user", "?1"), ("sec-fetch-dest", "document")],
                )
                .await
        })
        .await;
        consent::assert_refused(&second, StatusCode::BAD_REQUEST, None);
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateReused]);
        let after = fixture
            .get(&consent::local(&start_url), &[])
            .await;
        assert_eq!(after.status, StatusCode::OK, "the page still shows the link it describes");
    }

    /// A start POST another site's page sends, or one no person clicked, is
    /// refused, so neither a cross-site form nor script on the gateway's origin
    /// can skip the start page and bind a browser to someone else's link;
    /// nothing is claimed.
    #[tokio::test]
    async fn a_start_post_from_another_site_is_refused_and_claims_nothing() {
        let fixture = consent::Fixture::new().await;
        let state = consent::start_state(&fixture.start_url());
        let (results, events) = capture(async {
            let mut results = Vec::new();
            for headers in [
                vec![],
                vec![("origin", "https://attacker.example")],
                vec![("origin", "null")],
                vec![("sec-fetch-site", "cross-site"), ("origin", "https://attacker.example")],
                vec![("sec-fetch-site", "same-site")],
                vec![("sec-fetch-site", "same-origin"), ("origin", "https://attacker.example")],
                vec![("sec-fetch-site", "same-origin"), ("sec-fetch-dest", "document")],
                vec![("sec-fetch-site", "same-origin"), ("sec-fetch-user", "?1"), ("sec-fetch-dest", "empty")],
            ] {
                results.push(
                    fixture
                        .start_post(&state, &headers)
                        .await,
                );
            }
            results
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::FORBIDDEN, None);
        }
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::CrossSiteConsentStart; 8]);
        let started = fixture
            .start_post(&state, &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "the refused POSTs left the start state unused");
    }

    /// A token endpoint that refuses the exchange is the one refusal after the
    /// state is claimed: the state is used up, nothing is stored and the
    /// binding cookie is cleared.
    #[tokio::test]
    async fn a_refused_token_exchange_uses_up_the_state_and_stores_nothing() {
        let fixture = consent::Fixture::new().await;
        let mut provider = fixture.provider();
        provider.token_endpoint = provider
            .token_endpoint
            .map(|endpoint| endpoint.replace("/token", "/token-refused"));
        fixture
            .providers
            .update(provider)
            .await
            .unwrap();
        let (callback_state, cookie) = fixture.begin().await;
        let query = format!("code=c&state={callback_state}");
        let (results, events) = capture(async {
            vec![
                fixture
                    .callback("github", &query, Some(&cookie))
                    .await,
                fixture
                    .callback("github", &query, Some(&cookie))
                    .await,
            ]
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&cookie)));
        }
        assert_eq!(
            consent::reasons(&events),
            [DelegationFailureReason::TokenExchangeFailed, DelegationFailureReason::ConsentStateReused]
        );
        assert_eq!(fixture.vault_records(), 0);
        let decoded = crate::delegation_vault::oauth::decode_callback_state(&callback_state).unwrap();
        assert!(crate::delegation_vault::oauth::is_claimed(&decoded).await, "the refused exchange used up the state");
    }

    /// With the operator's `authorization_response_issuer` set, the callback
    /// needs that exact `iss`: missing or different is refused before the
    /// exchange.
    #[tokio::test]
    async fn a_recorded_issuer_makes_iss_required_and_exact() {
        let fixture = consent::Fixture::new().await;
        let mut provider = fixture.provider();
        provider.authorization_response_issuer = Some("https://vendor.example".to_string());
        fixture
            .providers
            .update(provider)
            .await
            .unwrap();
        let (callback_state, cookie) = fixture.begin().await;
        let (results, events) = capture(async {
            vec![
                fixture
                    .callback("github", &format!("code=c&state={callback_state}"), Some(&cookie))
                    .await,
                fixture
                    .callback(
                        "github",
                        &format!("code=c&state={callback_state}&iss=https%3A%2F%2Fvendor.example%2F"),
                        Some(&cookie),
                    )
                    .await,
            ]
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&cookie)));
        }
        assert_eq!(
            consent::reasons(&events),
            [DelegationFailureReason::IssMissing, DelegationFailureReason::IssMismatch]
        );
        assert_eq!(fixture.token_calls(), 0);
        assert_eq!(fixture.vault_records(), 0);

        let accepted = fixture
            .callback(
                "github",
                &format!("code=c&state={callback_state}&iss=https%3A%2F%2Fvendor.example"),
                Some(&cookie),
            )
            .await;
        assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
        assert_eq!(fixture.token_calls(), 1);
        assert_eq!(fixture.vault_records(), 1);
    }

    /// A stored provider whose redirect URI breaks the consent rules, or is
    /// another provider's, is refused at the start page and the start POST,
    /// before any cookie is set.
    #[tokio::test]
    async fn a_provider_with_a_non_conforming_or_shared_redirect_uri_is_refused_at_start() {
        let fixture = consent::Fixture::new().await;
        let start_url = fixture.start_url();
        let state = consent::start_state(&start_url);
        let mut other_tenant = fixture.provider();
        other_tenant.id = "github-tenant-b".to_string();
        other_tenant.tenant_id = Some("tenant-b".to_string());
        fixture
            .providers
            .create(other_tenant)
            .await
            .unwrap();
        let shared = fixture
            .get(&consent::local(&start_url), &[])
            .await;
        consent::assert_refused(&shared, StatusCode::BAD_REQUEST, None);
        fixture
            .providers
            .delete("github-tenant-b")
            .await
            .unwrap();

        for callback_url in [
            "http://198.51.100.7/v1/identity/oauth/callback/github",
            "https://198.51.100.7/v1/identity/oauth/callback/github?x=1",
            "https://198.51.100.7/elsewhere/github",
        ] {
            let mut provider = fixture.provider();
            provider.callback_url = Some(callback_url.to_string());
            fixture
                .providers
                .update(provider)
                .await
                .unwrap();
            let (results, events) = capture(async {
                vec![
                    fixture
                        .get(&consent::local(&start_url), &[])
                        .await,
                    fixture
                        .start_post(
                            &state,
                            &[
                                ("sec-fetch-site", "same-origin"),
                                ("sec-fetch-user", "?1"),
                                ("sec-fetch-dest", "document"),
                            ],
                        )
                        .await,
                ]
            })
            .await;
            for refused in &results {
                consent::assert_refused(refused, StatusCode::BAD_REQUEST, None);
            }
            assert_eq!(consent::reasons(&events), [DelegationFailureReason::RedirectUriInvalid; 2], "{callback_url}");
        }
    }

    /// Two consents for one provider started in one browser each have a
    /// cookie of their own, so both complete.
    #[tokio::test]
    async fn two_consents_for_one_provider_in_one_browser_both_complete() {
        let fixture = consent::Fixture::new().await;
        let (first, first_cookie) = fixture.begin().await;
        let (second, second_cookie) = fixture.begin().await;
        assert_ne!(consent::cookie_name(&first_cookie), consent::cookie_name(&second_cookie));
        let browser = format!("{first_cookie}; {second_cookie}");
        for state in [first, second] {
            let done = fixture
                .callback("github", &format!("code=c&state={state}"), Some(&browser))
                .await;
            assert_eq!(done.status, StatusCode::OK, "{}", done.body);
        }
        assert_eq!(fixture.vault_records(), 2);
    }

    /// The token request sends exactly the `redirect_uri` the authorization
    /// request sent, as the URL parser writes it.
    #[tokio::test]
    async fn the_token_request_sends_the_redirect_uri_the_authorization_request_sent() {
        let fixture = consent::Fixture::new().await;
        let mut provider = fixture.provider();
        provider.callback_url = Some("https://198.51.100.7:443/v1/identity/oauth/callback/github".to_string());
        fixture
            .providers
            .update(provider.clone())
            .await
            .unwrap();
        let start_url = crate::delegation_vault::oauth::build_authorization_url(
            &provider,
            "did:web:agent.example",
            "sha256:user",
            "surface",
            &[],
            "https://198.51.100.7",
            None,
        )
        .unwrap();
        let started = fixture
            .start_post(&consent::start_state(&start_url), &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
        let vendor = url::Url::parse(
            started
                .header("location")
                .unwrap(),
        )
        .unwrap();
        let authorize_redirect = consent::query_value(&vendor, "redirect_uri");
        assert_eq!(authorize_redirect, consent::REDIRECT_URI);
        let cookie = started
            .header("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let done = fixture
            .callback("github", &format!("code=c&state={}", consent::query_value(&vendor, "state")), Some(&cookie))
            .await;
        assert_eq!(done.status, StatusCode::OK, "{}", done.body);
        let forms = fixture.token_forms();
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0]["redirect_uri"], authorize_redirect);
    }

    /// A start POST whose client ID cannot be read, or whose authorization
    /// endpoint breaks the rules, is refused and leaves its start state
    /// unclaimed, so it completes once the provider is fixed.
    #[tokio::test]
    async fn a_start_post_refused_for_the_providers_settings_leaves_the_start_state_unclaimed() {
        let fixture = consent::Fixture::new().await;
        let state = consent::start_state(&fixture.start_url());
        let mut no_client = fixture.provider();
        no_client.client_id_secret_ref = Some("missing-client-id".to_string());
        let mut insecure = fixture.provider();
        insecure.authorization_endpoint = Some("http://vendor.example/authorize".to_string());
        for (provider, reason) in [
            (no_client, DelegationFailureReason::CredentialsUnavailable),
            (insecure, DelegationFailureReason::AuthorizationUrlInvalid),
        ] {
            fixture
                .providers
                .update(provider)
                .await
                .unwrap();
            let (refused, events) = capture(async {
                fixture
                    .start_post(&state, &[("origin", "https://198.51.100.7")])
                    .await
            })
            .await;
            consent::assert_refused(&refused, StatusCode::BAD_REQUEST, None);
            assert_eq!(consent::reasons(&events), [reason]);
            let start = crate::delegation_vault::oauth::decode_start_state(&state).unwrap();
            assert!(!crate::delegation_vault::oauth::is_claimed(&start).await, "{reason:?} claimed the start state");
        }
        fixture
            .providers
            .update(fixture.provider())
            .await
            .unwrap();
        let started = fixture
            .start_post(&state, &[("origin", "https://198.51.100.7")])
            .await;
        assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    }

    /// An expired start state is refused at the start page and its POST.
    #[tokio::test]
    async fn an_expired_start_state_is_refused_at_start() {
        let fixture = consent::Fixture::new().await;
        let start =
            crate::delegation_vault::oauth::decode_start_state(&consent::start_state(&fixture.start_url())).unwrap();
        let expired = crate::delegation_vault::oauth::encode_oauth_state(&crate::delegation_vault::OAuthState {
            expires_at: Utc::now() - chrono::Duration::seconds(1),
            ..start
        })
        .unwrap();
        let (results, events) = capture(async {
            vec![
                fixture
                    .get(&format!("/v1/identity/oauth/callback/github/start?state={expired}"), &[])
                    .await,
                fixture
                    .start_post(&expired, &[("origin", "https://198.51.100.7")])
                    .await,
            ]
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::BAD_REQUEST, None);
        }
        assert!(events.is_empty(), "an expired state is not audited: {events:?}");
    }

    /// A caller whose ID token names the person the link was minted for goes
    /// on to the vendor with a vendor state on the confirmation's own browser
    /// binding, a fresh nonce and PKCE verifier, and no new cookie; the code
    /// was exchanged at the login client's token endpoint with the sign-in's
    /// redirect URI and verifier, and the vendor callback then stores the
    /// grant.
    #[tokio::test]
    async fn a_confirmed_caller_goes_on_to_the_vendor_on_the_same_browser_binding() {
        use crate::delegation_vault::ConsentStage;
        use crate::delegation_vault::oauth::{
            browser_binding_matches, decode_callback_state, decode_confirmation_state,
        };
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let alice = consent::caller_hash("sub", "alice");
        let sign_in = fixture
            .sign_in(&strategy, &alice)
            .await;
        fixture.idp_answers(serde_json::json!({"id_token": fixture.id_token(&sign_in.nonce, serde_json::json!({}))}));
        let (confirmed, events) = capture(fixture.confirm_code(&sign_in)).await;
        assert_eq!(confirmed.status, StatusCode::FOUND, "{}", confirmed.body);
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(confirmed.header("set-cookie"), None, "the browser keeps its cookie");
        assert_eq!(confirmed.header("cache-control"), Some("no-store"));
        assert_eq!(confirmed.header("referrer-policy"), Some("no-referrer"));

        let confirmation = decode_confirmation_state(&sign_in.state).unwrap();
        let vendor = url::Url::parse(
            confirmed
                .header("location")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(&vendor[..url::Position::AfterPath], "https://vendor.example/authorize");
        assert_eq!(consent::query_value(&vendor, "client_id"), "github-client");
        assert_eq!(consent::query_value(&vendor, "redirect_uri"), consent::REDIRECT_URI);
        assert_eq!(consent::query_value(&vendor, "scope"), "repo read:user");
        assert_eq!(consent::query_value(&vendor, "prompt"), "consent");
        let callback = decode_callback_state(&consent::query_value(&vendor, "state")).unwrap();
        assert_eq!(callback.stage, Some(ConsentStage::Vendor(consent::confirm_binding(&strategy))));
        assert_eq!(callback.browser_binding, confirmation.browser_binding);
        let cookie_value = sign_in
            .cookie
            .split_once('=')
            .unwrap()
            .1;
        assert!(browser_binding_matches(&callback, Some(cookie_value)));
        assert_ne!(callback.nonce, confirmation.nonce);
        assert_ne!(
            callback.code_verifier, confirmation.code_verifier,
            "the identity provider's verifier is not reused"
        );
        assert_eq!(callback.expires_at, confirmation.expires_at, "the cookie's Max-Age still covers the vendor leg");
        assert_eq!(callback.user_identity_hash, alice);

        let forms = fixture.idp_forms();
        assert_eq!(forms.len(), 1);
        let expected: std::collections::HashMap<String, String> = [
            ("grant_type", "authorization_code"),
            ("code", "idp-code"),
            ("redirect_uri", "https://198.51.100.7/v1/identity/oauth/callback/github/confirm"),
            ("client_id", "login-client"),
            ("client_secret", "secret"),
            (
                "code_verifier",
                confirmation
                    .code_verifier
                    .as_deref()
                    .unwrap(),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
        assert_eq!(forms[0], expected);
        assert_eq!(fixture.token_calls(), 0, "the vendor's token endpoint is not called before the vendor answers");

        let stored = fixture
            .callback(
                "github",
                &format!("code=vendor-code&state={}", consent::query_value(&vendor, "state")),
                Some(&sign_in.cookie),
            )
            .await;
        assert_eq!(stored.status, StatusCode::OK, "{}", stored.body);
        assert_eq!(fixture.vault_records(), 1);
    }

    /// A person other than the one the link was minted for, signing in at
    /// the identity provider, is refused with 403 before the vendor: the
    /// cookie is cleared, nothing is stored and the audit names only the
    /// reason.
    #[tokio::test]
    async fn another_person_signing_in_is_refused_with_consent_identity_mismatch() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let sign_in = fixture
            .sign_in(&strategy, &consent::caller_hash("sub", "alice"))
            .await;
        fixture.idp_answers(
            serde_json::json!({"id_token": fixture.id_token(&sign_in.nonce, serde_json::json!({"sub": "mallory"}))}),
        );
        let (refused, events) = capture(fixture.confirm_code(&sign_in)).await;
        consent::assert_refused(&refused, StatusCode::FORBIDDEN, Some(&consent::cookie_name(&sign_in.cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentIdentityMismatch]);
        let audited = format!("{events:?}");
        assert!(!audited.contains("mallory"), "{audited}");
        let logged = logs.text();
        assert!(!logged.contains("mallory"), "{logged}");
        assert_eq!(fixture.vault_records(), 0);
        assert_eq!(fixture.token_calls(), 0);
    }

    /// A sign-in whose token answer has no ID token, or one that fails
    /// verification, confirms nobody: 403 `consent_identity_missing`.
    #[tokio::test]
    async fn a_sign_in_without_a_valid_id_token_is_refused_with_consent_identity_missing() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let alice = consent::caller_hash("sub", "alice");
        type Answer = fn(&consent::Fixture, &str) -> serde_json::Value;
        let answers: [(&str, Answer); 6] = [
            ("no id_token", |_, _| serde_json::json!({"access_token": "a", "token_type": "Bearer"})),
            ("an empty id_token", |_, _| serde_json::json!({"id_token": ""})),
            ("not a JWT", |_, _| serde_json::json!({"id_token": "not-a-jwt"})),
            (
                "another audience",
                |fixture, nonce| serde_json::json!({"id_token": fixture.id_token(nonce, serde_json::json!({"aud": "other-client"}))}),
            ),
            (
                "another issuer",
                |fixture, nonce| serde_json::json!({"id_token": fixture.id_token(nonce, serde_json::json!({"iss": "https://other.example"}))}),
            ),
            ("a forged signature", |fixture, nonce| {
                let token = fixture.id_token(nonce, serde_json::json!({}));
                serde_json::json!({"id_token": format!("{}.AAAA", token.rsplit_once('.').unwrap().0)})
            }),
        ];
        for (case, answer) in answers {
            let sign_in = fixture
                .sign_in(&strategy, &alice)
                .await;
            fixture.idp_answers(answer(&fixture, &sign_in.nonce));
            let (refused, events) = capture(fixture.confirm_code(&sign_in)).await;
            consent::assert_refused(&refused, StatusCode::FORBIDDEN, Some(&consent::cookie_name(&sign_in.cookie)));
            assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentIdentityMissing], "{case}");
        }
        assert_eq!(fixture.vault_records(), 0);
    }

    /// An ID token carrying another sign-in's nonce, or none, confirms nobody.
    #[tokio::test]
    async fn an_id_token_with_another_nonce_is_refused() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let alice = consent::caller_hash("sub", "alice");
        let other = fixture
            .sign_in(&strategy, &alice)
            .await;
        for nonce in [serde_json::json!(other.nonce), serde_json::Value::Null] {
            let sign_in = fixture
                .sign_in(&strategy, &alice)
                .await;
            fixture.idp_answers(
                serde_json::json!({"id_token": fixture.id_token(&sign_in.nonce, serde_json::json!({"nonce": nonce}))}),
            );
            let (refused, events) = capture(fixture.confirm_code(&sign_in)).await;
            consent::assert_refused(&refused, StatusCode::FORBIDDEN, Some(&consent::cookie_name(&sign_in.cookie)));
            assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentIdentityMissing], "{nonce}");
        }
        assert_eq!(fixture.vault_records(), 0);
    }

    /// A confirmation whose provider now confirms through another strategy,
    /// or whose strategy now verifies with other keys, is refused before the
    /// code is exchanged.
    #[tokio::test]
    async fn a_confirmation_whose_strategy_changed_is_refused_before_the_exchange() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let alice = consent::caller_hash("sub", "alice");

        let renamed = fixture
            .sign_in(&strategy, &alice)
            .await;
        let mut provider = fixture
            .providers
            .get(consent::PROVIDER_ID)
            .await
            .unwrap()
            .unwrap();
        provider
            .consent_confirmation
            .as_mut()
            .unwrap()
            .jwt_verification_strategy_id = "another-strategy".to_string();
        fixture
            .providers
            .update(provider.clone())
            .await
            .unwrap();
        let (refused, events) = capture(fixture.confirm_code(&renamed)).await;
        consent::assert_refused(&refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&renamed.cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateInvalid]);

        provider
            .consent_confirmation
            .as_mut()
            .unwrap()
            .jwt_verification_strategy_id = strategy.id.clone();
        fixture
            .providers
            .update(provider)
            .await
            .unwrap();
        let rekeyed = fixture
            .sign_in(&strategy, &alice)
            .await;
        let mut edited = strategy.clone();
        edited.jwks_source = crate::jwt_bearer::models::JwksSource::Remote {
            jwks_uri: "https://idp.example/jwks".to_string(),
        };
        fixture
            .strategies
            .update(edited)
            .await
            .unwrap();
        fixture.idp_answers(serde_json::json!({"id_token": fixture.id_token(&rekeyed.nonce, serde_json::json!({}))}));
        let (refused, events) = capture(fixture.confirm_code(&rekeyed)).await;
        consent::assert_refused(&refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&rekeyed.cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateInvalid]);
        assert!(fixture.idp_forms().is_empty(), "no code is exchanged");
        assert_eq!(fixture.vault_records(), 0);
    }

    /// A provider edited after the sign-in began to name the caller by a
    /// claim the save rules refuse is refused before the exchange.
    #[tokio::test]
    async fn a_confirmation_the_save_rules_now_refuse_is_refused_before_the_exchange() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let sign_in = fixture
            .sign_in(&strategy, &consent::caller_hash("sub", "alice"))
            .await;
        let mut provider = fixture
            .providers
            .get(consent::PROVIDER_ID)
            .await
            .unwrap()
            .unwrap();
        provider
            .consent_confirmation
            .as_mut()
            .unwrap()
            .id_token_principal_claim = Some("email".to_string());
        fixture
            .providers
            .update(provider)
            .await
            .unwrap();
        let (refused, events) = capture(fixture.confirm_code(&sign_in)).await;
        consent::assert_refused(&refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&sign_in.cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateInvalid]);
        assert!(fixture.idp_forms().is_empty());
    }

    /// A confirmation opened without the browser's binding cookie, or with
    /// another browser's, is refused with 403 and leaves the state unused.
    #[tokio::test]
    async fn a_confirmation_without_the_browsers_cookie_is_refused_and_left_unused() {
        use crate::delegation_vault::oauth::{decode_confirmation_state, is_claimed};
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let alice = consent::caller_hash("sub", "alice");
        let sign_in = fixture
            .sign_in(&strategy, &alice)
            .await;
        let other = fixture
            .sign_in(&strategy, &alice)
            .await;
        let name = consent::cookie_name(&sign_in.cookie);
        let wrong = format!(
            "{name}={}",
            other
                .cookie
                .split_once('=')
                .unwrap()
                .1
        );
        let query = format!("code=idp-code&state={}", sign_in.state);
        let (results, events) = capture(async {
            vec![
                fixture
                    .confirm(&query, None)
                    .await,
                fixture
                    .confirm(&query, Some(&other.cookie))
                    .await,
                fixture
                    .confirm(&query, Some(&wrong))
                    .await,
            ]
        })
        .await;
        for refused in &results {
            consent::assert_refused(refused, StatusCode::FORBIDDEN, Some(&name));
        }
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::BrowserBindingMismatch; 3]);
        assert!(!is_claimed(&decode_confirmation_state(&sign_in.state).unwrap()).await);
        assert!(fixture.idp_forms().is_empty());
    }

    /// A confirmation state confirms once: the same redirect again is refused.
    #[tokio::test]
    async fn a_confirmation_state_is_used_once() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let sign_in = fixture
            .sign_in(&strategy, &consent::caller_hash("sub", "alice"))
            .await;
        fixture.idp_answers(serde_json::json!({"id_token": fixture.id_token(&sign_in.nonce, serde_json::json!({}))}));
        assert_eq!(
            fixture
                .confirm_code(&sign_in)
                .await
                .status,
            StatusCode::FOUND
        );
        let (replayed, events) = capture(fixture.confirm_code(&sign_in)).await;
        consent::assert_refused(&replayed, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&sign_in.cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::ConsentStateReused]);
        assert_eq!(fixture.idp_forms().len(), 1);
    }

    /// An identity provider error ends the consent as denied: audited, the
    /// cookie cleared and no code exchanged.
    #[tokio::test]
    async fn an_identity_provider_error_is_a_denied_consent() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let alice = consent::caller_hash("sub", "alice");
        for (error, reason) in [
            ("access_denied", DelegationFailureReason::ConsentDenied),
            ("not%20a%20code", DelegationFailureReason::ConsentResponseInvalid),
        ] {
            let sign_in = fixture
                .sign_in(&strategy, &alice)
                .await;
            let (refused, events) = capture(fixture.confirm(
                &format!(
                    "error={error}&state={}",
                    url::form_urlencoded::byte_serialize(sign_in.state.as_bytes()).collect::<String>()
                ),
                Some(&sign_in.cookie),
            ))
            .await;
            consent::assert_refused(&refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&sign_in.cookie)));
            assert_eq!(consent::reasons(&events), [reason], "{error}");
        }
        assert!(fixture.idp_forms().is_empty());
        assert_eq!(fixture.vault_records(), 0);
    }

    /// An `iss` the identity provider sends must be the strategy's issuer
    /// (RFC 9207); without one the sign-in still confirms.
    #[tokio::test]
    async fn an_iss_other_than_the_strategys_issuer_is_refused() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(None, None)
            .await;
        let alice = consent::caller_hash("sub", "alice");
        let state_of = |sign_in: &consent::SignIn| {
            url::form_urlencoded::byte_serialize(sign_in.state.as_bytes()).collect::<String>()
        };
        let mismatched = fixture
            .sign_in(&strategy, &alice)
            .await;
        let (refused, events) = capture(fixture.confirm(
            &format!("code=idp-code&iss=https%3A%2F%2Fother.example&state={}", state_of(&mismatched)),
            Some(&mismatched.cookie),
        ))
        .await;
        consent::assert_refused(&refused, StatusCode::BAD_REQUEST, Some(&consent::cookie_name(&mismatched.cookie)));
        assert_eq!(consent::reasons(&events), [DelegationFailureReason::IssMismatch]);
        assert!(fixture.idp_forms().is_empty());

        let matching = fixture
            .sign_in(&strategy, &alice)
            .await;
        fixture.idp_answers(serde_json::json!({"id_token": fixture.id_token(&matching.nonce, serde_json::json!({}))}));
        let confirmed = fixture
            .confirm(
                &format!("code=idp-code&iss=https%3A%2F%2Fidp.example&state={}", state_of(&matching)),
                Some(&matching.cookie),
            )
            .await;
        assert_eq!(confirmed.status, StatusCode::FOUND, "{}", confirmed.body);
    }

    /// An identity provider that issues `sub` per application names the
    /// caller by `oid` in both tokens: the sign-in confirms the caller whose
    /// ID token has the same `oid` and another `sub`.
    #[tokio::test]
    async fn a_caller_named_by_oid_is_confirmed_whatever_their_pairwise_sub() {
        let fixture = consent::Fixture::new().await;
        let strategy = fixture
            .confirming_at_idp(Some("oid"), None)
            .await;
        let sign_in = fixture
            .sign_in(&strategy, &consent::caller_hash("oid", "person-1"))
            .await;
        fixture.idp_answers(serde_json::json!({"id_token": fixture.id_token(
            &sign_in.nonce,
            serde_json::json!({"sub": "pairwise-for-the-login-client", "oid": "person-1"}),
        )}));
        let confirmed = fixture
            .confirm_code(&sign_in)
            .await;
        assert_eq!(confirmed.status, StatusCode::FOUND, "{}", confirmed.body);
        assert!(
            confirmed
                .header("location")
                .unwrap()
                .starts_with("https://vendor.example/authorize?")
        );
    }

    mod consent {
        use super::*;
        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::audit::DelegationAuditEvent;
        use std::sync::atomic::{AtomicUsize, Ordering};

        pub const PROVIDER_ID: &str = "cp-github";
        pub const REDIRECT_URI: &str = "https://198.51.100.7/v1/identity/oauth/callback/github";
        pub const CALLBACK_PATH: &str = "/v1/identity/oauth/callback/github";
        pub const IDP_AUTHORIZE: &str = "https://203.0.113.20/authorize";

        pub fn confirm_binding(strategy: &JwtVerificationStrategy) -> crate::delegation_vault::ConsentConfirmBinding {
            crate::delegation_vault::ConsentConfirmBinding {
                strategy_id: strategy.id.clone(),
                strategy_digest: strategy
                    .verification_digest()
                    .unwrap(),
                tenant_id: None,
            }
        }

        /// The cookie pair a start POST set, its `Max-Age` and its other
        /// attributes.
        pub fn set_cookie(answer: &Answer) -> (String, i64, String) {
            let set_cookie = answer
                .header("set-cookie")
                .unwrap();
            let (pair, attributes) = set_cookie
                .split_once(';')
                .unwrap();
            let max_age: i64 = attributes
                .split(';')
                .find_map(|attribute| {
                    attribute
                        .trim()
                        .strip_prefix("Max-Age=")
                })
                .unwrap()
                .parse()
                .unwrap();
            (pair.to_string(), max_age, attributes.replace(&format!(" Max-Age={max_age};"), ""))
        }

        /// The name of a `name=value` cookie pair.
        pub fn cookie_name(pair: &str) -> String {
            pair.split_once('=')
                .map(|(name, _)| name.trim().to_string())
                .unwrap()
        }

        /// The `Set-Cookie` that clears the binding cookie `name`.
        pub fn cleared(name: &str) -> String {
            format!("{name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
        }

        pub struct Fixture {
            pub providers: Arc<FileSystemCredentialProviderStore>,
            pub strategies: Arc<crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore>,
            pub(super) vault: Arc<InMemoryVault>,
            app: Router,
            calls: Arc<AtomicUsize>,
            forms: Arc<Mutex<Vec<std::collections::HashMap<String, String>>>>,
            egress: crate::delegation_vault::oauth::TokenEgress,
            token_endpoint: String,
            idp_token_endpoint: String,
            idp_answer: Arc<Mutex<serde_json::Value>>,
            idp_forms: Arc<Mutex<Vec<std::collections::HashMap<String, String>>>>,
            _directory: tempfile::TempDir,
        }

        /// The issuer of the identity provider the confirmation tests sign in at.
        pub const IDP_ISSUER: &str = "https://idp.example";
        const IDP_KEY: [u8; 32] = [7; 32];

        /// A sign-in begun at the identity provider: the confirmation state
        /// and the browser's binding cookie pair, and the nonce the ID token
        /// must carry.
        pub struct SignIn {
            pub state: String,
            pub cookie: String,
            pub nonce: String,
        }

        /// The vault key of a caller whose access token from [`IDP_ISSUER`]
        /// names them `value` by `claim`, as the Access Point computes it.
        pub fn caller_hash(
            claim: &str,
            value: &str,
        ) -> String {
            crate::source_auth::AuthenticatedIdentity::JwtBearer {
                subject: value.to_string(),
                principal_claim: claim.to_string(),
                claims: serde_json::json!({"iss": IDP_ISSUER, claim: value}),
                strategy_id: None,
            }
            .principal_hash(None)
            .unwrap()
        }

        pub struct Answer {
            pub status: StatusCode,
            pub headers: axum::http::HeaderMap,
            pub body: String,
        }

        impl Answer {
            pub fn header(
                &self,
                name: &str,
            ) -> Option<&str> {
                self.headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
            }
        }

        /// A refusal: the status, the fixed page, no-store, no-referrer and,
        /// when `cleared` names a binding cookie, that cookie cleared; no
        /// other cookie is set.
        pub fn assert_refused(
            answer: &Answer,
            status: StatusCode,
            cleared: Option<&str>,
        ) {
            assert_eq!(answer.status, status, "{}", answer.body);
            assert_eq!(answer.body, crate::delegation_vault::handlers::CONSENT_REFUSED_PAGE);
            assert_eq!(answer.header("cache-control"), Some("no-store"));
            assert_eq!(answer.header("referrer-policy"), Some("no-referrer"));
            assert_eq!(answer.header("location"), None);
            assert_eq!(
                answer.header("set-cookie"),
                cleared
                    .map(cleared_cookie)
                    .as_deref()
            );
        }

        fn cleared_cookie(name: &str) -> String {
            cleared(name)
        }

        pub fn reasons(events: &[DelegationAuditEvent]) -> Vec<DelegationFailureReason> {
            events
                .iter()
                .filter_map(|event| match &event.event {
                    DelegationAuditAction::DelegationFailed { reason, .. } => Some(*reason),
                    _ => None,
                })
                .collect()
        }

        /// The path and query of a start URL, as the router sees it.
        pub fn local(url: &str) -> String {
            let url = url::Url::parse(url).unwrap();
            format!(
                "{}?{}",
                url.path(),
                url.query()
                    .unwrap_or_default()
            )
        }

        pub fn query_value(
            url: &url::Url,
            name: &str,
        ) -> String {
            url.query_pairs()
                .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
                .unwrap()
        }

        pub fn start_state(url: &str) -> String {
            url::Url::parse(url)
                .unwrap()
                .query_pairs()
                .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
                .unwrap()
        }

        impl Fixture {
            pub async fn new() -> Self {
                Self::with_identity_strategies(None).await
            }

            /// A fixture whose start POSTs look strategies up in
            /// `identity_strategies`, or in [`Fixture::strategies`] when `None`.
            pub async fn with_identity_strategies(
                identity_strategies: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>
            ) -> Self {
                let calls = Arc::new(AtomicUsize::new(0));
                let counter = calls.clone();
                let forms = Arc::new(Mutex::new(Vec::new()));
                let recorded = forms.clone();
                let idp_answer = Arc::new(Mutex::new(serde_json::json!({})));
                let idp_forms = Arc::new(Mutex::new(Vec::new()));
                let (answer, idp_recorded) = (idp_answer.clone(), idp_forms.clone());
                let vendor = Router::new()
                    .route(
                        "/idp-token",
                        post(move |axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| {
                            let answer = answer.clone();
                            let recorded = idp_recorded.clone();
                            async move {
                                recorded
                                    .lock()
                                    .unwrap()
                                    .push(form);
                                let body = answer.lock().unwrap().clone();
                                axum::Json(body)
                            }
                        }),
                    )
                    .route(
                        "/token",
                        post(move |axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| {
                            let counter = counter.clone();
                            let recorded = recorded.clone();
                            async move {
                                counter.fetch_add(1, Ordering::SeqCst);
                                recorded
                                    .lock()
                                    .unwrap()
                                    .push(form);
                                axum::Json(serde_json::json!({
                                    "access_token": "vendor-access", "token_type": "Bearer", "expires_in": 3600,
                                    "scope": "repo read:user"
                                }))
                            }
                        }),
                    )
                    .route(
                        "/token-refused",
                        post(|| async {
                            (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "invalid_grant"})))
                        }),
                    );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
                let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
                let idp_token_endpoint = format!("http://{}/idp-token", listener.local_addr().unwrap());
                tokio::spawn(async move {
                    axum::serve(listener, vendor)
                        .await
                        .unwrap();
                });
                let directory = tempfile::tempdir().unwrap();
                let secrets = Arc::new(
                    crate::secrets::FilesystemSecretsStore::new_async(
                        directory
                            .path()
                            .join("secrets")
                            .to_str()
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
                );
                for (secret_id, value) in [("github-client-id", "github-client"), ("github-client-secret", "secret")] {
                    secrets
                        .create(CreateSecretRequest {
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
                let providers = Arc::new(
                    FileSystemCredentialProviderStore::new(
                        directory
                            .path()
                            .join("providers"),
                    )
                    .await
                    .unwrap(),
                );
                let surfaces = Arc::new(
                    crate::surfaces::FileSystemAgentSurfaceStore::new(
                        directory
                            .path()
                            .join("surfaces"),
                    )
                    .await
                    .unwrap(),
                );
                let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
                    "surface_id": "surface", "name": "Agent Surface",
                    "access_point": {"listen_address": "https://gw.example", "route": "/mcp", "protocol": "mcp"},
                    "target": {"endpoint": "https://203.0.113.9/mcp"}
                }))
                .unwrap();
                crate::surfaces::AgentSurfaceStore::save(surfaces.as_ref(), &surface)
                    .await
                    .unwrap();
                let strategies = Arc::new(
                    crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(
                        directory
                            .path()
                            .join("strategies"),
                    )
                    .await
                    .unwrap(),
                );
                let vault = Arc::new(InMemoryVault {
                    tokens: Mutex::new(Vec::new()),
                    unreadable: false,
                });
                let mut fixture = Self {
                    providers,
                    strategies,
                    vault: vault.clone(),
                    app: Router::new(),
                    calls,
                    forms,
                    egress: crate::delegation_vault::oauth::TokenEgress {
                        timeout: std::time::Duration::from_secs(5),
                        exact_allowlist: Some(format!("{token_endpoint},{idp_token_endpoint}")),
                        policy: Default::default(),
                    },
                    token_endpoint,
                    idp_token_endpoint,
                    idp_answer,
                    idp_forms,
                    _directory: directory,
                };
                fixture
                    .providers
                    .create(fixture.provider())
                    .await
                    .unwrap();
                let mut state = state_with(Vec::new());
                state.vault_store = vault;
                state.provider_store = fixture.providers.clone();
                state.identity_strategies = identity_strategies.unwrap_or_else(|| fixture.strategies.clone());
                state.secrets_store = secrets;
                state.agent_surface_store = Some(surfaces);
                state.gateway_base_url = "https://198.51.100.7".to_string();
                state.provider_egress = fixture.egress.clone();
                fixture.app = create_delegation_vault_oauth_router(state)
                    .layer(axum::middleware::from_fn(crate::delegation_vault::consent_cookie::guard));
                fixture
            }

            /// The provider as first stored: an authorization code provider
            /// without an issuer whose redirect URI follows the consent rules.
            pub fn provider(&self) -> CredentialProvider {
                let mut provider: CredentialProvider = serde_json::from_value(serde_json::json!({
                    "id": PROVIDER_ID, "name": "GitHub", "provider_id": "github",
                    "authorization_endpoint": "https://vendor.example/authorize",
                    "client_id_secret_ref": "github-client-id", "client_secret_secret_ref": "github-client-secret",
                    "default_scopes": ["repo"],
                    "callback_path": CALLBACK_PATH, "callback_url": REDIRECT_URI,
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap();
                provider.token_endpoint = Some(self.token_endpoint.clone());
                provider
            }

            pub fn start_url(&self) -> String {
                crate::delegation_vault::oauth::build_authorization_url(
                    &self.provider(),
                    "did:web:agent.example",
                    "sha256:user",
                    "surface",
                    &["repo".to_string(), "read:user".to_string()],
                    "https://198.51.100.7",
                    None,
                )
                .unwrap()
            }

            /// Stores a strategy naming callers by `principal_claim` and gives
            /// the provider a `consent_confirmation` that confirms through it,
            /// and a vendor parameter the sign-in must not carry.
            pub async fn confirming(
                &self,
                principal_claim: Option<&str>,
            ) -> JwtVerificationStrategy {
                let strategy = self
                    .strategies
                    .create(
                        serde_json::from_value(serde_json::json!({
                            "id": "", "name": "Callers", "expected_issuer": "https://idp.example",
                            "jwks_source": {"type": "remote", "jwks_uri": "https://idp.example/jwks"},
                            "principal_claim": principal_claim,
                            "created_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:00:00Z"
                        }))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let mut provider = self.provider();
                provider.consent_confirmation = Some(
                    serde_json::from_value(serde_json::json!({
                        "client_id": "login-client", "client_secret_secret_ref": "github-client-secret",
                        "authorization_endpoint": IDP_AUTHORIZE, "token_endpoint": "https://203.0.113.20/token",
                        "jwt_verification_strategy_id": strategy.id
                    }))
                    .unwrap(),
                );
                provider
                    .additional_params
                    .insert("prompt".to_string(), "consent".to_string());
                self.providers
                    .update(provider)
                    .await
                    .unwrap();
                strategy
            }

            /// A start URL whose state confirms its caller through `strategy`.
            pub fn confirm_start_url(
                &self,
                strategy: &JwtVerificationStrategy,
            ) -> String {
                crate::delegation_vault::oauth::build_authorization_url(
                    &self.provider(),
                    "did:web:agent.example",
                    "sha256:user",
                    "surface",
                    &["repo".to_string(), "read:user".to_string()],
                    "https://198.51.100.7",
                    Some(crate::delegation_vault::ConsentStage::ConfirmStart(confirm_binding(strategy))),
                )
                .unwrap()
            }

            /// Stores a strategy for [`IDP_ISSUER`] with the identity
            /// provider's signing key inline, naming callers by
            /// `principal_claim`, and gives the provider a
            /// `consent_confirmation` through it whose ID token names the caller
            /// by `id_token_principal_claim`, exchanged at the fake identity
            /// provider's token endpoint.
            pub async fn confirming_at_idp(
                &self,
                principal_claim: Option<&str>,
                id_token_principal_claim: Option<&str>,
            ) -> JwtVerificationStrategy {
                use base64::Engine as _;
                let signing = ed25519_dalek::SigningKey::from_bytes(&IDP_KEY);
                let strategy = self
                    .strategies
                    .create(
                        serde_json::from_value(serde_json::json!({
                            "id": "", "name": "Callers", "expected_issuer": IDP_ISSUER,
                            "jwks_source": {"type": "static", "jwks": [{"kty": "OKP", "crv": "Ed25519",
                                "alg": "EdDSA", "kid": "idp-key",
                                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD
                                    .encode(signing.verifying_key().as_bytes())}]},
                            "principal_claim": principal_claim,
                            "created_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:00:00Z"
                        }))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let mut provider = self.provider();
                provider.consent_confirmation = Some(
                    serde_json::from_value(serde_json::json!({
                        "client_id": "login-client", "client_secret_secret_ref": "github-client-secret",
                        "authorization_endpoint": IDP_AUTHORIZE, "token_endpoint": self.idp_token_endpoint,
                        "jwt_verification_strategy_id": strategy.id,
                        "id_token_principal_claim": id_token_principal_claim
                    }))
                    .unwrap(),
                );
                provider
                    .additional_params
                    .insert("prompt".to_string(), "consent".to_string());
                self.providers
                    .update(provider)
                    .await
                    .unwrap();
                strategy
            }

            /// Posts the start page of a link that confirms the caller whose
            /// vault key is `user_identity_hash` through `strategy`.
            pub async fn sign_in(
                &self,
                strategy: &JwtVerificationStrategy,
                user_identity_hash: &str,
            ) -> SignIn {
                let start = crate::delegation_vault::oauth::build_authorization_url(
                    &self.provider(),
                    "did:web:agent.example",
                    user_identity_hash,
                    "surface",
                    &["repo".to_string(), "read:user".to_string()],
                    "https://198.51.100.7",
                    Some(crate::delegation_vault::ConsentStage::ConfirmStart(confirm_binding(strategy))),
                )
                .unwrap();
                let started = self
                    .start_post(&start_state(&start), &[("origin", "https://198.51.100.7")])
                    .await;
                assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
                let idp = url::Url::parse(
                    started
                        .header("location")
                        .unwrap(),
                )
                .unwrap();
                let (cookie, _, _) = set_cookie(&started);
                SignIn {
                    state: query_value(&idp, "state"),
                    cookie,
                    nonce: query_value(&idp, "nonce"),
                }
            }

            /// An ID token for the login client, signed by the identity
            /// provider, with `claims` added to or replacing its own.
            pub fn id_token(
                &self,
                nonce: &str,
                claims: serde_json::Value,
            ) -> String {
                use base64::Engine as _;
                use ed25519_dalek::Signer as _;
                let now = Utc::now().timestamp();
                let mut token = serde_json::json!({"iss": IDP_ISSUER, "sub": "alice", "aud": "login-client",
                    "exp": now + 300, "iat": now, "nonce": nonce});
                for (name, value) in claims.as_object().unwrap() {
                    token[name] = value.clone();
                }
                let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let input = format!(
                    "{}.{}",
                    encoding.encode(br#"{"alg":"EdDSA","typ":"JWT","kid":"idp-key"}"#),
                    encoding.encode(serde_json::to_vec(&token).unwrap())
                );
                let signature = ed25519_dalek::SigningKey::from_bytes(&IDP_KEY).sign(input.as_bytes());
                format!("{input}.{}", encoding.encode(signature.to_bytes()))
            }

            /// Makes the identity provider's token endpoint answer `body`.
            pub fn idp_answers(
                &self,
                body: serde_json::Value,
            ) {
                *self
                    .idp_answer
                    .lock()
                    .unwrap() = body;
            }

            /// The forms the identity provider's token endpoint received.
            pub fn idp_forms(&self) -> Vec<std::collections::HashMap<String, String>> {
                self.idp_forms
                    .lock()
                    .unwrap()
                    .clone()
            }

            /// The identity provider's redirect back to the confirmation
            /// route with `query`, from a browser sending `cookie`.
            pub async fn confirm(
                &self,
                query: &str,
                cookie: Option<&str>,
            ) -> Answer {
                let headers = cookie
                    .map(|cookie| vec![("cookie", cookie)])
                    .unwrap_or_default();
                self.get(&format!("/v1/identity/oauth/callback/github/confirm?{query}"), &headers)
                    .await
            }

            /// [`Self::confirm`] with `code` and the sign-in's own state and
            /// cookie.
            pub async fn confirm_code(
                &self,
                sign_in: &SignIn,
            ) -> Answer {
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("code", "idp-code")
                    .append_pair("state", &sign_in.state)
                    .finish();
                self.confirm(&query, Some(&sign_in.cookie))
                    .await
            }

            /// A callback state and the binding cookie of the browser that
            /// posted its start page.
            pub async fn begin(&self) -> (String, String) {
                let started = self
                    .start_post(&start_state(&self.start_url()), &[("origin", "https://198.51.100.7")])
                    .await;
                assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
                let vendor = url::Url::parse(
                    started
                        .header("location")
                        .unwrap(),
                )
                .unwrap();
                let cookie = started
                    .header("set-cookie")
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_string();
                (start_state(vendor.as_str()), cookie)
            }

            pub async fn get(
                &self,
                uri: &str,
                headers: &[(&str, &str)],
            ) -> Answer {
                self.send("GET", uri, headers, Body::empty())
                    .await
            }

            pub async fn start_post(
                &self,
                state: &str,
                headers: &[(&str, &str)],
            ) -> Answer {
                self.start_post_at("github", state, headers)
                    .await
            }

            pub async fn start_post_at(
                &self,
                path_segment: &str,
                state: &str,
                headers: &[(&str, &str)],
            ) -> Answer {
                let mut headers = headers.to_vec();
                headers.push(("content-type", "application/x-www-form-urlencoded"));
                let body = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", state)
                    .finish();
                self.send(
                    "POST",
                    &format!("/v1/identity/oauth/callback/{path_segment}/start"),
                    &headers,
                    Body::from(body),
                )
                .await
            }

            pub async fn callback(
                &self,
                provider: &str,
                query: &str,
                cookie: Option<&str>,
            ) -> Answer {
                let cookie = cookie.map(|pairs| format!("other=1; {pairs}"));
                let headers = cookie
                    .as_deref()
                    .map(|cookie| vec![("cookie", cookie)])
                    .unwrap_or_default();
                self.get(&format!("/v1/identity/oauth/callback/{provider}?{query}"), &headers)
                    .await
            }

            async fn send(
                &self,
                method: &str,
                uri: &str,
                headers: &[(&str, &str)],
                body: Body,
            ) -> Answer {
                let mut request = Request::builder()
                    .method(method)
                    .uri(uri);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                let response = self
                    .egress
                    .clone()
                    .scope(
                        self.app
                            .clone()
                            .oneshot(request.body(body).unwrap()),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let headers = response.headers().clone();
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                Answer {
                    status,
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                }
            }

            /// The forms the token endpoint received.
            pub fn token_forms(&self) -> Vec<std::collections::HashMap<String, String>> {
                self.forms
                    .lock()
                    .unwrap()
                    .clone()
            }

            pub fn token_calls(&self) -> usize {
                self.calls
                    .load(Ordering::SeqCst)
            }

            pub fn vault_records(&self) -> usize {
                self.vault
                    .tokens
                    .lock()
                    .unwrap()
                    .len()
            }
        }
    }

    #[tokio::test]
    async fn a_callbacks_provider_id_is_logged_only_as_a_plain_slug() {
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
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let text = logs.text();
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("OAuth consent refused"))
                .count(),
            2,
            "{text}"
        );
        assert!(!text.contains("provider_id="), "{text}");
        assert!(!text.contains("forged"), "{text}");
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
    /// `delegation_vault.view`, which also opens the legacy reads of the
    /// agent-keyed tokens.
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

    /// A failed vault read answers `500` with a fixed body: the error's
    /// detail goes to the log only.
    #[tokio::test]
    async fn a_failed_vault_read_answers_without_its_detail() {
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let state = DelegationVaultState {
            vault_store: Arc::new(InMemoryVault {
                tokens: Mutex::new(vec![seed_token("t1")]),
                unreadable: true,
            }),
            ..state_with(Vec::new())
        };
        let app = create_delegation_vault_router(state, Some(gate_for(storage)))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));
        for (uri, refusal) in [
            ("/api/v1/delegation-vault", r#"{"error":"Failed to list"}"#),
            ("/api/v1/delegation-vault/t1", r#"{"error":"Failed to get"}"#),
        ] {
            let (status, body) = response_of(app.clone(), "GET", uri).await;
            assert_eq!((status, body.as_str()), (StatusCode::INTERNAL_SERVER_ERROR.as_u16(), refusal), "{uri}");
        }
    }

    /// A failed revoke answers `500` with a fixed body. The error's detail,
    /// which can quote the caller's id, goes to the log only, escaped.
    #[tokio::test]
    async fn a_failed_revoke_answers_without_its_detail() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let (storage, _dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let state = DelegationVaultState {
            vault_store: Arc::new(InMemoryVault {
                tokens: Mutex::new(vec![seed_token("t1")]),
                unreadable: true,
            }),
            ..state_with(Vec::new())
        };
        let app = create_delegation_vault_router(state, Some(gate_for(storage)))
            .layer(Extension(AuthGuardOk("admin-1".to_string())));
        for uri in ["/api/v1/delegation-vault/t1", "/api/v1/delegation-vault/by-user/sha256:user-1"] {
            let (status, body) = response_of(app.clone(), "DELETE", uri).await;
            assert_eq!(
                (status, body.as_str()),
                (StatusCode::INTERNAL_SERVER_ERROR.as_u16(), r#"{"error":"Failed to revoke"}"#),
                "{uri}"
            );
        }
        let text = logs.text();
        let failures: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("revoke failed"))
            .collect();
        assert_eq!(failures.len(), 2, "{text}");
        assert!(
            failures
                .iter()
                .all(|line| line.contains(&format!("error={VAULT_READ_FAILURE:?}"))),
            "{text}"
        );
    }

    // ── A tenant's token reads only its own tenant's agent-keyed tokens ──

    async fn admin_reader(providers: InMemoryProviders) -> (Router, tempfile::TempDir) {
        let (storage, dir) = storage_with_user("admin-1", UserRole::Administrator).await;
        let app = create_delegation_vault_router(
            state_with_providers(tokens_of_two_tenants(), providers),
            Some(gate_for(storage)),
        )
        .layer(Extension(AuthGuardOk("admin-1".to_string())));
        (app, dir)
    }

    /// `app` as reached with a tenant's access token, which is always
    /// resource-scoped.
    fn as_tenant(
        app: Router,
        tenant_id: &str,
    ) -> Router {
        app.layer(Extension(PatTenantContext {
            token_id: "pat-t".to_string(),
            tenant_id: tenant_id.to_string(),
        }))
        .layer(Extension(PatDelegationContext {
            token_id: "pat-t".to_string(),
            delegation_depth: 0,
            resource_scoped: true,
        }))
    }

    /// `app` as reached with an access token scoped by required headers alone.
    fn as_header_scoped(app: Router) -> Router {
        app.layer(Extension(PatDelegationContext {
            token_id: "pat-h".to_string(),
            delegation_depth: 0,
            resource_scoped: true,
        }))
    }

    fn listed_ids(body: &str) -> Vec<String> {
        let mut ids: Vec<String> = serde_json::from_str::<Vec<serde_json::Value>>(body)
            .unwrap()
            .iter()
            .map(|item| {
                item["id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn a_tenant_token_lists_only_its_own_tenants_vault_tokens() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        for (tenant_id, expected) in [("tenant-a", "t-a"), ("tenant-b", "t-b")] {
            let (status, body) =
                response_of(as_tenant(app.clone(), tenant_id), "GET", "/api/v1/delegation-vault").await;
            assert_eq!(status, StatusCode::OK.as_u16(), "{body}");
            assert_eq!(listed_ids(&body), vec![expected.to_string()], "{tenant_id}");
        }
    }

    #[tokio::test]
    async fn a_tenant_token_gets_another_tenants_vault_token_as_not_found() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let tenant_a = || as_tenant(app.clone(), "tenant-a");
        let missing = response_of(tenant_a(), "GET", "/api/v1/delegation-vault/no-such-token").await;
        assert_eq!(missing, (StatusCode::NOT_FOUND.as_u16(), r#"{"error":"Delegation token not found"}"#.to_string()));
        assert_eq!(response_of(tenant_a(), "GET", "/api/v1/delegation-vault/t-b").await, missing);
        let (status, body) = response_of(tenant_a(), "GET", "/api/v1/delegation-vault/t-a").await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{body}");
        assert!(body.contains(r#""id":"t-a""#), "{body}");
        assert!(!body.contains("secret-access"), "{body}");
    }

    /// A token of an appliance-wide provider can belong to any tenant's
    /// caller, and one of a deleted provider to no known tenant.
    #[tokio::test]
    async fn untenanted_and_deleted_provider_tokens_are_hidden_from_a_tenant_token() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let missing =
            response_of(as_tenant(app.clone(), "tenant-a"), "GET", "/api/v1/delegation-vault/no-such-token").await;
        for id in ["t-global", "t-deleted"] {
            for tenant_id in ["tenant-a", "tenant-b"] {
                let uri = format!("/api/v1/delegation-vault/{id}");
                assert_eq!(
                    response_of(as_tenant(app.clone(), tenant_id), "GET", &uri).await,
                    missing,
                    "{tenant_id} {id}"
                );
            }
        }
    }

    /// Only an appliance-wide caller revokes. A tenant's token, which the
    /// middleware refuses before the handler, and a token scoped by required
    /// headers alone, which the middleware lets through, both get a bare 403
    /// here, and the vault keeps every token.
    #[tokio::test]
    async fn only_an_appliance_wide_caller_revokes_vault_tokens() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        for (caller, scoped) in [
            ("a tenant token", as_tenant(app.clone(), "tenant-a")),
            ("a token scoped by required headers alone", as_header_scoped(app.clone())),
        ] {
            for uri in ["/api/v1/delegation-vault/t-a", "/api/v1/delegation-vault/by-user/sha256:user-1"] {
                let (status, body) = response_of(scoped.clone(), "DELETE", uri).await;
                assert_eq!((status, body.as_str()), (StatusCode::FORBIDDEN.as_u16(), ""), "{caller} {uri}");
            }
        }
        let (status, body) = response_of(app, "GET", "/api/v1/delegation-vault").await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{body}");
        assert_eq!(listed_ids(&body), ["t-a", "t-b", "t-deleted", "t-global"]);
    }

    #[tokio::test]
    async fn an_appliance_wide_admin_session_reads_every_vault_token() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let (status, body) = response_of(app.clone(), "GET", "/api/v1/delegation-vault").await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{body}");
        assert_eq!(listed_ids(&body), ["t-a", "t-b", "t-deleted", "t-global"]);
        for id in ["t-global", "t-deleted"] {
            let (status, body) = response_of(app.clone(), "GET", &format!("/api/v1/delegation-vault/{id}")).await;
            assert_eq!(status, StatusCode::OK.as_u16(), "{body}");
            assert!(body.contains(&format!(r#""id":"{id}""#)), "{body}");
        }
    }

    /// A resource pattern without a tenant reads no token, even for a caller
    /// that is otherwise appliance-wide.
    #[tokio::test]
    async fn a_resource_scope_without_a_tenant_reads_no_vault_token() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let app = app.layer(Extension(crate::delegation_vault::test_support::pattern("tenant-a")));
        let (status, body) = response_of(app.clone(), "GET", "/api/v1/delegation-vault").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK.as_u16(), "[]"));
        let missing = response_of(app.clone(), "GET", "/api/v1/delegation-vault/no-such-token").await;
        assert_eq!(missing, (StatusCode::NOT_FOUND.as_u16(), r#"{"error":"Delegation token not found"}"#.to_string()));
        assert_eq!(response_of(app, "GET", "/api/v1/delegation-vault/t-a").await, missing);
    }

    #[tokio::test]
    async fn a_token_scoped_by_required_headers_alone_reads_no_vault_token() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let (status, body) = response_of(as_header_scoped(app.clone()), "GET", "/api/v1/delegation-vault").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK.as_u16(), "[]"));
        let (status, body) = response_of(as_header_scoped(app), "GET", "/api/v1/delegation-vault/t-a").await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::NOT_FOUND.as_u16(), r#"{"error":"Delegation token not found"}"#)
        );
    }

    /// While the credential providers cannot be read, a tenant's token reads
    /// nothing and the answer names no detail; an appliance-wide caller, which
    /// needs no provider, still reads.
    #[tokio::test]
    async fn a_tenant_read_fails_closed_when_the_provider_store_fails() {
        let directory = tempfile::tempdir().unwrap();
        let log = audit_log_of_two_tenants(directory.path()).await;
        let (app, _dir) = admin_reader(InMemoryProviders::unreadable()).await;
        for (uri, refusal) in [
            ("/api/v1/delegation-vault", r#"{"error":"Failed to list"}"#),
            ("/api/v1/delegation-vault/t-a", r#"{"error":"Failed to get"}"#),
            ("/api/v1/delegation-audit", r#"{"error":"Failed to read audit log"}"#),
        ] {
            let (status, body) =
                reading_audit_log_from(log.clone(), response_of(as_tenant(app.clone(), "tenant-a"), "GET", uri)).await;
            assert_eq!((status, body.as_str()), (StatusCode::INTERNAL_SERVER_ERROR.as_u16(), refusal), "{uri}");
        }
        let (status, body) = response_of(app.clone(), "GET", "/api/v1/delegation-vault").await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{body}");
        assert_eq!(listed_ids(&body), ["t-a", "t-b", "t-deleted", "t-global"]);
        let (status, page) = audit_page(app, "/api/v1/delegation-audit", &log).await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{page}");
        assert_eq!(page["total"], 6);
    }

    // ── A tenant's token reads only its own tenant's delegation audit ──

    async fn audit_page(
        app: Router,
        uri: &str,
        log: &std::path::Path,
    ) -> (u16, serde_json::Value) {
        let (status, body) = reading_audit_log_from(log.to_path_buf(), response_of(app, "GET", uri)).await;
        (status, serde_json::from_str(&body).unwrap())
    }

    fn provider_ids(page: &serde_json::Value) -> Vec<Option<&str>> {
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["provider_id"].as_str())
            .collect()
    }

    /// Totals and category counts count only the records the token reads, and
    /// the text filter finds nothing among the others.
    #[tokio::test]
    async fn a_tenant_token_reads_only_its_own_tenants_delegation_audit() {
        let directory = tempfile::tempdir().unwrap();
        let log = audit_log_of_two_tenants(directory.path()).await;
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;

        let (status, page) = audit_page(as_tenant(app.clone(), "tenant-a"), "/api/v1/delegation-audit", &log).await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{page}");
        assert_eq!(provider_ids(&page), [Some("cp-a")]);
        assert_eq!((&page["total"], &page["total_pages"]), (&serde_json::json!(1), &serde_json::json!(1)));
        assert_eq!(page["category_counts"], serde_json::json!({"consent_granted": 1}));

        let (_, page) = audit_page(as_tenant(app.clone(), "tenant-b"), "/api/v1/delegation-audit", &log).await;
        assert_eq!(provider_ids(&page), [Some("cp-b")]);
        assert_eq!(page["category_counts"], serde_json::json!({"token_injected": 1}));

        let (status, page) = audit_page(as_tenant(app, "tenant-a"), "/api/v1/delegation-audit?filter=cp-b", &log).await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{page}");
        assert_eq!(page["events"], serde_json::json!([]));
        assert_eq!(page["total"], 0);
        assert_eq!(page["category_counts"], serde_json::json!({}));
    }

    #[tokio::test]
    async fn an_appliance_wide_admin_session_reads_the_whole_delegation_audit() {
        let directory = tempfile::tempdir().unwrap();
        let log = audit_log_of_two_tenants(directory.path()).await;
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let (status, page) = audit_page(app, "/api/v1/delegation-audit", &log).await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{page}");
        assert_eq!(page["total"], 6);
        assert_eq!(
            provider_ids(&page),
            [Some("github"), None, Some("cp-deleted"), Some("cp-global"), Some("cp-b"), Some("cp-a")]
        );
        assert_eq!(
            page["category_counts"],
            serde_json::json!({"consent_granted": 2, "token_injected": 3, "token_revoked": 1})
        );
    }

    #[tokio::test]
    async fn a_token_scoped_by_required_headers_alone_reads_no_delegation_audit_record() {
        let directory = tempfile::tempdir().unwrap();
        let log = audit_log_of_two_tenants(directory.path()).await;
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let (status, page) = audit_page(as_header_scoped(app), "/api/v1/delegation-audit", &log).await;
        assert_eq!(status, StatusCode::OK.as_u16(), "{page}");
        assert_eq!(page["events"], serde_json::json!([]));
        assert_eq!(page["total"], 0);
        assert_eq!(page["category_counts"], serde_json::json!({}));
    }

    /// A failed read of the audit log answers `500` with a fixed body: the
    /// error's detail goes to the log only.
    #[tokio::test]
    async fn a_failed_delegation_audit_read_answers_without_its_detail() {
        let (app, _dir) = admin_reader(InMemoryProviders::of_two_tenants()).await;
        let (status, body) = without_an_audit_log(response_of(app, "GET", "/api/v1/delegation-audit")).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::INTERNAL_SERVER_ERROR.as_u16(), r#"{"error":"Failed to read the audit log"}"#)
        );
    }
}
