use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Router, middleware};
use chrono::Utc;
use tower::ServiceExt;

use crate::access_tokens::store::hash_secret;
use crate::access_tokens::{AccessToken, FsAccessTokenStore, generate_token};
use crate::audit::producer::capture;
use crate::auth::session::SessionManager;
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::auth_manager::middleware::{AuthGuardState, RbacGuard, require_session_auth};
use crate::auth_manager::resource_scope::RequiredHeader;
use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
use crate::delegation_vault::DelegationToken;
use crate::delegation_vault::audit::{DelegationAuditEvent, reading_audit_log_from};
use crate::delegation_vault::handlers::DelegationVaultState;
use crate::delegation_vault::oauth::{TokenEgress, build_authorization_url};
use crate::delegation_vault::read_scope::tests::{audit_log_of_two_tenants, provider};
use crate::delegation_vault::read_scope::{VaultReadScope, VaultReader};
use crate::delegation_vault::router::{create_delegation_vault_oauth_router, create_delegation_vault_router};
use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
use crate::secrets::{CreateSecretRequest, SecretsStore};

const TENANT_HEADER: &str = "x-external-account";

/// The delegation vault's management routes behind the real session and
/// access-token middleware, with file-system stores: credential providers
/// `cp-a` of `tenant-a`, `cp-b` of `tenant-b` and the appliance-wide
/// `cp-global`, and a vault token of each, `t-a`, `t-b` and `t-global`.
struct Vault {
    app: Router,
    /// The public OAuth callback route, on the same stores.
    callback: Router,
    auth: AuthGuardState,
    providers: Arc<dyn CredentialProviderStorage>,
    secrets: Arc<dyn SecretsStore>,
    tokens: Arc<FsAccessTokenStore>,
    vault: Arc<dyn DelegationVaultStorage>,
    admin_session: String,
    directory: tempfile::TempDir,
}

fn vault_token(
    id: &str,
    credential_provider_id: &str,
) -> DelegationToken {
    serde_json::from_value(serde_json::json!({
        "id": id, "agent_did": format!("did:web:agent-{id}.example"), "user_identity_hash": "sha256:user",
        "credential_provider_id": credential_provider_id, "provider_id": "github", "access_token": "secret-access",
        "scopes": ["repo"], "consent_granted_at": "2026-09-01T00:00:00Z",
        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
    }))
    .unwrap()
}

async fn vault() -> Vault {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);
    let providers = FileSystemCredentialProviderStore::new(path("providers"))
        .await
        .unwrap();
    for (id, tenant_id) in [("cp-a", Some("tenant-a")), ("cp-b", Some("tenant-b")), ("cp-global", None)] {
        providers
            .create(provider(id, tenant_id))
            .await
            .unwrap();
    }
    let providers: Arc<dyn CredentialProviderStorage> = Arc::new(providers);
    let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
        FileSystemDelegationVaultStore::new(path("vault"))
            .await
            .unwrap(),
    );
    for (id, credential_provider_id) in [("t-a", "cp-a"), ("t-b", "cp-b"), ("t-global", "cp-global")] {
        vault
            .store(vault_token(id, credential_provider_id))
            .await
            .unwrap();
    }
    let secrets: Arc<dyn SecretsStore> = Arc::new(
        crate::secrets::FilesystemSecretsStore::new_async(
            path("secrets")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap(),
    );
    let state = DelegationVaultState {
        vault_store: vault.clone(),
        provider_store: providers.clone(),
        secrets_store: secrets.clone(),
        gateway_base_url: "https://gw.example".to_string(),
        agent_surface_store: None,
        oauth_callback_route: "/v1/identity/oauth/callback".to_string(),
        vc_signer: None,
        vc_issuer: None,
        vault_population_notifier: None,
        egress_allowlist: None,
        resource_origins: Default::default(),
        issuers: Default::default(),
    };

    let users = Arc::new(
        PasskeyStorage::new(
            path("users")
                .to_string_lossy()
                .into_owned(),
            path("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap(),
    );
    let now = Utc::now();
    for user_id in ["owner-1", "admin-1"] {
        users
            .save_user(&UserData {
                user_id: user_id.to_string(),
                username: user_id.to_string(),
                passkeys: Vec::new(),
                role: UserRole::Administrator,
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
    }
    let sessions = Arc::new(SessionManager::new());
    let admin_session = sessions
        .create_session("admin-1".to_string(), "admin-1".to_string())
        .await;
    let tokens = Arc::new(
        FsAccessTokenStore::new(&path("access-tokens"))
            .await
            .unwrap(),
    );
    let rbac = Arc::new(crate::rbac::RbacConfig::default());
    let auth = AuthGuardState::new(sessions, None, Arc::new(crate::terms::TermsManager::disabled()))
        .with_pat_authenticator(Some(tokens.clone()));
    let callback = create_delegation_vault_oauth_router(state.clone());
    let app = create_delegation_vault_router(state, Some(RbacGuard::new(users, rbac)))
        .layer(middleware::from_fn_with_state(auth.clone(), require_session_auth));
    Vault {
        app,
        callback,
        auth,
        providers,
        secrets,
        tokens,
        vault,
        admin_session,
        directory,
    }
}

/// A token endpoint on the loopback that exchanges any authorization code for
/// an access token. Returns its URL.
async fn token_endpoint() -> String {
    let app = Router::new().route(
        "/token",
        post(|| async {
            axum::Json(serde_json::json!({
                "access_token": "consent-access", "token_type": "Bearer", "expires_in": 3600
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .ok();
    });
    endpoint
}

impl Vault {
    /// The read scope a vault route takes from a request with `bearer`
    /// behind the same middleware.
    async fn read_scope(
        &self,
        bearer: &str,
        tenant_id: Option<&str>,
    ) -> VaultReadScope {
        let seen = Arc::new(Mutex::new(None));
        let probe = {
            let (providers, seen) = (self.providers.clone(), seen.clone());
            move |reader: VaultReader| async move {
                let scope = VaultReadScope::of(Some(providers.as_ref()), &reader)
                    .await
                    .unwrap();
                *seen.lock().unwrap() = Some(scope);
                StatusCode::NO_CONTENT
            }
        };
        let app = Router::new()
            .route("/api/v1/delegation-vault", get(probe))
            .layer(middleware::from_fn_with_state(self.auth.clone(), require_session_auth));
        let (status, body) = send(&app, "GET", "/api/v1/delegation-vault", bearer, tenant_id).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        seen.lock()
            .unwrap()
            .take()
            .expect("the probe saw the request")
    }

    /// Stores the OAuth authorization code provider `id` of `tenant_id`, with
    /// the slug `calendar`, its token endpoint at `token_endpoint` and its
    /// client secrets in its tenant.
    async fn oauth_provider(
        &self,
        id: &str,
        tenant_id: &str,
        token_endpoint: &str,
    ) {
        for secret_id in [format!("{id}-client-id"), format!("{id}-client-secret")] {
            self.secrets
                .create(CreateSecretRequest {
                    tenant_id: Some(tenant_id.to_string()),
                    name: secret_id.clone(),
                    secret_id: secret_id.clone(),
                    description: None,
                    value: format!("{secret_id}-value"),
                    secret_type: "ApiKey".to_string(),
                    tags: Vec::new(),
                })
                .await
                .unwrap();
        }
        self.providers
            .create(
                serde_json::from_value(serde_json::json!({
                    "id": id, "tenant_id": tenant_id, "name": "Calendar", "provider_id": "calendar",
                    "provider_type": "oauth2_authorization_code",
                    "authorization_endpoint": "https://calendar.example/authorize", "token_endpoint": token_endpoint,
                    "client_id_secret_ref": format!("{id}-client-id"),
                    "client_secret_secret_ref": format!("{id}-client-secret"),
                    "callback_url": "https://203.0.113.20/v1/identity/oauth/callback/calendar",
                    "default_scopes": ["calendar.read"],
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
    }

    /// Completes a user's consent to the provider `credential_provider_id`
    /// through the OAuth callback, with the state its authorization URL
    /// carries, and returns the audit records the callback submitted.
    async fn grant_consent(
        &self,
        credential_provider_id: &str,
        token_endpoint: &str,
    ) -> Vec<DelegationAuditEvent> {
        let provider = self
            .providers
            .get(credential_provider_id)
            .await
            .unwrap()
            .expect("the provider exists");
        let authorization_url = build_authorization_url(
            &provider,
            "did:web:agent.example",
            "sha256:user",
            "surface-1",
            &[],
            "https://gw.example",
            &self.secrets,
        )
        .await
        .unwrap();
        let state = url::Url::parse(&authorization_url)
            .unwrap()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .expect("the authorization URL carries a state");
        let uri = format!(
            "/v1/identity/oauth/callback/{}?code=code-1&state={}",
            provider.provider_id,
            urlencoding::encode(&state)
        );
        let egress = TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: Some(token_endpoint.to_string()),
            policy: Default::default(),
        };
        let (page, events) = capture(egress.scope(async {
            let response = self
                .callback
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            String::from_utf8(body.to_vec()).unwrap()
        }))
        .await;
        assert!(page.contains("Authorization Successful"), "{page}");
        events
    }
}

/// An access token of the administrator `owner-1`, with every feature scope.
async fn access_token(
    tokens: &FsAccessTokenStore,
    pattern: Option<&str>,
    required_headers: Vec<RequiredHeader>,
) -> String {
    let (id, secret) = generate_token();
    tokens
        .create(AccessToken {
            id,
            name: "vault reader".to_string(),
            description: String::new(),
            token_hash: hash_secret(&secret),
            user_id: "owner-1".to_string(),
            scopes: Vec::new(),
            resource_pattern: pattern.map(str::to_string),
            required_headers,
            created_by: "owner-1".to_string(),
            parent_token_id: None,
            delegation_depth: 0,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            rotation_generation: 0,
            rotated_at: None,
            rotated_by: None,
        })
        .await
        .unwrap();
    secret
}

fn tenant_header(tenant_id: &str) -> Vec<RequiredHeader> {
    vec![RequiredHeader {
        name: TENANT_HEADER.to_string(),
        pattern: tenant_id.to_string(),
    }]
}

async fn tenant_access_token(
    tokens: &FsAccessTokenStore,
    tenant_id: &str,
) -> String {
    access_token(tokens, Some("TENANT:${x-external-account}:credential-providers:.*"), tenant_header(tenant_id)).await
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: &str,
    tenant_id: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {bearer}"));
    if let Some(tenant_id) = tenant_id {
        request = request.header(TENANT_HEADER, tenant_id);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
}

fn ids(list: &serde_json::Value) -> Vec<&str> {
    let mut ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn a_tenant_access_token_reads_only_its_tenants_vault_tokens() {
    let fixture = vault().await;
    let secret = tenant_access_token(&fixture.tokens, "tenant-a").await;
    let tenant_a = Some("tenant-a");

    let (status, list) = send(&fixture.app, "GET", "/api/v1/delegation-vault", &secret, tenant_a).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(ids(&list), ["t-a"]);

    let (status, own) = send(&fixture.app, "GET", "/api/v1/delegation-vault/t-a", &secret, tenant_a).await;
    assert_eq!(status, StatusCode::OK, "{own}");
    assert_eq!(own["credential_provider_id"], "cp-a");

    let missing = send(&fixture.app, "GET", "/api/v1/delegation-vault/no-such-token", &secret, tenant_a).await;
    assert_eq!(missing, (StatusCode::NOT_FOUND, serde_json::json!({"error": "Delegation token not found"})));
    for id in ["t-b", "t-global"] {
        let uri = format!("/api/v1/delegation-vault/{id}");
        assert_eq!(send(&fixture.app, "GET", &uri, &secret, tenant_a).await, missing, "{id}");
    }
}

#[tokio::test]
async fn an_access_token_with_required_headers_alone_reads_no_vault_token() {
    let fixture = vault().await;
    let secret = access_token(&fixture.tokens, None, tenant_header("tenant-a")).await;
    let tenant_a = Some("tenant-a");

    let (status, list) = send(&fixture.app, "GET", "/api/v1/delegation-vault", &secret, tenant_a).await;
    assert_eq!((status, list), (StatusCode::OK, serde_json::json!([])));
    let (status, body) = send(&fixture.app, "GET", "/api/v1/delegation-vault/t-a", &secret, tenant_a).await;
    assert_eq!((status, body), (StatusCode::NOT_FOUND, serde_json::json!({"error": "Delegation token not found"})));
}

#[tokio::test]
async fn an_appliance_wide_access_token_reads_every_vault_token() {
    let fixture = vault().await;
    let secret = access_token(&fixture.tokens, None, Vec::new()).await;

    for bearer in [secret.as_str(), fixture.admin_session.as_str()] {
        let (status, list) = send(&fixture.app, "GET", "/api/v1/delegation-vault", bearer, None).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(ids(&list), ["t-a", "t-b", "t-global"]);
        let (status, global) = send(&fixture.app, "GET", "/api/v1/delegation-vault/t-global", bearer, None).await;
        assert_eq!(status, StatusCode::OK, "{global}");
        assert_eq!(global["credential_provider_id"], "cp-global");
    }
}

#[tokio::test]
async fn a_vault_reader_takes_the_whole_caller_from_the_request() {
    let fixture = vault().await;
    let appliance_wide = access_token(&fixture.tokens, None, Vec::new()).await;
    let tenant = tenant_access_token(&fixture.tokens, "tenant-a").await;
    let header_only = access_token(&fixture.tokens, None, tenant_header("tenant-a")).await;

    assert_eq!(
        fixture
            .read_scope(&fixture.admin_session, None)
            .await,
        VaultReadScope::Appliance
    );
    assert_eq!(
        fixture
            .read_scope(&appliance_wide, None)
            .await,
        VaultReadScope::Appliance
    );
    assert_eq!(
        fixture
            .read_scope(&tenant, Some("tenant-a"))
            .await,
        VaultReadScope::Tenant(HashSet::from(["cp-a".to_string()]))
    );
    assert_eq!(
        fixture
            .read_scope(&header_only, Some("tenant-a"))
            .await,
        VaultReadScope::Nothing
    );
}

#[tokio::test]
async fn a_tenant_access_token_still_cannot_revoke_a_vault_token() {
    let fixture = vault().await;
    let secret = tenant_access_token(&fixture.tokens, "tenant-a").await;

    for id in ["t-a", "t-b"] {
        let uri = format!("/api/v1/delegation-vault/{id}");
        let (status, _) = send(&fixture.app, "DELETE", &uri, &secret, Some("tenant-a")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{id}");
        assert!(
            fixture
                .vault
                .get(id)
                .await
                .unwrap()
                .is_some(),
            "{id} is kept"
        );
    }
}

async fn read_audit(
    fixture: &Vault,
    log: &std::path::Path,
    bearer: &str,
    tenant_id: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    reading_audit_log_from(log.to_path_buf(), send(&fixture.app, "GET", "/api/v1/delegation-audit", bearer, tenant_id))
        .await
}

#[tokio::test]
async fn a_tenant_access_token_reads_only_its_tenants_delegation_audit() {
    let fixture = vault().await;
    let log = audit_log_of_two_tenants(fixture.directory.path()).await;
    let tenant_secret = tenant_access_token(&fixture.tokens, "tenant-a").await;
    let header_secret = access_token(&fixture.tokens, None, tenant_header("tenant-a")).await;

    let (status, page) = read_audit(&fixture, &log, &tenant_secret, Some("tenant-a")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["total"], 1);
    assert_eq!(page["events"][0]["provider_id"], "cp-a");
    assert_eq!(page["category_counts"], serde_json::json!({"consent_granted": 1}));

    let (status, page) = read_audit(&fixture, &log, &header_secret, Some("tenant-a")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["total"], 0);
    assert_eq!(page["events"], serde_json::json!([]));

    let (status, page) = read_audit(&fixture, &log, &fixture.admin_session, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["total"], 6);
}

/// The OAuth callback's `consent_granted` names its provider's id, so the
/// provider's tenant reads it. Another tenant does not, though its own
/// provider has the same `provider_id` slug.
#[tokio::test]
async fn a_tenant_access_token_reads_the_consent_its_tenants_provider_recorded() {
    let fixture = vault().await;
    let token_endpoint = token_endpoint().await;
    for (id, tenant_id) in [("cp-calendar-a", "tenant-a"), ("cp-calendar-b", "tenant-b")] {
        fixture
            .oauth_provider(id, tenant_id, &token_endpoint)
            .await;
    }
    let events = fixture
        .grant_consent("cp-calendar-a", &token_endpoint)
        .await;
    let log = fixture
        .directory
        .path()
        .join("consent-audit.jsonl");
    let lines: String = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap() + "\n")
        .collect();
    std::fs::write(&log, lines).unwrap();

    let tenant_a = tenant_access_token(&fixture.tokens, "tenant-a").await;
    let (status, page) = read_audit(&fixture, &log, &tenant_a, Some("tenant-a")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["total"], 1, "{page}");
    assert_eq!(
        (&page["events"][0]["event"], &page["events"][0]["provider_id"]),
        (&serde_json::json!("consent_granted"), &serde_json::json!("cp-calendar-a")),
        "{page}"
    );

    let tenant_b = tenant_access_token(&fixture.tokens, "tenant-b").await;
    let (status, page) = read_audit(&fixture, &log, &tenant_b, Some("tenant-b")).await;
    assert_eq!((status, &page["total"]), (StatusCode::OK, &serde_json::json!(0)), "{page}");
}
