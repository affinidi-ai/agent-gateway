use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Path};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Router, middleware};
use chrono::Utc;
use tower::ServiceExt;

use crate::access_tokens::store::hash_secret;
use crate::access_tokens::{AccessToken, FsAccessTokenStore, generate_token};
use crate::auth::session::SessionManager;
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::auth_manager::middleware::{AuthGuardState, RbacGuard, require_session_auth};
use crate::auth_manager::pat::PatResourceScope;
use crate::auth_manager::resource_scope::RequiredHeader;
use crate::component_tests::helpers::audit_events::AuditEvents;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

async fn gateway_get(
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Path(id): Path<String>,
) -> StatusCode {
    let resource_tenant = match id.as_str() {
        "gateway-a" => Some("tenant-a"),
        "gateway-b" => Some("tenant-b"),
        "gateway-global" => None,
        _ => return StatusCode::NOT_FOUND,
    };
    let context = context
        .as_ref()
        .map(|Extension(context)| context);
    let scope = scope
        .as_ref()
        .map(|Extension(scope)| scope);
    if can_access(resource_tenant, context) && scope_allows_resource(scope, context, ResourceKind::Gateways, &id) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn accepted() -> StatusCode {
    StatusCode::OK
}

async fn new_store() -> Arc<FsAccessTokenStore> {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = FsAccessTokenStore::new(directory.path())
        .await
        .expect("token store");
    std::mem::forget(directory);
    Arc::new(store)
}

async fn create_token(
    store: &FsAccessTokenStore,
    pattern: Option<&str>,
    headers: Vec<RequiredHeader>,
) -> (String, String) {
    create_token_with(store, "user-1", pattern, headers, Vec::new()).await
}

async fn create_token_owned_by(
    store: &FsAccessTokenStore,
    owner: &str,
    pattern: Option<&str>,
    headers: Vec<RequiredHeader>,
) -> (String, String) {
    create_token_with(store, owner, pattern, headers, Vec::new()).await
}

async fn create_token_with_scopes(
    store: &FsAccessTokenStore,
    pattern: Option<&str>,
    headers: Vec<RequiredHeader>,
    scopes: Vec<String>,
) -> (String, String) {
    create_token_with(store, "user-1", pattern, headers, scopes).await
}

async fn create_token_with(
    store: &FsAccessTokenStore,
    owner: &str,
    pattern: Option<&str>,
    headers: Vec<RequiredHeader>,
    scopes: Vec<String>,
) -> (String, String) {
    let (id, secret) = generate_token();
    store
        .create(AccessToken {
            id: id.clone(),
            name: "component token".to_string(),
            description: String::new(),
            token_hash: hash_secret(&secret),
            user_id: owner.to_string(),
            scopes,
            resource_pattern: pattern.map(str::to_string),
            required_headers: headers,
            created_by: owner.to_string(),
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
        .expect("create token");
    (id, secret)
}

fn app(store: Arc<FsAccessTokenStore>) -> Router {
    app_with_trusted_tenant_header(store, None)
}

/// Like `app`, but allows configuring the trusted-edge tenant-header
/// assertion so tests can exercise the honored-with-trusted-edge path.
fn app_with_trusted_tenant_header(
    store: Arc<FsAccessTokenStore>,
    trusted_tenant_header: Option<crate::tenancy::TrustedTenantHeader>,
) -> Router {
    let auth = AuthGuardState::new(
        Arc::new(SessionManager::new()),
        None,
        std::sync::Arc::new(crate::terms::TermsManager::disabled()),
    )
    .with_pat_authenticator(Some(store))
    .with_trusted_tenant_header(trusted_tenant_header.map(Arc::new));
    Router::new()
        .route("/v1/gateways/{id}", get(gateway_get))
        .route("/v1/unenforced", get(accepted).post(accepted))
        .layer(middleware::from_fn_with_state(auth, require_session_auth))
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    secret: Option<&str>,
    account: Option<&str>,
) -> StatusCode {
    let mut builder = Request::builder()
        .method(method)
        .uri(path);
    if let Some(secret) = secret {
        builder = builder.header("Authorization", format!("Bearer {secret}"));
    }
    if let Some(account) = account {
        builder = builder.header("x-external-account", account);
    }
    app.clone()
        .oneshot(
            builder
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn tenant_pat_filters_owned_and_global_gateway_records() {
    let store = new_store().await;
    let (_, secret) = create_token(
        &store,
        Some("TENANT:${x-external-account}:gateways:.*"),
        vec![RequiredHeader {
            name: "x-external-account".to_string(),
            // Exact-literal selector: this test only ever sends "tenant-a"
            // and proves tenant-scoped filtering for a fixed tenant, not
            // cross-tenant header-switching, so it is bound to the tenant
            // it exercises.
            pattern: "tenant-a".to_string(),
        }],
    )
    .await;
    let app = app(store);

    assert_eq!(request(&app, "GET", "/v1/gateways/gateway-a", Some(&secret), Some("tenant-a")).await, StatusCode::OK);
    assert_eq!(
        request(&app, "GET", "/v1/gateways/gateway-b", Some(&secret), Some("tenant-a")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "GET", "/v1/gateways/gateway-global", Some(&secret), Some("tenant-a")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn tenant_pat_requires_its_validated_selector_header() {
    let store = new_store().await;
    let (_, secret) = create_token(
        &store,
        Some("TENANT:${x-external-account}:gateways:.*"),
        vec![RequiredHeader {
            name: "x-external-account".to_string(),
            // Exact-literal selector; see note above.
            pattern: "tenant-a".to_string(),
        }],
    )
    .await;
    let app = app(store);

    assert_eq!(request(&app, "GET", "/v1/gateways/gateway-a", Some(&secret), None).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn scoped_pat_denies_an_unclassified_mutation_but_global_pat_allows_it() {
    let store = new_store().await;
    let (_, scoped_secret) = create_token(
        &store,
        Some("TENANT:${x-external-account}:gateways:.*"),
        vec![RequiredHeader {
            name: "x-external-account".to_string(),
            // Exact-literal selector; see note above.
            pattern: "tenant-a".to_string(),
        }],
    )
    .await;
    let (_, global_secret) = create_token(&store, None, Vec::new()).await;
    let app = app(store);

    assert_eq!(
        request(&app, "POST", "/v1/unenforced", Some(&scoped_secret), Some("tenant-a")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(request(&app, "POST", "/v1/unenforced", Some(&global_secret), None).await, StatusCode::OK);
}

#[tokio::test]
async fn revocation_invalidates_the_pat_immediately() {
    let store = new_store().await;
    let (id, secret) = create_token(&store, None, Vec::new()).await;
    let app = app(store.clone());

    assert_eq!(request(&app, "GET", "/v1/gateways/gateway-global", Some(&secret), None).await, StatusCode::OK);
    store
        .revoke(&id)
        .await
        .expect("revoke");
    assert_eq!(
        request(&app, "GET", "/v1/gateways/gateway-global", Some(&secret), None).await,
        StatusCode::UNAUTHORIZED
    );
}

async fn save_user(
    users: &PasskeyStorage,
    user_id: &str,
    role: UserRole,
) {
    let now = Utc::now();
    users
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
        .expect("save user");
}

async fn create_managed_token(
    store: &FsAccessTokenStore,
    scopes: &[&str],
    parent_token_id: Option<&str>,
) -> (String, String) {
    let (id, secret) = generate_token();
    store
        .create(AccessToken {
            id: id.clone(),
            name: "managed token".to_string(),
            description: String::new(),
            token_hash: hash_secret(&secret),
            user_id: "user-1".to_string(),
            scopes: scopes
                .iter()
                .map(ToString::to_string)
                .collect(),
            resource_pattern: None,
            required_headers: Vec::new(),
            created_by: "user-1".to_string(),
            parent_token_id: parent_token_id.map(str::to_string),
            delegation_depth: u32::from(parent_token_id.is_some()),
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            rotation_generation: 0,
            rotated_at: None,
            rotated_by: None,
        })
        .await
        .expect("create managed token");
    (id, secret)
}

struct RotationApp {
    app: Router,
    store: Arc<FsAccessTokenStore>,
    admin_session: String,
    power_user_session: String,
}

async fn rotation_app() -> RotationApp {
    rotation_app_with_rbac(crate::rbac::RbacConfig::default()).await
}

async fn rotation_app_with_rbac(rbac: crate::rbac::RbacConfig) -> RotationApp {
    let store = new_store().await;
    let user_directory = tempfile::tempdir().expect("tempdir");
    let users = Arc::new(
        PasskeyStorage::new(
            user_directory
                .path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            user_directory
                .path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .expect("user storage"),
    );
    std::mem::forget(user_directory);
    save_user(&users, "user-1", UserRole::Administrator).await;
    save_user(&users, "admin-1", UserRole::Administrator).await;
    save_user(&users, "power-1", UserRole::PowerUser).await;
    let sessions = Arc::new(SessionManager::new());
    let admin_session = sessions
        .create_session("admin-1".to_string(), "admin-1".to_string())
        .await;
    let power_user_session = sessions
        .create_session("power-1".to_string(), "power-1".to_string())
        .await;
    let rbac = Arc::new(rbac);
    let auth = AuthGuardState::new(sessions, None, Arc::new(crate::terms::TermsManager::disabled()))
        .with_pat_authenticator(Some(store.clone()));
    let app = Router::new()
        .route("/v1/gateways/{id}", get(gateway_get))
        .merge(crate::access_tokens::router::create_access_tokens_router(
            store.clone(),
            rbac.clone(),
            Arc::new(crate::tenancy::TenancyConfig::default()),
            Some(RbacGuard::new(users, rbac)),
        ))
        .layer(middleware::from_fn_with_state(auth, require_session_auth));
    RotationApp {
        app,
        store,
        admin_session,
        power_user_session,
    }
}

async fn rotate(
    app: &Router,
    id: &str,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/access-tokens/{id}/rotate"));
    if let Some(bearer) = bearer {
        builder = builder.header("Authorization", format!("Bearer {bearer}"));
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&body)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&body).into_owned()));
    (status, json)
}

#[tokio::test]
async fn rotation_through_the_api_swaps_the_pat_secret_in_place() {
    let fixture = rotation_app().await;
    let (id, old_secret) = create_token(&fixture.store, None, Vec::new()).await;

    let (status, body) = rotate(&fixture.app, &id, Some(&old_secret)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], id);
    assert_eq!(body["name"], "component token");
    let new_secret = body["token"]
        .as_str()
        .expect("new secret")
        .to_string();
    assert_ne!(new_secret, old_secret);

    assert_eq!(
        request(&fixture.app, "GET", "/v1/gateways/gateway-global", Some(&old_secret), None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&fixture.app, "GET", "/v1/gateways/gateway-global", Some(&new_secret), None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rotation_without_authentication_is_unauthorized() {
    let fixture = rotation_app().await;
    let (id, _) = create_token(&fixture.store, None, Vec::new()).await;

    assert_eq!(
        rotate(&fixture.app, &id, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rotation_by_a_session_role_without_access_tokens_edit_is_forbidden() {
    let fixture = rotation_app().await;
    let (id, secret) = create_token(&fixture.store, None, Vec::new()).await;

    assert_eq!(
        rotate(&fixture.app, &id, Some(&fixture.power_user_session))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(request(&fixture.app, "GET", "/v1/gateways/gateway-global", Some(&secret), None).await, StatusCode::OK);
}

#[tokio::test]
async fn rotation_by_a_pat_without_access_tokens_edit_is_forbidden() {
    let fixture = rotation_app().await;
    let (id, secret) = create_managed_token(&fixture.store, &["access_tokens.view"], None).await;

    assert_eq!(
        rotate(&fixture.app, &id, Some(&secret))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_pat_rotates_its_own_descendant() {
    let fixture = rotation_app().await;
    let (parent_id, parent_secret) = create_managed_token(&fixture.store, &["access_tokens.edit"], None).await;
    let (child_id, child_secret) =
        create_managed_token(&fixture.store, &["access_tokens.edit"], Some(&parent_id)).await;

    let (status, body) = rotate(&fixture.app, &child_id, Some(&parent_secret)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], child_id);
    assert_eq!(body["rotated_by"], "user-1");
    assert_ne!(body["token"], child_secret);
}

#[tokio::test]
async fn a_pat_cannot_rotate_a_token_outside_its_lineage_and_the_denial_leaves_it_usable() {
    let fixture = rotation_app().await;
    let (_, caller_secret) = create_managed_token(&fixture.store, &["access_tokens.edit"], None).await;
    let (other_id, other_secret) = create_managed_token(&fixture.store, &["access_tokens.edit"], None).await;

    assert_eq!(
        rotate(&fixture.app, &other_id, Some(&caller_secret))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        request(&fixture.app, "GET", "/v1/gateways/gateway-global", Some(&other_secret), None).await,
        StatusCode::OK
    );
    assert_eq!(
        rotate(&fixture.app, &other_id, Some(&fixture.admin_session))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rotating_an_unknown_token_is_not_found_and_emits_rotate_denied() {
    let fixture = rotation_app().await;
    let audit = AuditEvents::capture();

    assert_eq!(
        rotate(&fixture.app, "agat_missing", Some(&fixture.admin_session))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let denied = audit.named("access_token.rotate_denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["token_id"], "agat_missing");
    assert_eq!(denied[0]["caller_user_id"], "admin-1");
    assert_eq!(denied[0]["status"], "404");
}

#[tokio::test]
async fn a_non_administrator_granted_access_tokens_edit_cannot_rotate_another_users_token() {
    let mut rbac = crate::rbac::RbacConfig::default();
    rbac.permissions
        .insert("access_tokens.edit".to_string(), "poweruser".to_string());
    let fixture = rotation_app_with_rbac(rbac).await;
    let (admin_token_id, admin_secret) = create_token_owned_by(&fixture.store, "admin-1", None, Vec::new()).await;
    let audit = AuditEvents::capture();

    let (status, body) = rotate(&fixture.app, &admin_token_id, Some(&fixture.power_user_session)).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let denied = audit.named("access_token.rotate_denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["token_id"], admin_token_id);
    assert_eq!(denied[0]["caller_user_id"], "power-1");
    assert_eq!(denied[0]["status"], "403");
    assert!(
        audit
            .named("access_token.rotated")
            .is_empty()
    );
    assert_eq!(
        request(&fixture.app, "GET", "/v1/gateways/gateway-global", Some(&admin_secret), None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_non_administrator_granted_access_tokens_edit_rotates_their_own_token() {
    let mut rbac = crate::rbac::RbacConfig::default();
    rbac.permissions
        .insert("access_tokens.edit".to_string(), "poweruser".to_string());
    let fixture = rotation_app_with_rbac(rbac).await;
    let (own_token_id, _) = create_token_owned_by(&fixture.store, "power-1", None, Vec::new()).await;

    let (status, body) = rotate(&fixture.app, &own_token_id, Some(&fixture.power_user_session)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rotated_by"], "power-1");
}

#[tokio::test]
async fn an_administrator_rotates_another_users_token() {
    let fixture = rotation_app().await;
    let (id, old_secret) = create_token(&fixture.store, None, Vec::new()).await;
    let audit = AuditEvents::capture();

    let (status, body) = rotate(&fixture.app, &id, Some(&fixture.admin_session)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rotated_by"], "admin-1");
    let rotated = audit.named("access_token.rotated");
    assert_eq!(rotated.len(), 1);
    assert_eq!(rotated[0]["owner_user_id"], "user-1");
    assert_eq!(rotated[0]["rotated_for_other_user"], "true");
    assert_eq!(
        request(&fixture.app, "GET", "/v1/gateways/gateway-global", Some(&old_secret), None).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rotating_a_revoked_token_is_a_conflict() {
    let fixture = rotation_app().await;
    let (id, _) = create_token(&fixture.store, None, Vec::new()).await;
    fixture
        .store
        .revoke(&id)
        .await
        .expect("revoke");

    assert_eq!(
        rotate(&fixture.app, &id, Some(&fixture.admin_session))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn missing_bearer_is_unauthorized() {
    let app = app(new_store().await);
    assert_eq!(request(&app, "GET", "/v1/gateways/gateway-global", None, None).await, StatusCode::UNAUTHORIZED);
}

// ── auth-time enforcement of the tenant-selector classifier ──
//
// These tokens are created via a direct `store.create()` call (bypassing the
// issue-time `validate_scope_and_tenant_selector` check in the handlers), the
// same way a token issued before this hardening — or written directly to the
// store — would look. This proves `require_session_auth` itself fails closed
// (and can be opened via a configured trusted edge) independent of issue-time
// validation.

#[tokio::test]
async fn already_issued_broad_selector_token_fails_closed_without_trusted_edge() {
    let store = new_store().await;
    let (_, secret) = create_token(
        &store,
        Some("TENANT:${x-external-account}:gateways:.*"),
        vec![RequiredHeader {
            name: "x-external-account".to_string(),
            // Broad selector: an already-issued token bypassing issue-time
            // validation (e.g. pre-upgrade, or a direct store write).
            pattern: "[a-z0-9-]+".to_string(),
        }],
    )
    .await;
    let app = app(store); // no trusted_tenant_header configured

    assert_eq!(
        request(&app, "GET", "/v1/gateways/gateway-a", Some(&secret), Some("tenant-a")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn already_issued_broad_selector_token_is_honored_with_trusted_edge() {
    let store = new_store().await;
    let (_, secret) = create_token(
        &store,
        Some("TENANT:${x-external-account}:gateways:.*"),
        vec![RequiredHeader {
            name: "x-external-account".to_string(),
            pattern: "[a-z0-9-]+".to_string(),
        }],
    )
    .await;
    let app = app_with_trusted_tenant_header(
        store,
        Some(crate::tenancy::TrustedTenantHeader {
            header: "x-external-account".to_string(),
            edge_strips_client_values: true,
        }),
    );

    assert_eq!(request(&app, "GET", "/v1/gateways/gateway-a", Some(&secret), Some("tenant-a")).await, StatusCode::OK);
    assert_eq!(
        request(&app, "GET", "/v1/gateways/gateway-b", Some(&secret), Some("tenant-a")).await,
        StatusCode::NOT_FOUND
    );
}

fn tenant_selector_header() -> Vec<RequiredHeader> {
    vec![RequiredHeader {
        name: "x-external-account".to_string(),
        pattern: "tenant-a".to_string(),
    }]
}

async fn token_info_app(
    store: Arc<FsAccessTokenStore>,
    sessions: Arc<SessionManager>,
) -> (Router, tempfile::TempDir) {
    token_info_app_with_terms(store, sessions, Arc::new(crate::terms::TermsManager::disabled())).await
}

async fn token_info_app_with_terms(
    store: Arc<FsAccessTokenStore>,
    sessions: Arc<SessionManager>,
    terms: Arc<crate::terms::TermsManager>,
) -> (Router, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("tempdir");
    let user_storage = Arc::new(
        crate::auth::storage::PasskeyStorage::new(
            directory
                .path()
                .join("passkeys")
                .to_string_lossy()
                .to_string(),
            directory
                .path()
                .join("avatars")
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("user storage"),
    );
    let auth = AuthGuardState::new(sessions.clone(), None, terms).with_pat_authenticator(Some(store));
    let app = Router::new()
        .route("/v1/token-info", get(crate::auth_manager::permissions::get_token_info))
        .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
        .layer(Extension(sessions))
        .layer(Extension(user_storage))
        .layer(middleware::from_fn_with_state(auth, require_session_auth));
    (app, directory)
}

async fn token_info(
    app: &Router,
    bearer: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("GET")
        .uri("/v1/token-info");
    if let Some(bearer) = bearer {
        builder = builder.header("Authorization", format!("Bearer {bearer}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    if body.is_empty() {
        return (status, serde_json::Value::Null);
    }
    (status, serde_json::from_slice(&body).expect("json body"))
}

#[tokio::test]
async fn token_info_reports_a_scoped_pats_id_and_scopes() {
    let store = new_store().await;
    let (id, secret) = create_token_with_scopes(
        &store,
        None,
        Vec::new(),
        vec!["gateways.view".to_string(), "secrets.view".to_string()],
    )
    .await;
    let (app, _directory) = token_info_app(store, Arc::new(SessionManager::new())).await;

    let (status, body) = token_info(&app, Some(&secret), &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], "user-1");
    assert_eq!(body["token_id"], id);
    assert_eq!(body["scopes"], serde_json::json!(["gateways.view", "secrets.view"]));
    assert!(body.get("token").is_none());
    assert!(
        body.get("token_hash")
            .is_none()
    );
}

#[tokio::test]
async fn token_info_serves_a_tenant_scoped_pat_without_exposing_secrets() {
    let store = new_store().await;
    let (id, secret) =
        create_token(&store, Some("TENANT:${x-external-account}:gateways:.*"), tenant_selector_header()).await;
    let (app, _directory) = token_info_app(store, Arc::new(SessionManager::new())).await;

    let (status, body) = token_info(&app, Some(&secret), &[("x-external-account", "tenant-a")]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_id"], id);
    assert_eq!(body["user_id"], "user-1");
    let text = body.to_string();
    assert!(!text.contains(&secret));
    assert!(!text.contains(&hash_secret(&secret)));
    assert!(body.get("token").is_none());
    assert!(
        body.get("token_hash")
            .is_none()
    );
}

#[tokio::test]
async fn token_info_serves_a_tenant_scoped_pat_without_its_selector_header() {
    let store = new_store().await;
    let (id, secret) =
        create_token(&store, Some("TENANT:${x-external-account}:gateways:.*"), tenant_selector_header()).await;
    let (app, _directory) = token_info_app(store, Arc::new(SessionManager::new())).await;

    let (status, body) = token_info(&app, Some(&secret), &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], "user-1");
    assert_eq!(body["token_id"], id);
}

#[tokio::test]
async fn token_info_still_fails_closed_for_a_broad_selector_without_trusted_edge() {
    let store = new_store().await;
    let (_, secret) = create_token(
        &store,
        Some("TENANT:${x-external-account}:gateways:.*"),
        vec![RequiredHeader {
            name: "x-external-account".to_string(),
            pattern: "[a-z0-9-]+".to_string(),
        }],
    )
    .await;
    let (app, _directory) = token_info_app(store, Arc::new(SessionManager::new())).await;

    assert_eq!(
        token_info(&app, Some(&secret), &[])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn token_info_selector_exemption_does_not_cover_lookalike_paths() {
    let store = new_store().await;
    let (_, secret) =
        create_token(&store, Some("TENANT:${x-external-account}:gateways:.*"), tenant_selector_header()).await;
    let auth =
        AuthGuardState::new(Arc::new(SessionManager::new()), None, Arc::new(crate::terms::TermsManager::disabled()))
            .with_pat_authenticator(Some(store));
    let app = Router::new()
        .route("/v1/token-info/", get(accepted))
        .route("/v1/token-info/{rest}", get(accepted))
        .route("/v1/token-infox", get(accepted))
        .route("/api/v1/token-info/{rest}", get(accepted))
        .layer(middleware::from_fn_with_state(auth, require_session_auth));

    for path in ["/v1/token-info/", "/v1/token-info/x", "/v1/token-infox", "/api/v1/token-info/x"] {
        assert_eq!(request(&app, "GET", path, Some(&secret), None).await, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(request(&app, "GET", path, Some(&secret), Some("tenant-a")).await, StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn token_info_reports_null_scopes_for_an_unrestricted_pat() {
    let store = new_store().await;
    let (id, secret) = create_token(&store, None, Vec::new()).await;
    let (app, _directory) = token_info_app(store, Arc::new(SessionManager::new())).await;

    let (status, body) = token_info(&app, Some(&secret), &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_id"], id);
    assert!(body["scopes"].is_null());
}

#[tokio::test]
async fn token_info_reports_null_token_for_a_session_bearer() {
    let sessions = Arc::new(SessionManager::new());
    let session_token = sessions
        .create_session("alice".into(), "user-2".into())
        .await;
    let (app, _directory) = token_info_app(new_store().await, sessions).await;

    let (status, body) = token_info(&app, Some(&session_token), &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], "user-2");
    assert!(body["token_id"].is_null());
    assert!(body["scopes"].is_null());
}

#[tokio::test]
async fn token_info_accepts_a_session_from_the_cookie() {
    let sessions = Arc::new(SessionManager::new());
    let session_token = sessions
        .create_session("alice".into(), "user-2".into())
        .await;
    let (app, _directory) = token_info_app(new_store().await, sessions).await;

    let cookie = format!("session_token={session_token}");
    let (status, body) = token_info(&app, None, &[("cookie", &cookie)]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], "user-2");
    assert!(body["token_id"].is_null());
}

#[tokio::test]
async fn token_info_requires_the_pat_owner_to_accept_terms() {
    let terms_directory = tempfile::tempdir().expect("tempdir");
    let terms = crate::terms::TermsManager::open(
        true,
        "did:web:gateway.example".to_string(),
        terms_directory
            .path()
            .join("terms"),
        Some(crate::terms::TermsVersion {
            terms_type: crate::terms::TermsType::Affinidi,
            document_id: crate::terms::AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
            version_id: "terms-v1".to_string(),
            version: "1".to_string(),
            title: "Terms".to_string(),
            url: "https://example.com/terms".to_string(),
            requires_reconsent: true,
            published_at: Utc::now(),
            published_by: None,
        }),
    )
    .await
    .expect("terms manager");
    let store = new_store().await;
    let (_, secret) = create_token(&store, None, Vec::new()).await;
    let (app, _directory) = token_info_app_with_terms(store, Arc::new(SessionManager::new()), Arc::new(terms)).await;

    let (status, body) = token_info(&app, Some(&secret), &[]).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "TERMS_ACCEPTANCE_REQUIRED");
}

#[tokio::test]
async fn token_info_requires_authentication() {
    let (app, _directory) = token_info_app(new_store().await, Arc::new(SessionManager::new())).await;

    assert_eq!(
        token_info(&app, None, &[])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        token_info(&app, Some("agpat_not-a-real-token"), &[])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn token_info_rejects_a_revoked_pat() {
    let store = new_store().await;
    let (id, secret) = create_token(&store, None, Vec::new()).await;
    let (app, _directory) = token_info_app(store.clone(), Arc::new(SessionManager::new())).await;

    assert_eq!(
        token_info(&app, Some(&secret), &[])
            .await
            .0,
        StatusCode::OK
    );
    store
        .revoke(&id)
        .await
        .expect("revoke");
    assert_eq!(
        token_info(&app, Some(&secret), &[])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

async fn new_user_storage(
    role: crate::auth::types::UserRole
) -> (Arc<crate::auth::storage::PasskeyStorage>, String, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("tempdir");
    let users_dir = directory.path().join("users");
    let avatars_dir = directory
        .path()
        .join("avatars");
    std::fs::create_dir_all(&users_dir).expect("users dir");
    std::fs::create_dir_all(&avatars_dir).expect("avatars dir");
    std::fs::write(avatars_dir.join("default.png"), b"").expect("avatar");

    let user_id = uuid::Uuid::new_v4().to_string();
    let user = crate::auth::storage::UserData {
        user_id: user_id.clone(),
        username: "pat-owner".to_string(),
        passkeys: vec![],
        role,
        status: crate::auth::types::UserStatus::Approved,
        is_primary: false,
        first_name: None,
        last_name: None,
        email: None,
        department: None,
        job_title: None,
        avatar_path: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_logged_in: None,
        saml_id: None,
    };
    std::fs::write(users_dir.join(format!("{user_id}.json")), serde_json::to_string(&user).expect("user json"))
        .expect("write user");
    let storage = crate::auth::storage::PasskeyStorage::new(
        users_dir
            .to_string_lossy()
            .into_owned(),
        avatars_dir
            .to_string_lossy()
            .into_owned(),
    )
    .await
    .expect("user storage");
    (Arc::new(storage), user_id, directory)
}

async fn create_owned_token(
    store: &FsAccessTokenStore,
    user_id: &str,
    scopes: &[&str],
) -> String {
    let (id, secret) = generate_token();
    store
        .create(AccessToken {
            id,
            name: "scoped token".to_string(),
            description: String::new(),
            token_hash: hash_secret(&secret),
            user_id: user_id.to_string(),
            scopes: scopes
                .iter()
                .map(|scope| scope.to_string())
                .collect(),
            resource_pattern: None,
            required_headers: Vec::new(),
            created_by: user_id.to_string(),
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
        .expect("create token");
    secret
}

#[tokio::test]
async fn permissions_route_reports_only_a_scoped_pats_own_scopes() {
    let (users, user_id, _users_dir) = new_user_storage(crate::auth::types::UserRole::Administrator).await;
    let sessions = Arc::new(SessionManager::new());
    let store = new_store().await;
    let secret = create_owned_token(&store, &user_id, &["secrets.view", "issuers.view"]).await;

    let auth =
        AuthGuardState::new(sessions.clone(), Some(users.clone()), Arc::new(crate::terms::TermsManager::disabled()))
            .with_pat_authenticator(Some(store));
    let app = Router::new()
        .route("/v1/permissions", get(crate::auth_manager::permissions::get_permissions))
        .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
        .layer(middleware::from_fn_with_state(auth, require_session_auth))
        .layer(Extension(sessions))
        .layer(Extension(users))
        .layer(Extension(Arc::new(crate::rbac::RbacConfig::default())));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/permissions")
                .header("Authorization", format!("Bearer {secret}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .expect("cache-control"),
        "no-store"
    );
    assert_eq!(
        response
            .headers()
            .get("vary")
            .expect("vary"),
        "Authorization, Cookie"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let permissions: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let granted: Vec<&str> = permissions
        .as_object()
        .expect("object")
        .iter()
        .filter(|(_, value)| value.as_bool() == Some(true))
        .map(|(name, _)| name.as_str())
        .collect();
    let mut expected = vec!["departments.view", "issuers.view", "secrets.view"];
    let mut granted = granted;
    granted.sort_unstable();
    expected.sort_unstable();
    assert_eq!(granted, expected);
}

struct JwtStrategiesApp {
    app: Router,
    store: Arc<FsAccessTokenStore>,
    sessions: Arc<SessionManager>,
    user_id: String,
    // Held so the temp directories are removed when the test ends.
    _users_dir: tempfile::TempDir,
    _strategies_dir: tempfile::TempDir,
}

async fn jwt_strategies_app() -> JwtStrategiesApp {
    let (users, user_id, users_dir) = new_user_storage(crate::auth::types::UserRole::Administrator).await;
    let sessions = Arc::new(SessionManager::new());
    let store = new_store().await;
    let directory = tempfile::tempdir().expect("tempdir");
    let strategies = crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(directory.path().to_path_buf())
        .await
        .expect("strategy store");

    let auth =
        AuthGuardState::new(sessions.clone(), Some(users.clone()), Arc::new(crate::terms::TermsManager::disabled()))
            .with_pat_authenticator(Some(store.clone()));
    let app = crate::jwt_bearer::router::create_jwt_verification_strategies_router(Arc::new(strategies))
        .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
        .layer(middleware::from_fn_with_state(auth, require_session_auth))
        .layer(Extension(sessions.clone()))
        .layer(Extension(users))
        .layer(Extension(Arc::new(crate::rbac::RbacConfig::default())));
    JwtStrategiesApp {
        app,
        store,
        sessions,
        user_id,
        _users_dir: users_dir,
        _strategies_dir: directory,
    }
}

#[tokio::test]
async fn jwt_strategy_list_refuses_a_pat_without_the_view_scope() {
    let fixture = jwt_strategies_app().await;
    let secret = create_owned_token(&fixture.store, &fixture.user_id, &["secrets.view"]).await;

    assert_eq!(
        request(&fixture.app, "GET", "/v1/jwt-verification-strategies", Some(&secret), None).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn jwt_strategy_list_accepts_a_pat_with_the_view_scope() {
    let fixture = jwt_strategies_app().await;
    let secret = create_owned_token(&fixture.store, &fixture.user_id, &["jwt_verification_strategies.view"]).await;

    assert_eq!(
        request(&fixture.app, "GET", "/v1/jwt-verification-strategies", Some(&secret), None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn jwt_strategy_delete_refuses_a_pat_without_the_delete_scope() {
    let fixture = jwt_strategies_app().await;
    let secret = create_owned_token(&fixture.store, &fixture.user_id, &["jwt_verification_strategies.view"]).await;

    assert_eq!(
        request(&fixture.app, "DELETE", "/v1/jwt-verification-strategies/missing", Some(&secret), None).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn jwt_strategy_delete_lets_a_pat_with_the_delete_scope_reach_the_handler() {
    let fixture = jwt_strategies_app().await;
    let secret = create_owned_token(&fixture.store, &fixture.user_id, &["jwt_verification_strategies.delete"]).await;

    assert_eq!(
        request(&fixture.app, "DELETE", "/v1/jwt-verification-strategies/missing", Some(&secret), None).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn jwt_strategy_list_accepts_a_session_login_on_role_alone() {
    let fixture = jwt_strategies_app().await;
    let session = fixture
        .sessions
        .create_session("pat-owner".to_string(), fixture.user_id.clone())
        .await;

    assert_eq!(
        request(&fixture.app, "GET", "/v1/jwt-verification-strategies", Some(&session), None).await,
        StatusCode::OK
    );
}
