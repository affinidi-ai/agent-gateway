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
    create_token_owned_by(store, "user-1", pattern, headers).await
}

async fn create_token_owned_by(
    store: &FsAccessTokenStore,
    owner: &str,
    pattern: Option<&str>,
    headers: Vec<RequiredHeader>,
) -> (String, String) {
    let (id, secret) = generate_token();
    store
        .create(AccessToken {
            id: id.clone(),
            name: "component token".to_string(),
            description: String::new(),
            token_hash: hash_secret(&secret),
            user_id: owner.to_string(),
            scopes: Vec::new(),
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
