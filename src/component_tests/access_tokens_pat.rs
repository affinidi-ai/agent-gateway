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
    let (id, secret) = generate_token();
    store
        .create(AccessToken {
            id: id.clone(),
            name: "component token".to_string(),
            description: String::new(),
            token_hash: hash_secret(&secret),
            user_id: "user-1".to_string(),
            scopes: Vec::new(),
            resource_pattern: pattern.map(str::to_string),
            required_headers: headers,
            created_by: "user-1".to_string(),
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

#[tokio::test]
async fn rotation_through_the_api_swaps_the_pat_secret_in_place() {
    let store = new_store().await;
    let (id, old_secret) = create_token(&store, None, Vec::new()).await;
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
    let now = Utc::now();
    users
        .save_user(&UserData {
            user_id: "user-1".to_string(),
            username: "user-1".to_string(),
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
        .expect("save user");
    let rbac = Arc::new(crate::rbac::RbacConfig::default());
    let auth =
        AuthGuardState::new(Arc::new(SessionManager::new()), None, Arc::new(crate::terms::TermsManager::disabled()))
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

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/access-tokens/{id}/rotate"))
                .header("Authorization", format!("Bearer {old_secret}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(body["id"], id);
    assert_eq!(body["name"], "component token");
    let new_secret = body["token"]
        .as_str()
        .expect("new secret")
        .to_string();
    assert_ne!(new_secret, old_secret);

    assert_eq!(
        request(&app, "GET", "/v1/gateways/gateway-global", Some(&old_secret), None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(request(&app, "GET", "/v1/gateways/gateway-global", Some(&new_secret), None).await, StatusCode::OK);
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
