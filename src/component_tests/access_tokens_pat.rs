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
use crate::auth_manager::middleware::{AuthGuardState, require_session_auth};
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
    create_token_with_scopes(store, pattern, headers, Vec::new()).await
}

async fn create_token_with_scopes(
    store: &FsAccessTokenStore,
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
            user_id: "user-1".to_string(),
            scopes,
            resource_pattern: pattern.map(str::to_string),
            required_headers: headers,
            created_by: "user-1".to_string(),
            parent_token_id: None,
            delegation_depth: 0,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
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

async fn token_info_app(
    store: Arc<FsAccessTokenStore>,
    sessions: Arc<SessionManager>,
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
    let auth = AuthGuardState::new(sessions.clone(), None, Arc::new(crate::terms::TermsManager::disabled()))
        .with_pat_authenticator(Some(store));
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
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("GET")
        .uri("/v1/token-info");
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
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
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

    let (status, body) = token_info(&app, Some(&secret)).await;

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
async fn token_info_reports_null_scopes_for_an_unrestricted_pat() {
    let store = new_store().await;
    let (id, secret) = create_token(&store, None, Vec::new()).await;
    let (app, _directory) = token_info_app(store, Arc::new(SessionManager::new())).await;

    let (status, body) = token_info(&app, Some(&secret)).await;

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

    let (status, body) = token_info(&app, Some(&session_token)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], "user-2");
    assert!(body["token_id"].is_null());
    assert!(body["scopes"].is_null());
}

#[tokio::test]
async fn token_info_requires_authentication() {
    let (app, _directory) = token_info_app(new_store().await, Arc::new(SessionManager::new())).await;

    assert_eq!(token_info(&app, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        token_info(&app, Some("agpat_not-a-real-token"))
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
        token_info(&app, Some(&secret))
            .await
            .0,
        StatusCode::OK
    );
    store
        .revoke(&id)
        .await
        .expect("revoke");
    assert_eq!(
        token_info(&app, Some(&secret))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
