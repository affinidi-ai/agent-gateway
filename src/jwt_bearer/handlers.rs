//! JWT verification strategy CRUD HTTP handlers
//!
//! All endpoints require `Administrator` role.  Non-admin callers receive `403 Forbidden`.

use axum::{Extension, Json, extract::Path, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::jwt_bearer::{
    JwtVerificationStrategyStorage,
    models::{JwksSource, JwtVerificationStrategy},
};
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

// ── Shared state ──────────────────────────────────────────────────────────────

/// Axum state type for JWT verification strategy handlers.
pub type JwtVerificationStrategyState = Arc<dyn JwtVerificationStrategyStorage>;

// ── Request / response bodies ─────────────────────────────────────────────────

/// Body for `POST /v1/jwt-verification-strategies` and `PUT /v1/jwt-verification-strategies/{id}`.
#[derive(Debug, Deserialize)]
pub struct JwtVerificationStrategyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub expected_issuer: String,
    pub jwks_source: JwksSource,
}

/// Error response body.
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl ErrorBody {
    fn json(msg: impl Into<String>) -> Json<Self> {
        Json(Self { error: msg.into() })
    }
}

// ── RBAC helper ───────────────────────────────────────────────────────────────

async fn require_permission(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
    feature: &Feature,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let user = storage
        .load_user_by_id(user_id)
        .await
        .map_err(|e| {
            error!("Failed to load user {} for RBAC check: {}", user_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))
        })?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, ErrorBody::json("User not found")))?;

    if !rbac_config.has_permission(&user.role, feature) {
        warn!(
            user_id = %user_id,
            feature = %feature.as_str(),
            "JWT verification strategy CRUD rejected — insufficient permissions"
        );
        return Err((StatusCode::FORBIDDEN, ErrorBody::json("Insufficient permissions")));
    }
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `POST /v1/jwt-verification-strategies`  — create a new strategy.
pub async fn create_strategy(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<JwtVerificationStrategyState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut body): Json<JwtVerificationStrategyRequest>,
) -> impl IntoResponse {
    if let Err(e) =
        require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::JwtVerificationStrategiesEdit).await
    {
        return e.into_response();
    }

    // Enforce the appliance credentials limit (per-type plus the total).
    if let Err(e) = crate::config::enforce_add("credentials.jwt").await {
        return (StatusCode::FORBIDDEN, ErrorBody::json(e.message())).into_response();
    }

    if let JwksSource::Remote { ref jwks_uri } = body.jwks_source
        && let Err(e) = crate::url_validation::validate_url_not_cloud_metadata(jwks_uri)
    {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(format!("jwks_uri rejected: {}", e))).into_response();
    }

    body.tenant_id = match tenant_for_create(body.tenant_id.take(), pat.is_some(), tenant_context(&context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => return (StatusCode::FORBIDDEN, ErrorBody::json(message)).into_response(),
    };
    let id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::JwtVerificationStrategies,
        &id,
    ) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("strategy is outside this token's permitted scope"))
            .into_response();
    }

    let strategy = JwtVerificationStrategy {
        id,
        tenant_id: body.tenant_id,
        name: body.name,
        expected_issuer: body.expected_issuer,
        jwks_source: body.jwks_source,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    match store.create(strategy).await {
        Ok(created) => {
            info!(id = %created.id, name = %created.name, "JWT verification strategy created");
            (StatusCode::CREATED, Json(created)).into_response()
        }
        Err(e) => {
            error!("Failed to create JWT verification strategy: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to create strategy")).into_response()
        }
    }
}

/// `GET /v1/jwt-verification-strategies`  — list all strategies.
pub async fn list_strategies(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<JwtVerificationStrategyState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) =
        require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::JwtVerificationStrategiesView).await
    {
        return e.into_response();
    }

    match store.list().await {
        Ok(mut strategies) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            strategies.retain(|strategy| {
                can_access(strategy.tenant_id.as_deref(), context)
                    && scope_allows_resource(scope, context, ResourceKind::JwtVerificationStrategies, &strategy.id)
            });
            strategies.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
            });
            (StatusCode::OK, Json(strategies)).into_response()
        }
        Err(e) => {
            error!("Failed to list JWT verification strategies: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to list strategies")).into_response()
        }
    }
}

/// `GET /v1/jwt-verification-strategies/{id}`  — get a strategy by UUID.
pub async fn get_strategy(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<JwtVerificationStrategyState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) =
        require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::JwtVerificationStrategiesView).await
    {
        return e.into_response();
    }

    match store.get(&id).await {
        Ok(Some(strategy))
            if can_access(strategy.tenant_id.as_deref(), tenant_context(&context))
                && scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::JwtVerificationStrategies,
                    &strategy.id,
                ) =>
        {
            (StatusCode::OK, Json(strategy)).into_response()
        }
        Ok(Some(_)) => (StatusCode::NOT_FOUND, ErrorBody::json(format!("Strategy '{}' not found", id))).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, ErrorBody::json(format!("Strategy '{}' not found", id))).into_response(),
        Err(e) => {
            error!("Failed to get JWT verification strategy {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to get strategy")).into_response()
        }
    }
}

/// `PUT /v1/jwt-verification-strategies/{id}`  — update a strategy.  The `id` cannot change.
pub async fn update_strategy(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<JwtVerificationStrategyState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(body): Json<JwtVerificationStrategyRequest>,
) -> impl IntoResponse {
    if let Err(e) =
        require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::JwtVerificationStrategiesEdit).await
    {
        return e.into_response();
    }

    let existing = match store.get(&id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, ErrorBody::json(format!("Strategy '{}' not found", id))).into_response();
        }
        Err(e) => {
            error!("Failed to load JWT verification strategy {} for update: {}", id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to load strategy")).into_response();
        }
    };
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::JwtVerificationStrategies,
            &existing.id,
        )
    {
        return (StatusCode::FORBIDDEN, ErrorBody::json("strategy is outside this token's permitted scope"))
            .into_response();
    }

    if let JwksSource::Remote { ref jwks_uri } = body.jwks_source
        && let Err(e) = crate::url_validation::validate_url_not_cloud_metadata(jwks_uri)
    {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(format!("jwks_uri rejected: {}", e))).into_response();
    }

    let updated = JwtVerificationStrategy {
        id: existing.id.clone(),
        tenant_id: existing.tenant_id,
        name: body.name,
        expected_issuer: body.expected_issuer,
        jwks_source: body.jwks_source,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    match store.update(updated).await {
        Ok(strategy) => {
            info!(id = %strategy.id, name = %strategy.name, "JWT verification strategy updated");
            (StatusCode::OK, Json(strategy)).into_response()
        }
        Err(e) => {
            error!("Failed to update JWT verification strategy {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to update strategy")).into_response()
        }
    }
}

/// `DELETE /v1/jwt-verification-strategies/{id}`  — delete a strategy.
pub async fn delete_strategy(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<JwtVerificationStrategyState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) =
        require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::JwtVerificationStrategiesDelete).await
    {
        return e.into_response();
    }

    let existing = match store.get(&id).await {
        Ok(Some(strategy)) => strategy,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, ErrorBody::json(format!("Strategy '{}' not found", id))).into_response();
        }
        Err(error) => {
            error!(%error, "Failed to load JWT strategy before deletion");
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to load strategy")).into_response();
        }
    };
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::JwtVerificationStrategies,
            &existing.id,
        )
    {
        return (StatusCode::FORBIDDEN, ErrorBody::json("strategy is outside this token's permitted scope"))
            .into_response();
    }

    match store.delete(&id).await {
        Ok(()) => {
            info!(id = %id, "JWT verification strategy deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            error!("Failed to delete JWT verification strategy {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to delete strategy")).into_response()
        }
    }
}

// ── JWKS URI validation ───────────────────────────────────────────────────────

/// Query parameters for `GET /v1/jwt-verification-strategies/validate-jwks-uri`.
#[derive(Debug, Deserialize)]
pub struct JwksUriQuery {
    pub uri: String,
}

/// Response body for `GET /v1/jwt-verification-strategies/validate-jwks-uri`.
#[derive(Debug, Serialize)]
pub struct JwksUriValidationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `POST /v1/jwt-verification-strategies/validate-jwks-uri`
///
/// Probes whether the given URI is reachable and returns a parseable JWKS.
/// Returns `200 OK` with `{ "valid": true, "key_count": N }` on success, or
/// `400 Bad Request` with `{ "valid": false, "error": "…" }` on failure.
///
/// Requires `JwtVerificationStrategiesView` (or `Edit`) permission.
pub async fn validate_jwks_uri(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<crate::auth::storage::PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<crate::rbac::RbacConfig>>,
    Extension(jwks_client): Extension<Arc<crate::jwt_bearer::JwksClient>>,
    Json(params): Json<JwksUriQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &crate::rbac::Feature::JwtVerificationStrategiesView,
    )
    .await
    {
        return e.into_response();
    }

    match jwks_client
        .fetch_jwks(&params.uri)
        .await
    {
        Ok(jwks) => {
            info!(uri = %params.uri, key_count = %jwks.keys.len(), "JWKS URI validation succeeded");
            (
                StatusCode::OK,
                Json(JwksUriValidationResponse {
                    valid: true,
                    key_count: Some(jwks.keys.len()),
                    error: None,
                }),
            )
                .into_response()
        }
        Err(e) => {
            warn!(uri = %params.uri, error = %e, "JWKS URI validation failed");
            (
                StatusCode::BAD_REQUEST,
                Json(JwksUriValidationResponse {
                    valid: false,
                    key_count: None,
                    error: Some(e.to_string()),
                }),
            )
                .into_response()
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::jwt_bearer::{
        models::JwtVerificationStrategy, router::create_jwt_verification_strategies_router,
        storage::JwtVerificationStrategyStorage,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
    };
    use chrono::Utc;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;

    // ── in-memory strategy store ──────────────────────────────────────────────

    #[derive(Clone, Default)]
    struct MemStore {
        inner: Arc<dashmap::DashMap<String, JwtVerificationStrategy>>,
    }

    #[async_trait]
    impl JwtVerificationStrategyStorage for MemStore {
        async fn create(
            &self,
            mut s: JwtVerificationStrategy,
        ) -> Result<JwtVerificationStrategy> {
            s.id = uuid::Uuid::new_v4().to_string();
            s.created_at = Utc::now();
            s.updated_at = Utc::now();
            self.inner
                .insert(s.id.clone(), s.clone());
            Ok(s)
        }
        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<JwtVerificationStrategy>> {
            Ok(self
                .inner
                .get(id)
                .map(|e| e.clone()))
        }
        async fn list(&self) -> Result<Vec<JwtVerificationStrategy>> {
            Ok(self
                .inner
                .iter()
                .map(|e| e.clone())
                .collect())
        }
        async fn update(
            &self,
            s: JwtVerificationStrategy,
        ) -> Result<JwtVerificationStrategy> {
            if !self.inner.contains_key(&s.id) {
                anyhow::bail!("strategy not found: {}", s.id);
            }
            self.inner
                .insert(s.id.clone(), s.clone());
            Ok(s)
        }
        async fn delete(
            &self,
            id: &str,
        ) -> Result<()> {
            self.inner.remove(id);
            Ok(())
        }
    }

    // ── PasskeyStorage backed by TempDir ──────────────────────────────────────

    async fn make_passkey_storage(role: UserRole) -> (PasskeyStorage, TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let users_dir = dir.path().join("users");
        let avatars_dir = dir.path().join("avatars");
        std::fs::create_dir_all(&users_dir).unwrap();
        std::fs::create_dir_all(&avatars_dir).unwrap();
        std::fs::write(avatars_dir.join("default.png"), b"").unwrap();

        let user_id = uuid::Uuid::new_v4().to_string();
        let user_data = UserData {
            user_id: user_id.clone(),
            username: "testuser".to_string(),
            passkeys: vec![],
            role,
            status: UserStatus::Approved,
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
        std::fs::write(users_dir.join(format!("{}.json", user_id)), serde_json::to_string(&user_data).unwrap())
            .unwrap();

        let storage = PasskeyStorage::new(
            users_dir
                .to_string_lossy()
                .into_owned(),
            avatars_dir
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();

        (storage, dir, user_id)
    }

    // ── Test router builder ────────────────────────────────────────────────────────

    fn build_test_router(
        store: Arc<MemStore>,
        passkey_storage: Arc<PasskeyStorage>,
        rbac_config: Arc<RbacConfig>,
        user_id: String,
        jwks_client: Arc<crate::jwt_bearer::JwksClient>,
    ) -> Router {
        create_jwt_verification_strategies_router(store)
            .layer(middleware::from_fn(move |mut req: axum::extract::Request, next: middleware::Next| {
                let uid = user_id.clone();
                let ps = passkey_storage.clone();
                let rbac = rbac_config.clone();
                async move {
                    req.extensions_mut()
                        .insert(uid);
                    req.extensions_mut()
                        .insert(ps);
                    req.extensions_mut()
                        .insert(rbac);
                    next.run(req).await
                }
            }))
            .layer(Extension(jwks_client))
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    async fn response_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn strategy_json(name: &str) -> String {
        serde_json::json!({
            "name": name,
            "expected_issuer": "https://issuer.example.com",
            "jwks_source": { "type": "remote", "jwks_uri": "https://issuer.example.com/.well-known/jwks.json" }
        })
        .to_string()
    }

    fn assert_strategy_fields(
        actual: &serde_json::Value,
        expected: &serde_json::Value,
    ) {
        let expected_obj = expected
            .as_object()
            .expect("expected must be a JSON object");
        for (key, expected_val) in expected_obj {
            assert_eq!(
                &actual[key], expected_val,
                "field '{}' mismatch: got {}, expected {}",
                key, actual[key], expected_val
            );
        }
    }

    async fn create_via_api(
        router: &Router,
        name: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/jwt-verification-strategies")
            .header("content-type", "application/json")
            .body(Body::from(strategy_json(name)))
            .unwrap();
        let resp = router
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        let status = resp.status();
        (status, response_body(resp).await)
    }

    // ── CRUD handler tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_without_name_returns_422() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/jwt-verification-strategies")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "expected_issuer": "https://issuer.example.com",
                    "jwks_source": { "type": "remote", "jwks_uri": "https://issuer.example.com/.well-known/jwks.json" }
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            router
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn test_create_returns_201_with_generated_id() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let (status, body) = create_via_api(&router, "Acme IdP").await;
        assert_eq!(status, StatusCode::CREATED);
        let id = body["id"]
            .as_str()
            .expect("response must contain a string 'id'");
        assert!(!id.is_empty(), "id must be a non-empty generated UUID");
        assert_strategy_fields(
            &body,
            &serde_json::json!({ "name": "Acme IdP", "expected_issuer": "https://issuer.example.com" }),
        );
    }

    #[tokio::test]
    async fn test_list_returns_200_and_all_strategies() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let (_, strategy_a) = create_via_api(&router, "Strategy A").await;
        let (_, strategy_b) = create_via_api(&router, "Strategy B").await;

        let req = Request::builder()
            .method("GET")
            .uri("/v1/jwt-verification-strategies")
            .body(Body::empty())
            .unwrap();
        let resp = router
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        let strategies = body.as_array().unwrap();
        assert_eq!(strategies.len(), 2);

        for expected in &[&strategy_a, &strategy_b] {
            let id = expected["id"]
                .as_str()
                .unwrap();
            let found = strategies
                .iter()
                .find(|s| s["id"] == id)
                .unwrap_or_else(|| panic!("strategy with id '{}' must be in the list", id));
            assert_strategy_fields(found, expected);
        }
    }

    #[tokio::test]
    async fn test_get_returns_200_for_existing_strategy() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let (_, created) = create_via_api(&router, "My IdP").await;
        let id = created["id"]
            .as_str()
            .unwrap()
            .to_string();

        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/jwt-verification-strategies/{}", id))
            .body(Body::empty())
            .unwrap();
        let resp = router
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert_strategy_fields(&body, &created);
    }

    #[tokio::test]
    async fn test_get_returns_404_for_missing_strategy() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("GET")
            .uri("/v1/jwt-verification-strategies/00000000-dead-beef-0000-000000000000")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_update_returns_200_and_preserves_id() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let (_, created) = create_via_api(&router, "Original Name").await;
        let id = created["id"]
            .as_str()
            .unwrap()
            .to_string();

        let update_request = serde_json::json!({
            "name": "Updated Name",
            "expected_issuer": "https://updated.example.com",
            "jwks_source": { "type": "remote", "jwks_uri": "https://updated.example.com/.well-known/jwks.json" }
        });

        let req = Request::builder()
            .method("PUT")
            .uri(format!("/v1/jwt-verification-strategies/{}", id))
            .header("content-type", "application/json")
            .body(Body::from(update_request.to_string()))
            .unwrap();
        let resp = router
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert_eq!(body["id"], id.as_str(), "id must not change on update");
        assert_strategy_fields(
            &body,
            &serde_json::json!({ "name": "Updated Name", "expected_issuer": "https://updated.example.com" }),
        );
    }

    #[tokio::test]
    async fn test_update_returns_404_for_missing_strategy() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("PUT")
            .uri("/v1/jwt-verification-strategies/00000000-dead-beef-0000-000000000000")
            .header("content-type", "application/json")
            .body(Body::from(strategy_json("X")))
            .unwrap();
        assert_eq!(
            router
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_delete_returns_204_and_strategy_is_gone() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let (_, created) = create_via_api(&router, "ToDelete").await;
        let id = created["id"]
            .as_str()
            .unwrap()
            .to_string();

        let del_req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/jwt-verification-strategies/{}", id))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router
                .clone()
                .oneshot(del_req)
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/jwt-verification-strategies/{}", id))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router
                .oneshot(get_req)
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    // ── RBAC enforcement tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_non_admin_create_returns_403() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::User).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/jwt-verification-strategies")
            .header("content-type", "application/json")
            .body(Body::from(strategy_json("X")))
            .unwrap();
        assert_eq!(
            router
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_non_admin_list_returns_403() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::User).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("GET")
            .uri("/v1/jwt-verification-strategies")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_non_admin_delete_returns_403() {
        let store = Arc::new(MemStore::default());
        let (admin_ps, _admin_dir, admin_uid) = make_passkey_storage(UserRole::Administrator).await;
        let admin_jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let admin_router = build_test_router(
            store.clone(),
            Arc::new(admin_ps),
            Arc::new(RbacConfig::default()),
            admin_uid,
            admin_jwks_client,
        );
        let (_, created) = create_via_api(&admin_router, "Protected").await;
        let id = created["id"]
            .as_str()
            .unwrap()
            .to_string();

        let (user_ps, _user_dir, user_uid) = make_passkey_storage(UserRole::User).await;
        let user_jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let user_router =
            build_test_router(store, Arc::new(user_ps), Arc::new(RbacConfig::default()), user_uid, user_jwks_client);
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/jwt-verification-strategies/{}", id))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            user_router
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    // ── validate_jwks_uri tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_validate_jwks_uri_returns_200_with_valid_uri() {
        use crate::jwt_bearer::test_utils::{rsa_jwks_body, start_jwks_server};

        let jwks_body = rsa_jwks_body("key1", "sEzp_testN", "AQAB");
        let (base_url, _server) = start_jwks_server(jwks_body, None).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base_url);

        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/jwt-verification-strategies/validate-jwks-uri")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "uri": jwks_uri }).to_string()))
            .unwrap();
        let resp = router
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert_eq!(body["valid"], true);
        assert_eq!(body["key_count"], 1);
    }

    #[tokio::test]
    async fn test_validate_jwks_uri_returns_400_with_invalid_uri() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/jwt-verification-strategies/validate-jwks-uri")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "uri": "http://127.0.0.1:1/jwks.json" }).to_string()))
            .unwrap();
        let resp = router
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_body(resp).await;
        assert_eq!(body["valid"], false);
        assert!(
            body["error"]
                .as_str()
                .is_some(),
            "error field must be a string"
        );
    }

    #[tokio::test]
    async fn test_validate_jwks_uri_non_admin_returns_403() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::User).await;
        let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks_client);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/jwt-verification-strategies/validate-jwks-uri")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "uri": "https://example.com/jwks.json" }).to_string()))
            .unwrap();
        assert_eq!(
            router
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}
