//! JWT verification strategy CRUD HTTP handlers
//!
//! Every endpoint requires the caller's role to grant the endpoint's
//! `jwt_verification_strategies.*` feature. A personal access token restricted
//! to explicit feature scopes must also include that feature. Otherwise the
//! caller receives `403 Forbidden`.

use axum::{Extension, Json, extract::Path, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::middleware::pat_scope_allows;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::jwt_bearer::{
    JwtVerificationStrategyStorage,
    models::{JwksSource, JwtVerificationStrategy, normalize_principal_claim},
};
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};

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

/// Refuses a remote `jwks_uri` the JWKS fetch would refuse: one that is not an
/// http(s) URL or whose host resolves to loopback, an unspecified address or
/// cloud metadata. A host that does
/// not resolve now is saved, and is vetted again on every fetch.
async fn check_jwks_source(source: &JwksSource) -> Result<(), axum::response::Response> {
    let JwksSource::Remote { jwks_uri } = source else {
        return Ok(());
    };
    match crate::jwt_bearer::jwks::vet_jwks_uri(jwks_uri).await {
        Err(crate::jwt_bearer::errors::JwtBearerError::JwksUriBlocked) => {
            Err((StatusCode::BAD_REQUEST, ErrorBody::json(JWKS_URI_BLOCKED)).into_response())
        }
        _ => Ok(()),
    }
}

/// Why a `jwks_uri` is refused on save and by the probe.
const JWKS_URI_BLOCKED: &str = "jwks_uri rejected: it must be an http(s) URL without a user name or password whose host resolves to neither loopback nor cloud metadata";

/// The probe's answer for a `jwks_uri` it could vet but not use.
const JWKS_URI_UNUSABLE: &str = "jwks_uri could not be fetched or did not return a valid JWKS";

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
    #[serde(default)]
    pub principal_claim: Option<String>,
}

/// A `Warning` header for each other strategy of `saved`'s tenant scope that
/// names callers of the same issuer by a different claim. An issuer names
/// callers by one claim in a tenant, so token exchange and `jwt-bearer`
/// redemption refuse that issuer's tokens until one of them is deleted.
async fn mixed_claim_warnings(
    store: &dyn JwtVerificationStrategyStorage,
    saved: &JwtVerificationStrategy,
) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    let Ok(claim) = saved.principal_claim_name() else {
        return headers;
    };
    let Ok(strategies) = store.list().await else {
        return headers;
    };
    for other in strategies
        .iter()
        .filter(|other| {
            other.id != saved.id && other.tenant_id == saved.tenant_id && other.expected_issuer == saved.expected_issuer
        })
    {
        let Ok(other_claim) = other.principal_claim_name() else {
            continue;
        };
        if other_claim == claim {
            continue;
        }
        let warning = format!(
            "JWT verification strategy '{}' names callers of issuer '{}' by '{other_claim}', and this one by \
             '{claim}': an issuer names callers by one claim in a tenant, so token exchange and jwt-bearer \
             redemption refuse its tokens until one of the two is deleted",
            other.id, saved.expected_issuer
        );
        warn!(strategy_id = %saved.id, other_strategy_id = %other.id, "{warning}");
        if let Some(value) = crate::identity::handlers::surfaces::warning_header(&warning) {
            headers.append(axum::http::header::WARNING, value);
        }
    }
    headers
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
    pat: Option<&PatContext>,
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
    if !pat_scope_allows(pat, feature) {
        warn!(
            user_id = %user_id,
            feature = %feature.as_str(),
            "JWT verification strategy CRUD rejected — access-token scope excludes permission"
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
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::JwtVerificationStrategiesEdit,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }

    // Enforce the appliance credentials limit (per-type plus the total).
    if let Err(e) = crate::config::enforce_add("credentials.jwt").await {
        return (StatusCode::FORBIDDEN, ErrorBody::json(e.message())).into_response();
    }

    if let Err(response) = check_jwks_source(&body.jwks_source).await {
        return response;
    }

    let principal_claim = match normalize_principal_claim(
        body.principal_claim
            .as_deref(),
    ) {
        Ok(claim) => claim,
        Err(message) => return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response(),
    };

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
        principal_claim,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    match store.create(strategy).await {
        Ok(created) => {
            info!(id = %created.id, name = %created.name, "JWT verification strategy created");
            let warnings = mixed_claim_warnings(store.as_ref(), &created).await;
            (StatusCode::CREATED, warnings, Json(created)).into_response()
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
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::JwtVerificationStrategiesView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
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
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::JwtVerificationStrategiesView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
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
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(body): Json<JwtVerificationStrategyRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::JwtVerificationStrategiesEdit,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
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
        return (StatusCode::NOT_FOUND, ErrorBody::json(format!("Strategy '{}' not found", id))).into_response();
    }
    if !can_mutate(existing.tenant_id.as_deref(), tenant_context(&context)) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("strategy is outside this token's permitted scope"))
            .into_response();
    }

    if let Err(response) = check_jwks_source(&body.jwks_source).await {
        return response;
    }

    // A stored claim the API would refuse is kept as it is: it names no caller
    // when used, and no request can name it, so it can only be replaced by a new
    // strategy.
    let stored_claim = existing
        .normalized_principal_claim()
        .unwrap_or_else(|_| {
            existing
                .principal_claim
                .clone()
        });
    if let Some(requested) = body
        .principal_claim
        .as_deref()
    {
        let requested = match normalize_principal_claim(Some(requested)) {
            Ok(claim) => claim,
            Err(message) => return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response(),
        };
        if requested != stored_claim {
            return (
                StatusCode::BAD_REQUEST,
                ErrorBody::json(
                    "principal_claim cannot be changed after creation: create a new strategy and point the surface at it",
                ),
            )
                .into_response();
        }
    }

    let updated = JwtVerificationStrategy {
        id: existing.id.clone(),
        tenant_id: existing.tenant_id,
        name: body.name,
        expected_issuer: body.expected_issuer,
        jwks_source: body.jwks_source,
        principal_claim: stored_claim,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    match store.update(updated).await {
        Ok(strategy) => {
            info!(id = %strategy.id, name = %strategy.name, "JWT verification strategy updated");
            let warnings = mixed_claim_warnings(store.as_ref(), &strategy).await;
            (StatusCode::OK, warnings, Json(strategy)).into_response()
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
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::JwtVerificationStrategiesDelete,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
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
        return (StatusCode::NOT_FOUND, ErrorBody::json(format!("Strategy '{}' not found", id))).into_response();
    }
    if !can_mutate(existing.tenant_id.as_deref(), tenant_context(&context)) {
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

/// JSON request body for `POST /v1/jwt-verification-strategies/validate-jwks-uri`.
#[derive(Debug, Deserialize)]
pub struct JwksUriQuery {
    pub uri: String,
}

/// Response body for `POST /v1/jwt-verification-strategies/validate-jwks-uri`.
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
/// Probes whether the given URI passes the Configured egress policy and returns a
/// parseable JWKS. Returns `200 OK` with `{ "valid": true, "key_count": N }` on
/// success, or `400 Bad Request` with `{ "valid": false, "error": "…" }` on
/// failure, where `error` is one of two fixed messages and the detail is only
/// logged.
///
/// Requires `JwtVerificationStrategiesEdit`. A personal access token restricted
/// to explicit feature scopes must also include that feature.
pub async fn validate_jwks_uri(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<crate::auth::storage::PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<crate::rbac::RbacConfig>>,
    Extension(jwks_client): Extension<Arc<crate::jwt_bearer::JwksClient>>,
    pat: Option<Extension<PatContext>>,
    Json(params): Json<JwksUriQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &crate::rbac::Feature::JwtVerificationStrategiesEdit,
        pat.as_ref()
            .map(|Extension(pat)| pat),
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
            let error = match e {
                crate::jwt_bearer::errors::JwtBearerError::JwksUriBlocked => JWKS_URI_BLOCKED,
                _ => JWKS_URI_UNUSABLE,
            };
            (
                StatusCode::BAD_REQUEST,
                Json(JwksUriValidationResponse {
                    valid: false,
                    key_count: None,
                    error: Some(error.to_string()),
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

    async fn send_strategy(
        router: &Router,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router
            .clone()
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        (status, response_body(response).await)
    }

    fn strategy_body(principal_claim: Option<&str>) -> serde_json::Value {
        let mut body = serde_json::json!({
            "name": "Entra callers",
            "expected_issuer": "https://login.example.com/tenant/v2.0",
            "jwks_source": { "type": "remote", "jwks_uri": "https://login.example.com/tenant/keys" }
        });
        if let Some(claim) = principal_claim {
            body["principal_claim"] = serde_json::json!(claim);
        }
        body
    }

    #[tokio::test]
    async fn a_strategy_stores_the_principal_claim_it_is_created_with() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store,
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );

        let (status, created) =
            send_strategy(&router, "POST", "/v1/jwt-verification-strategies", strategy_body(Some("oid"))).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["principal_claim"], "oid");

        let (_, read) = send_strategy(
            &router,
            "GET",
            &format!(
                "/v1/jwt-verification-strategies/{}",
                created["id"]
                    .as_str()
                    .unwrap()
            ),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(read["principal_claim"], "oid");

        let (status, default) =
            send_strategy(&router, "POST", "/v1/jwt-verification-strategies", strategy_body(None)).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(
            default
                .get("principal_claim")
                .is_none(),
            "the default claim is not stored: {default}"
        );

        let (status, named_default) =
            send_strategy(&router, "POST", "/v1/jwt-verification-strategies", strategy_body(Some("sub"))).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(
            named_default
                .get("principal_claim")
                .is_none(),
            "naming sub is the default: {named_default}"
        );
    }

    #[tokio::test]
    async fn a_principal_claim_that_does_not_name_a_caller_is_refused() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store,
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        for claim in ["", "two words", "iss", "aud", "exp", "jti", "tid", "azp", "client_id", &"x".repeat(129)] {
            let (status, body) =
                send_strategy(&router, "POST", "/v1/jwt-verification-strategies", strategy_body(Some(claim))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{claim:?}: {body}");
        }
    }

    #[tokio::test]
    async fn the_principal_claim_cannot_be_changed_after_creation() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store,
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        let (_, created) =
            send_strategy(&router, "POST", "/v1/jwt-verification-strategies", strategy_body(Some("oid"))).await;
        let path = format!(
            "/v1/jwt-verification-strategies/{}",
            created["id"]
                .as_str()
                .unwrap()
        );

        for other in [Some("email"), Some("sub")] {
            let (status, body) = send_strategy(&router, "PUT", &path, strategy_body(other)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{other:?}: {body}");
            assert!(
                body["error"]
                    .as_str()
                    .unwrap()
                    .contains("cannot be changed"),
                "{body}"
            );
        }

        let (status, same) = send_strategy(&router, "PUT", &path, strategy_body(Some("oid"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(same["principal_claim"], "oid");

        let (status, omitted) = send_strategy(&router, "PUT", &path, strategy_body(None)).await;
        assert_eq!(status, StatusCode::OK, "an update that does not mention the claim keeps it");
        assert_eq!(omitted["principal_claim"], "oid");

        let (_, default) = send_strategy(&router, "POST", "/v1/jwt-verification-strategies", strategy_body(None)).await;
        let default_path = format!(
            "/v1/jwt-verification-strategies/{}",
            default["id"]
                .as_str()
                .unwrap()
        );
        let (status, named_default) = send_strategy(&router, "PUT", &default_path, strategy_body(Some("sub"))).await;
        assert_eq!(status, StatusCode::OK, "naming sub on a default strategy is no change: {named_default}");
        assert!(
            named_default
                .get("principal_claim")
                .is_none()
        );
    }

    /// A strategy that names callers of an issuer by a claim another strategy
    /// of its tenant scope does not is saved with a warning, since STS then
    /// refuses that issuer's tokens; one that agrees is not warned of.
    #[tokio::test]
    async fn a_second_claim_for_one_issuer_is_saved_with_a_warning() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store,
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        let create = |claim: Option<&str>| {
            Request::builder()
                .method("POST")
                .uri("/v1/jwt-verification-strategies")
                .header("content-type", "application/json")
                .body(Body::from(strategy_body(claim).to_string()))
                .unwrap()
        };
        let warnings = |response: &axum::response::Response| -> Vec<String> {
            response
                .headers()
                .get_all(axum::http::header::WARNING)
                .iter()
                .map(|value| {
                    value
                        .to_str()
                        .unwrap()
                        .to_string()
                })
                .collect()
        };

        let by_sub = router
            .clone()
            .oneshot(create(None))
            .await
            .unwrap();
        assert_eq!(by_sub.status(), StatusCode::CREATED);
        assert!(warnings(&by_sub).is_empty());
        let by_sub_id = response_body(by_sub).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let by_oid = router
            .clone()
            .oneshot(create(Some("oid")))
            .await
            .unwrap();
        assert_eq!(by_oid.status(), StatusCode::CREATED);
        let found = warnings(&by_oid);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("299 - "), "{found:?}");
        assert!(found[0].contains(&by_sub_id) && found[0].contains("one claim in a tenant"), "{found:?}");

        let second_oid = router
            .clone()
            .oneshot(create(Some("oid")))
            .await
            .unwrap();
        let found = warnings(&second_oid);
        assert_eq!(found.len(), 1, "only the strategy naming sub disagrees: {found:?}");
        assert!(found[0].contains(&by_sub_id), "{found:?}");
    }

    /// A strategy written to storage by hand skips the API's checks: naming
    /// `sub` there is still the default, and a claim the API would refuse can
    /// be kept but not changed.
    #[tokio::test]
    async fn an_update_compares_with_the_stored_claim_in_its_api_form() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store.clone(),
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        for (id, stored) in [("named-sub", "sub"), ("named-iss", "iss")] {
            let mut strategy = seeded_strategy(None);
            strategy.id = id.to_string();
            strategy.principal_claim = Some(stored.to_string());
            store
                .inner
                .insert(id.to_string(), strategy);
        }

        let (status, body) =
            send_strategy(&router, "PUT", "/v1/jwt-verification-strategies/named-sub", strategy_body(Some("sub")))
                .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.get("principal_claim")
                .is_none(),
            "the stored sub is saved in its API form: {body}"
        );

        let (status, body) =
            send_strategy(&router, "PUT", "/v1/jwt-verification-strategies/named-iss", strategy_body(Some("oid")))
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) =
            send_strategy(&router, "PUT", "/v1/jwt-verification-strategies/named-iss", strategy_body(None)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["principal_claim"], "iss", "it is kept, and names no caller when used");
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
        assert_eq!(body["error"], JWKS_URI_BLOCKED);
    }

    async fn probe(
        router: &Router,
        uri: &str,
    ) -> (StatusCode, serde_json::Value) {
        send_strategy(
            router,
            "POST",
            "/v1/jwt-verification-strategies/validate-jwks-uri",
            serde_json::json!({ "uri": uri }),
        )
        .await
    }

    #[tokio::test]
    async fn the_probe_answers_fixed_messages_without_the_upstream_detail() {
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            Arc::new(MemStore::default()),
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );

        for uri in ["https://127.0.0.1:8443/keys", "https://[::1]/keys", "https://169.254.169.254/keys"] {
            let (status, body) = probe(&router, uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, serde_json::json!({ "valid": false, "error": JWKS_URI_BLOCKED }), "{uri}");
        }

        let (base_url, _server) = crate::jwt_bearer::test_utils::start_jwks_server("not json".into(), None).await;
        let (status, body) = probe(&router, &format!("{base_url}/.well-known/jwks.json")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, serde_json::json!({ "valid": false, "error": JWKS_URI_UNUSABLE }));
    }

    #[tokio::test]
    async fn the_probe_needs_the_edit_permission() {
        let mut rbac = RbacConfig::default();
        rbac.permissions
            .insert("jwt_verification_strategies.view".into(), "user".into());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::User).await;
        let router = build_test_router(
            Arc::new(MemStore::default()),
            Arc::new(ps),
            Arc::new(rbac.clone()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        let (status, _) = probe(&router, "https://example.com/jwks.json").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "view alone does not allow the probe");

        rbac.permissions
            .insert("jwt_verification_strategies.edit".into(), "user".into());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::User).await;
        let router = build_test_router(
            Arc::new(MemStore::default()),
            Arc::new(ps),
            Arc::new(rbac),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        let (status, body) = probe(&router, "https://169.254.169.254/keys").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "edit allows the probe: {body}");
        assert_eq!(body["error"], JWKS_URI_BLOCKED);
    }

    #[tokio::test]
    async fn a_loopback_or_metadata_jwks_uri_is_refused_on_create_and_update() {
        let store = Arc::new(MemStore::default());
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store.clone(),
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        let with_uri = |uri: &str| {
            let mut body = strategy_body(None);
            body["jwks_source"]["jwks_uri"] = serde_json::json!(uri);
            body
        };

        for uri in ["https://127.0.0.1:8080/keys", "https://169.254.169.254/keys", "https://[fd00:ec2::254]/keys"] {
            let (status, body) = send_strategy(&router, "POST", "/v1/jwt-verification-strategies", with_uri(uri)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert_eq!(body["error"], JWKS_URI_BLOCKED);
        }
        assert!(
            store
                .list()
                .await
                .unwrap()
                .is_empty(),
            "nothing is stored"
        );

        let (status, created) =
            send_strategy(&router, "POST", "/v1/jwt-verification-strategies", with_uri("https://1.2.3.4/keys")).await;
        assert_eq!(status, StatusCode::CREATED, "a public address is saved: {created}");
        let (status, private) =
            send_strategy(&router, "POST", "/v1/jwt-verification-strategies", with_uri("https://192.168.1.1/keys"))
                .await;
        assert_eq!(status, StatusCode::CREATED, "a private network address is saved: {private}");
        let path = format!(
            "/v1/jwt-verification-strategies/{}",
            created["id"]
                .as_str()
                .unwrap()
        );
        let (status, body) = send_strategy(&router, "PUT", &path, with_uri("https://[::1]/keys")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], JWKS_URI_BLOCKED);
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

    fn tenant_context_a() -> PatTenantContext {
        PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }
    }

    fn seeded_strategy(tenant_id: Option<&str>) -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            principal_claim: None,
            id: "strategy-a".to_string(),
            tenant_id: tenant_id.map(str::to_string),
            name: "Operator strategy".to_string(),
            expected_issuer: "https://operator.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://operator.example.com/.well-known/jwks.json".to_string(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn tenant_router(store: Arc<MemStore>) -> (Router, TempDir) {
        let (ps, dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store,
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        )
        .layer(Extension(tenant_context_a()));
        (router, dir)
    }

    fn replacement_body() -> String {
        serde_json::json!({
            "name": "Tenant strategy",
            "expected_issuer": "https://tenant.example.com",
            "jwks_source": { "type": "remote", "jwks_uri": "https://tenant.example.com/.well-known/jwks.json" }
        })
        .to_string()
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_rewrite_or_delete_an_appliance_wide_strategy() {
        let store = Arc::new(MemStore::default());
        store
            .inner
            .insert("strategy-a".to_string(), seeded_strategy(None));
        let (router, _dir) = tenant_router(store.clone()).await;

        let read = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/jwt-verification-strategies/strategy-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);

        let update = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/jwt-verification-strategies/strategy-a")
                    .header("content-type", "application/json")
                    .body(Body::from(replacement_body()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::FORBIDDEN);

        let delete = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/jwt-verification-strategies/strategy-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::FORBIDDEN);

        let stored = store
            .get("strategy-a")
            .await
            .unwrap()
            .expect("strategy must survive");
        assert_eq!(stored.expected_issuer, "https://operator.example.com");
        assert_eq!(stored.tenant_id, None);
    }

    #[tokio::test]
    async fn another_tenants_strategy_is_not_found_on_rewrite_or_delete() {
        let store = Arc::new(MemStore::default());
        store
            .inner
            .insert("strategy-a".to_string(), seeded_strategy(Some("tenant-b")));
        let (router, _dir) = tenant_router(store.clone()).await;

        let update = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/jwt-verification-strategies/strategy-a")
                    .header("content-type", "application/json")
                    .body(Body::from(replacement_body()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::NOT_FOUND);

        let delete = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/jwt-verification-strategies/strategy-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::NOT_FOUND);

        let stored = store
            .get("strategy-a")
            .await
            .unwrap()
            .expect("strategy must survive");
        assert_eq!(stored.expected_issuer, "https://operator.example.com");
    }

    #[tokio::test]
    async fn a_tenant_token_can_update_its_own_strategy() {
        let store = Arc::new(MemStore::default());
        store
            .inner
            .insert("strategy-a".to_string(), seeded_strategy(Some("tenant-a")));
        let (router, _dir) = tenant_router(store.clone()).await;

        let update = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/jwt-verification-strategies/strategy-a")
                    .header("content-type", "application/json")
                    .body(Body::from(replacement_body()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        let stored = store
            .get("strategy-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.expected_issuer, "https://tenant.example.com");
        assert_eq!(stored.tenant_id.as_deref(), Some("tenant-a"));
    }
}
