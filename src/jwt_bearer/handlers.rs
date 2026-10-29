//! JWT verification strategy CRUD HTTP handlers
//!
//! Every endpoint requires the caller's role to grant the endpoint's
//! `jwt_verification_strategies.*` feature. A personal access token restricted
//! to explicit feature scopes must also include that feature. Otherwise the
//! caller receives `403 Forbidden`.
//!
//! Outbound probes (authorization server discovery and the JWKS URI check, alone
//! or as part of a save) need the edit feature, are limited per user, are logged
//! as audit events, and report failures as fixed codes. A tenant-scoped caller
//! probes under the strict egress posture.

use axum::{Extension, Json, extract::Path, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::audit::config_events::{ManagementActor, verification_strategy_changed};
use crate::audit::events::ConfigChange;
use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::middleware::pat_scope_allows;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::authz_metadata::{DiscoveryError, DiscoveryOptions, EgressPosture};
use crate::jwt_bearer::{
    JwksClient, JwtVerificationStrategyStorage,
    fetch::posture_for_caller,
    models::{
        AuthorizationServerMetadata, JwksSource, JwtVerificationStrategy, normalize_scope_claims,
        validate_expected_issuer,
    },
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

// ── Shared state ──────────────────────────────────────────────────────────────

/// Outbound probes one user may start per minute, in a burst or spread out.
const PROBES_PER_MINUTE: NonZeroU32 = match NonZeroU32::new(10) {
    Some(rate) => rate,
    None => panic!("the probe rate is positive"),
};

type ProbeLimiter = governor::DefaultKeyedRateLimiter<String>;

/// Axum state for JWT verification strategy handlers.
#[derive(Clone)]
pub struct JwtVerificationStrategyState {
    pub store: Arc<dyn JwtVerificationStrategyStorage>,
    /// The JWKS client token validation uses, so an update or delete evicts its cached keys.
    pub jwks: Arc<JwksClient>,
    probes: Arc<ProbeLimiter>,
}

impl JwtVerificationStrategyState {
    pub fn new(
        store: Arc<dyn JwtVerificationStrategyStorage>,
        jwks: Arc<JwksClient>,
    ) -> Self {
        Self {
            store,
            jwks,
            probes: Arc::new(governor::RateLimiter::keyed(governor::Quota::per_minute(PROBES_PER_MINUTE))),
        }
    }

    fn admits_probe(
        &self,
        user_id: &str,
    ) -> bool {
        self.probes
            .check_key(&user_id.to_string())
            .is_ok()
    }
}

// ── Request / response bodies ─────────────────────────────────────────────────

/// Body for `POST /v1/jwt-verification-strategies` and `PUT /v1/jwt-verification-strategies/{id}`.
#[derive(Debug, Deserialize)]
pub struct JwtVerificationStrategyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub expected_issuer: String,
    pub jwks_source: JwksSource,
    /// `true` discovers and pins the authorization server metadata, `false` clears it,
    /// and omitted keeps it, re-discovering when the issuer or JWKS URI changes.
    #[serde(default)]
    pub discover_metadata: Option<bool>,
    /// Claims read for granted scopes. Omitted keeps the stored list.
    #[serde(default)]
    pub scope_claims: Option<Vec<String>>,
}

/// Error response body.
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

impl ErrorBody {
    fn json(msg: impl Into<String>) -> Json<Self> {
        Json(Self { error: msg.into(), code: None })
    }

    fn coded(
        code: &'static str,
        msg: &'static str,
    ) -> Json<Self> {
        Json(Self {
            error: msg.to_string(),
            code: Some(code),
        })
    }
}

const RATE_LIMITED_CODE: &str = "rate_limited";
const RATE_LIMITED_MESSAGE: &str = "Too many outbound checks; try again in a minute";

fn rate_limited() -> axum::response::Response {
    (StatusCode::TOO_MANY_REQUESTS, ErrorBody::coded(RATE_LIMITED_CODE, RATE_LIMITED_MESSAGE)).into_response()
}

fn discovery_failed(error: &DiscoveryError) -> axum::response::Response {
    (StatusCode::UNPROCESSABLE_ENTITY, ErrorBody::coded(error.code(), error.message())).into_response()
}

/// Who started an outbound probe, and the egress posture it runs under.
struct ProbeCaller<'a> {
    user_id: &'a str,
    tenant_id: Option<&'a str>,
    posture: EgressPosture,
}

impl<'a> ProbeCaller<'a> {
    fn new(
        user_id: &'a str,
        context: Option<&'a PatTenantContext>,
    ) -> Self {
        Self {
            user_id,
            tenant_id: context.map(|context| context.tenant_id.as_str()),
            posture: posture_for_caller(context),
        }
    }

    fn audit(
        &self,
        probe: &'static str,
        url: &str,
        failure: Option<(&'static str, &dyn std::fmt::Display)>,
    ) {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|url| {
                url.host_str()
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let result = failure.map_or("ok", |(code, _)| code);
        info!(
            target: "audit",
            event = "jwt_verification_strategy.probe",
            probe,
            caller_user_id = %self.user_id,
            tenant_id = self.tenant_id.unwrap_or(""),
            posture = self.posture.as_str(),
            host = %host,
            result,
        );
        if let Some((_, error)) = failure {
            warn!(probe, host = %host, %error, "JWT verification strategy probe failed");
        }
    }

    async fn discover(
        &self,
        probe: &'static str,
        issuer: &str,
    ) -> Result<AuthorizationServerMetadata, DiscoveryError> {
        let outcome = crate::authz_metadata::discover(issuer, self.posture, DiscoveryOptions::default()).await;
        crate::metrics::backends::prometheus::track_discovery(match &outcome {
            Ok(_) => "ok",
            Err(error) => error.code(),
        });
        self.audit(
            probe,
            issuer,
            outcome
                .as_ref()
                .err()
                .map(|error| (error.code(), error as &dyn std::fmt::Display)),
        );
        outcome
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
    axum::extract::State(state): axum::extract::State<JwtVerificationStrategyState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    actor: ManagementActor,
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

    if let JwksSource::Remote { ref jwks_uri } = body.jwks_source
        && let Err(e) = crate::url_validation::validate_url_not_cloud_metadata(jwks_uri)
    {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(format!("jwks_uri rejected: {}", e))).into_response();
    }
    if let Err(message) = validate_expected_issuer(&body.expected_issuer) {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response();
    }
    let scope_claims = match body
        .scope_claims
        .take()
        .map(normalize_scope_claims)
        .transpose()
    {
        Ok(claims) => claims.flatten(),
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

    let authorization_server = if body.discover_metadata == Some(true) {
        if !state.admits_probe(&user_id) {
            return rate_limited();
        }
        match ProbeCaller::new(&user_id, tenant_context(&context))
            .discover("save", &body.expected_issuer)
            .await
        {
            Ok(metadata) => Some(metadata),
            Err(error) => return discovery_failed(&error),
        }
    } else {
        None
    };

    let strategy = JwtVerificationStrategy {
        id,
        tenant_id: body.tenant_id,
        name: body.name,
        expected_issuer: body.expected_issuer,
        jwks_source: body.jwks_source,
        authorization_server,
        scope_claims,
        ..Default::default()
    };

    match state
        .store
        .create(strategy)
        .await
    {
        Ok(created) => {
            info!(id = %created.id, name = %created.name, "JWT verification strategy created");
            verification_strategy_changed(&actor, ConfigChange::Created, None, &created);
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
    axum::extract::State(state): axum::extract::State<JwtVerificationStrategyState>,
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

    match state.store.list().await {
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
    axum::extract::State(state): axum::extract::State<JwtVerificationStrategyState>,
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

    match state.store.get(&id).await {
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
    axum::extract::State(state): axum::extract::State<JwtVerificationStrategyState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    actor: ManagementActor,
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

    let existing = match state.store.get(&id).await {
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

    if let JwksSource::Remote { ref jwks_uri } = body.jwks_source
        && let Err(e) = crate::url_validation::validate_url_not_cloud_metadata(jwks_uri)
    {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(format!("jwks_uri rejected: {}", e))).into_response();
    }
    if let Err(message) = validate_expected_issuer(&body.expected_issuer) {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response();
    }
    let scope_claims = match body
        .scope_claims
        .map(normalize_scope_claims)
        .transpose()
    {
        Ok(Some(claims)) => claims,
        Ok(None) => existing.scope_claims.clone(),
        Err(message) => return (StatusCode::BAD_REQUEST, ErrorBody::json(message)).into_response(),
    };

    let mut updated = JwtVerificationStrategy {
        name: body.name,
        expected_issuer: body.expected_issuer,
        jwks_source: body.jwks_source,
        scope_claims,
        updated_at: chrono::Utc::now(),
        ..existing.clone()
    };
    let caller = ProbeCaller::new(&user_id, tenant_context(&context));
    updated.authorization_server = match body.discover_metadata {
        Some(true) => {
            if !state.admits_probe(&user_id) {
                return rate_limited();
            }
            match caller
                .discover("save", &updated.expected_issuer)
                .await
            {
                Ok(metadata) => Some(metadata),
                Err(error) => return discovery_failed(&error),
            }
        }
        Some(false) => None,
        None => rediscover_if_moved(&state, &caller, &existing, &updated).await,
    };

    match state
        .store
        .update(updated)
        .await
    {
        Ok(strategy) => {
            state
                .jwks
                .evict(&strategy.id)
                .await;
            info!(id = %strategy.id, name = %strategy.name, "JWT verification strategy updated");
            verification_strategy_changed(&actor, ConfigChange::Updated, Some(&existing), &strategy);
            (StatusCode::OK, Json(strategy)).into_response()
        }
        Err(e) => {
            error!("Failed to update JWT verification strategy {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to update strategy")).into_response()
        }
    }
}

/// The pin to keep when a save omits `discover_metadata`.
///
/// A pinned strategy whose issuer or JWKS URI changed is discovered again. If that
/// fails or the caller is out of probes, the existing pin is kept only while its issuer
/// still equals the strategy's expected issuer; otherwise the pin is cleared.
async fn rediscover_if_moved(
    state: &JwtVerificationStrategyState,
    caller: &ProbeCaller<'_>,
    existing: &JwtVerificationStrategy,
    updated: &JwtVerificationStrategy,
) -> Option<AuthorizationServerMetadata> {
    let pinned = existing
        .authorization_server
        .clone()?;
    let moved =
        updated.expected_issuer != existing.expected_issuer || updated.remote_jwks_uri() != existing.remote_jwks_uri();
    if !moved {
        return Some(pinned);
    }
    let fallback = (pinned.issuer == updated.expected_issuer).then_some(pinned);
    let pin = if fallback.is_some() {
        "kept"
    } else {
        "cleared"
    };
    if !state.admits_probe(caller.user_id) {
        warn!(id = %existing.id, pin, "Skipped re-discovery for a moved strategy: probe limit reached");
        return fallback;
    }
    match caller
        .discover("save", &updated.expected_issuer)
        .await
    {
        Ok(metadata) => Some(metadata),
        Err(_) => {
            warn!(id = %existing.id, pin, "Re-discovery failed for a moved strategy");
            fallback
        }
    }
}

/// `DELETE /v1/jwt-verification-strategies/{id}`  — delete a strategy.
pub async fn delete_strategy(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(state): axum::extract::State<JwtVerificationStrategyState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    actor: ManagementActor,
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

    let existing = match state.store.get(&id).await {
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

    match state.store.delete(&id).await {
        Ok(()) => {
            state.jwks.evict(&id).await;
            info!(id = %id, "JWT verification strategy deleted");
            verification_strategy_changed(&actor, ConfigChange::Deleted, Some(&existing), &existing);
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
    pub error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
}

/// `POST /v1/jwt-verification-strategies/validate-jwks-uri`
///
/// Probes whether the given URI is reachable and returns a JWKS the cache would
/// accept. Returns `200 OK` with `{ "valid": true, "key_count": N }` on success,
/// `400 Bad Request` with `{ "valid": false, "error", "code" }` on failure, and
/// `429 Too Many Requests` past the per-user probe limit.
///
/// Requires `JwtVerificationStrategiesEdit`. A personal access token restricted
/// to explicit feature scopes must also include that feature.
pub async fn validate_jwks_uri(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<crate::auth::storage::PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<crate::rbac::RbacConfig>>,
    axum::extract::State(state): axum::extract::State<JwtVerificationStrategyState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    Json(params): Json<JwksUriQuery>,
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
    if !state.admits_probe(&user_id) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(JwksUriValidationResponse {
                valid: false,
                key_count: None,
                error: Some(RATE_LIMITED_MESSAGE),
                code: Some(RATE_LIMITED_CODE),
            }),
        )
            .into_response();
    }

    let caller = ProbeCaller::new(&user_id, tenant_context(&context));
    let outcome = state
        .jwks
        .fetch_jwks(&params.uri, caller.posture)
        .await;
    caller.audit(
        "jwks_uri",
        &params.uri,
        outcome
            .as_ref()
            .err()
            .map(|error| (error.failure().code(), error as &dyn std::fmt::Display)),
    );
    match outcome {
        Ok(jwks) => (
            StatusCode::OK,
            Json(JwksUriValidationResponse {
                valid: true,
                key_count: Some(jwks.keys.len()),
                error: None,
                code: None,
            }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(JwksUriValidationResponse {
                valid: false,
                key_count: None,
                error: Some(error.failure().message()),
                code: Some(error.failure().code()),
            }),
        )
            .into_response(),
    }
}

// ── Authorization server discovery ────────────────────────────────────────────

/// JSON request body for `POST /v1/jwt-verification-strategies/discover`.
#[derive(Debug, Deserialize)]
pub struct DiscoverRequest {
    pub issuer: String,
}

/// `POST /v1/jwt-verification-strategies/discover`
///
/// Discovers the authorization server metadata of `issuer` (RFC 8414, then OpenID
/// Connect Discovery) without storing anything. Returns `200 OK` with the metadata a
/// save with `discover_metadata: true` would pin, `422 Unprocessable Entity` with
/// `{ "error", "code" }` when discovery fails, and `429 Too Many Requests` past the
/// per-user probe limit.
///
/// Requires `JwtVerificationStrategiesEdit`. A personal access token restricted
/// to explicit feature scopes must also include that feature.
pub async fn discover_metadata(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(state): axum::extract::State<JwtVerificationStrategyState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    Json(request): Json<DiscoverRequest>,
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
    if !state.admits_probe(&user_id) {
        return rate_limited();
    }
    match ProbeCaller::new(&user_id, tenant_context(&context))
        .discover("discover", &request.issuer)
        .await
    {
        Ok(metadata) => (StatusCode::OK, Json(metadata)).into_response(),
        Err(error) => discovery_failed(&error),
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
        create_jwt_verification_strategies_router(JwtVerificationStrategyState::new(store, jwks_client)).layer(
            middleware::from_fn(move |mut req: axum::extract::Request, next: middleware::Next| {
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
            }),
        )
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

    fn tenant_context_a() -> PatTenantContext {
        PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }
    }

    fn seeded_strategy(tenant_id: Option<&str>) -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: "strategy-a".to_string(),
            tenant_id: tenant_id.map(str::to_string),
            name: "Operator strategy".to_string(),
            expected_issuer: "https://operator.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://operator.example.com/.well-known/jwks.json".to_string(),
            },
            ..Default::default()
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

    async fn cached_strategy(
        server: &crate::component_tests::helpers::mock_auth_server::MockAuthServer,
        store: &MemStore,
        jwks: &crate::jwt_bearer::JwksClient,
    ) -> JwtVerificationStrategy {
        let strategy = JwtVerificationStrategy {
            jwks_source: JwksSource::Remote { jwks_uri: server.jwks_uri() },
            ..seeded_strategy(None)
        };
        store
            .inner
            .insert(strategy.id.clone(), strategy.clone());
        jwks.get_key(&strategy, &server.jwks_uri(), "rs256-0")
            .await
            .unwrap();
        assert!(
            jwks.is_cached(&strategy.id)
                .await
        );
        strategy
    }

    async fn send(
        router: &Router,
        method: &str,
        body: Option<String>,
    ) -> StatusCode {
        let request = Request::builder()
            .method(method)
            .uri("/v1/jwt-verification-strategies/strategy-a")
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, Body::from))
            .unwrap();
        router
            .clone()
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn update_and_delete_evict_the_cached_jwks() {
        let server = crate::component_tests::helpers::mock_auth_server::MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let jwks = Arc::new(crate::jwt_bearer::JwksClient::new());
        let strategy = cached_strategy(&server, &store, &jwks).await;
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks.clone());

        assert_eq!(send(&router, "PUT", Some(replacement_body())).await, StatusCode::OK);
        assert!(
            !jwks
                .is_cached(&strategy.id)
                .await
        );

        jwks.get_key(&strategy, &server.jwks_uri(), "rs256-0")
            .await
            .unwrap();
        assert_eq!(send(&router, "DELETE", None).await, StatusCode::NO_CONTENT);
        assert!(
            !jwks
                .is_cached(&strategy.id)
                .await
        );
    }

    #[tokio::test]
    async fn a_refused_update_or_delete_keeps_the_cached_jwks() {
        let server = crate::component_tests::helpers::mock_auth_server::MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let jwks = Arc::new(crate::jwt_bearer::JwksClient::new());
        let strategy = cached_strategy(&server, &store, &jwks).await;
        let (ps, _dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(store, Arc::new(ps), Arc::new(RbacConfig::default()), uid, jwks.clone())
            .layer(Extension(tenant_context_a()));

        assert_eq!(send(&router, "PUT", Some(replacement_body())).await, StatusCode::FORBIDDEN);
        assert_eq!(send(&router, "DELETE", None).await, StatusCode::FORBIDDEN);
        assert!(
            jwks.is_cached(&strategy.id)
                .await
        );
    }

    #[tokio::test]
    async fn an_update_keeps_the_stored_tenant_and_creation_time() {
        let store = Arc::new(MemStore::default());
        let seeded = JwtVerificationStrategy {
            created_at: Utc::now() - chrono::Duration::days(3),
            updated_at: Utc::now() - chrono::Duration::days(3),
            ..seeded_strategy(Some("tenant-a"))
        };
        store
            .inner
            .insert(seeded.id.clone(), seeded.clone());
        let (router, _dir) = tenant_router(store.clone()).await;

        assert_eq!(send(&router, "PUT", Some(replacement_body())).await, StatusCode::OK);
        let stored = store
            .get("strategy-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(stored.created_at, seeded.created_at);
        assert!(stored.updated_at > seeded.updated_at);
        assert_eq!(stored.name, "Tenant strategy");
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

    // ── discovery and probes ──────────────────────────────────────────────────

    use crate::component_tests::helpers::audit_events::AuditEvents;
    use crate::component_tests::helpers::mock_auth_server::{Endpoint, Fault, IssuerShape, MockAuthServer};
    use crate::jwt_bearer::models::AuthorizationServerMetadata;

    const PUBLIC_JWKS: &str = "https://keys.example.com/jwks.json";

    async fn admin_router(store: Arc<MemStore>) -> (Router, TempDir) {
        let (ps, dir, uid) = make_passkey_storage(UserRole::Administrator).await;
        let router = build_test_router(
            store,
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        (router, dir)
    }

    async fn post_json(
        router: &Router,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value, String) {
        put_or_post(router, "POST", uri, body).await
    }

    async fn exhaust_probe_limit(router: &Router) {
        for _ in 0..PROBES_PER_MINUTE.get() {
            post_json(
                router,
                "/v1/jwt-verification-strategies/validate-jwks-uri",
                serde_json::json!({ "uri": "not-a-url" }),
            )
            .await;
        }
    }

    async fn put_or_post(
        router: &Router,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value, String) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router
            .clone()
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (status, serde_json::from_str(&text).unwrap_or(serde_json::Value::Null), text)
    }

    fn pin_of(server: &MockAuthServer) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: server.issuer().to_string(),
            metadata_url: server.rfc8414_metadata_url(),
            token_endpoint: server.token_endpoint(),
            jwks_uri: server.jwks_uri(),
        }
    }

    fn strategy_body(
        issuer: &str,
        jwks_uri: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": "Discovered",
            "expected_issuer": issuer,
            "jwks_source": { "type": "remote", "jwks_uri": jwks_uri }
        })
    }

    fn with(
        mut body: serde_json::Value,
        field: &str,
        value: serde_json::Value,
    ) -> serde_json::Value {
        body[field] = value;
        body
    }

    async fn seed_pinned(
        store: &MemStore,
        server: &MockAuthServer,
    ) -> JwtVerificationStrategy {
        let strategy = JwtVerificationStrategy {
            expected_issuer: server.issuer().to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: PUBLIC_JWKS.to_string(),
            },
            authorization_server: Some(pin_of(server)),
            ..seeded_strategy(None)
        };
        store
            .inner
            .insert(strategy.id.clone(), strategy.clone());
        strategy
    }

    async fn stored(store: &MemStore) -> JwtVerificationStrategy {
        store
            .get("strategy-a")
            .await
            .unwrap()
            .expect("strategy-a is stored")
    }

    #[tokio::test]
    async fn discover_returns_the_metadata_a_save_would_pin() {
        let server = MockAuthServer::builder()
            .issuer_shape(IssuerShape::TrailingSlash)
            .start()
            .await;
        let (router, _dir) = admin_router(Arc::new(MemStore::default())).await;

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": server.issuer() }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::to_value(pin_of(&server)).unwrap());
    }

    #[tokio::test]
    async fn a_failed_discovery_returns_a_fixed_code_and_no_address() {
        let server = MockAuthServer::start().await;
        server.set_fault(Endpoint::Discovery, Fault::IssuerMismatch);
        let (router, _dir) = admin_router(Arc::new(MemStore::default())).await;

        let (status, body, text) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": server.issuer() }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "issuer_mismatch");
        assert_eq!(body["error"], "The discovered issuer does not match the expected issuer");

        let (status, body, text_closed) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": "http://127.0.0.1:1" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "unreachable");
        for text in [text, text_closed] {
            assert!(!text.contains("127.0.0.1"), "{text}");
        }
    }

    #[tokio::test]
    async fn an_issuer_with_whitespace_is_refused_before_any_request() {
        let server = MockAuthServer::start().await;
        let (router, _dir) = admin_router(Arc::new(MemStore::default())).await;

        for issuer in [format!("{} ", server.issuer()), format!("{}/te\nnant", server.issuer())] {
            let (status, body, _) =
                post_json(&router, "/v1/jwt-verification-strategies/discover", serde_json::json!({ "issuer": issuer }))
                    .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{issuer:?}");
            assert_eq!(body["code"], "invalid_url", "{issuer:?}");
            assert_eq!(body["error"], crate::authz_metadata::DiscoveryFailure::InvalidUrl.message(), "{issuer:?}");
        }
        assert_eq!(server.requests(), Vec::new());

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": server.issuer() }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::to_value(pin_of(&server)).unwrap());
    }

    #[tokio::test]
    async fn a_tenant_caller_cannot_probe_the_appliance_network() {
        let server = MockAuthServer::start().await;
        let (router, _dir) = tenant_router(Arc::new(MemStore::default())).await;

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": server.issuer() }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "invalid_url");
        assert_eq!(body["error"], crate::authz_metadata::DiscoveryFailure::InvalidUrl.message());

        let loopback_https = server
            .issuer()
            .replacen("http://", "https://", 1);
        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": loopback_https }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "blocked");

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/validate-jwks-uri",
            serde_json::json!({ "uri": server.jwks_uri() }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "invalid_url");

        let loopback_jwks = server
            .jwks_uri()
            .replacen("http://", "https://", 1);
        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/validate-jwks-uri",
            serde_json::json!({ "uri": loopback_jwks }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "blocked");
        assert_eq!(server.request_count(Endpoint::Discovery), 0);
        assert_eq!(server.request_count(Endpoint::Jwks), 0);
    }

    #[tokio::test]
    async fn probes_need_the_edit_permission() {
        let (ps, _dir, uid) = make_passkey_storage(UserRole::User).await;
        let router = build_test_router(
            Arc::new(MemStore::default()),
            Arc::new(ps),
            Arc::new(RbacConfig::default()),
            uid,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
        );
        let (status, _, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": "https://issuer.example.com" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn probes_are_limited_per_user() {
        let (router, _dir) = admin_router(Arc::new(MemStore::default())).await;
        for _ in 0..PROBES_PER_MINUTE.get() {
            let (status, body, _) = post_json(
                &router,
                "/v1/jwt-verification-strategies/validate-jwks-uri",
                serde_json::json!({ "uri": "not-a-url" }),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["code"], "invalid_url");
        }
        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": "https://issuer.example.com" }),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "rate_limited");
        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies/validate-jwks-uri",
            serde_json::json!({ "uri": "not-a-url" }),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["valid"], false);
        assert_eq!(body["code"], "rate_limited");
    }

    #[tokio::test]
    async fn every_probe_is_audited_with_its_result() {
        let server = MockAuthServer::start().await;
        let (router, _dir) = admin_router(Arc::new(MemStore::default())).await;
        let audit = AuditEvents::capture();

        post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": server.issuer() }),
        )
        .await;
        post_json(
            &router,
            "/v1/jwt-verification-strategies/validate-jwks-uri",
            serde_json::json!({ "uri": "http://169.254.169.254/jwks.json" }),
        )
        .await;

        let events = audit.named("jwt_verification_strategy.probe");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["probe"], "discover");
        assert_eq!(events[0]["result"], "ok");
        assert_eq!(events[0]["posture"], "cloud_metadata_only");
        assert_eq!(events[0]["host"], "127.0.0.1");
        assert_eq!(events[1]["probe"], "jwks_uri");
        assert_eq!(events[1]["result"], "blocked");
    }

    #[tokio::test]
    async fn discovery_attempts_are_counted_by_outcome() {
        let counter = |result: &str| {
            crate::metrics::backends::prometheus::DISCOVERY
                .with_label_values(&[result])
                .get()
        };
        let server = MockAuthServer::start().await;
        let (router, _dir) = admin_router(Arc::new(MemStore::default())).await;
        let discover = || {
            post_json(
                &router,
                "/v1/jwt-verification-strategies/discover",
                serde_json::json!({ "issuer": server.issuer() }),
            )
        };

        let ok_before = counter("ok");
        let (status, _, _) = discover().await;
        assert_eq!(status, StatusCode::OK);
        assert!(counter("ok") > ok_before);

        server.set_fault(Endpoint::Discovery, Fault::IssuerMismatch);
        let mismatch_before = counter("issuer_mismatch");
        let (status, _, _) = discover().await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(counter("issuer_mismatch") > mismatch_before);
    }

    #[tokio::test]
    async fn the_jwks_probe_reports_fixed_codes_without_addresses() {
        let (router, _dir) = admin_router(Arc::new(MemStore::default())).await;
        for (uri, code) in [
            ("http://127.0.0.1:1/jwks.json", "unreachable"),
            ("http://169.254.169.254/jwks.json", "blocked"),
            ("file:///etc/passwd", "invalid_url"),
        ] {
            let (status, body, text) = post_json(
                &router,
                "/v1/jwt-verification-strategies/validate-jwks-uri",
                serde_json::json!({ "uri": uri }),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["valid"], false);
            assert_eq!(body["code"], code, "{uri}");
            assert!(!text.contains("127.0.0.1") && !text.contains("169.254"), "{text}");
        }
    }

    #[tokio::test]
    async fn create_with_discovery_pins_the_metadata() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let (router, _dir) = admin_router(store.clone()).await;

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies",
            with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", true.into()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["authorization_server"], serde_json::to_value(pin_of(&server)).unwrap());
        let id = body["id"].as_str().unwrap();
        let saved = store
            .get(id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saved.authorization_server, Some(pin_of(&server)));
    }

    #[tokio::test]
    async fn trust_anchor_changes_are_recorded_with_the_actor_and_the_pin() {
        use crate::delegation_vault::audit::DelegationAuditAction::VerificationStrategyChanged;
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let (router, _dir) = admin_router(store.clone()).await;

        let (id, events) = crate::audit::producer::capture(async {
            let (status, body, _) = post_json(
                &router,
                "/v1/jwt-verification-strategies",
                with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", true.into()),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let id = body["id"]
                .as_str()
                .unwrap()
                .to_string();
            let cleared = with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", false.into());
            let uri = format!("/v1/jwt-verification-strategies/{id}");
            let (status, _, _) = put_or_post(&router, "PUT", &uri, cleared).await;
            assert_eq!(status, StatusCode::OK);
            let request = Request::builder()
                .method("DELETE")
                .uri(&uri)
                .body(Body::empty())
                .unwrap();
            let deleted = router
                .clone()
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
            id
        })
        .await;

        let changes: Vec<_> = events
            .iter()
            .map(|event| match &event.event {
                VerificationStrategyChanged {
                    change,
                    strategy_id,
                    pinned,
                    pin_changed,
                    ..
                } => {
                    assert_eq!(strategy_id, &id);
                    (*change, *pinned, *pin_changed)
                }
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(
            changes,
            vec![
                (ConfigChange::Created, true, true),
                (ConfigChange::Updated, false, true),
                (ConfigChange::Deleted, false, false)
            ]
        );
        assert!(events.iter().all(|event| {
            event
                .caller
                .as_ref()
                .is_some_and(|caller| caller.auth_method == "session" && caller.sub.is_some())
        }));
    }

    #[tokio::test]
    async fn a_create_whose_discovery_fails_stores_nothing() {
        let server = MockAuthServer::start().await;
        server.set_fault(Endpoint::Discovery, Fault::NotFound);
        let store = Arc::new(MemStore::default());
        let (router, _dir) = admin_router(store.clone()).await;

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies",
            with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", true.into()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "http_status");
        assert_eq!(body["error"], "The server did not return the document");
        assert!(
            store
                .list()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_create_without_discovery_pins_nothing_and_makes_no_request() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let (router, _dir) = admin_router(store.clone()).await;

        let (status, body, _) =
            post_json(&router, "/v1/jwt-verification-strategies", strategy_body(server.issuer(), PUBLIC_JWKS)).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(
            body.get("authorization_server")
                .is_none()
        );
        assert_eq!(server.request_count(Endpoint::Discovery), 0);
    }

    #[tokio::test]
    async fn an_update_that_omits_discovery_keeps_the_pin_without_a_request() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        seed_pinned(&store, &server).await;
        let (router, _dir) = admin_router(store.clone()).await;

        let renamed = with(strategy_body(server.issuer(), PUBLIC_JWKS), "name", "Renamed".into());
        let (status, _, _) = put_or_post(&router, "PUT", "/v1/jwt-verification-strategies/strategy-a", renamed).await;
        assert_eq!(status, StatusCode::OK);
        let saved = stored(&store).await;
        assert_eq!(saved.name, "Renamed");
        assert_eq!(saved.authorization_server, Some(pin_of(&server)));
        assert_eq!(server.request_count(Endpoint::Discovery), 0);
    }

    #[tokio::test]
    async fn an_update_with_discovery_false_clears_the_pin() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        seed_pinned(&store, &server).await;
        let (router, _dir) = admin_router(store.clone()).await;

        let cleared = with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", false.into());
        let (status, body, _) =
            put_or_post(&router, "PUT", "/v1/jwt-verification-strategies/strategy-a", cleared).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.get("authorization_server")
                .is_none()
        );
        assert_eq!(
            stored(&store)
                .await
                .authorization_server,
            None
        );
    }

    #[tokio::test]
    async fn a_moved_issuer_is_discovered_again() {
        let old = MockAuthServer::start().await;
        let new = MockAuthServer::builder()
            .issuer_shape(IssuerShape::TrailingSlash)
            .start()
            .await;
        let store = Arc::new(MemStore::default());
        seed_pinned(&store, &old).await;
        let (router, _dir) = admin_router(store.clone()).await;

        let (status, _, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            strategy_body(new.issuer(), PUBLIC_JWKS),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stored(&store)
                .await
                .authorization_server,
            Some(pin_of(&new))
        );
    }

    #[tokio::test]
    async fn a_moved_issuer_whose_discovery_fails_clears_the_old_pin() {
        let old = MockAuthServer::start().await;
        let new = MockAuthServer::start().await;
        new.set_fault(Endpoint::Discovery, Fault::NotFound);
        let store = Arc::new(MemStore::default());
        seed_pinned(&store, &old).await;
        let (router, _dir) = admin_router(store.clone()).await;

        let (status, body, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            strategy_body(new.issuer(), PUBLIC_JWKS),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.get("authorization_server")
                .is_none()
        );
        let saved = stored(&store).await;
        assert_eq!(saved.expected_issuer, new.issuer());
        assert_eq!(saved.authorization_server, None);
        assert!(new.request_count(Endpoint::Discovery) > 0);
    }

    #[tokio::test]
    async fn a_moved_issuer_past_the_probe_limit_clears_the_old_pin_without_a_request() {
        let old = MockAuthServer::start().await;
        let new = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        seed_pinned(&store, &old).await;
        let (router, _dir) = admin_router(store.clone()).await;
        exhaust_probe_limit(&router).await;

        let (status, _, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            strategy_body(new.issuer(), PUBLIC_JWKS),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved = stored(&store).await;
        assert_eq!(saved.expected_issuer, new.issuer());
        assert_eq!(saved.authorization_server, None);
        assert_eq!(new.request_count(Endpoint::Discovery), 0);
    }

    #[tokio::test]
    async fn a_moved_jwks_uri_whose_discovery_fails_keeps_the_pin_of_the_same_issuer() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        seed_pinned(&store, &server).await;
        server.set_fault(Endpoint::Discovery, Fault::NotFound);
        let (router, _dir) = admin_router(store.clone()).await;

        let (status, _, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            strategy_body(server.issuer(), "https://keys.example.com/rotated.json"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved = stored(&store).await;
        assert_eq!(saved.remote_jwks_uri(), Some("https://keys.example.com/rotated.json"));
        assert_eq!(saved.authorization_server, Some(pin_of(&server)));
        assert!(server.request_count(Endpoint::Discovery) > 0);
    }

    #[tokio::test]
    async fn an_update_with_discovery_true_that_fails_changes_nothing() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let seeded = seed_pinned(&store, &server).await;
        server.set_fault(Endpoint::Discovery, Fault::IssuerMismatch);
        let (router, _dir) = admin_router(store.clone()).await;

        let body = with(
            with(strategy_body(server.issuer(), PUBLIC_JWKS), "name", "Changed".into()),
            "discover_metadata",
            true.into(),
        );
        let (status, response, _) =
            put_or_post(&router, "PUT", "/v1/jwt-verification-strategies/strategy-a", body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response["code"], "issuer_mismatch");
        let saved = stored(&store).await;
        assert_eq!(saved.name, seeded.name);
        assert_eq!(saved.authorization_server, seeded.authorization_server);
    }

    #[tokio::test]
    async fn a_templated_issuer_is_refused_on_create_and_update() {
        let store = Arc::new(MemStore::default());
        store
            .inner
            .insert("strategy-a".to_string(), seeded_strategy(None));
        let (router, _dir) = admin_router(store.clone()).await;
        let templated = strategy_body(
            "https://login.microsoftonline.com/{tenantid}/v2.0",
            "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        );

        let (status, _, _) = post_json(&router, "/v1/jwt-verification-strategies", templated.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = put_or_post(&router, "PUT", "/v1/jwt-verification-strategies/strategy-a", templated).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            stored(&store)
                .await
                .expected_issuer,
            "https://operator.example.com"
        );
    }

    #[tokio::test]
    async fn scope_claims_are_validated_stored_and_kept_when_omitted() {
        let store = Arc::new(MemStore::default());
        store
            .inner
            .insert("strategy-a".to_string(), seeded_strategy(None));
        let (router, _dir) = admin_router(store.clone()).await;
        let base = strategy_body("https://operator.example.com", "https://operator.example.com/.well-known/jwks.json");

        let (status, _, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            with(base.clone(), "scope_claims", serde_json::json!(["scp", "scp"])),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            stored(&store)
                .await
                .scope_claims,
            None
        );

        let (status, body, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            with(base.clone(), "scope_claims", serde_json::json!(["scp", "roles"])),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["scope_claims"], serde_json::json!(["scp", "roles"]));

        let (status, _, _) =
            put_or_post(&router, "PUT", "/v1/jwt-verification-strategies/strategy-a", base.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stored(&store)
                .await
                .scope_claims,
            Some(vec!["scp".to_string(), "roles".to_string()])
        );

        let (status, body, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            with(base, "scope_claims", serde_json::json!(["scope", "scp"])),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.get("scope_claims")
                .is_none()
        );
        assert_eq!(
            stored(&store)
                .await
                .scope_claims,
            None
        );
    }

    #[tokio::test]
    async fn create_stores_custom_scope_claims_and_refuses_invalid_ones() {
        let store = Arc::new(MemStore::default());
        let (router, _dir) = admin_router(store.clone()).await;
        let base = strategy_body("https://operator.example.com", "https://operator.example.com/.well-known/jwks.json");

        let (status, _, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies",
            with(base.clone(), "scope_claims", serde_json::json!([])),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(store.inner.is_empty());

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies",
            with(base, "scope_claims", serde_json::json!(["roles"])),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["scope_claims"], serde_json::json!(["roles"]));
        let saved = store
            .get(body["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saved.scope_claims, Some(vec!["roles".to_string()]));
    }

    #[tokio::test]
    async fn a_tenant_save_with_discovery_runs_under_the_strict_posture() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let (router, _dir) = tenant_router(store.clone()).await;

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies",
            with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", true.into()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "invalid_url");
        assert_eq!(server.request_count(Endpoint::Discovery), 0);
        assert!(
            store
                .list()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_tenant_save_moving_to_an_http_issuer_clears_the_old_pin_without_a_request() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let old_pin = AuthorizationServerMetadata {
            issuer: "https://operator.example.com".to_string(),
            metadata_url: "https://operator.example.com/.well-known/oauth-authorization-server".to_string(),
            token_endpoint: "https://operator.example.com/token".to_string(),
            jwks_uri: "https://operator.example.com/.well-known/jwks.json".to_string(),
        };
        store.inner.insert(
            "strategy-a".to_string(),
            JwtVerificationStrategy {
                authorization_server: Some(old_pin),
                ..seeded_strategy(Some("tenant-a"))
            },
        );
        let (router, _dir) = tenant_router(store.clone()).await;

        let (status, body, _) = put_or_post(
            &router,
            "PUT",
            "/v1/jwt-verification-strategies/strategy-a",
            strategy_body(server.issuer(), PUBLIC_JWKS),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.get("authorization_server")
                .is_none()
        );
        let saved = stored(&store).await;
        assert_eq!(saved.expected_issuer, server.issuer());
        assert_eq!(saved.authorization_server, None);
        assert_eq!(server.request_count(Endpoint::Discovery), 0);
    }

    #[tokio::test]
    async fn a_create_with_discovery_past_the_probe_limit_is_refused_and_stores_nothing() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let (router, _dir) = admin_router(store.clone()).await;
        exhaust_probe_limit(&router).await;

        let (status, body, _) = post_json(
            &router,
            "/v1/jwt-verification-strategies",
            with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", true.into()),
        )
        .await;

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "rate_limited");
        assert_eq!(server.request_count(Endpoint::Discovery), 0);
        assert!(
            store
                .list()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_update_with_discovery_past_the_probe_limit_is_refused_and_changes_nothing() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        let seeded = seed_pinned(&store, &server).await;
        let (router, _dir) = admin_router(store.clone()).await;
        exhaust_probe_limit(&router).await;

        let body = with(
            with(strategy_body(server.issuer(), PUBLIC_JWKS), "name", "Changed".into()),
            "discover_metadata",
            true.into(),
        );
        let (status, response, _) =
            put_or_post(&router, "PUT", "/v1/jwt-verification-strategies/strategy-a", body).await;

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response["code"], "rate_limited");
        assert_eq!(server.request_count(Endpoint::Discovery), 0);
        let saved = stored(&store).await;
        assert_eq!(saved.name, seeded.name);
        assert_eq!(saved.authorization_server, seeded.authorization_server);
    }

    #[tokio::test]
    async fn an_update_with_discovery_true_pins_the_discovered_metadata() {
        let server = MockAuthServer::start().await;
        let store = Arc::new(MemStore::default());
        store
            .inner
            .insert("strategy-a".to_string(), seeded_strategy(None));
        let (router, _dir) = admin_router(store.clone()).await;

        let body = with(strategy_body(server.issuer(), PUBLIC_JWKS), "discover_metadata", true.into());
        let (status, response, _) =
            put_or_post(&router, "PUT", "/v1/jwt-verification-strategies/strategy-a", body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["authorization_server"], serde_json::to_value(pin_of(&server)).unwrap());
        let saved = stored(&store).await;
        assert_eq!(saved.expected_issuer, server.issuer());
        assert_eq!(saved.authorization_server, Some(pin_of(&server)));
        assert!(server.request_count(Endpoint::Discovery) > 0);
    }

    #[tokio::test]
    async fn a_tenant_probe_is_audited_with_its_tenant_and_the_strict_posture() {
        let server = MockAuthServer::start().await;
        let (router, _dir) = tenant_router(Arc::new(MemStore::default())).await;
        let audit = AuditEvents::capture();

        post_json(
            &router,
            "/v1/jwt-verification-strategies/discover",
            serde_json::json!({ "issuer": server.issuer() }),
        )
        .await;

        let events = audit.named("jwt_verification_strategy.probe");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["tenant_id"], "tenant-a");
        assert_eq!(events[0]["posture"], "strict");
        assert_eq!(events[0]["result"], "invalid_url");
    }
}
