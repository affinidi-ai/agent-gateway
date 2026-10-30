//! API handlers for credential provider CRUD operations

use super::{
    CreateCredentialProviderRequest, CredentialProvider, CredentialProviderListItem, CredentialProviderType,
    ProviderGrant, UpdateCredentialProviderRequest, jwt_assertion::SigningKey, storage::CredentialProviderStorage,
};
use crate::delegation_vault::gateway_token::{GatewayTokenError, GrantEgress, ProviderSecrets};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::audit::config_events::{ManagementActor, credential_provider_changed};
use crate::audit::events::ConfigChange;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::secrets::SecretsStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, can_reference, scope_allows_resource, tenant_for_create,
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

#[derive(Clone)]
pub struct CredentialProviderState {
    pub store: Arc<dyn CredentialProviderStorage>,
    pub secrets_store: Arc<dyn SecretsStore>,
    pub identity_strategies: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    pub oauth_callback_route: String,
    /// Surfaces, to refuse a delete or type change that would break a surface's
    /// use of the provider.
    pub surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
}

/// Whether a surface's Target Authentication uses a provider, whether a surface binds it
/// where a JWT bearer binding is refused, and the tenants of the surfaces that reference it.
#[derive(Default)]
struct ProviderUsage {
    target_authentication: bool,
    jwt_bearer_refused: bool,
    surface_tenants: Vec<Option<String>>,
}

/// The surfaces could not be read to find how they use a provider.
#[derive(Debug, thiserror::Error)]
#[error("Surface usage lookup failed")]
struct ProviderUsageError;

impl IntoResponse for ProviderUsageError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal server error" })))
            .into_response()
    }
}

async fn provider_usage(
    state: &CredentialProviderState,
    provider_id: &str,
) -> Result<ProviderUsage, ProviderUsageError> {
    let Some(surfaces) = state.surfaces.as_ref() else {
        return Ok(ProviderUsage::default());
    };
    let mut usage = ProviderUsage::default();
    for surface in surfaces
        .list_all()
        .await
        .map_err(|_| ProviderUsageError)?
    {
        let references = crate::identity::handlers::surface_tenancy::collect_surface_reference_keys(&surface)
            .map_err(|_| ProviderUsageError)?;
        if references
            .iter()
            .any(|reference| reference.kind == ResourceKind::CredentialProviders && reference.id == provider_id)
        {
            usage
                .surface_tenants
                .push(surface.tenant_id.clone());
            let views =
                crate::identity::handlers::surface_tenancy::resolved_views(&surface).map_err(|_| ProviderUsageError)?;
            usage.jwt_bearer_refused |=
                crate::identity::handlers::surfaces::check_jwt_bearer_bindings(&views, |id| id == provider_id).is_err();
        }
        if crate::identity::handlers::surface_tenancy::target_auth_provider_ids(&surface)
            .map_err(|_| ProviderUsageError)?
            .iter()
            .any(|id| id == provider_id)
        {
            usage.target_authentication = true;
        }
    }
    Ok(usage)
}

fn provider_in_use(message: &str) -> Response {
    (StatusCode::CONFLICT, Json(serde_json::json!({ "error": message }))).into_response()
}

/// Why a provider's consent strategy or secret reference was rejected.
#[derive(Debug, thiserror::Error)]
enum ProviderReferenceError {
    #[error("Consent identity strategy is invalid or not accessible")]
    InvalidConsentStrategy,
    #[error("Identity verification configuration unavailable")]
    IdentityConfigurationUnavailable,
    #[error("Secret reference is not accessible")]
    SecretNotAccessible,
    #[error("Secret reference lookup failed")]
    SecretLookupFailed,
    #[error("jwt_bearer.signing_key_secret_ref: {0}")]
    InvalidSigningKey(super::jwt_assertion::SigningKeyError),
}

impl IntoResponse for ProviderReferenceError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidConsentStrategy | Self::SecretNotAccessible | Self::InvalidSigningKey(_) => {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
            }
            Self::IdentityConfigurationUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string()).into_response()
            }
            Self::SecretLookupFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal server error" })))
                    .into_response()
            }
        }
    }
}

async fn validate_consent_strategy(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), ProviderReferenceError> {
    let Some(id) = provider
        .consent_identity_strategy_id
        .as_deref()
    else {
        return Ok(());
    };
    if id.trim().is_empty()
        || id.len() > 256
        || !matches!(provider.provider_type.grant(), ProviderGrant::UserConsent)
        || provider
            .resource
            .as_deref()
            .is_none_or(|resource| crate::sts::mcp_profile::canonical_https_url(resource).is_err())
    {
        return Err(ProviderReferenceError::InvalidConsentStrategy);
    }
    let strategy = state
        .identity_strategies
        .as_ref()
        .ok_or(ProviderReferenceError::InvalidConsentStrategy)?
        .get(id)
        .await
        .map_err(|_| ProviderReferenceError::IdentityConfigurationUnavailable)?
        .ok_or(ProviderReferenceError::InvalidConsentStrategy)?;
    if !can_reference(provider.tenant_id.as_deref(), strategy.tenant_id.as_deref())
        || !scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::JwtVerificationStrategies,
            id,
        )
        || crate::sts::mcp_profile::canonical_https_url(&strategy.expected_issuer).is_err()
    {
        return Err(ProviderReferenceError::InvalidConsentStrategy);
    }
    Ok(())
}

async fn validate_secret_references(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), ProviderReferenceError> {
    let tenant_id = provider.tenant_id.as_deref();
    let references: Vec<String> = provider
        .secret_refs()
        .map(str::to_string)
        .collect();
    for secret_id in &references {
        let secret = state
            .secrets_store
            .get_by_secret_id(secret_id)
            .await
            .map_err(|error| {
                warn!(%error, "Failed to validate credential provider secret reference");
                ProviderReferenceError::SecretLookupFailed
            })?
            .ok_or(ProviderReferenceError::SecretNotAccessible)?;
        if secret.tenant_id.as_deref() != tenant_id
            || !scope_allows_resource(
                resource_scope(scope),
                tenant_context(context),
                ResourceKind::Secrets,
                &secret.secret_id,
            )
        {
            return Err(ProviderReferenceError::SecretNotAccessible);
        }
    }
    Ok(())
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": message }))).into_response()
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

#[allow(clippy::result_large_err)]
fn require_https_token_endpoint(endpoint: &str) -> Result<(), Response> {
    if GrantEgress::from_environment().permits_token_endpoint(endpoint) {
        Ok(())
    } else {
        Err(bad_request("token_endpoint must be an https URL"))
    }
}

/// Checks the fields each provider type needs, without reading any secret.
#[allow(clippy::result_large_err)]
fn validate_provider_shape(provider: &CredentialProvider) -> Result<(), Response> {
    match provider.provider_type {
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::OAuth2ClientCredentials => {
            let Some(endpoint) = provider
                .token_endpoint
                .as_deref()
                .filter(|endpoint| !endpoint.trim().is_empty())
            else {
                return Err(bad_request("token_endpoint is required for OAuth providers"));
            };
            require_https_token_endpoint(endpoint)?;
            if is_blank(
                provider
                    .client_id_secret_ref
                    .as_deref(),
            ) || is_blank(
                provider
                    .client_secret_secret_ref
                    .as_deref(),
            ) {
                return Err(bad_request(
                    "client_id_secret_ref and client_secret_secret_ref are required for OAuth providers",
                ));
            }
        }
        CredentialProviderType::OAuth2JwtBearer => {
            let Some(endpoint) = provider
                .token_endpoint
                .as_deref()
                .filter(|endpoint| !endpoint.trim().is_empty())
            else {
                return Err(bad_request("token_endpoint is required for JWT bearer providers"));
            };
            require_https_token_endpoint(endpoint)?;
            let Some(settings) = provider.jwt_bearer.as_ref() else {
                return Err(bad_request("jwt_bearer settings are required for JWT bearer providers"));
            };
            settings
                .validate()
                .map_err(bad_request)?;
            if is_blank(
                provider
                    .client_id_secret_ref
                    .as_deref(),
            ) && !is_blank(
                provider
                    .client_secret_secret_ref
                    .as_deref(),
            ) {
                return Err(bad_request("client_secret_secret_ref requires client_id_secret_ref"));
            }
            if provider
                .consent_identity_strategy_id
                .is_some()
            {
                return Err(bad_request("consent_identity_strategy_id applies only to authorization code providers"));
            }
        }
        CredentialProviderType::ApiKey => {
            if is_blank(
                provider
                    .api_key_secret_ref
                    .as_deref(),
            ) {
                return Err(bad_request("api_key_secret_ref is required for ApiKey providers"));
            }
        }
    }
    if provider.jwt_bearer.is_some() && !matches!(provider.provider_type, CredentialProviderType::OAuth2JwtBearer) {
        return Err(bad_request("jwt_bearer settings apply only to JWT bearer providers"));
    }
    Ok(())
}

/// For a provider that obtains a gateway token, every secret it references must
/// belong to the provider's own tenant, and a JWT bearer signing key must parse for
/// its algorithm.
async fn validate_gateway_grant_secrets(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
) -> Result<(), ProviderReferenceError> {
    if provider.provider_type.grant() != ProviderGrant::GatewayToken && provider.jwt_bearer.is_none() {
        return Ok(());
    }
    let secrets = ProviderSecrets::new(&state.secrets_store, provider);
    for secret_ref in provider.secret_refs() {
        if secrets
            .resolve(secret_ref)
            .await
            .is_err()
        {
            return Err(ProviderReferenceError::SecretNotAccessible);
        }
    }
    let Some(settings) = provider.jwt_bearer.as_ref() else {
        return Ok(());
    };
    let key = secrets
        .resolve(&settings.signing_key_secret_ref)
        .await
        .map_err(|error| match error {
            GatewayTokenError::Forbidden | GatewayTokenError::SecretUnavailable => {
                ProviderReferenceError::SecretNotAccessible
            }
            _ => ProviderReferenceError::SecretLookupFailed,
        })?;
    SigningKey::parse(&key, settings.signing_algorithm)
        .map(|_| ())
        .map_err(ProviderReferenceError::InvalidSigningKey)
}

/// Validate a set of named URL fields against the SSRF blocklist.
/// Returns an error response on the first invalid URL, or `None` if all pass.
fn validate_url_fields(fields: &[(&str, Option<&str>)]) -> Option<Response> {
    for (name, value) in fields {
        let Some(raw) = value else { continue };
        if let Err(e) = crate::url_validation::validate_oauth_endpoint_url(raw) {
            return Some(
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("{}: {}", name, e)})))
                    .into_response(),
            );
        }
    }
    None
}

/// POST /api/v1/credential-providers
pub async fn create_provider(
    State(state): State<CredentialProviderState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    actor: ManagementActor,
    Json(mut req): Json<CreateCredentialProviderRequest>,
) -> impl IntoResponse {
    req.tenant_id = match tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": message }))).into_response(),
    };
    // Enforce the appliance credentials limit (per-type plus the total).
    if let Err(e) = crate::config::enforce_add("credentials.providers").await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": e.message() }))).into_response();
    }
    // Validate required fields
    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "name is required"}))).into_response();
    }
    if req
        .provider_id
        .trim()
        .is_empty()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "provider_id is required"})))
            .into_response();
    }

    if let Some(resource) = &req.resource
        && crate::sts::mcp_profile::canonical_https_url(resource).is_err()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "resource must be a canonical HTTPS URI"})))
            .into_response();
    }

    // Validate user-supplied URLs before storing them
    if let Some(resp) = validate_url_fields(&[
        ("token_endpoint", req.token_endpoint.as_deref()),
        (
            "authorization_endpoint",
            req.authorization_endpoint
                .as_deref(),
        ),
        ("callback_url", req.callback_url.as_deref()),
    ]) {
        return resp;
    }

    // Check for duplicate provider_id
    match state
        .store
        .find_by_provider_id(&req.provider_id)
        .await
    {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!("provider_id '{}' already exists", req.provider_id)
                })),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                target: "credential_delegation",
                error = %e,
                "Failed to check for duplicate provider_id"
            );
        }
    }

    let provider_id_clean = req
        .provider_id
        .trim()
        .to_lowercase();
    let id = Uuid::new_v4().to_string();
    if !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::CredentialProviders, &id)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "credential provider is outside this token's permitted scope" })),
        )
            .into_response();
    }
    let now = Utc::now();

    let provider = CredentialProvider {
        id: id.clone(),
        tenant_id: req.tenant_id,
        name: req.name.trim().to_string(),
        provider_id: provider_id_clean.clone(),
        provider_type: req.provider_type,
        authorization_endpoint: req.authorization_endpoint,
        token_endpoint: req
            .token_endpoint
            .map(|s| s.trim().to_string()),
        client_id_secret_ref: req
            .client_id_secret_ref
            .map(|s| s.trim().to_string()),
        client_secret_secret_ref: req
            .client_secret_secret_ref
            .map(|s| s.trim().to_string()),
        default_scopes: req.default_scopes,
        callback_path: format!("{}/{}", state.oauth_callback_route, provider_id_clean),
        callback_url: req
            .callback_url
            .map(|s| s.trim().to_string()),
        resource: req.resource,
        consent_identity_strategy_id: req.consent_identity_strategy_id,
        token_refresh_enabled: req.token_refresh_enabled,
        additional_params: req.additional_params,
        api_key_secret_ref: req
            .api_key_secret_ref
            .map(|s| s.trim().to_string()),
        jwt_bearer: req.jwt_bearer,
        description: req.description,
        created_at: now,
        updated_at: now,
    };

    if let Err(response) = validate_provider_shape(&provider) {
        return response;
    }
    if let Err(error) = validate_secret_references(&state, &provider, &context, &scope).await {
        return error.into_response();
    }
    if let Err(error) = validate_gateway_grant_secrets(&state, &provider).await {
        return error.into_response();
    }
    if let Err(error) = validate_consent_strategy(&state, &provider, &context, &scope).await {
        return error.into_response();
    }

    match state
        .store
        .create(provider.clone())
        .await
    {
        Ok(created) => {
            credential_provider_changed(&actor, ConfigChange::Created, &created);
            (StatusCode::CREATED, Json(serde_json::to_value(created).unwrap())).into_response()
        }
        Err(e) => {
            warn!(
                target: "credential_delegation",
                error = %e,
                "Failed to create credential provider"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to create: {}", e)})))
                .into_response()
        }
    }
}

/// GET /api/v1/credential-providers
pub async fn list_providers(
    State(state): State<CredentialProviderState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match state.store.list().await {
        Ok(mut providers) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            providers.retain(|provider| {
                can_access(provider.tenant_id.as_deref(), context)
                    && scope_allows_resource(scope, context, ResourceKind::CredentialProviders, &provider.id)
            });
            let items: Vec<CredentialProviderListItem> = providers
                .iter()
                .map(|p| p.into())
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(items).unwrap())).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to list: {}", e)})))
                .into_response()
        }
    }
}

/// GET /api/v1/credential-providers/{id}
pub async fn get_provider(
    State(state): State<CredentialProviderState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match state.store.get(&id).await {
        Ok(Some(provider))
            if can_access(provider.tenant_id.as_deref(), tenant_context(&context))
                && scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::CredentialProviders,
                    &provider.id,
                ) =>
        {
            (StatusCode::OK, Json(serde_json::to_value(provider).unwrap())).into_response()
        }
        Ok(Some(_)) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"}))).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to get: {}", e)})))
                .into_response()
        }
    }
}

/// PUT /api/v1/credential-providers/{id}
pub async fn update_provider(
    State(state): State<CredentialProviderState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    actor: ManagementActor,
    Json(req): Json<UpdateCredentialProviderRequest>,
) -> impl IntoResponse {
    let existing = match state.store.get(&id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to get: {}", e)})),
            )
                .into_response();
        }
    };
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::CredentialProviders,
            &existing.id,
        )
    {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
            .into_response();
    }
    if !can_mutate(existing.tenant_id.as_deref(), tenant_context(&context)) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "credential provider is outside this token's permitted scope" })),
        )
            .into_response();
    }

    if let Some(Some(resource)) = &req.resource
        && crate::sts::mcp_profile::canonical_https_url(resource).is_err()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "resource must be a canonical HTTPS URI"})))
            .into_response();
    }

    // Validate any user-supplied URLs before applying the update
    if let Some(resp) = validate_url_fields(&[
        ("token_endpoint", req.token_endpoint.as_deref()),
        (
            "authorization_endpoint",
            req.authorization_endpoint
                .as_ref()
                .and_then(Option::as_deref),
        ),
        (
            "callback_url",
            req.callback_url
                .as_ref()
                .and_then(Option::as_deref),
        ),
    ]) {
        return resp;
    }

    let effective_type = req
        .provider_type
        .clone()
        .unwrap_or_else(|| existing.provider_type.clone());
    let retyped = effective_type != existing.provider_type;
    let changes_token_endpoint = req.token_endpoint.is_some();
    let clears_a_reference = [
        &req.client_id_secret_ref,
        &req.client_secret_secret_ref,
        &req.api_key_secret_ref,
        &req.callback_url,
        &req.resource,
        &req.consent_identity_strategy_id,
    ]
    .into_iter()
    .any(|field| matches!(field, Some(None)));
    let updated = CredentialProvider {
        id: existing.id,
        tenant_id: existing.tenant_id,
        name: req
            .name
            .unwrap_or(existing.name),
        provider_id: existing.provider_id, // immutable
        provider_type: effective_type.clone(),
        authorization_endpoint: req
            .authorization_endpoint
            .unwrap_or(existing.authorization_endpoint),
        token_endpoint: req
            .token_endpoint
            .or(existing.token_endpoint),
        client_id_secret_ref: req
            .client_id_secret_ref
            .unwrap_or(existing.client_id_secret_ref),
        client_secret_secret_ref: req
            .client_secret_secret_ref
            .unwrap_or(existing.client_secret_secret_ref),
        default_scopes: req
            .default_scopes
            .unwrap_or(existing.default_scopes),
        callback_path: existing.callback_path, // auto-generated, immutable
        callback_url: req
            .callback_url
            .unwrap_or(existing.callback_url),
        resource: req
            .resource
            .unwrap_or(existing.resource),
        consent_identity_strategy_id: req
            .consent_identity_strategy_id
            .unwrap_or(existing.consent_identity_strategy_id),
        token_refresh_enabled: req
            .token_refresh_enabled
            .unwrap_or(existing.token_refresh_enabled),
        additional_params: req
            .additional_params
            .unwrap_or(existing.additional_params),
        api_key_secret_ref: req
            .api_key_secret_ref
            .unwrap_or(existing.api_key_secret_ref),
        jwt_bearer: match effective_type {
            CredentialProviderType::OAuth2JwtBearer => req
                .jwt_bearer
                .or(existing.jwt_bearer),
            CredentialProviderType::OAuth2AuthorizationCode
            | CredentialProviderType::OAuth2ClientCredentials
            | CredentialProviderType::ApiKey => req.jwt_bearer,
        },
        description: req
            .description
            .unwrap_or(existing.description),
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };

    if (retyped || changes_token_endpoint || clears_a_reference || updated.jwt_bearer.is_some())
        && let Err(response) = validate_provider_shape(&updated)
    {
        return response;
    }
    if let Err(error) = validate_secret_references(&state, &updated, &context, &scope).await {
        return error.into_response();
    }
    if let Err(error) = validate_gateway_grant_secrets(&state, &updated).await {
        return error.into_response();
    }

    if let Err(error) = validate_consent_strategy(&state, &updated, &context, &scope).await {
        return error.into_response();
    }
    if retyped {
        match provider_usage(&state, &updated.id).await {
            Ok(usage)
                if (usage.target_authentication
                    && !updated
                        .provider_type
                        .serves_target_authentication())
                    || (usage.jwt_bearer_refused
                        && matches!(updated.provider_type, CredentialProviderType::OAuth2JwtBearer)) =>
            {
                return provider_in_use("A surface uses this credential provider in a way the new type cannot serve");
            }
            Ok(usage)
                if usage
                    .surface_tenants
                    .iter()
                    .any(|tenant| !updated.usable_by(tenant.as_deref())) =>
            {
                return provider_in_use(
                    "A surface of another tenant uses this credential provider, and the new type sends the gateway's own credential",
                );
            }
            Ok(_) => {}
            Err(error) => return error.into_response(),
        }
    }

    match state
        .store
        .update(updated.clone())
        .await
    {
        Ok(u) => {
            crate::delegation_vault::gateway_token::target_token_cache().invalidate_provider(&u.id);
            credential_provider_changed(&actor, ConfigChange::Updated, &u);
            (StatusCode::OK, Json(serde_json::to_value(u).unwrap())).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to update: {}", e)})))
                .into_response()
        }
    }
}

/// DELETE /api/v1/credential-providers/{id}
pub async fn delete_provider(
    State(state): State<CredentialProviderState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    actor: ManagementActor,
) -> impl IntoResponse {
    let existing = match state.store.get(&id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
                .into_response();
        }
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": error.to_string()})))
                .into_response();
        }
    };
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::CredentialProviders,
            &existing.id,
        )
    {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
            .into_response();
    }
    if !can_mutate(existing.tenant_id.as_deref(), tenant_context(&context)) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "credential provider is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match provider_usage(&state, &existing.id).await {
        Ok(usage) if usage.target_authentication => {
            return provider_in_use("A surface's Target Authentication uses this credential provider");
        }
        Ok(_) => {}
        Err(error) => return error.into_response(),
    }
    match state.store.delete(&id).await {
        Ok(true) => {
            crate::delegation_vault::gateway_token::target_token_cache().invalidate_provider(&existing.id);
            info!(
                target: "credential_delegation",
                id = %id,
                "Credential provider deleted via API"
            );
            credential_provider_changed(&actor, ConfigChange::Deleted, &existing);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to delete: {}", e)})))
                .into_response()
        }
    }
}

/// POST /api/v1/credential-providers/validate
/// Tests that the token endpoint is reachable
pub async fn validate_provider(Json(req): Json<serde_json::Value>) -> impl IntoResponse {
    let token_endpoint = match req
        .get("token_endpoint")
        .and_then(|v| v.as_str())
    {
        Some(url) => url.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "token_endpoint is required"})))
                .into_response();
        }
    };

    if let Err(e) = crate::url_validation::validate_oauth_endpoint_url(&token_endpoint) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("token_endpoint: {}", e)})))
            .into_response();
    }

    let client = crate::http_client::with_short_timeout().unwrap_or_else(|_| reqwest::Client::new());

    match client
        .get(&token_endpoint)
        .send()
        .await
    {
        Ok(resp) => {
            // We just check reachability — OAuth token endpoints typically return 400/405
            // for GET requests, which is fine
            let status = resp.status().as_u16();
            info!(
                target: "credential_delegation",
                token_endpoint = %token_endpoint,
                http_status = %status,
                "Token endpoint validation check"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "reachable": true,
                    "http_status": status,
                    "token_endpoint": token_endpoint,
                })),
            )
                .into_response()
        }
        Err(e) => {
            warn!(
                target: "credential_delegation",
                token_endpoint = %token_endpoint,
                error = %e,
                "Token endpoint validation failed"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "reachable": false,
                    "error": format!("{}", e),
                    "token_endpoint": token_endpoint,
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod consent_strategy_tests {
    use super::*;
    use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
    use serde_json::json;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn consent_strategy_references_enforce_tenancy_scope_and_provider_contract() {
        let directory = tempfile::tempdir().unwrap();
        let strategies = Arc::new(
            FileSystemJwtVerificationStrategyStore::new(
                directory
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap(),
        );
        let mut strategy =
            crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &json!({"keys": []}))
                .unwrap();
        strategy.tenant_id = Some("tenant-a".into());
        let strategy = strategies
            .create(strategy)
            .await
            .unwrap();
        let mut state = CredentialProviderState {
            store: Arc::new(
                super::super::storage::FileSystemCredentialProviderStore::new(
                    directory
                        .path()
                        .join("providers"),
                )
                .await
                .unwrap(),
            ),
            secrets_store: Arc::new(
                crate::secrets::FilesystemSecretsStore::new(
                    directory
                        .path()
                        .join("secrets")
                        .to_str()
                        .unwrap(),
                )
                .unwrap(),
            ),
            identity_strategies: Some(strategies.clone()),
            oauth_callback_route: "/oauth/callback".into(),
            surfaces: None,
        };
        let mut provider: CredentialProvider = serde_json::from_value(json!({
            "id": "provider", "name": "Provider", "provider_id": "provider", "tenant_id": "tenant-a",
            "resource": "https://provider.example/api", "consent_identity_strategy_id": strategy.id,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        let context = Some(Extension(PatTenantContext {
            token_id: "test-token".into(),
            tenant_id: "tenant-a".into(),
        }));
        let allowed = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(&format!(
                r"\ATENANT:tenant-a:jwt-verification-strategies:{}\z",
                regex::escape(&strategy.id),
            ))
            .unwrap(),
        ))));
        let denied = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:credential-providers:provider\z").unwrap(),
        ))));
        let invalid = |result: Result<(), ProviderReferenceError>| {
            matches!(result, Err(ProviderReferenceError::InvalidConsentStrategy))
        };
        assert!(
            validate_consent_strategy(&state, &provider, &context, &allowed)
                .await
                .is_ok()
        );
        assert!(invalid(validate_consent_strategy(&state, &provider, &context, &denied).await));
        for tenant in [None, Some("tenant-b".into())] {
            provider.tenant_id = tenant;
            assert!(invalid(validate_consent_strategy(&state, &provider, &None, &None).await));
        }
        provider.tenant_id = Some("tenant-a".into());
        let mut global = strategy.clone();
        global.tenant_id = None;
        strategies
            .update(global.clone())
            .await
            .unwrap();
        assert!(
            validate_consent_strategy(&state, &provider, &context, &allowed)
                .await
                .is_ok()
        );
        provider.provider_type = CredentialProviderType::OAuth2ClientCredentials;
        assert!(invalid(validate_consent_strategy(&state, &provider, &None, &None).await));
        provider.provider_type = CredentialProviderType::OAuth2AuthorizationCode;
        provider.resource = None;
        assert!(invalid(validate_consent_strategy(&state, &provider, &None, &None).await));
        provider.resource = Some("https://provider.example/api".into());
        global.expected_issuer = "http://identity.example/".into();
        strategies
            .update(global)
            .await
            .unwrap();
        assert!(invalid(validate_consent_strategy(&state, &provider, &None, &None).await));
        strategies
            .delete(&strategy.id)
            .await
            .unwrap();
        assert!(invalid(validate_consent_strategy(&state, &provider, &None, &None).await));
        state.identity_strategies = None;
        assert!(invalid(validate_consent_strategy(&state, &provider, &None, &None).await));
        provider.consent_identity_strategy_id = None;
        assert!(
            validate_consent_strategy(&state, &provider, &None, &None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn reference_errors_render_generic_responses() {
        for (error, status, body) in [
            (
                ProviderReferenceError::InvalidConsentStrategy,
                StatusCode::BAD_REQUEST,
                r#"{"error":"Consent identity strategy is invalid or not accessible"}"#,
            ),
            (
                ProviderReferenceError::IdentityConfigurationUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity verification configuration unavailable",
            ),
            (
                ProviderReferenceError::SecretNotAccessible,
                StatusCode::BAD_REQUEST,
                r#"{"error":"Secret reference is not accessible"}"#,
            ),
            (
                ProviderReferenceError::SecretLookupFailed,
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Internal server error"}"#,
            ),
            (
                ProviderReferenceError::InvalidSigningKey(
                    super::super::jwt_assertion::SigningKeyError::AlgorithmMismatch,
                ),
                StatusCode::BAD_REQUEST,
                r#"{"error":"jwt_bearer.signing_key_secret_ref: signing key does not match the signing algorithm"}"#,
            ),
        ] {
            let response = error.into_response();
            assert_eq!(response.status(), status);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(std::str::from_utf8(&bytes).unwrap(), body);
        }
    }

    struct Surfaces {
        readable: bool,
        surfaces: Vec<crate::config::agent_surface::AgentSurface>,
    }

    #[async_trait::async_trait]
    impl crate::surfaces::AgentSurfaceStore for Surfaces {
        async fn save(
            &self,
            _surface: &crate::config::agent_surface::AgentSurface,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
            Ok(None)
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::config::agent_surface::AgentSurface>> {
            if self.readable {
                Ok(self.surfaces.clone())
            } else {
                anyhow::bail!("surface store unavailable")
            }
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_usage_reads_every_surface_or_fails_with_a_generic_error() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = state_with_provider(&directory, None).await;

        state.surfaces = Some(Arc::new(Surfaces {
            readable: true,
            surfaces: Vec::new(),
        }));
        let usage = provider_usage(&state, "provider")
            .await
            .expect("readable surfaces give a usage");
        assert!(!usage.target_authentication);
        assert!(!usage.jwt_bearer_refused);
        assert!(
            usage
                .surface_tenants
                .is_empty()
        );

        state.surfaces = Some(Arc::new(Surfaces {
            readable: false,
            surfaces: Vec::new(),
        }));
        let Err(error) = provider_usage(&state, "provider").await else {
            panic!("an unreadable surface store must refuse");
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"error":"Internal server error"}"#);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_usage_finds_bindings_that_refuse_a_jwt_bearer_provider() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = state_with_provider(&directory, None).await;
        let bound = |endpoint: &str, authenticated: bool| {
            let mut access_point = json!({"listen_address": "127.0.0.1:0", "route": "/s", "protocol": "a2a"});
            if authenticated {
                access_point["caller_authentication"] = json!({"methods": [{"type": "jwt_bearer",
                    "jwt_verification_strategy_id": "strategy", "audiences": []}]});
            }
            serde_json::from_value::<crate::config::agent_surface::AgentSurface>(json!({
                "name": "s", "access_point": access_point, "target": {"endpoint": endpoint},
                "outbound_credentials": [{"credential_provider_id": "provider"}]
            }))
            .unwrap()
        };
        let usage_of = |surfaces: Vec<crate::config::agent_surface::AgentSurface>| {
            let mut state = state.clone();
            state.surfaces = Some(Arc::new(Surfaces { readable: true, surfaces }));
            async move {
                provider_usage(&state, "provider")
                    .await
                    .expect("readable surfaces give a usage")
            }
        };

        let safe = usage_of(vec![bound("https://agent.example", true)]).await;
        assert!(!safe.jwt_bearer_refused);
        assert!(!safe.target_authentication);
        assert_eq!(safe.surface_tenants, vec![None]);
        assert!(
            usage_of(vec![bound("https://agent.example", true), bound("http://agent.example", true)])
                .await
                .jwt_bearer_refused
        );
        assert!(
            usage_of(vec![bound("https://agent.example", false)])
                .await
                .jwt_bearer_refused
        );
        state.surfaces = None;
        assert!(
            !provider_usage(&state, "provider")
                .await
                .expect("no surface store gives an empty usage")
                .jwt_bearer_refused
        );
    }

    async fn state_with_provider(
        directory: &tempfile::TempDir,
        tenant_id: Option<&str>,
    ) -> CredentialProviderState {
        let state = CredentialProviderState {
            store: Arc::new(
                super::super::storage::FileSystemCredentialProviderStore::new(
                    directory
                        .path()
                        .join("providers"),
                )
                .await
                .unwrap(),
            ),
            secrets_store: Arc::new(
                crate::secrets::FilesystemSecretsStore::new(
                    directory
                        .path()
                        .join("secrets")
                        .to_str()
                        .unwrap(),
                )
                .unwrap(),
            ),
            identity_strategies: None,
            oauth_callback_route: "/oauth/callback".into(),
            surfaces: None,
        };
        let provider: CredentialProvider = serde_json::from_value(json!({
            "id": "provider", "name": "Operator provider", "provider_id": "provider", "tenant_id": tenant_id,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        state
            .store
            .create(provider)
            .await
            .unwrap();
        state
    }

    fn tenant_a() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    fn rename() -> Json<UpdateCredentialProviderRequest> {
        Json(serde_json::from_value(json!({ "name": "Tenant provider" })).unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tenant_token_cannot_update_or_delete_an_appliance_wide_provider() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, None).await;

        let read = get_provider(State(state.clone()), Path("provider".into()), tenant_a(), None)
            .await
            .into_response();
        assert_eq!(read.status(), StatusCode::OK);

        let update = update_provider(
            State(state.clone()),
            Path("provider".into()),
            tenant_a(),
            None,
            ManagementActor::default(),
            rename(),
        )
        .await
        .into_response();
        assert_eq!(update.status(), StatusCode::FORBIDDEN);

        let delete = delete_provider(
            State(state.clone()),
            Path("provider".into()),
            tenant_a(),
            None,
            ManagementActor::default(),
        )
        .await
        .into_response();
        assert_eq!(delete.status(), StatusCode::FORBIDDEN);

        let after = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("appliance-wide provider must survive");
        assert_eq!(after.name, "Operator provider");
        assert_eq!(after.tenant_id, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_tenants_provider_is_not_found_on_update_or_delete() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, Some("tenant-b")).await;

        let update = update_provider(
            State(state.clone()),
            Path("provider".into()),
            tenant_a(),
            None,
            ManagementActor::default(),
            rename(),
        )
        .await
        .into_response();
        assert_eq!(update.status(), StatusCode::NOT_FOUND);

        let delete = delete_provider(
            State(state.clone()),
            Path("provider".into()),
            tenant_a(),
            None,
            ManagementActor::default(),
        )
        .await
        .into_response();
        assert_eq!(delete.status(), StatusCode::NOT_FOUND);

        let after = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("another tenant's provider must survive");
        assert_eq!(after.name, "Operator provider");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_changes_are_recorded_with_the_actor() {
        use crate::delegation_vault::audit::DelegationAuditAction::CredentialProviderChanged;
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, None).await;
        let actor = ManagementActor::new(Some("admin-1"), Some("token-1"));

        let (statuses, events) = crate::audit::producer::capture(async {
            let update =
                update_provider(State(state.clone()), Path("provider".into()), None, None, actor.clone(), rename())
                    .await
                    .into_response()
                    .status();
            let delete = delete_provider(State(state.clone()), Path("provider".into()), None, None, actor.clone())
                .await
                .into_response()
                .status();
            (update, delete)
        })
        .await;

        assert_eq!(statuses, (StatusCode::OK, StatusCode::NO_CONTENT));
        let changes: Vec<ConfigChange> = events
            .iter()
            .map(|event| match &event.event {
                CredentialProviderChanged { change, provider_type } => {
                    assert_eq!(provider_type, "oauth2_authorization_code");
                    *change
                }
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(changes, vec![ConfigChange::Updated, ConfigChange::Deleted]);
        for event in &events {
            assert_eq!(event.provider_id.as_deref(), Some("provider"));
            let caller = event
                .caller
                .as_ref()
                .expect("attributed");
            assert_eq!(caller.auth_method, "access_token");
            assert_eq!(caller.token_id.as_deref(), Some("token-1"));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_provider_change_records_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, None).await;

        let (status, events) = crate::audit::producer::capture(async {
            delete_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, ManagementActor::default())
                .await
                .into_response()
                .status()
        })
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(events.is_empty(), "{events:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tenant_token_can_update_and_delete_its_own_provider() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, Some("tenant-a")).await;

        let update = update_provider(
            State(state.clone()),
            Path("provider".into()),
            tenant_a(),
            None,
            ManagementActor::default(),
            rename(),
        )
        .await
        .into_response();
        assert_eq!(update.status(), StatusCode::OK);
        assert_eq!(
            state
                .store
                .get("provider")
                .await
                .unwrap()
                .map(|provider| provider.name),
            Some("Tenant provider".to_string())
        );

        let delete = delete_provider(
            State(state.clone()),
            Path("provider".into()),
            tenant_a(),
            None,
            ManagementActor::default(),
        )
        .await
        .into_response();
        assert_eq!(delete.status(), StatusCode::NO_CONTENT);
        assert!(
            state
                .store
                .get("provider")
                .await
                .unwrap()
                .is_none()
        );
    }

    async fn api_key_provider_bound_by_a_tenant(directory: &tempfile::TempDir) -> CredentialProviderState {
        let mut state = state_with_provider(directory, None).await;
        for secret_id in ["API_KEY", "CLIENT_ID", "CLIENT_SECRET"] {
            state
                .secrets_store
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: None,
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: "value".into(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let provider: CredentialProvider = serde_json::from_value(json!({
            "id": "provider", "name": "Operator provider", "provider_id": "provider",
            "provider_type": "api_key", "api_key_secret_ref": "API_KEY",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        state
            .store
            .update(provider)
            .await
            .unwrap();
        let surface = serde_json::from_value::<crate::config::agent_surface::AgentSurface>(json!({
            "name": "s", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/s", "protocol": "a2a"},
            "target": {"endpoint": "https://agent.example"},
            "outbound_credentials": [{"credential_provider_id": "provider"}]
        }))
        .unwrap();
        state.surfaces = Some(Arc::new(Surfaces {
            readable: true,
            surfaces: vec![surface],
        }));
        state
    }

    async fn update_as_operator(
        state: &CredentialProviderState,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = update_provider(
            State(state.clone()),
            Path("provider".into()),
            None,
            None,
            ManagementActor::default(),
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_that_repeats_the_stored_type_skips_the_retype_guards() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = api_key_provider_bound_by_a_tenant(&directory).await;

        let same_type = json!({"provider_type": "api_key", "name": "Renamed provider"});
        let (status, body) = update_as_operator(&state, same_type).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], "Renamed provider");
        assert_eq!(body["provider_type"], "api_key");

        state.surfaces = Some(Arc::new(Surfaces {
            readable: false,
            surfaces: Vec::new(),
        }));
        let describe = json!({"provider_type": "api_key", "description": "Unchanged type"});
        let (status, body) = update_as_operator(&state, describe).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let stored = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("provider is stored");
        assert_eq!(stored.name, "Renamed provider");
        assert_eq!(stored.description.as_deref(), Some("Unchanged type"));
        assert_eq!(stored.provider_type, CredentialProviderType::ApiKey);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retype_still_runs_the_usage_guards() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = api_key_provider_bound_by_a_tenant(&directory).await;
        let retype = json!({
            "provider_type": "oauth2_client_credentials", "name": "Retyped provider",
            "token_endpoint": "https://192.0.2.10/token",
            "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"
        });

        let (status, body) = update_as_operator(&state, retype.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            body["error"],
            "A surface of another tenant uses this credential provider, and the new type sends the gateway's own credential"
        );

        state.surfaces = Some(Arc::new(Surfaces {
            readable: false,
            surfaces: Vec::new(),
        }));
        let (status, body) = update_as_operator(&state, retype).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["error"], "Internal server error");

        let stored = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("provider is stored");
        assert_eq!(stored.name, "Operator provider");
        assert_eq!(stored.provider_type, CredentialProviderType::ApiKey);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_refuses_a_resource_that_is_not_a_canonical_https_uri() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, None).await;

        let (status, body) = update_as_operator(&state, json!({ "resource": "http://insecure.example/api" })).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "resource must be a canonical HTTPS URI");
        let stored = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("provider is stored");
        assert_eq!(stored.resource, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_keeps_an_absent_description_and_authorization_endpoint_and_clears_a_null_one() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, None).await;
        let stored = || async {
            state
                .store
                .get("provider")
                .await
                .unwrap()
                .expect("provider is stored")
        };

        let set = json!({"description": "Calendar", "authorization_endpoint": "https://192.0.2.10/authorize"});
        let (status, body) = update_as_operator(&state, set).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["description"], "Calendar");
        assert_eq!(body["authorization_endpoint"], "https://192.0.2.10/authorize");

        let (status, body) = update_as_operator(&state, json!({"name": "Renamed"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            stored()
                .await
                .description
                .as_deref(),
            Some("Calendar")
        );
        assert_eq!(
            stored()
                .await
                .authorization_endpoint
                .as_deref(),
            Some("https://192.0.2.10/authorize")
        );

        let (status, body) = update_as_operator(&state, json!({"description": "x"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            stored()
                .await
                .description
                .as_deref(),
            Some("x")
        );

        let (status, body) = update_as_operator(&state, json!({"authorization_endpoint": "not a url"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            stored()
                .await
                .authorization_endpoint
                .is_some()
        );

        let clear = json!({"description": null, "authorization_endpoint": null});
        let (status, body) = update_as_operator(&state, clear).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.get("description")
                .is_none_or(serde_json::Value::is_null),
            "{body}"
        );
        assert!(
            body.get("authorization_endpoint")
                .is_none_or(serde_json::Value::is_null),
            "{body}"
        );
        assert_eq!(stored().await.description, None);
        assert_eq!(
            stored()
                .await
                .authorization_endpoint,
            None
        );
        assert_eq!(stored().await.name, "Renamed");
    }

    #[tokio::test]
    async fn save_refuses_an_http_token_endpoint_for_every_oauth_provider_type() {
        for provider_type in [
            CredentialProviderType::OAuth2AuthorizationCode,
            CredentialProviderType::OAuth2ClientCredentials,
            CredentialProviderType::OAuth2JwtBearer,
        ] {
            let mut provider: CredentialProvider = serde_json::from_value(json!({
                "id": "provider", "name": "Provider", "provider_id": "provider",
                "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET",
                "jwt_bearer": {"assertion_issuer": "gateway@example.test", "signing_key_secret_ref": "KEY",
                    "signing_algorithm": "ES256"},
                "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
            }))
            .unwrap();
            if provider_type != CredentialProviderType::OAuth2JwtBearer {
                provider.jwt_bearer = None;
            }
            provider.provider_type = provider_type.clone();

            provider.token_endpoint = Some("http://auth.example/token".into());
            let response = validate_provider_shape(&provider).expect_err("an http token endpoint is refused");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{provider_type:?}");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"error":"token_endpoint must be an https URL"}"#);

            provider.token_endpoint = Some("https://auth.example/token".into());
            assert!(validate_provider_shape(&provider).is_ok(), "{provider_type:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_that_moves_the_token_endpoint_to_http_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, None).await;
        let mut provider = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("provider is stored");
        provider.provider_type = CredentialProviderType::OAuth2ClientCredentials;
        provider.token_endpoint = Some("https://auth.example/token".into());
        provider.client_id_secret_ref = Some("CLIENT_ID".into());
        provider.client_secret_secret_ref = Some("CLIENT_SECRET".into());
        state
            .store
            .update(provider)
            .await
            .unwrap();

        let (status, body) = update_as_operator(&state, json!({"token_endpoint": "http://192.0.2.10/token"})).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "token_endpoint must be an https URL");
        let stored = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("provider is stored");
        assert_eq!(
            stored
                .token_endpoint
                .as_deref(),
            Some("https://auth.example/token")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_refuses_a_secret_reference_that_is_not_accessible() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, None).await;

        let (status, body) = update_as_operator(&state, json!({ "api_key_secret_ref": "MISSING_KEY" })).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "Secret reference is not accessible");
        let stored = state
            .store
            .get("provider")
            .await
            .unwrap()
            .expect("provider is stored");
        assert_eq!(stored.api_key_secret_ref, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delete_fails_closed_when_the_surfaces_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = state_with_provider(&directory, None).await;
        state.surfaces = Some(Arc::new(Surfaces {
            readable: false,
            surfaces: Vec::new(),
        }));

        let response =
            delete_provider(State(state.clone()), Path("provider".into()), None, None, ManagementActor::default())
                .await
                .into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"error":"Internal server error"}"#);
        assert!(
            state
                .store
                .get("provider")
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[cfg(test)]
mod jwt_bearer_api_tests {
    use super::*;
    use crate::credential_providers::jwt_assertion::test_keys::{ec_pkcs8_pem, rsa_pkcs8_pem};
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore};
    use serde_json::{Value, json};

    const ENDPOINT: &str = "https://192.0.2.10/token";

    async fn state(directory: &tempfile::TempDir) -> CredentialProviderState {
        let secrets = FilesystemSecretsStore::new_async(
            directory
                .path()
                .join("secrets")
                .to_str()
                .expect("utf-8 path"),
        )
        .await
        .expect("secrets store opens");
        for (secret_id, value, tenant_id) in [
            ("EC_KEY", ec_pkcs8_pem(), None),
            ("RSA_KEY", rsa_pkcs8_pem(), None),
            ("TENANT_KEY", ec_pkcs8_pem(), Some("tenant-a")),
            ("JB_ID", "jb-client", None),
            ("JB_SECRET", "jb-secret", None),
            ("TENANT_ID", "tenant-client", Some("tenant-a")),
            ("TENANT_SECRET", "tenant-secret", Some("tenant-a")),
        ] {
            secrets
                .create(CreateSecretRequest {
                    tenant_id: tenant_id.map(str::to_string),
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: value.into(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .expect("secret is created");
        }
        CredentialProviderState {
            store: Arc::new(
                super::super::storage::FileSystemCredentialProviderStore::new(
                    directory
                        .path()
                        .join("providers"),
                )
                .await
                .expect("provider store opens"),
            ),
            secrets_store: Arc::new(secrets),
            identity_strategies: None,
            oauth_callback_route: "/oauth/callback".into(),
            surfaces: None,
        }
    }

    fn request(
        provider_id: &str,
        key_ref: &str,
        algorithm: &str,
    ) -> Value {
        json!({
            "name": "Vertex agent", "provider_id": provider_id, "provider_type": "oauth2_jwt_bearer",
            "token_endpoint": ENDPOINT, "default_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "jwt_bearer": {"assertion_issuer": "gateway@project.iam.gserviceaccount.com",
                "signing_key_secret_ref": key_ref, "signing_algorithm": algorithm, "key_id": "key-1"}
        })
    }

    async fn create(
        state: &CredentialProviderState,
        context: Option<Extension<PatTenantContext>>,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = create_provider(
            State(state.clone()),
            None,
            context,
            None,
            ManagementActor::default(),
            Json(serde_json::from_value(body).expect("request deserializes")),
        )
        .await
        .into_response();
        body_of(response).await
    }

    async fn body_of(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body reads");
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn assert_no_key_material(body: &Value) {
        let text = body.to_string();
        assert!(!text.contains("PRIVATE KEY"), "{text}");
        assert!(!text.contains("jb-secret"), "{text}");
    }

    #[tokio::test]
    async fn test_create_jwt_bearer_provider_stores_settings_and_never_returns_the_key() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let mut body = request("vertex", "EC_KEY", "ES256");
        body["client_id_secret_ref"] = "JB_ID".into();
        body["client_secret_secret_ref"] = "JB_SECRET".into();
        let (status, created) = create(&state, None, body).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["provider_type"], "oauth2_jwt_bearer");
        assert_eq!(created["jwt_bearer"]["signing_key_secret_ref"], "EC_KEY");
        assert_eq!(created["jwt_bearer"]["signing_algorithm"], "ES256");
        assert_no_key_material(&created);

        let id = created["id"]
            .as_str()
            .expect("id is a string")
            .to_string();
        let (status, fetched) = body_of(
            get_provider(State(state.clone()), Path(id), None, None)
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fetched["jwt_bearer"]["assertion_issuer"], "gateway@project.iam.gserviceaccount.com");
        assert_no_key_material(&fetched);

        let (status, listed) = body_of(
            list_providers(State(state.clone()), None, None)
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed[0]["jwt_bearer"]["key_id"], "key-1");
        assert!(
            listed[0]["jwt_bearer"]
                .get("signing_key_secret_ref")
                .is_none()
        );
        assert_no_key_material(&listed);
    }

    #[tokio::test]
    async fn test_create_jwt_bearer_provider_rejects_invalid_configuration() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let mut http_endpoint = request("http-endpoint", "EC_KEY", "ES256");
        http_endpoint["token_endpoint"] = "http://192.0.2.10/token".into();
        let mut no_settings = request("no-settings", "EC_KEY", "ES256");
        no_settings
            .as_object_mut()
            .expect("object")
            .remove("jwt_bearer");
        let mut secret_without_id = request("secret-only", "EC_KEY", "ES256");
        secret_without_id["client_secret_secret_ref"] = "JB_SECRET".into();
        let mut empty_issuer = request("empty-issuer", "EC_KEY", "ES256");
        empty_issuer["jwt_bearer"]["assertion_issuer"] = "".into();
        let mut settings_on_client_credentials = request("cc", "EC_KEY", "ES256");
        settings_on_client_credentials["provider_type"] = "oauth2_client_credentials".into();
        settings_on_client_credentials["client_id_secret_ref"] = "JB_ID".into();
        settings_on_client_credentials["client_secret_secret_ref"] = "JB_SECRET".into();
        for (body, message) in [
            (request("mismatch", "EC_KEY", "RS256"), "does not match the signing algorithm"),
            (request("not-a-key", "JB_SECRET", "RS256"), "PKCS#8"),
            (request("missing-key", "MISSING", "ES256"), "not accessible"),
            (http_endpoint, "https"),
            (no_settings, "jwt_bearer settings are required"),
            (secret_without_id, "requires client_id_secret_ref"),
            (empty_issuer, "assertion_issuer"),
            (settings_on_client_credentials, "apply only to JWT bearer providers"),
        ] {
            let (status, response) = create(&state, None, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
            let error = response["error"]
                .as_str()
                .expect("error message");
            assert!(error.contains(message), "{error} should mention {message}");
            assert!(!error.contains("PRIVATE"), "{error}");
        }
        assert!(
            state
                .store
                .list()
                .await
                .expect("list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_create_refuses_a_provider_missing_the_fields_its_type_needs() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let mut no_jwt_endpoint = request("no-endpoint", "EC_KEY", "ES256");
        no_jwt_endpoint
            .as_object_mut()
            .expect("object")
            .remove("token_endpoint");
        let mut jwt_with_consent = request("consent", "EC_KEY", "ES256");
        jwt_with_consent["consent_identity_strategy_id"] = "strategy".into();
        let oauth_without_endpoint = json!({
            "name": "CC", "provider_id": "cc", "provider_type": "oauth2_client_credentials",
            "client_id_secret_ref": "JB_ID", "client_secret_secret_ref": "JB_SECRET"
        });
        let api_key_without_ref = json!({"name": "Key", "provider_id": "key", "provider_type": "api_key"});
        for (body, message) in [
            (no_jwt_endpoint, "token_endpoint is required for JWT bearer providers"),
            (jwt_with_consent, "consent_identity_strategy_id applies only to authorization code providers"),
            (oauth_without_endpoint, "token_endpoint is required for OAuth providers"),
            (api_key_without_ref, "api_key_secret_ref is required for ApiKey providers"),
        ] {
            let (status, response) = create(&state, None, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
            assert_eq!(response["error"], message);
        }
        assert!(
            state
                .store
                .list()
                .await
                .expect("list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_gateway_grant_secret_checks_name_the_refused_reference() {
        use crate::credential_providers::jwt_assertion::SigningKeyError;
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let provider = |mut body: Value, tenant_id: Option<&str>| -> CredentialProvider {
            body["id"] = "provider".into();
            body["tenant_id"] = tenant_id.into();
            body["created_at"] = "2026-09-01T00:00:00Z".into();
            body["updated_at"] = "2026-09-01T00:00:00Z".into();
            serde_json::from_value(body).expect("provider deserializes")
        };

        assert!(
            validate_gateway_grant_secrets(&state, &provider(request("ok", "EC_KEY", "ES256"), None))
                .await
                .is_ok()
        );
        assert!(
            validate_gateway_grant_secrets(
                &state,
                &provider(request("tenant", "TENANT_KEY", "ES256"), Some("tenant-a"))
            )
            .await
            .is_ok()
        );
        let user_consent = json!({"name": "Consent", "provider_id": "consent",
            "provider_type": "oauth2_authorization_code", "client_id_secret_ref": "MISSING"});
        assert!(
            validate_gateway_grant_secrets(&state, &provider(user_consent, None))
                .await
                .is_ok()
        );

        for (body, tenant_id, expected) in [
            (
                request("mismatch", "EC_KEY", "RS256"),
                None,
                r#"{"error":"jwt_bearer.signing_key_secret_ref: signing key does not match the signing algorithm"}"#,
            ),
            (request("missing", "MISSING", "ES256"), None, r#"{"error":"Secret reference is not accessible"}"#),
            (
                request("other-tenant", "EC_KEY", "ES256"),
                Some("tenant-a"),
                r#"{"error":"Secret reference is not accessible"}"#,
            ),
        ] {
            let error = validate_gateway_grant_secrets(&state, &provider(body, tenant_id))
                .await
                .expect_err("the reference is refused");
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body reads");
            assert_eq!(std::str::from_utf8(&bytes).expect("utf-8"), expected);
        }
        assert!(matches!(
            validate_gateway_grant_secrets(&state, &provider(request("not-a-key", "JB_SECRET", "ES256"), None)).await,
            Err(ProviderReferenceError::InvalidSigningKey(SigningKeyError::Format))
        ));
    }

    #[tokio::test]
    async fn test_tenant_jwt_bearer_provider_uses_only_its_own_tenants_secrets() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let tenant_a = || {
            Some(Extension(PatTenantContext {
                token_id: "token-a".into(),
                tenant_id: "tenant-a".into(),
            }))
        };
        let (status, response) = create(&state, tenant_a(), request("appliance-key", "EC_KEY", "ES256")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "Secret reference is not accessible");

        let (status, created) = create(&state, tenant_a(), request("tenant-key", "TENANT_KEY", "ES256")).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["tenant_id"], "tenant-a");

        let (status, response) = create(&state, None, request("appliance-uses-tenant", "TENANT_KEY", "ES256")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    }

    #[tokio::test]
    async fn test_tenant_provider_of_any_type_uses_only_its_own_tenants_secrets() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let tenant_a = || {
            Some(Extension(PatTenantContext {
                token_id: "token-a".into(),
                tenant_id: "tenant-a".into(),
            }))
        };
        let oauth = |provider_id: &str, provider_type: &str, id_ref: &str, secret_ref: &str| {
            json!({
                "name": provider_id, "provider_id": provider_id, "provider_type": provider_type,
                "token_endpoint": ENDPOINT, "authorization_endpoint": "https://192.0.2.10/authorize",
                "client_id_secret_ref": id_ref, "client_secret_secret_ref": secret_ref
            })
        };

        let (status, response) =
            create(&state, tenant_a(), oauth("cc-appliance", "oauth2_client_credentials", "JB_ID", "JB_SECRET")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "Secret reference is not accessible");

        let (status, created) =
            create(&state, tenant_a(), oauth("cc-tenant", "oauth2_client_credentials", "TENANT_ID", "TENANT_SECRET"))
                .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["tenant_id"], "tenant-a");

        let (status, response) =
            create(&state, tenant_a(), oauth("code-appliance", "oauth2_authorization_code", "JB_ID", "JB_SECRET"))
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "Secret reference is not accessible");

        let (status, created) =
            create(&state, tenant_a(), oauth("code-tenant", "oauth2_authorization_code", "TENANT_ID", "TENANT_SECRET"))
                .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
    }

    #[tokio::test]
    async fn test_update_jwt_bearer_provider_revalidates_its_key_and_type() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let (status, created) = create(&state, None, request("vertex", "RSA_KEY", "RS256")).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"]
            .as_str()
            .expect("id is a string")
            .to_string();
        let update = |body: Value| {
            let state = state.clone();
            let id = id.clone();
            async move {
                body_of(
                    update_provider(
                        State(state),
                        Path(id),
                        None,
                        None,
                        ManagementActor::default(),
                        Json(serde_json::from_value(body).expect("update deserializes")),
                    )
                    .await
                    .into_response(),
                )
                .await
            }
        };

        let (status, renamed) = update(json!({"name": "Vertex renamed"})).await;
        assert_eq!(status, StatusCode::OK, "{renamed}");
        assert_eq!(renamed["jwt_bearer"]["signing_key_secret_ref"], "RSA_KEY");

        let (status, response) = update(json!({"jwt_bearer": {"assertion_issuer": "issuer",
            "signing_key_secret_ref": "RSA_KEY", "signing_algorithm": "ES256"}}))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");

        let (status, response) = update(json!({"provider_type": "oauth2_client_credentials"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");

        let (status, retyped) = update(json!({"provider_type": "oauth2_client_credentials",
            "client_id_secret_ref": "JB_ID", "client_secret_secret_ref": "JB_SECRET"}))
        .await;
        assert_eq!(status, StatusCode::OK, "{retyped}");
        assert!(
            retyped
                .get("jwt_bearer")
                .is_none(),
            "settings are dropped when the type changes"
        );
    }

    #[tokio::test]
    async fn test_jwt_bearer_audience_is_trimmed_stored_and_round_tripped() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let mut body = request("vertex", "EC_KEY", "ES256");
        body["jwt_bearer"]["audience"] = "  https://issuer.example/  ".into();
        let (status, created) = create(&state, None, body).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["jwt_bearer"]["audience"], "https://issuer.example/");
        let id = created["id"]
            .as_str()
            .expect("id is a string")
            .to_string();

        let (status, listed) = body_of(
            list_providers(State(state.clone()), None, None)
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed[0]["jwt_bearer"]["audience"], "https://issuer.example/");

        let settings = |audience: Value| {
            json!({"jwt_bearer": {"assertion_issuer": "gateway@project.iam.gserviceaccount.com",
                "signing_key_secret_ref": "EC_KEY", "signing_algorithm": "ES256", "audience": audience}})
        };
        let (status, updated) = update(&state, &id, settings("urn:example:as".into())).await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["jwt_bearer"]["audience"], "urn:example:as");

        let (status, updated) = update(&state, &id, settings("   ".into())).await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert!(
            updated["jwt_bearer"]
                .get("audience")
                .is_none(),
            "{updated}"
        );
        let stored = state
            .store
            .get(&id)
            .await
            .expect("get")
            .expect("provider is stored");
        assert_eq!(
            stored
                .jwt_bearer
                .expect("settings are stored")
                .audience,
            None
        );

        let (status, response) = update(&state, &id, settings("https://issuer.example/ a".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(
            response["error"],
            "jwt_bearer.audience must be 1 to 512 bytes with no whitespace or control characters"
        );
    }

    #[tokio::test]
    async fn test_create_refuses_an_invalid_jwt_bearer_audience() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let message = "jwt_bearer.audience must be 1 to 512 bytes with no whitespace or control characters";
        for audience in ["two words".to_string(), "a\u{1}b".to_string(), "a".repeat(513)] {
            let mut body = request("bad-audience", "EC_KEY", "ES256");
            body["jwt_bearer"]["audience"] = audience.clone().into();
            let (status, response) = create(&state, None, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
            assert_eq!(response["error"], message, "{audience:?}");
        }
        assert!(
            state
                .store
                .list()
                .await
                .expect("list")
                .is_empty()
        );
    }

    async fn update(
        state: &CredentialProviderState,
        id: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        body_of(
            update_provider(
                State(state.clone()),
                Path(id.to_string()),
                None,
                None,
                ManagementActor::default(),
                Json(serde_json::from_value(body).expect("update deserializes")),
            )
            .await
            .into_response(),
        )
        .await
    }

    #[tokio::test]
    async fn test_update_clears_client_references_with_null_and_the_next_grant_sends_no_client_auth() {
        use crate::delegation_vault::gateway_token::{
            ProviderSecrets, request_gateway_grant, test_endpoint::TokenEndpoint,
        };

        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let mut body = request("vertex", "EC_KEY", "ES256");
        body["client_id_secret_ref"] = "JB_ID".into();
        body["client_secret_secret_ref"] = "JB_SECRET".into();
        let (status, created) = create(&state, None, body).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"]
            .as_str()
            .expect("id is a string")
            .to_string();

        let (status, renamed) = update(&state, &id, json!({"name": "Vertex renamed"})).await;
        assert_eq!(status, StatusCode::OK, "{renamed}");
        assert_eq!(renamed["client_id_secret_ref"], "JB_ID", "an absent reference is kept");
        assert_eq!(renamed["client_secret_secret_ref"], "JB_SECRET");

        let (status, cleared) =
            update(&state, &id, json!({"client_id_secret_ref": null, "client_secret_secret_ref": null})).await;
        assert_eq!(status, StatusCode::OK, "{cleared}");
        let (status, fetched) = body_of(
            get_provider(State(state.clone()), Path(id.clone()), None, None)
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for body in [&cleared, &fetched] {
            assert!(
                body.get("client_id_secret_ref")
                    .is_none(),
                "{body}"
            );
            assert!(
                body.get("client_secret_secret_ref")
                    .is_none(),
                "{body}"
            );
        }

        let endpoint = TokenEndpoint::start(
            StatusCode::OK,
            json!({"access_token": "gateway-token", "token_type": "bearer", "expires_in": 3600}).to_string(),
        )
        .await;
        let mut stored = state
            .store
            .get(&id)
            .await
            .expect("store reads")
            .expect("provider is stored");
        stored.token_endpoint = Some(endpoint.url.clone());
        request_gateway_grant(&stored, &[], &ProviderSecrets::new(&state.secrets_store, &stored), &endpoint.egress())
            .await
            .expect("grant succeeds");
        assert_eq!(endpoint.last_authorization(), None);
        assert!(
            !endpoint
                .last_form()
                .contains_key("client_id")
        );
    }

    #[tokio::test]
    async fn test_update_refuses_to_clear_references_an_oauth_provider_requires() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = state(&directory).await;
        let (status, created) = create(
            &state,
            None,
            json!({
                "name": "cc", "provider_id": "cc", "provider_type": "oauth2_client_credentials",
                "token_endpoint": ENDPOINT, "client_id_secret_ref": "JB_ID", "client_secret_secret_ref": "JB_SECRET"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"]
            .as_str()
            .expect("id is a string")
            .to_string();

        let (status, response) = update(&state, &id, json!({"client_secret_secret_ref": null})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        let stored = state
            .store
            .get(&id)
            .await
            .expect("store reads")
            .expect("provider is stored");
        assert_eq!(
            stored
                .client_secret_secret_ref
                .as_deref(),
            Some("JB_SECRET")
        );
    }
}
