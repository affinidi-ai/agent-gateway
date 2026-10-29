//! API handlers for credential provider CRUD operations

use super::{
    CreateCredentialProviderRequest, CredentialProvider, CredentialProviderListItem, CredentialProviderType,
    UpdateCredentialProviderRequest, storage::CredentialProviderStorage,
};
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
    #[error("jwt_signing_key_secret_ref must reference a PEM private key matching jwt_signing_algorithm")]
    InvalidSigningKey,
    #[error("jwt_certificate_secret_ref must reference a PEM certificate")]
    InvalidCertificate,
}

impl IntoResponse for ProviderReferenceError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidConsentStrategy
            | Self::SecretNotAccessible
            | Self::InvalidSigningKey
            | Self::InvalidCertificate => {
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
        || provider.provider_type != CredentialProviderType::OAuth2AuthorizationCode
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
    tenant_id: Option<&str>,
    references: impl IntoIterator<Item = Option<&str>>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), ProviderReferenceError> {
    for secret_id in references
        .into_iter()
        .flatten()
    {
        let secret = state
            .secrets_store
            .get_by_secret_id(secret_id)
            .await
            .map_err(|error| {
                warn!(%error, "Failed to validate credential provider secret reference");
                ProviderReferenceError::SecretLookupFailed
            })?
            .ok_or(ProviderReferenceError::SecretNotAccessible)?;
        if !can_reference(tenant_id, secret.tenant_id.as_deref())
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

/// Why the fields of a provider that signs a JWT were rejected.
#[derive(Debug, thiserror::Error)]
enum JwtProviderFieldError {
    #[error("{0} is required for this provider type")]
    Missing(&'static str),
    #[error("client_secret_secret_ref is not allowed: this provider authenticates with a signed JWT")]
    ClientSecretNotAllowed,
    #[error("jwt_signing_algorithm is not supported for this provider type")]
    UnsupportedAlgorithm,
    #[error("jwt_audience: {0}")]
    InvalidAudience(String),
}

impl IntoResponse for JwtProviderFieldError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
    }
}

/// The required fields, algorithm and audience of an `oauth2_jwt_bearer` or
/// `oauth2_client_credentials_jwt_auth` provider; other types pass unchecked.
fn validate_jwt_provider(provider: &CredentialProvider) -> Result<(), JwtProviderFieldError> {
    let required = match provider.provider_type {
        CredentialProviderType::OAuth2JwtBearer => vec![
            (
                "token_endpoint",
                provider
                    .token_endpoint
                    .as_deref(),
            ),
            (
                "jwt_issuer",
                provider
                    .jwt
                    .jwt_issuer
                    .as_deref(),
            ),
            (
                "jwt_signing_key_secret_ref",
                provider
                    .jwt
                    .jwt_signing_key_secret_ref
                    .as_deref(),
            ),
        ],
        CredentialProviderType::OAuth2ClientCredentialsJwtAuth => vec![
            (
                "token_endpoint",
                provider
                    .token_endpoint
                    .as_deref(),
            ),
            (
                "client_id_secret_ref",
                provider
                    .client_id_secret_ref
                    .as_deref(),
            ),
            (
                "jwt_signing_key_secret_ref",
                provider
                    .jwt
                    .jwt_signing_key_secret_ref
                    .as_deref(),
            ),
            (
                "jwt_certificate_secret_ref",
                provider
                    .jwt
                    .jwt_certificate_secret_ref
                    .as_deref(),
            ),
        ],
        CredentialProviderType::OAuth2AuthorizationCode
        | CredentialProviderType::OAuth2ClientCredentials
        | CredentialProviderType::ApiKey => return Ok(()),
    };
    if let Some((field, _)) = required
        .into_iter()
        .find(|(_, value)| value.is_none_or(|value| value.trim().is_empty()))
    {
        return Err(JwtProviderFieldError::Missing(field));
    }
    if provider.provider_type == CredentialProviderType::OAuth2ClientCredentialsJwtAuth
        && provider
            .client_secret_secret_ref
            .is_some()
    {
        return Err(JwtProviderFieldError::ClientSecretNotAllowed);
    }
    if let Some(algorithm) = provider
        .jwt
        .jwt_signing_algorithm
        && !provider
            .provider_type
            .allows_jwt_algorithm(algorithm)
    {
        return Err(JwtProviderFieldError::UnsupportedAlgorithm);
    }
    if let Some(audience) = provider
        .jwt
        .jwt_audience
        .as_deref()
    {
        crate::url_validation::validate_oauth_endpoint_url(audience)
            .map_err(|error| JwtProviderFieldError::InvalidAudience(error.to_string()))?;
    }
    Ok(())
}

/// Resolve the signing key and certificate a JWT-signing provider references and check
/// they parse, so a wrong format fails the save rather than the first token request.
/// Runs after [`validate_secret_references`] has checked the caller may use them.
async fn validate_jwt_key_material(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
) -> Result<(), ProviderReferenceError> {
    use crate::delegation_vault::jwt_assertion;

    let Some(algorithm) = provider.jwt_signing_algorithm() else {
        return Ok(());
    };
    let resolve = |secret_id: Option<String>| async move {
        let Some(secret_id) = secret_id else {
            return Ok(None);
        };
        state
            .secrets_store
            .get_by_secret_id(&secret_id)
            .await
            .map_err(|error| {
                warn!(%error, "Failed to resolve credential provider key material");
                ProviderReferenceError::SecretLookupFailed
            })?
            .map(|secret| Some(zeroize::Zeroizing::new(secret.value)))
            .ok_or(ProviderReferenceError::SecretNotAccessible)
    };
    if let Some(key) = resolve(
        provider
            .jwt
            .jwt_signing_key_secret_ref
            .clone(),
    )
    .await?
    {
        jwt_assertion::check_signing_key(&key, algorithm).map_err(|_| ProviderReferenceError::InvalidSigningKey)?;
    }
    if let Some(certificate) = resolve(
        provider
            .jwt
            .jwt_certificate_secret_ref
            .clone(),
    )
    .await?
    {
        jwt_assertion::certificate_thumbprint(&certificate).map_err(|_| ProviderReferenceError::InvalidCertificate)?;
    }
    Ok(())
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

    // Type-specific validation
    match &req.provider_type {
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::OAuth2ClientCredentials => {
            if req
                .token_endpoint
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "token_endpoint is required for OAuth providers"})),
                )
                    .into_response();
            }
            if req
                .client_id_secret_ref
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
                || req
                    .client_secret_secret_ref
                    .as_deref()
                    .is_none_or(|s| s.trim().is_empty())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "client_id_secret_ref and client_secret_secret_ref are required for OAuth providers"})),
                )
                    .into_response();
            }
        }
        CredentialProviderType::ApiKey => {
            if req
                .api_key_secret_ref
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "api_key_secret_ref is required for ApiKey providers"})),
                )
                    .into_response();
            }
        }
        CredentialProviderType::OAuth2JwtBearer | CredentialProviderType::OAuth2ClientCredentialsJwtAuth => {}
    }
    req.jwt = req.jwt.normalized();

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

    if let Err(error) = validate_secret_references(
        &state,
        req.tenant_id.as_deref(),
        [
            req.client_id_secret_ref
                .as_deref(),
            req.client_secret_secret_ref
                .as_deref(),
            req.api_key_secret_ref
                .as_deref(),
            req.jwt
                .jwt_signing_key_secret_ref
                .as_deref(),
            req.jwt
                .jwt_certificate_secret_ref
                .as_deref(),
        ],
        &context,
        &scope,
    )
    .await
    {
        return error.into_response();
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
        jwt: req.jwt,
        description: req.description,
        created_at: now,
        updated_at: now,
    };

    if let Err(error) = validate_jwt_provider(&provider) {
        return error.into_response();
    }
    if let Err(error) = validate_jwt_key_material(&state, &provider).await {
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
        Ok(created) => (StatusCode::CREATED, Json(serde_json::to_value(created).unwrap())).into_response(),
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

    if let Some(resource) = &req.resource
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
                .as_deref(),
        ),
        ("callback_url", req.callback_url.as_deref()),
    ]) {
        return resp;
    }

    let updated = CredentialProvider {
        id: existing.id,
        tenant_id: existing.tenant_id,
        name: req
            .name
            .unwrap_or(existing.name),
        provider_id: existing.provider_id, // immutable
        provider_type: req
            .provider_type
            .unwrap_or(existing.provider_type),
        authorization_endpoint: req
            .authorization_endpoint
            .or(existing.authorization_endpoint),
        token_endpoint: req
            .token_endpoint
            .or(existing.token_endpoint),
        client_id_secret_ref: req
            .client_id_secret_ref
            .or(existing.client_id_secret_ref),
        client_secret_secret_ref: req
            .client_secret_secret_ref
            .or(existing.client_secret_secret_ref)
            .filter(|secret_ref| !secret_ref.trim().is_empty()),
        default_scopes: req
            .default_scopes
            .unwrap_or(existing.default_scopes),
        callback_path: existing.callback_path, // auto-generated, immutable
        callback_url: req
            .callback_url
            .or(existing.callback_url),
        resource: req
            .resource
            .or(existing.resource),
        consent_identity_strategy_id: req
            .consent_identity_strategy_id
            .or(existing.consent_identity_strategy_id),
        token_refresh_enabled: req
            .token_refresh_enabled
            .unwrap_or(existing.token_refresh_enabled),
        additional_params: req
            .additional_params
            .unwrap_or(existing.additional_params),
        api_key_secret_ref: req
            .api_key_secret_ref
            .or(existing.api_key_secret_ref),
        jwt: req
            .jwt
            .or(existing.jwt)
            .normalized(),
        description: req
            .description
            .or(existing.description),
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };

    if let Err(error) = validate_jwt_provider(&updated) {
        return error.into_response();
    }
    if let Err(error) = validate_secret_references(
        &state,
        updated.tenant_id.as_deref(),
        [
            updated
                .client_id_secret_ref
                .as_deref(),
            updated
                .client_secret_secret_ref
                .as_deref(),
            updated
                .api_key_secret_ref
                .as_deref(),
            updated
                .jwt
                .jwt_signing_key_secret_ref
                .as_deref(),
            updated
                .jwt
                .jwt_certificate_secret_ref
                .as_deref(),
        ],
        &context,
        &scope,
    )
    .await
    {
        return error.into_response();
    }
    if let Err(error) = validate_jwt_key_material(&state, &updated).await {
        return error.into_response();
    }

    if let Err(error) = validate_consent_strategy(&state, &updated, &context, &scope).await {
        return error.into_response();
    }

    match state
        .store
        .update(updated.clone())
        .await
    {
        Ok(u) => (StatusCode::OK, Json(serde_json::to_value(u).unwrap())).into_response(),
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
    match state.store.delete(&id).await {
        Ok(true) => {
            info!(
                target: "credential_delegation",
                id = %id,
                "Credential provider deleted via API"
            );
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
mod jwt_provider_tests {
    use super::*;
    use crate::delegation_vault::jwt_assertion::test_keys;
    use serde_json::{Value, json};

    async fn state(directory: &tempfile::TempDir) -> CredentialProviderState {
        CredentialProviderState {
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
        }
    }

    async fn add_secret(
        state: &CredentialProviderState,
        secret_id: &str,
        value: &str,
    ) {
        state
            .secrets_store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: value.into(),
                secret_type: "general".into(),
                tags: vec![],
            })
            .await
            .unwrap();
    }

    async fn create(
        state: &CredentialProviderState,
        body: Value,
    ) -> (StatusCode, Value) {
        let response =
            create_provider(State(state.clone()), None, None, None, Json(serde_json::from_value(body).unwrap()))
                .await
                .into_response();
        body_of(response).await
    }

    async fn update(
        state: &CredentialProviderState,
        id: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = update_provider(
            State(state.clone()),
            Path(id.into()),
            None,
            None,
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        .into_response();
        body_of(response).await
    }

    async fn body_of(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn jwt_bearer(provider_id: &str) -> Value {
        json!({
            "name": "Vertex", "provider_id": provider_id, "provider_type": "oauth2_jwt_bearer",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwt_issuer": " agent@project.iam.gserviceaccount.com ",
            "jwt_signing_key_secret_ref": "SA_KEY",
            "jwt_key_id": "key-1",
            "default_scopes": ["https://www.googleapis.com/auth/cloud-platform"]
        })
    }

    fn jwt_auth(provider_id: &str) -> Value {
        json!({
            "name": "Foundry", "provider_id": provider_id, "provider_type": "oauth2_client_credentials_jwt_auth",
            "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "client_id_secret_ref": "CLIENT_ID",
            "jwt_signing_key_secret_ref": "SA_KEY",
            "jwt_certificate_secret_ref": "CERT"
        })
    }

    async fn with_key_material(directory: &tempfile::TempDir) -> CredentialProviderState {
        let state = state(directory).await;
        add_secret(&state, "SA_KEY", &test_keys::rsa_pkcs8().private_pem).await;
        add_secret(&state, "EC_KEY", &test_keys::ec_p256().private_pem).await;
        add_secret(&state, "CERT", &test_keys::certificate_pem()).await;
        add_secret(&state, "CLIENT_ID", "client-123").await;
        add_secret(&state, "CLIENT_SECRET", "client-secret").await;
        add_secret(&state, "NOT_A_KEY", "key-secret-marker").await;
        state
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_jwt_bearer_provider_is_created_with_trimmed_settings_and_no_client_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (status, body) = create(&state, jwt_bearer("vertex")).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["provider_type"], "oauth2_jwt_bearer");
        assert_eq!(body["jwt_issuer"], "agent@project.iam.gserviceaccount.com");
        let stored = state
            .store
            .find_by_provider_id("vertex")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored
                .jwt
                .jwt_signing_key_secret_ref
                .as_deref(),
            Some("SA_KEY")
        );
        assert_eq!(stored.jwt_signing_algorithm(), Some(crate::credential_providers::JwtSigningAlgorithm::RS256));
        assert_eq!(stored.client_id_secret_ref, None);
        assert_eq!(stored.client_secret_secret_ref, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_credentials_jwt_provider_is_created_with_a_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (status, body) = create(&state, jwt_auth("foundry")).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["provider_type"], "oauth2_client_credentials_jwt_auth");
        assert_eq!(body["jwt_certificate_secret_ref"], "CERT");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_jwt_provider_missing_a_required_field_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        for (mut body, field) in [
            (jwt_bearer("a"), "jwt_issuer"),
            (jwt_bearer("b"), "jwt_signing_key_secret_ref"),
            (jwt_bearer("c"), "token_endpoint"),
            (jwt_auth("d"), "client_id_secret_ref"),
            (jwt_auth("e"), "jwt_certificate_secret_ref"),
            (jwt_auth("f"), "jwt_signing_key_secret_ref"),
        ] {
            body.as_object_mut()
                .unwrap()
                .remove(field);
            let (status, response) = create(&state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
            assert_eq!(response["error"], format!("{field} is required for this provider type"));
        }
        let mut blank_issuer = jwt_bearer("g");
        blank_issuer["jwt_issuer"] = json!("   ");
        let (status, response) = create(&state, blank_issuer).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_issuer is required for this provider type");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_credentials_jwt_provider_with_a_client_secret_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let mut body = jwt_auth("foundry");
        body["client_secret_secret_ref"] = json!("CLIENT_SECRET");
        let (status, response) = create(&state, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response["error"],
            "client_secret_secret_ref is not allowed: this provider authenticates with a signed JWT"
        );
        assert!(
            state
                .store
                .find_by_provider_id("foundry")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_algorithm_outside_the_type_or_a_blocked_audience_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let mut pss_bearer = jwt_bearer("a");
        pss_bearer["jwt_signing_algorithm"] = json!("PS256");
        let mut ec_auth = jwt_auth("b");
        ec_auth["jwt_signing_algorithm"] = json!("ES256");
        for body in [pss_bearer, ec_auth] {
            let (status, response) = create(&state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(response["error"], "jwt_signing_algorithm is not supported for this provider type");
        }
        let mut internal = jwt_bearer("c");
        internal["jwt_audience"] = json!("http://169.254.169.254/token");
        let (status, response) = create(&state, internal).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .starts_with("jwt_audience: ")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn key_material_in_the_wrong_format_fails_the_save_without_echoing_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let mut not_a_key = jwt_bearer("a");
        not_a_key["jwt_signing_key_secret_ref"] = json!("NOT_A_KEY");
        let mut ec_as_rsa = jwt_bearer("b");
        ec_as_rsa["jwt_signing_key_secret_ref"] = json!("EC_KEY");
        for body in [not_a_key, ec_as_rsa] {
            let (status, response) = create(&state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                response["error"],
                "jwt_signing_key_secret_ref must reference a PEM private key matching jwt_signing_algorithm"
            );
            assert!(
                !response
                    .to_string()
                    .contains("key-secret-marker")
            );
        }
        let mut ec_bearer = jwt_bearer("c");
        ec_bearer["jwt_signing_key_secret_ref"] = json!("EC_KEY");
        ec_bearer["jwt_signing_algorithm"] = json!("ES256");
        assert_eq!(
            create(&state, ec_bearer)
                .await
                .0,
            StatusCode::CREATED
        );
        let mut bad_certificate = jwt_auth("d");
        bad_certificate["jwt_certificate_secret_ref"] = json!("NOT_A_KEY");
        let (status, response) = create(&state, bad_certificate).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_certificate_secret_ref must reference a PEM certificate");
        let mut missing_secret = jwt_bearer("e");
        missing_secret["jwt_signing_key_secret_ref"] = json!("NO_SUCH_SECRET");
        let (status, response) = create(&state, missing_secret).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "Secret reference is not accessible");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_validates_the_merged_provider_and_an_empty_client_secret_clears_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (status, created) = create(
            &state,
            json!({
                "name": "Foundry", "provider_id": "foundry", "provider_type": "oauth2_client_credentials",
                "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
                "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"]
            .as_str()
            .unwrap();
        let switch = json!({
            "provider_type": "oauth2_client_credentials_jwt_auth",
            "jwt_signing_key_secret_ref": "SA_KEY", "jwt_certificate_secret_ref": "CERT"
        });
        let (status, response) = update(&state, id, switch.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response["error"],
            "client_secret_secret_ref is not allowed: this provider authenticates with a signed JWT"
        );
        let mut cleared = switch;
        cleared["client_secret_secret_ref"] = json!("");
        let (status, response) = update(&state, id, cleared).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["provider_type"], "oauth2_client_credentials_jwt_auth");
        assert!(
            response
                .get("client_secret_secret_ref")
                .is_none()
        );
        let (status, response) = update(&state, id, json!({"jwt_signing_key_secret_ref": "NOT_A_KEY"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response["error"],
            "jwt_signing_key_secret_ref must reference a PEM private key matching jwt_signing_algorithm"
        );
        let (status, response) = update(&state, id, json!({"jwt_certificate_secret_ref": " "})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_certificate_secret_ref is required for this provider type");
        let (status, response) = update(&state, id, json!({"name": "Renamed"})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["jwt_certificate_secret_ref"], "CERT");
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
        ] {
            let response = error.into_response();
            assert_eq!(response.status(), status);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(std::str::from_utf8(&bytes).unwrap(), body);
        }
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

        let update = update_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, rename())
            .await
            .into_response();
        assert_eq!(update.status(), StatusCode::FORBIDDEN);

        let delete = delete_provider(State(state.clone()), Path("provider".into()), tenant_a(), None)
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

        let update = update_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, rename())
            .await
            .into_response();
        assert_eq!(update.status(), StatusCode::NOT_FOUND);

        let delete = delete_provider(State(state.clone()), Path("provider".into()), tenant_a(), None)
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
    async fn a_tenant_token_can_update_and_delete_its_own_provider() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_with_provider(&directory, Some("tenant-a")).await;

        let update = update_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, rename())
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

        let delete = delete_provider(State(state.clone()), Path("provider".into()), tenant_a(), None)
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
}
