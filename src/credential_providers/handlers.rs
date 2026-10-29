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

use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatContext, PatDelegationContext, PatResourceScope};
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
    /// Reads the issuer's metadata an external consent provider is checked against.
    pub issuer_metadata: super::external::IssuerMetadata,
    /// The surfaces whose bindings keep a provider from being deleted.
    pub surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    /// The vault whose grants a deleted provider's removal revokes.
    pub vault: Option<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>>,
    /// The test allow-list of authorization server fixtures a revocation may
    /// reach; `None` in production.
    pub egress_allowlist: Option<String>,
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
}

impl IntoResponse for ProviderReferenceError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidConsentStrategy | Self::SecretNotAccessible => {
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

/// The type-specific fields a provider without an issuer needs, if one is missing.
fn legacy_type_error(provider: &CredentialProvider) -> Option<&'static str> {
    let blank = |value: Option<&str>| value.is_none_or(|value| value.trim().is_empty());
    match provider.provider_type {
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::OAuth2ClientCredentials => {
            if blank(
                provider
                    .token_endpoint
                    .as_deref(),
            ) {
                return Some("token_endpoint is required for OAuth providers");
            }
            if blank(
                provider
                    .client_id_secret_ref
                    .as_deref(),
            ) || blank(
                provider
                    .client_secret_secret_ref
                    .as_deref(),
            ) {
                return Some("client_id_secret_ref and client_secret_secret_ref are required for OAuth providers");
            }
            None
        }
        CredentialProviderType::ApiKey => blank(
            provider
                .api_key_secret_ref
                .as_deref(),
        )
        .then_some("api_key_secret_ref is required for ApiKey providers"),
    }
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
        description: req.description,
        issuer: req.issuer,
        revocation_endpoint: req.revocation_endpoint,
        token_endpoint_auth_method: req.token_endpoint_auth_method,
        client_id: req.client_id,
        allow_unadvertised_pkce: req.allow_unadvertised_pkce,
        created_at: now,
        updated_at: now,
    };

    if let Err(error) = super::external::validate(&provider) {
        return error.into_response();
    }
    if !provider.is_external_consent()
        && let Some(message) = legacy_type_error(&provider)
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": message }))).into_response();
    }

    if let Some(resource) = &provider.resource
        && crate::sts::mcp_profile::canonical_https_url(resource).is_err()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "resource must be a canonical HTTPS URI"})))
            .into_response();
    }

    // Validate user-supplied URLs before storing them
    if let Some(resp) = validate_url_fields(&[
        (
            "token_endpoint",
            provider
                .token_endpoint
                .as_deref(),
        ),
        (
            "authorization_endpoint",
            provider
                .authorization_endpoint
                .as_deref(),
        ),
        (
            "revocation_endpoint",
            provider
                .revocation_endpoint
                .as_deref(),
        ),
        (
            "callback_url",
            provider
                .callback_url
                .as_deref(),
        ),
    ]) {
        return resp;
    }

    if let Err(error) = validate_secret_references(
        &state,
        provider.tenant_id.as_deref(),
        [
            provider
                .client_id_secret_ref
                .as_deref(),
            provider
                .client_secret_secret_ref
                .as_deref(),
            provider
                .api_key_secret_ref
                .as_deref(),
        ],
        &context,
        &scope,
    )
    .await
    {
        return error.into_response();
    }

    // A provider's slug is unique within its tenant, and among untenanted providers.
    match state
        .store
        .find_by_provider_id(provider.tenant_id.as_deref(), &provider.provider_id)
        .await
    {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!("provider_id '{}' already exists", provider.provider_id)
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
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Internal server error"})))
                .into_response();
        }
    }

    if let Err(error) = validate_consent_strategy(&state, &provider, &context, &scope).await {
        return error.into_response();
    }

    if let Some(issuer) = provider.issuer.clone() {
        let metadata = match (state.issuer_metadata)(issuer).await {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(
                    target: "credential_delegation",
                    provider_id = %provider.provider_id,
                    code = error.code(),
                    detail = error.detail(),
                    "Refused a credential provider whose issuer's metadata could not be read"
                );
                return super::external::ExternalProviderError::MetadataUnavailable(error.failure()).into_response();
            }
        };
        if let Err(error) = super::external::check_metadata(&provider, &metadata) {
            warn!(
                target: "credential_delegation",
                provider_id = %provider.provider_id,
                error = ?error,
                "Refused a credential provider that does not match its issuer's metadata"
            );
            return error.into_response();
        }
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
    if let Err(error) = super::external::refuse_changes(&existing, &req) {
        return error.into_response();
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
            .or(existing.client_secret_secret_ref),
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
        description: req
            .description
            .or(existing.description),
        issuer: existing.issuer,
        revocation_endpoint: existing.revocation_endpoint,
        token_endpoint_auth_method: existing.token_endpoint_auth_method,
        client_id: existing.client_id,
        allow_unadvertised_pkce: existing.allow_unadvertised_pkce,
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };

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
        ],
        &context,
        &scope,
    )
    .await
    {
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
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
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
    if let Err(response) =
        refuse_bound_provider(&state, &existing, tenant_context(&context), resource_scope(&scope)).await
    {
        return response;
    }
    let actor = crate::delegation_vault::audit::management_caller_context(
        caller
            .as_ref()
            .map(|Extension(AuthGuardOk(user_id))| user_id.as_str()),
        delegation
            .as_ref()
            .map(|Extension(delegation)| delegation.token_id.as_str()),
    );
    if let Err(response) = remove_provider_grants(&state, &existing, actor.as_ref()).await {
        return response;
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

fn unavailable(message: &'static str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": message }))).into_response()
}

/// Refuse to delete a provider a surface binds, in its base or a variant,
/// through `outbound_credentials` or a Transit Point's `transit_credentials`.
/// Only the surfaces that may reference the provider are read: its own
/// tenant's, or every surface for an untenanted provider. Bindings are read
/// from the stored lists, so a surface whose variants cannot be resolved still
/// counts by what it names. The refusal names the surface only when the caller
/// may see it.
async fn refuse_bound_provider(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), Response> {
    let Some(surfaces) = state.surfaces.as_ref() else {
        return Err(unavailable("Agent surfaces are unavailable, so the provider's bindings cannot be checked"));
    };
    let surfaces = surfaces
        .list_all()
        .await
        .map_err(|error| {
            warn!(target: "credential_delegation", error = %error, "Failed to list surfaces for a provider delete");
            unavailable("Agent surfaces are unavailable, so the provider's bindings cannot be checked")
        })?;
    let bound_by = surfaces
        .iter()
        .filter(|surface| can_reference(surface.tenant_id.as_deref(), provider.tenant_id.as_deref()))
        .find(|surface| {
            crate::identity::handlers::surface_tenancy::bound_credential_provider_ids(surface)
                .contains(provider.id.as_str())
        });
    let Some(surface) = bound_by else {
        return Ok(());
    };
    let mut body = serde_json::json!({
        "error": "The credential provider is bound by an agent surface; remove the binding first",
        "code": "provider_in_use",
    });
    if can_access(surface.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::Surfaces, &surface.surface_id)
    {
        body["surface_id"] = serde_json::json!(surface.surface_id);
    }
    Err((StatusCode::CONFLICT, Json(body)).into_response())
}

/// Revoke at the authorization server, then delete, every grant by binding made
/// with an external consent provider being deleted, naming `actor` in the
/// audit. A revocation that fails is audited and the grant deleted all the
/// same. A vault that cannot list or delete the grants keeps the provider, as
/// does one that cannot read them because at-rest encryption is now off while
/// grants are stored: they would otherwise be left unrevoked on disk.
async fn remove_provider_grants(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
    actor: Option<&crate::delegation_vault::audit::AuditCallerContext>,
) -> Result<(), Response> {
    if !provider.is_external_consent() {
        return Ok(());
    }
    let Some(vault) = state.vault.as_ref() else {
        return Err(unavailable("The delegation vault is unavailable, so the provider's grants cannot be removed"));
    };
    let grants = match vault
        .provider_grants(&provider.id)
        .await
    {
        Ok(grants) => grants,
        Err(error) if error.is::<crate::delegation_vault::grants::EncryptionRequired>() => {
            return match vault
                .has_stored_grants()
                .await
            {
                Ok(false) => Ok(()),
                Ok(true) => Err(unavailable(
                    "Delegated grants are stored but cannot be read while at-rest encryption is off, so they \
                     cannot be revoked or removed; enable [encryption] with the key they were written under, then \
                     delete the provider",
                )),
                Err(error) => {
                    warn!(target: "credential_delegation", error = %error, "Failed to look for stored grants");
                    Err(unavailable("The delegation vault is unavailable, so the provider's grants cannot be removed"))
                }
            };
        }
        Err(error) => {
            warn!(target: "credential_delegation", error = %error, "Failed to list a provider's grants");
            return Err(unavailable("The delegation vault is unavailable, so the provider's grants cannot be removed"));
        }
    };
    let providers = std::collections::HashMap::from([(provider.id.clone(), provider.clone())]);
    crate::delegation_vault::revocation::remove_grants(
        vault,
        grants,
        &providers,
        &state.secrets_store,
        state
            .egress_allowlist
            .as_deref(),
        actor,
    )
    .await
    .map_err(|error| {
        warn!(target: "credential_delegation", error = %error, "Failed to delete a provider's grant");
        unavailable("The delegation vault is unavailable, so the provider's grants cannot be removed")
    })
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
            issuer_metadata: super::super::external::strict_issuer_metadata(),
            surfaces: None,
            vault: None,
            egress_allowlist: None,
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
            issuer_metadata: super::super::external::strict_issuer_metadata(),
            surfaces: Some(Arc::new(
                crate::surfaces::FileSystemAgentSurfaceStore::new(
                    directory
                        .path()
                        .join("surfaces"),
                )
                .await
                .unwrap(),
            )),
            vault: None,
            egress_allowlist: None,
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

        let delete = delete_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, None, None)
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

        let delete = delete_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, None, None)
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

        let delete = delete_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, None, None)
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

#[cfg(test)]
mod external_provider_tests {
    use super::*;
    use crate::authz_metadata::{ClientAuthzMetadata, DiscoveryError, DiscoveryFailure};
    use crate::credential_providers::external::tests::{external_provider, metadata};
    use serde_json::json;

    fn answering(
        answer: Result<ClientAuthzMetadata, DiscoveryFailure>
    ) -> crate::credential_providers::external::IssuerMetadata {
        Arc::new(move |_issuer| {
            let answer = answer
                .clone()
                .map_err(|failure| DiscoveryError::new(failure, "detail for logs only"));
            Box::pin(async move { answer })
        })
    }

    async fn state(
        directory: &tempfile::TempDir,
        answer: Result<ClientAuthzMetadata, DiscoveryFailure>,
    ) -> CredentialProviderState {
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
            issuer_metadata: answering(answer),
            surfaces: None,
            vault: None,
            egress_allowlist: None,
        }
    }

    fn tenant(tenant_id: &str) -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: format!("token-{tenant_id}"),
            tenant_id: tenant_id.into(),
        }))
    }

    fn create_request(change: impl FnOnce(&mut serde_json::Value)) -> Json<CreateCredentialProviderRequest> {
        let mut body = serde_json::to_value(external_provider()).unwrap();
        for field in ["id", "tenant_id", "callback_path", "created_at", "updated_at"] {
            body.as_object_mut()
                .unwrap()
                .remove(field);
        }
        change(&mut body);
        Json(serde_json::from_value(body).unwrap())
    }

    async fn create(
        state: &CredentialProviderState,
        tenant_id: &str,
        request: Json<CreateCredentialProviderRequest>,
    ) -> (StatusCode, serde_json::Value) {
        let response = create_provider(State(state.clone()), None, tenant(tenant_id), None, request)
            .await
            .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    async fn stored(state: &CredentialProviderState) -> Vec<CredentialProvider> {
        state
            .store
            .list()
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_that_matches_its_issuers_metadata_is_created_with_its_client_fields() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(&directory, Ok(metadata())).await;
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let providers = stored(&state).await;
        assert_eq!(providers.len(), 1);
        let provider = &providers[0];
        assert_eq!(provider.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(provider.issuer.as_deref(), Some("https://203.0.113.10"));
        assert_eq!(provider.client_id.as_deref(), Some("dcr-client-1"));
        assert_eq!(provider.token_endpoint_auth_method, Some(super::super::TokenEndpointAuthMethod::None));
        assert_eq!(
            provider
                .revocation_endpoint
                .as_deref(),
            Some("https://203.0.113.10/token")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_that_differs_from_its_issuers_metadata_is_refused_and_not_stored() {
        let directory = tempfile::tempdir().unwrap();
        let mut moved = metadata();
        moved.token_endpoint = "https://203.0.113.66/token".into();
        let state = state(&directory, Ok(moved)).await;
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "provider_metadata_mismatch");
        assert_eq!(body["field"], "token_endpoint");
        assert!(
            stored(&state)
                .await
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_whose_issuers_metadata_cannot_be_read_is_refused_without_the_reason() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(&directory, Err(DiscoveryFailure::Blocked)).await;
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "provider_metadata_unavailable");
        assert_eq!(body["reason"], "unreachable");
        assert!(
            !body
                .to_string()
                .contains("detail for logs only")
        );
        assert!(
            stored(&state)
                .await
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_that_breaks_a_static_rule_is_refused_before_its_metadata_is_read() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(&directory, Err(DiscoveryFailure::Blocked)).await;
        let (status, body) = create(
            &state,
            "tenant-a",
            create_request(|body| body["additional_params"] = json!({"redirect_uri": "https://attacker.example/"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "invalid_provider");
        assert!(
            stored(&state)
                .await
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_slugs_are_unique_within_a_tenant_only() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(&directory, Ok(metadata())).await;
        assert_eq!(
            create(&state, "tenant-a", create_request(|_| {}))
                .await
                .0,
            StatusCode::CREATED
        );
        let (status, body) = create(&state, "tenant-b", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::CREATED, "another tenant may use the same slug: {body}");
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, _) =
            create(&state, "tenant-a", create_request(|body| body["provider_id"] = json!(" BORIS-0123456789AB ")))
                .await;
        assert_eq!(status, StatusCode::CONFLICT, "slugs compare as stored: trimmed and lower case");
        assert_eq!(stored(&state).await.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_keeps_an_external_providers_client_but_may_rename_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(&directory, Ok(metadata())).await;
        assert_eq!(
            create(&state, "tenant-a", create_request(|_| {}))
                .await
                .0,
            StatusCode::CREATED
        );
        let id = stored(&state).await[0]
            .id
            .clone();
        let put = |body: serde_json::Value| {
            let state = state.clone();
            let id = id.clone();
            async move {
                update_provider(
                    State(state),
                    Path(id),
                    tenant("tenant-a"),
                    None,
                    Json(serde_json::from_value(body).unwrap()),
                )
                .await
                .into_response()
                .status()
            }
        };
        assert_eq!(put(json!({"client_id": "another-client"})).await, StatusCode::BAD_REQUEST);
        assert_eq!(put(json!({"token_endpoint": "https://203.0.113.66/token"})).await, StatusCode::BAD_REQUEST);
        assert_eq!(put(json!({"name": "Linear (work)", "client_id": "dcr-client-1"})).await, StatusCode::OK);
        let provider = &stored(&state).await[0];
        assert_eq!(provider.name, "Linear (work)");
        assert_eq!(provider.client_id.as_deref(), Some("dcr-client-1"));
        assert_eq!(
            provider
                .token_endpoint
                .as_deref(),
            Some("https://203.0.113.10/token")
        );
    }

    fn bound_surface(binding: serde_json::Value) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "surface", "name": "surface", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://managed.example/agent"},
            "transit": {"points": [{"id": "tp-1", "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp",
                "require_transit_token": true}]},
            "variants": []
        }))
        .map(|mut surface: crate::config::agent_surface::AgentSurface| {
            match binding["where"].as_str() {
                Some("transit_point") => {
                    surface
                        .transit
                        .as_mut()
                        .unwrap()
                        .points[0]
                        .transit_credentials = Some(serde_json::from_value(binding["binding"].clone()).unwrap());
                }
                Some("surface") => {
                    surface.outbound_credentials = vec![serde_json::from_value(binding["binding"].clone()).unwrap()];
                }
                _ => {
                    surface.variants = vec![
                        serde_json::from_value(json!({"id": "v-1", "alias": "candidate",
                        "name": "candidate", "enabled": true, "overrides": {"transit": {"points": [{"id": "tp-1",
                        "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp", "require_transit_token": true,
                        "transit_credentials": binding["binding"].clone()}]}}}))
                        .unwrap(),
                    ];
                }
            }
            surface
        })
        .unwrap()
    }

    async fn delete_state(
        directory: &tempfile::TempDir,
        server: &crate::delegation_vault::revocation::tests::RecordingServer,
    ) -> CredentialProviderState {
        unsafe {
            std::env::set_var("PROVIDER_DELETE_TEST_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        }
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "PROVIDER_DELETE_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let mut state = state(directory, Ok(metadata())).await;
        state.surfaces = Some(Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(
                directory
                    .path()
                    .join("surfaces"),
            )
            .await
            .unwrap(),
        ));
        state.vault = Some(Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        ));
        state.egress_allowlist = Some(server.origin());
        let mut provider = external_provider();
        provider.revocation_endpoint = Some(server.url.clone());
        state
            .store
            .create(provider)
            .await
            .unwrap();
        state
    }

    async fn delete(
        state: &CredentialProviderState,
        id: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = delete_provider(State(state.clone()), Path(id.into()), tenant("tenant-a"), None, None, None)
            .await
            .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_any_surface_binds_is_not_deleted() {
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let state = delete_state(&directory, &server).await;
        for (case, binding) in [
            (
                "a Transit Point",
                json!({"where": "transit_point", "binding": {"credential_provider_id": "provider",
                    "consent_mode": "external", "subject": "owner"}}),
            ),
            ("the surface", json!({"where": "surface", "binding": {"credential_provider_id": "provider"}})),
            (
                "a variant only",
                json!({"where": "variant", "binding": {"credential_provider_id": "provider",
                    "consent_mode": "external", "subject": "owner"}}),
            ),
        ] {
            state
                .surfaces
                .as_ref()
                .unwrap()
                .save(&bound_surface(binding))
                .await
                .unwrap();
            let (status, body) = delete(&state, "provider").await;
            assert_eq!(status, StatusCode::CONFLICT, "{case}: {body}");
            assert_eq!(body["code"], "provider_in_use", "{case}");
            assert_eq!(body["surface_id"], "surface", "{case}");
            assert!(
                state
                    .store
                    .get("provider")
                    .await
                    .unwrap()
                    .is_some(),
                "{case}"
            );
        }
        assert!(server.requests().is_empty(), "nothing is revoked while the provider is bound");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deleting_a_provider_revokes_and_deletes_its_grants_and_no_other() {
        use crate::delegation_vault::grants::GrantKey;
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let state = delete_state(&directory, &server).await;
        let vault = state.vault.clone().unwrap();
        let caller = "c".repeat(64);
        let keys = [
            GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "provider"),
            GrantKey::caller(Some("tenant-a"), "surface", "tp-1", "provider", &caller).unwrap(),
        ];
        let other = GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "other-provider");
        for (key, token) in keys
            .iter()
            .zip(["owner-access", "caller-access"])
            .chain([(&other, "other-access")])
        {
            vault
                .store_grant(crate::delegation_vault::grants::tests::grant(key, token))
                .await
                .unwrap();
        }

        let (status, body) = delete(&state, "provider").await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

        assert_eq!(
            server.revoked_tokens(),
            ["caller-access", "caller-access-refresh", "owner-access", "owner-access-refresh"]
        );
        for key in &keys {
            assert!(
                vault
                    .grant(key)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            vault
                .grant(&other)
                .await
                .unwrap()
                .is_some(),
            "another provider's grant is kept"
        );
        assert!(
            state
                .store
                .get("provider")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_revocation_still_removes_the_grant_and_the_provider() {
        use crate::delegation_vault::grants::GrantKey;
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(503).await;
        let state = delete_state(&directory, &server).await;
        let vault = state.vault.clone().unwrap();
        let key = GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "provider");
        vault
            .store_grant(crate::delegation_vault::grants::tests::grant(&key, "owner-access"))
            .await
            .unwrap();
        assert_eq!(
            delete(&state, "provider")
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(server.requests().len(), 2);
        assert!(
            vault
                .grant(&key)
                .await
                .unwrap()
                .is_none()
        );
    }

    async fn delete_as(
        state: &CredentialProviderState,
        context: Option<Extension<PatTenantContext>>,
        scope: Option<Extension<PatResourceScope>>,
    ) -> (StatusCode, serde_json::Value) {
        let response = delete_provider(
            State(state.clone()),
            Path("provider".into()),
            context,
            scope,
            Some(Extension(AuthGuardOk("operator".into()))),
            Some(Extension(PatDelegationContext {
                token_id: "pat-1".into(),
                delegation_depth: 0,
                resource_scoped: false,
            })),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    /// A surface of `tenant` whose two variants share an alias and whose first
    /// is disabled, so the second cannot be resolved. The second binds
    /// `provider` through `outbound_credentials` when one is named.
    fn unresolvable_surface(
        surface_id: &str,
        tenant: &str,
        provider: Option<&str>,
    ) -> crate::config::agent_surface::AgentSurface {
        let overrides = match provider {
            Some(provider) => json!({"outbound_credentials": [{"credential_provider_id": provider}]}),
            None => json!({}),
        };
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": surface_id, "name": surface_id, "tenant_id": tenant,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{surface_id}"),
                "protocol": "mcp"},
            "target": {"endpoint": "https://managed.example/agent"},
            "variants": [
                {"id": "v-1", "alias": "same", "name": "first", "enabled": false, "overrides": {}},
                {"id": "v-2", "alias": "same", "name": "second", "enabled": true, "overrides": overrides}
            ]
        }))
        .unwrap();
        assert!(
            crate::identity::handlers::surface_tenancy::collect_surface_reference_keys(&surface).is_err(),
            "the fixture's variants cannot be resolved"
        );
        surface
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_tenants_surfaces_and_an_unresolvable_surface_that_binds_nothing_never_block_a_delete() {
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let state = delete_state(&directory, &server).await;
        let surfaces = state
            .surfaces
            .clone()
            .unwrap();
        let mut planted = bound_surface(json!({"where": "surface", "binding": {"credential_provider_id": "provider"}}));
        planted.surface_id = "tenant-b-surface".into();
        planted.tenant_id = Some("tenant-b".into());
        for surface in [
            planted,
            unresolvable_surface("tenant-b-broken", "tenant-b", Some("provider")),
            unresolvable_surface("tenant-a-broken", "tenant-a", None),
        ] {
            surfaces
                .save(&surface)
                .await
                .unwrap();
        }
        let (status, body) = delete(&state, "provider").await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert!(
            !body
                .to_string()
                .contains("tenant-b"),
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unresolvable_surface_still_binds_the_provider_it_names_and_is_named_only_to_who_may_see_it() {
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let state = delete_state(&directory, &server).await;
        state
            .surfaces
            .as_ref()
            .unwrap()
            .save(&unresolvable_surface("tenant-a-broken", "tenant-a", Some("provider")))
            .await
            .unwrap();
        let (status, body) = delete_as(&state, tenant("tenant-a"), None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], "provider_in_use");
        assert_eq!(body["surface_id"], "tenant-a-broken");

        let provider_only = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:credential-providers:provider\z").unwrap(),
        ))));
        let (status, body) = delete_as(&state, tenant("tenant-a"), provider_only).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], "provider_in_use");
        assert!(
            body.get("surface_id")
                .is_none(),
            "a surface outside the token's scope is not named: {body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_with_grants_that_cannot_be_read_while_encryption_is_off_is_kept() {
        use crate::delegation_vault::grants::GrantKey;
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let mut state = delete_state(&directory, &server).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "provider");
        state
            .vault
            .as_ref()
            .unwrap()
            .store_grant(crate::delegation_vault::grants::tests::grant(&key, "owner-access"))
            .await
            .unwrap();

        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig::default()).unwrap();
        let unencrypted = |path: std::path::PathBuf| async move {
            let vault: Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage> = Arc::new(
                crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(path)
                    .await
                    .unwrap(),
            );
            vault
        };
        state.vault = Some(unencrypted(directory.path().join("vault")).await);
        let (status, body) = delete(&state, "provider").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("at-rest encryption is off")),
            "{body}"
        );
        assert!(
            state
                .store
                .get("provider")
                .await
                .unwrap()
                .is_some(),
            "the provider is kept"
        );
        assert!(
            directory
                .path()
                .join("vault/delegated_grants")
                .join(format!("{}.json.enc", key.record_id()))
                .exists(),
            "the grant is kept to be revoked once it can be read"
        );
        assert!(server.requests().is_empty());

        state.vault = Some(
            unencrypted(
                directory
                    .path()
                    .join("empty-vault"),
            )
            .await,
        );
        assert_eq!(
            delete(&state, "provider")
                .await
                .0,
            StatusCode::NO_CONTENT,
            "with no grant stored there is nothing to orphan"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_providers_revocations_name_the_caller_that_deleted_it() {
        use crate::delegation_vault::grants::GrantKey;
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let state = delete_state(&directory, &server).await;
        state
            .vault
            .as_ref()
            .unwrap()
            .store_grant(crate::delegation_vault::grants::tests::grant(
                &GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "provider"),
                "owner-access",
            ))
            .await
            .unwrap();
        let ((status, _), events) =
            crate::audit::producer::capture(async { delete_as(&state, tenant("tenant-a"), None).await }).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let revoked: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.event, crate::delegation_vault::audit::DelegationAuditAction::TokenRevoked))
            .collect();
        assert_eq!(revoked.len(), 1);
        let caller = revoked[0]
            .caller
            .as_ref()
            .expect("the revocation names its actor");
        assert_eq!(caller.sub.as_deref(), Some("operator"));
        assert_eq!(caller.token_id.as_deref(), Some("pat-1"));
    }
}
