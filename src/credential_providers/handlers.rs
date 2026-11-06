//! API handlers for credential provider CRUD operations

use super::{
    CreateCredentialProviderRequest, CredentialProvider, CredentialProviderListItem, CredentialProviderType,
    JwtAssertionSettings, JwtSigningAlgorithm, UpdateCredentialProviderRequest, ValidateCredentialProviderRequest,
    storage::CredentialProviderStorage,
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
use crate::delegation_vault::oauth::TokenEgress;
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
    /// gateway.json's `external_consent_resource_origins`: the resource origins
    /// permitted, beyond the issuer's own host, for each issuer's providers.
    pub resource_origins: Arc<std::collections::HashMap<String, Vec<String>>>,
    /// gateway.json's `external_consent_issuers`: when set, the only issuers an
    /// external consent provider may name, with the origins their endpoints may
    /// use beyond the issuer's own host.
    pub issuers: Arc<Option<std::collections::HashMap<String, Vec<String>>>>,
    pub references: super::references::ReferenceStores,
    /// Decides which referrers a 409 may name; `None` names none.
    pub rbac: Option<crate::auth_manager::middleware::RbacGuard>,
}

/// A provider as the API returns it, with `resource_origin`, the only origin
/// an external consent provider's grants are sent to, so a client can show it.
fn provider_body(provider: &CredentialProvider) -> serde_json::Value {
    let mut body = serde_json::to_value(provider).unwrap_or_default();
    if provider.is_external_consent()
        && let (Some(fields), Some(origin)) = (body.as_object_mut(), super::external::resource_origin(provider))
    {
        fields.insert("resource_origin".to_string(), serde_json::Value::String(origin));
    }
    body
}

const PROVIDER_IN_USE_BY_TARGET_AUTH: &str = "The credential provider is used for Target authentication, which cannot use a provider that needs a user's consent";

async fn viewable_kinds(
    state: &CredentialProviderState,
    caller: &Option<Extension<AuthGuardOk>>,
    pat: &Option<Extension<PatContext>>,
) -> super::references::ViewableKinds {
    super::references::ViewableKinds::of_caller(
        state.rbac.as_ref(),
        caller
            .as_ref()
            .map(|Extension(caller)| caller),
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
}

fn reference_scan_failed(error: anyhow::Error) -> Response {
    warn!(target: "credential_delegation", %error, "Failed to find what references a credential provider");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Internal server error"}))).into_response()
}

/// Why a provider's settings, secret references or consent strategy were rejected.
#[derive(Debug, thiserror::Error)]
enum ProviderValidationError {
    #[error("token_endpoint must be an https URL")]
    TokenEndpointNotHttps,
    #[error("{0} is required for this provider type")]
    Missing(&'static str),
    #[error("client_secret_secret_ref is not allowed: this provider authenticates with a signed JWT")]
    ClientSecretNotAllowed,
    #[error("jwt_signing_algorithm is not supported for this provider type")]
    UnsupportedAlgorithm,
    #[error("jwt_audience: {0}")]
    InvalidAudience(String),
    #[error("Consent identity strategy is invalid or not accessible")]
    InvalidConsentStrategy,
    #[error("Identity verification configuration unavailable")]
    IdentityConfigurationUnavailable,
    #[error("Secret reference is not accessible")]
    SecretNotAccessible,
    #[error("Secret reference lookup failed")]
    SecretLookupFailed,
    #[error(
        "jwt_signing_key_secret_ref must reference a PEM private key or a Google service account JSON key matching jwt_signing_algorithm"
    )]
    InvalidSigningKey,
    #[error("jwt_certificate_secret_ref must reference a PEM certificate")]
    InvalidCertificate,
}

impl IntoResponse for ProviderValidationError {
    fn into_response(self) -> Response {
        match self {
            Self::TokenEndpointNotHttps
            | Self::Missing(_)
            | Self::ClientSecretNotAllowed
            | Self::UnsupportedAlgorithm
            | Self::InvalidAudience(_)
            | Self::InvalidConsentStrategy
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
) -> Result<(), ProviderValidationError> {
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
        return Err(ProviderValidationError::InvalidConsentStrategy);
    }
    let strategy = state
        .identity_strategies
        .as_ref()
        .ok_or(ProviderValidationError::InvalidConsentStrategy)?
        .get(id)
        .await
        .map_err(|_| ProviderValidationError::IdentityConfigurationUnavailable)?
        .ok_or(ProviderValidationError::InvalidConsentStrategy)?;
    if !can_reference(provider.tenant_id.as_deref(), strategy.tenant_id.as_deref())
        || !scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::JwtVerificationStrategies,
            id,
        )
        || crate::sts::mcp_profile::canonical_https_url(&strategy.expected_issuer).is_err()
    {
        return Err(ProviderValidationError::InvalidConsentStrategy);
    }
    Ok(())
}

async fn stored_secret(
    state: &CredentialProviderState,
    secret_id: &str,
) -> Result<crate::secrets::Secret, ProviderValidationError> {
    state
        .secrets_store
        .get_by_secret_id(secret_id)
        .await
        .map_err(|error| {
            warn!(%error, "Failed to validate credential provider secret reference");
            ProviderValidationError::SecretLookupFailed
        })?
        .ok_or(ProviderValidationError::SecretNotAccessible)
}

/// Refuse `provider` when a secret it names no longer exists. Run while the save holds the
/// provider lock, it catches a secret deleted since [`validate_secret_references`] checked it.
async fn refuse_gone_secrets(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
) -> Result<(), ProviderValidationError> {
    for secret_id in provider.secret_refs() {
        stored_secret(state, secret_id).await?;
    }
    Ok(())
}

/// Refuse a secret reference that `may_use`, given the secret's tenant and whether the
/// reference is kept from the stored provider, does not admit, or the caller's scope does not
/// cover.
async fn validate_secret_references(
    state: &CredentialProviderState,
    may_use: impl Fn(Option<&str>, bool) -> bool,
    references: &[(&str, bool)],
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), ProviderValidationError> {
    for &(secret_id, kept) in references {
        let secret = stored_secret(state, secret_id).await?;
        if !may_use(secret.tenant_id.as_deref(), kept)
            || !scope_allows_resource(
                resource_scope(scope),
                tenant_context(context),
                ResourceKind::Secrets,
                &secret.secret_id,
            )
        {
            return Err(ProviderValidationError::SecretNotAccessible);
        }
    }
    Ok(())
}

/// The required fields (`jwt_subject` included for a JWT Bearer grant), algorithm and
/// audience of an `oauth2_jwt_bearer` or `oauth2_client_credentials_jwt_auth` provider;
/// other types pass unchecked.
fn validate_jwt_provider(provider: &CredentialProvider) -> Result<(), ProviderValidationError> {
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
        ],
        CredentialProviderType::OAuth2AuthorizationCode
        | CredentialProviderType::OAuth2ClientCredentials
        | CredentialProviderType::ApiKey => return Ok(()),
    };
    if let Some((field, _)) = required
        .into_iter()
        .find(|(_, value)| value.is_none_or(|value| value.trim().is_empty()))
    {
        return Err(ProviderValidationError::Missing(field));
    }
    if provider.lacks_jwt_subject() {
        return Err(ProviderValidationError::Missing("jwt_subject"));
    }
    if provider.provider_type == CredentialProviderType::OAuth2ClientCredentialsJwtAuth
        && provider
            .client_secret_secret_ref
            .is_some()
    {
        return Err(ProviderValidationError::ClientSecretNotAllowed);
    }
    if let Some(algorithm) = provider
        .jwt
        .jwt_signing_algorithm
        && !provider
            .provider_type
            .allows_jwt_algorithm(algorithm)
    {
        return Err(ProviderValidationError::UnsupportedAlgorithm);
    }
    if let Some(audience) = provider
        .jwt
        .jwt_audience
        .as_deref()
    {
        crate::url_validation::validate_oauth_endpoint_url(audience)
            .map_err(|error| ProviderValidationError::InvalidAudience(error.to_string()))?;
    }
    Ok(())
}

/// Resolve the signing key and certificate a JWT-signing provider references and check
/// they parse, so a wrong format fails the save rather than the first token request.
/// `algorithm` is `None` for a type that signs nothing. Runs after
/// [`validate_secret_references`] has checked the caller may use them.
async fn validate_jwt_key_material(
    state: &CredentialProviderState,
    algorithm: Option<JwtSigningAlgorithm>,
    jwt: &JwtAssertionSettings,
) -> Result<(), ProviderValidationError> {
    use crate::delegation_vault::jwt_assertion;

    let Some(algorithm) = algorithm else {
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
                ProviderValidationError::SecretLookupFailed
            })?
            .map(|secret| Some(zeroize::Zeroizing::new(secret.value)))
            .ok_or(ProviderValidationError::SecretNotAccessible)
    };
    if let Some(key) = resolve(
        jwt.jwt_signing_key_secret_ref
            .clone(),
    )
    .await?
    {
        jwt_assertion::check_signing_key(&key, algorithm).map_err(|_| ProviderValidationError::InvalidSigningKey)?;
    }
    if let Some(certificate) = resolve(
        jwt.jwt_certificate_secret_ref
            .clone(),
    )
    .await?
    {
        jwt_assertion::certificate_thumbprint(&certificate).map_err(|_| ProviderValidationError::InvalidCertificate)?;
    }
    Ok(())
}

/// A new provider, or one whose token endpoint or type changes, must have a token endpoint
/// that meets the https rule. A stored provider saved with the same http endpoint keeps it
/// while `credential_policy.token_endpoint_https` is `warn`.
fn validate_token_endpoint_scheme(
    egress: &TokenEgress,
    previous: Option<&CredentialProvider>,
    provider: &CredentialProvider,
) -> Result<(), ProviderValidationError> {
    if provider.provider_type == CredentialProviderType::ApiKey {
        return Ok(());
    }
    let Some(endpoint) = provider
        .token_endpoint
        .as_deref()
    else {
        return Ok(());
    };
    if egress.permits_token_endpoint(endpoint) {
        return Ok(());
    }
    let unchanged = previous.is_some_and(|previous| {
        previous.provider_type != CredentialProviderType::ApiKey
            && previous
                .token_endpoint
                .as_deref()
                == Some(endpoint)
    });
    if unchanged && egress.admits_token_endpoint(endpoint) {
        return Ok(());
    }
    Err(ProviderValidationError::TokenEndpointNotHttps)
}

/// The checks a provider passes before it is stored, `previous` being the stored record an
/// update replaces. Tenancy and token scope are checked on every secret reference before the
/// key material is read.
async fn validate_provider_settings(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
    previous: Option<&CredentialProvider>,
    egress: &TokenEgress,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), ProviderValidationError> {
    validate_token_endpoint_scheme(egress, previous, provider)?;
    validate_jwt_provider(provider)?;
    let isolation = egress
        .policy
        .tenant_credential_isolation;
    validate_secret_references(
        state,
        |secret_tenant_id, kept| {
            !provider.secret_is_outside_tenant(secret_tenant_id)
                || kept && !isolation.is_enforced() && provider.may_use_secret(secret_tenant_id)
        },
        &provider.secret_refs_kept_from(previous),
        context,
        scope,
    )
    .await?;
    validate_jwt_key_material(state, provider.jwt_signing_algorithm(), &provider.jwt).await?;
    validate_consent_strategy(state, provider, context, scope).await
}

/// A blank secret reference is no reference: the dashboard sends unused fields empty.
fn blank_to_none(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
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
        CredentialProviderType::OAuth2JwtBearer | CredentialProviderType::OAuth2ClientCredentialsJwtAuth => None,
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
    req.client_secret_secret_ref = blank_to_none(
        req.client_secret_secret_ref
            .take(),
    );
    req.jwt = req.jwt.normalized();
    let now = Utc::now();

    let mut provider = CredentialProvider {
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
        issuer: req.issuer,
        revocation_endpoint: req.revocation_endpoint,
        token_endpoint_auth_method: req.token_endpoint_auth_method,
        client_id: req.client_id,
        allow_unadvertised_pkce: req.allow_unadvertised_pkce,
        authorization_response_iss_parameter_supported: None,
        scope_comparison: req.scope_comparison,
        revocation_ends_authorization: req.revocation_ends_authorization,
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

    if let Err(error) =
        validate_provider_settings(&state, &provider, None, &TokenEgress::from_environment(), &context, &scope).await
    {
        return error.into_response();
    }

    if provider.is_external_consent() && tenant_context(&context).is_some() && state.issuers.is_none() {
        warn!(
            target: "credential_delegation",
            provider_id = ?provider.provider_id,
            "Refused a tenant's credential provider with an issuer: the gateway lists no external_consent_issuers"
        );
        return super::external::ExternalProviderError::IssuersRequired.into_response();
    }
    if provider.is_external_consent() && !super::external::resource_permitted(&provider, &state.resource_origins) {
        warn!(
            target: "credential_delegation",
            provider_id = ?provider.provider_id,
            "Refused a credential provider whose resource is not permitted for its issuer"
        );
        return super::external::ExternalProviderError::ResourceNotPermitted.into_response();
    }
    if provider.is_external_consent()
        && let Err(field) = super::external::issuer_permitted(
            &provider,
            state
                .issuers
                .as_ref()
                .as_ref(),
        )
    {
        warn!(
            target: "credential_delegation",
            provider_id = ?provider.provider_id,
            field,
            "Refused a credential provider that the gateway's external_consent_issuers does not permit"
        );
        return super::external::ExternalProviderError::IssuerNotPermitted(field).into_response();
    }

    if let Some(issuer) = provider.issuer.clone() {
        let metadata = match (state.issuer_metadata)(issuer).await {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(
                    target: "credential_delegation",
                    provider_id = ?provider.provider_id,
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
                provider_id = ?provider.provider_id,
                error = ?error,
                "Refused a credential provider that does not match its issuer's metadata"
            );
            return error.into_response();
        }
        if let Err(field) = super::external::metadata_permitted(
            &metadata,
            state
                .issuers
                .as_ref()
                .as_ref(),
        ) {
            warn!(
                target: "credential_delegation",
                provider_id = ?provider.provider_id,
                field,
                "Refused a credential provider whose issuer's metadata the gateway's external_consent_issuers does \
                 not permit"
            );
            return super::external::ExternalProviderError::IssuerNotPermitted(field).into_response();
        }
        provider.authorization_response_iss_parameter_supported =
            Some(metadata.authorization_response_iss_parameter_supported);
    }

    let _bindings = crate::identity::handlers::surface_grants::hold_provider_bindings().await;
    if let Err(error) = refuse_gone_secrets(&state, &provider).await {
        return error.into_response();
    }
    match state
        .store
        .create(provider.clone())
        .await
    {
        Ok(created) => (StatusCode::CREATED, Json(provider_body(&created))).into_response(),
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
            (StatusCode::OK, Json(provider_body(&provider))).into_response()
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
#[allow(clippy::too_many_arguments)]
pub async fn update_provider(
    State(state): State<CredentialProviderState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
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

    let previous = existing.clone();
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
        // A blank reference in the request clears the stored one.
        client_secret_secret_ref: blank_to_none(
            req.client_secret_secret_ref
                .or(existing.client_secret_secret_ref),
        ),
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
        issuer: existing.issuer,
        revocation_endpoint: existing.revocation_endpoint,
        token_endpoint_auth_method: existing.token_endpoint_auth_method,
        client_id: existing.client_id,
        allow_unadvertised_pkce: existing.allow_unadvertised_pkce,
        authorization_response_iss_parameter_supported: existing.authorization_response_iss_parameter_supported,
        scope_comparison: existing.scope_comparison,
        revocation_ends_authorization: existing.revocation_ends_authorization,
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };

    let retypes_to_need_consent = previous
        .provider_type
        .sends_gateway_credential()
        && !updated
            .provider_type
            .sends_gateway_credential();
    if retypes_to_need_consent && let Err(refusal) = refuse_retype_while_target_auth_uses(&state, &previous).await {
        return retype_refused(&state, refusal, &context, &scope, &caller, &pat).await;
    }

    if let Err(error) = validate_provider_settings(
        &state,
        &updated,
        Some(&previous),
        &TokenEgress::from_environment(),
        &context,
        &scope,
    )
    .await
    {
        return error.into_response();
    }

    let _bindings = if retypes_to_need_consent {
        let bindings = crate::identity::handlers::surface_grants::hold_provider_bindings_exclusively().await;
        if let Err(refusal) = refuse_retype_while_target_auth_uses(&state, &previous).await {
            return retype_refused(&state, refusal, &context, &scope, &caller, &pat).await;
        }
        BindingsHold::Exclusive { _guard: bindings }
    } else {
        BindingsHold::Shared {
            _guard: crate::identity::handlers::surface_grants::hold_provider_bindings().await,
        }
    };
    if let Err(error) = refuse_gone_secrets(&state, &updated).await {
        return error.into_response();
    }

    match state
        .store
        .update(updated.clone())
        .await
    {
        Ok(u) => (StatusCode::OK, Json(provider_body(&u))).into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to update: {}", e)})))
                .into_response()
        }
    }
}

/// The provider bindings lock as an update holds it until its store.
enum BindingsHold {
    Exclusive { _guard: tokio::sync::RwLockWriteGuard<'static, ()> },
    Shared { _guard: tokio::sync::RwLockReadGuard<'static, ()> },
}

/// Why a provider was not retyped to one that needs a user's consent.
#[derive(Debug, thiserror::Error)]
enum RetypeRefusal {
    #[error("{PROVIDER_IN_USE_BY_TARGET_AUTH}")]
    InUseByTargetAuth(Vec<super::references::Referrer>),
    #[error("reference scan failed: {0}")]
    ScanFailed(anyhow::Error),
}

/// Refuse to retype `previous` to a provider that needs a user's consent while a surface's
/// Target authentication uses it. The update holds the provider lock exclusively across this
/// check and its store, so no surface write binds the provider in between.
async fn refuse_retype_while_target_auth_uses(
    state: &CredentialProviderState,
    previous: &CredentialProvider,
) -> Result<(), RetypeRefusal> {
    let referrers = state
        .references
        .target_auth_referrers_of_provider(&previous.id)
        .await
        .map_err(RetypeRefusal::ScanFailed)?;
    if referrers.is_empty() {
        Ok(())
    } else {
        Err(RetypeRefusal::InUseByTargetAuth(referrers))
    }
}

/// Answer `refusal` with a `409` naming the referrers the caller may see, or a `500`.
async fn retype_refused(
    state: &CredentialProviderState,
    refusal: RetypeRefusal,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    caller: &Option<Extension<AuthGuardOk>>,
    pat: &Option<Extension<PatContext>>,
) -> Response {
    match refusal {
        RetypeRefusal::InUseByTargetAuth(referrers) => super::references::conflict_response(
            PROVIDER_IN_USE_BY_TARGET_AUTH,
            &referrers,
            &viewable_kinds(state, caller, pat).await,
            tenant_context(context),
            resource_scope(scope),
        ),
        RetypeRefusal::ScanFailed(error) => reference_scan_failed(error),
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
    let actor = crate::delegation_vault::audit::management_caller_context(
        caller
            .as_ref()
            .map(|Extension(AuthGuardOk(user_id))| user_id.as_str()),
        delegation
            .as_ref()
            .map(|Extension(delegation)| delegation.token_id.as_str()),
    );
    remove_provider(&state, &id, &context, &scope, actor.as_ref())
        .await
        .0
}

/// Delete provider `id` for the caller of `context` and `scope`, naming
/// `actor` in the audit of its grants' revocations. Returns the answer and,
/// when the provider had grants, the task that revokes them. The provider
/// lock is held while the bindings are checked and the grants and the
/// provider deleted, never while a vendor is called: the task revokes the
/// grants once the provider is deleted and the lock released, or puts them
/// back when it was not.
async fn remove_provider(
    state: &CredentialProviderState,
    id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    actor: Option<&crate::delegation_vault::audit::AuditCallerContext>,
) -> (Response, Option<tokio::task::JoinHandle<()>>) {
    let existing = match state.store.get(id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return (
                (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
                    .into_response(),
                None,
            );
        }
        Err(error) => {
            return (
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": error.to_string()})))
                    .into_response(),
                None,
            );
        }
    };
    if !can_access(existing.tenant_id.as_deref(), tenant_context(context))
        || !scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::CredentialProviders,
            &existing.id,
        )
    {
        return (
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
                .into_response(),
            None,
        );
    }
    if !can_mutate(existing.tenant_id.as_deref(), tenant_context(context)) {
        return (
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "credential provider is outside this token's permitted scope" })),
            )
                .into_response(),
            None,
        );
    }
    // Held, with the task that deletes the provider's grants, until the
    // provider is deleted, so no surface write binds it after the check below
    // found it unbound.
    let bindings = Arc::new(crate::identity::handlers::surface_grants::hold_provider_bindings_exclusively().await);
    if let Err(response) = refuse_bound_provider(state, &existing, tenant_context(context), resource_scope(scope)).await
    {
        return (response, None);
    }
    let (deleted, outcome) = tokio::sync::oneshot::channel();
    let outcome = crate::delegation_vault::revocation::ChangeOutcome {
        saved: outcome,
        stored: Box::pin(provider_deleted(Arc::clone(&state.store), id.to_string())),
    };
    let revocations = match remove_provider_grants(state, &existing, actor, Arc::clone(&bindings), outcome).await {
        Ok(revocations) => revocations,
        Err(response) => return (response, None),
    };
    let result = state.store.delete(id).await;
    let _ = deleted.send(result.is_ok());
    drop(bindings);
    let response = match result {
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
    };
    (response, revocations)
}

/// Whether provider `id` is gone, read by the task that deleted its grants
/// when the delete was dropped before it reported. A read that fails counts
/// as gone, so the grants are revoked rather than kept unrevoked.
async fn provider_deleted(
    store: Arc<dyn CredentialProviderStorage>,
    id: String,
) -> bool {
    !matches!(store.get(&id).await, Ok(Some(_)))
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

/// Delete every grant by binding made with an external consent provider being
/// deleted, then, once `outcome` says the provider was deleted, revoke each
/// at the authorization server, naming `actor` in the audit, on the task
/// returned. `bindings` is the provider lock, which the task holds until the
/// outcome is known and drops before any vendor is called. Only this
/// provider's grants are read. A revocation that fails is audited and the
/// grant deleted all the same. A vault that cannot list or delete the grants
/// keeps the provider, as does a grant of this provider that cannot be read,
/// for example because at-rest encryption is now off: it would otherwise be
/// left unrevoked on disk. The refusal names that grant, which an operator
/// can purge.
async fn remove_provider_grants(
    state: &CredentialProviderState,
    provider: &CredentialProvider,
    actor: Option<&crate::delegation_vault::audit::AuditCallerContext>,
    bindings: Arc<tokio::sync::RwLockWriteGuard<'static, ()>>,
    outcome: crate::delegation_vault::revocation::ChangeOutcome,
) -> Result<Option<tokio::task::JoinHandle<()>>, Response> {
    if !provider.is_external_consent() {
        return Ok(None);
    }
    let Some(vault) = state.vault.as_ref() else {
        return Err(unavailable("The delegation vault is unavailable, so the provider's grants cannot be removed"));
    };
    let grants = match vault
        .provider_grants(&provider.id)
        .await
    {
        Ok(grants) => grants,
        Err(error) => {
            if let Some(unreadable) = error.downcast_ref::<crate::delegation_vault::grants::UnreadableGrant>() {
                let message = format!(
                    "The provider's delegated grant {} cannot be read ({}), so it can be neither revoked nor removed \
                     and the provider is kept. Make it readable again (for at-rest encryption, enable [encryption] \
                     with the key it was written under), or have an operator purge it with DELETE \
                     /api/v1/delegation-vault/grants/{}, which leaves it unrevoked at the vendor, then delete the \
                     provider",
                    unreadable.grant_id, unreadable.reason, unreadable.grant_id
                );
                return Err(
                    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": message }))).into_response()
                );
            }
            if error.is::<crate::delegation_vault::grants::PepperMismatch>() {
                return Err(unavailable(
                    "The delegated grants stored were written under another identity hash pepper, so the provider's \
                     grants cannot be found; restore the AG_IDENTITY_HASH_PEPPER they were written under, or have \
                     an operator purge them",
                ));
            }
            warn!(target: "credential_delegation", error = %error, "Failed to list a provider's grants");
            return Err(unavailable("The delegation vault is unavailable, so the provider's grants cannot be removed"));
        }
    };
    if grants.is_empty() {
        return Ok(None);
    }
    let revoker = crate::delegation_vault::revocation::Revoker {
        providers: std::collections::HashMap::from([(provider.id.clone(), provider.clone())]),
        secrets: Some(Arc::clone(&state.secrets_store)),
        exact_allowlist: state.egress_allowlist.clone(),
        actor: actor.cloned(),
        vault: Some(Arc::clone(vault)),
    };
    crate::delegation_vault::revocation::delete_then_revoke(vault, grants, revoker, bindings, Some(outcome))
        .await
        .map(Some)
        .map_err(|error| {
            warn!(target: "credential_delegation", error = %error, "Failed to delete a provider's grant");
            unavailable("The delegation vault is unavailable, so the provider's grants cannot be removed")
        })
}

/// POST /api/v1/credential-providers/validate
/// Checks the key material a JWT-signing provider references, with the same tenancy rules
/// as a save, then that the token endpoint is reachable
pub async fn validate_provider(
    State(state): State<CredentialProviderState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<ValidateCredentialProviderRequest>,
) -> impl IntoResponse {
    let client = crate::http_client::with_short_timeout().unwrap_or_else(|_| reqwest::Client::new());
    validate_provider_with(&state, &client, &TokenEgress::from_environment(), pat.is_some(), &context, &scope, req)
        .await
}

/// The algorithm the requested provider would sign with, once its key material checks
/// out; `None` for a type that signs nothing.
async fn validate_key_material_request(
    state: &CredentialProviderState,
    tenant_id: Option<&str>,
    req: &ValidateCredentialProviderRequest,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<Option<JwtSigningAlgorithm>, ProviderValidationError> {
    let jwt = req.jwt.clone().normalized();
    if req
        .provider_type
        .as_ref()
        .is_some_and(|provider_type| jwt.lacks_subject_for(provider_type))
    {
        return Err(ProviderValidationError::Missing("jwt_subject"));
    }
    let algorithm = req
        .provider_type
        .as_ref()
        .and_then(|provider_type| provider_type.jwt_signing_algorithm(jwt.jwt_signing_algorithm));
    if let (Some(provider_type), Some(algorithm)) = (&req.provider_type, algorithm)
        && !provider_type.allows_jwt_algorithm(algorithm)
    {
        return Err(ProviderValidationError::UnsupportedAlgorithm);
    }
    validate_secret_references(
        state,
        |secret_tenant_id, _| secret_tenant_id == tenant_id,
        &[
            jwt.jwt_signing_key_secret_ref
                .as_deref(),
            jwt.jwt_certificate_secret_ref
                .as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(|reference| (reference, false))
        .collect::<Vec<_>>(),
        context,
        scope,
    )
    .await?;
    validate_jwt_key_material(state, algorithm, &jwt).await?;
    Ok(algorithm)
}

async fn validate_provider_with(
    state: &CredentialProviderState,
    client: &reqwest::Client,
    egress: &TokenEgress,
    pat_authenticated: bool,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    mut req: ValidateCredentialProviderRequest,
) -> Response {
    let tenant_id = match tenant_for_create(req.tenant_id.take(), pat_authenticated, tenant_context(context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": message }))).into_response(),
    };
    let Some(token_endpoint) = req.token_endpoint.take() else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "token_endpoint is required"})))
            .into_response();
    };

    if let Err(e) = crate::url_validation::validate_oauth_endpoint_url(&token_endpoint) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("token_endpoint: {}", e)})))
            .into_response();
    }
    if !egress.permits_token_endpoint(&token_endpoint) {
        return ProviderValidationError::TokenEndpointNotHttps.into_response();
    }

    // Local checks first, so a request that fails them sends nothing to the endpoint.
    let algorithm = match validate_key_material_request(state, tenant_id.as_deref(), &req, context, scope).await {
        Ok(algorithm) => algorithm,
        Err(error) => return error.into_response(),
    };

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
            let mut body = serde_json::json!({
                "reachable": true,
                "http_status": status,
                "token_endpoint": token_endpoint,
            });
            if algorithm.is_some() {
                body["key_material"] = serde_json::json!("ok");
            }
            (StatusCode::OK, Json(body)).into_response()
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
            issuer_metadata: super::super::external::strict_issuer_metadata(),
            surfaces: None,
            vault: None,
            egress_allowlist: None,
            resource_origins: Arc::default(),
            issuers: Arc::default(),
            references: Default::default(),
            rbac: None,
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
            "jwt_subject": "admin@example.com",
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
        let key_file = |private_key: &str| {
            json!({"type": "service_account", "private_key_id": "abc123", "private_key": private_key}).to_string()
        };
        add_secret(&state, "SA_JSON", &key_file(&test_keys::rsa_pkcs8().private_pem)).await;
        add_secret(&state, "BAD_JSON", &key_file("key-secret-marker")).await;
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
            .find_by_provider_id(None, "vertex")
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
    async fn create_with_a_blank_client_secret_reference_stores_none() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        // The body the dashboard sends: unused references blank, not absent.
        let blanks = json!({
            "client_secret_secret_ref": "", "jwt_certificate_secret_ref": "", "jwt_audience": "",
            "jwt_key_id": "", "jwt_issuer": "", "jwt_subject": ""
        });
        for (mut body, provider_id) in [(jwt_bearer("vertex"), "vertex"), (jwt_auth("foundry"), "foundry")] {
            for (field, value) in blanks.as_object().unwrap() {
                body.as_object_mut()
                    .unwrap()
                    .entry(field.as_str())
                    .or_insert(value.clone());
            }
            let (status, response) = create(&state, body).await;
            assert_eq!(status, StatusCode::CREATED, "{provider_id}: {response}");
            let stored = state
                .store
                .find_by_provider_id(None, provider_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.client_secret_secret_ref, None, "{provider_id}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_credentials_jwt_provider_needs_no_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let mut body = jwt_auth("ory");
        body.as_object_mut()
            .unwrap()
            .remove("jwt_certificate_secret_ref");
        body["jwt_key_id"] = json!("key1");
        let (status, response) = create(&state, body).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        assert!(
            response
                .get("jwt_certificate_secret_ref")
                .is_none(),
            "{response}"
        );
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
            (jwt_auth("f"), "jwt_signing_key_secret_ref"),
            (jwt_bearer("h"), "jwt_subject"),
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
    async fn a_jwt_bearer_provider_needs_a_subject_to_be_created() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let mut blank_subject = jwt_bearer("blank");
        blank_subject["jwt_subject"] = json!("  ");
        let (status, response) = create(&state, blank_subject).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_subject is required for this provider type");
        assert!(
            state
                .store
                .find_by_provider_id(None, "blank")
                .await
                .unwrap()
                .is_none()
        );
        let (status, response) = create(&state, jwt_bearer("named")).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        assert_eq!(response["jwt_subject"], "admin@example.com");
        let mut without_subject = jwt_auth("client-assertion");
        without_subject
            .as_object_mut()
            .unwrap()
            .remove("jwt_subject");
        assert_eq!(
            create(&state, without_subject)
                .await
                .0,
            StatusCode::CREATED
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stored_jwt_bearer_provider_without_a_subject_is_refused_on_update_until_it_names_one() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let stored: CredentialProvider = serde_json::from_value(json!({
            "id": "stored-vertex", "name": "Vertex", "provider_id": "stored-vertex",
            "provider_type": "oauth2_jwt_bearer", "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwt_issuer": "agent@project.iam.gserviceaccount.com", "jwt_signing_key_secret_ref": "SA_KEY",
            "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
        }))
        .unwrap();
        assert!(stored.lacks_jwt_subject());
        state
            .store
            .create(stored.clone())
            .await
            .unwrap();
        let (status, response) = update(&state, "stored-vertex", json!({"name": "Renamed"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_subject is required for this provider type");
        let unchanged = state
            .store
            .find_by_provider_id(None, "stored-vertex")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.name, "Vertex");
        assert!(unchanged.lacks_jwt_subject());
        let (status, response) =
            update(&state, "stored-vertex", json!({"name": "Renamed", "jwt_subject": "admin@example.com"})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["jwt_subject"], "admin@example.com");
        let updated = state
            .store
            .find_by_provider_id(None, "stored-vertex")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.name, "Renamed");
        assert_eq!(
            updated
                .jwt
                .jwt_subject
                .as_deref(),
            Some("admin@example.com")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clearing_the_subject_of_a_jwt_bearer_provider_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (status, response) = create(&state, jwt_bearer("named")).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        let id = response["id"]
            .as_str()
            .unwrap()
            .to_string();
        let id = id.as_str();
        let (status, response) = update(&state, id, json!({"jwt_subject": ""})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_subject is required for this provider type");
        let kept = state
            .store
            .find_by_provider_id(None, "named")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            kept.jwt
                .jwt_subject
                .as_deref(),
            Some("admin@example.com")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_a_surface_authenticates_with_is_not_retyped_to_need_consent() {
        use crate::surfaces::AgentSurfaceStore;
        let directory = tempfile::tempdir().unwrap();
        let admin = crate::credential_providers::references::test_support::administrator().await;
        let mut state = with_key_material(&directory).await;
        state.rbac = Some(admin.rbac.clone());
        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(
                directory
                    .path()
                    .join("surfaces"),
            )
            .await
            .unwrap(),
        );
        state.references.surfaces = Some(surfaces.clone());
        let mut ids = Vec::new();
        for provider_id in ["machine", "bound"] {
            let (status, created) = create(
                &state,
                json!({
                    "name": provider_id, "provider_id": provider_id, "provider_type": "oauth2_client_credentials",
                    "token_endpoint": "https://192.0.2.1/token",
                    "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"
                }),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            ids.push(
                created["id"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
        let surface = |surface_id: &str, extra: Value| -> crate::config::agent_surface::AgentSurface {
            let mut body = json!({
                "surface_id": surface_id, "name": format!("{surface_id} name"),
                "access_point": {"listen_address": "0.0.0.0:8443", "route": format!("/{surface_id}"), "protocol": "a2a"},
                "target": {"endpoint": "https://api.example.com"}
            });
            for (key, value) in extra.as_object().unwrap() {
                body[key] = value.clone();
            }
            serde_json::from_value(body).unwrap()
        };
        surfaces
            .save(&surface(
                "uses-target-auth",
                json!({"target": {"endpoint": "https://api.example.com",
                    "auth": {"method": {"credential_provider": {"provider_id": ids[0]}}}}}),
            ))
            .await
            .unwrap();
        surfaces
            .save(&surface("uses-binding", json!({"outbound_credentials": [{"credential_provider_id": ids[1]}]})))
            .await
            .unwrap();

        let retype = |pat: Option<PatContext>| {
            let state = state.clone();
            let caller = admin.caller.clone();
            let id = ids[0].clone();
            async move {
                body_of(
                    update_provider(
                        State(state),
                        Path(id),
                        None,
                        None,
                        Some(Extension(caller)),
                        pat.map(Extension),
                        Json(serde_json::from_value(json!({"provider_type": "oauth2_authorization_code"})).unwrap()),
                    )
                    .await
                    .into_response(),
                )
                .await
            }
        };
        let (status, response) = retype(None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response["message"], PROVIDER_IN_USE_BY_TARGET_AUTH);
        assert_eq!(
            response["references"],
            json!([{"kind": "surface", "id": "uses-target-auth", "name": "uses-target-auth name"}])
        );
        assert_eq!(response["hidden_references"], 0);
        let (status, response) = retype(Some(PatContext(Some(vec!["credential_providers.edit".into()])))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!((response["references"].clone(), response["hidden_references"].clone()), (json!([]), json!(1)));
        let (status, response) = update(&state, &ids[1], json!({"provider_type": "oauth2_authorization_code"})).await;
        assert_eq!(status, StatusCode::OK, "a binding may use a provider that needs consent: {response}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retyping_a_provider_to_need_consent_waits_for_the_surface_writes_binding_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(
                directory
                    .path()
                    .join("surfaces"),
            )
            .await
            .unwrap(),
        );
        let mut state = state;
        state.references.surfaces = Some(surfaces);
        let (status, created) = create(
            &state,
            json!({
                "name": "machine", "provider_id": "machine", "provider_type": "oauth2_client_credentials",
                "token_endpoint": "https://192.0.2.1/token",
                "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"]
            .as_str()
            .unwrap()
            .to_string();
        let writing = crate::identity::handlers::surface_grants::hold_provider_bindings().await;
        let retype = tokio::spawn({
            let state = state.clone();
            let id = id.clone();
            async move {
                update(
                    &state,
                    &id,
                    json!({
                        "provider_type": "oauth2_authorization_code",
                        "authorization_endpoint": "https://192.0.2.1/authorize",
                        "token_endpoint": "https://192.0.2.1/token"
                    }),
                )
                .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while futures::FutureExt::now_or_never(crate::identity::handlers::surface_grants::hold_provider_bindings())
                .is_some()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the retype queues for the exclusive bindings lock");
        assert!(!retype.is_finished(), "the retype waits for the surface write that holds the lock");
        drop(writing);
        let (status, response) = retype.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["provider_type"], "oauth2_authorization_code");
    }

    async fn delete_secret_named(
        state: &CredentialProviderState,
        secret_id: &str,
    ) {
        let secret = state
            .secrets_store
            .get_by_secret_id(secret_id)
            .await
            .unwrap()
            .unwrap();
        state
            .secrets_store
            .delete(&secret.id)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn creating_a_provider_naming_a_secret_deleted_while_it_waited_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let deleting = crate::identity::handlers::surface_grants::hold_provider_bindings_exclusively().await;
        let creating = tokio::spawn({
            let state = state.clone();
            async move { create(&state, api_key_provider("key", "CLIENT_SECRET")).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!creating.is_finished(), "the create waits for the secret delete that holds the lock");
        delete_secret_named(&state, "CLIENT_SECRET").await;
        drop(deleting);

        let (status, response) = creating.await.unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "Secret reference is not accessible");
        assert!(
            state
                .store
                .find_by_provider_id(None, "key")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn updating_a_provider_to_a_secret_deleted_while_it_waited_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (status, created) = create(&state, api_key_provider("key", "CLIENT_ID")).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"]
            .as_str()
            .unwrap()
            .to_string();
        let deleting = crate::identity::handlers::surface_grants::hold_provider_bindings_exclusively().await;
        let updating = tokio::spawn({
            let state = state.clone();
            let id = id.clone();
            async move { update(&state, &id, json!({"api_key_secret_ref": "CLIENT_SECRET"})).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!updating.is_finished(), "the update waits for the secret delete that holds the lock");
        delete_secret_named(&state, "CLIENT_SECRET").await;
        drop(deleting);

        let (status, response) = updating.await.unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "Secret reference is not accessible");
        let stored = state
            .store
            .get(&id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored
                .api_key_secret_ref
                .as_deref(),
            Some("CLIENT_ID")
        );
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
                .find_by_provider_id(None, "foundry")
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
    async fn a_service_account_json_key_is_accepted_on_create_and_validate() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let mut body = jwt_bearer("vertex-json");
        body["jwt_signing_key_secret_ref"] = json!("SA_JSON");
        let (status, response) = create(&state, body).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        let (http, _requests, _server) = token_endpoint_answering_get().await;
        let (status, response) = validate(&state, &http, None, validate_jwt_bearer("SA_JSON")).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["key_material"], "ok");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_service_account_json_key_without_a_usable_private_key_is_refused_without_echoing_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let mut body = jwt_bearer("vertex-bad-json");
        body["jwt_signing_key_secret_ref"] = json!("BAD_JSON");
        let (status, response) = create(&state, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response["error"],
            "jwt_signing_key_secret_ref must reference a PEM private key or a Google service account JSON key matching jwt_signing_algorithm"
        );
        assert!(
            !response
                .to_string()
                .contains("key-secret-marker")
        );
        let (http, _requests, _server) = token_endpoint_answering_get().await;
        let (status, _) = validate(&state, &http, None, validate_jwt_bearer("BAD_JSON")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
                "jwt_signing_key_secret_ref must reference a PEM private key or a Google service account JSON key matching jwt_signing_algorithm"
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
            "jwt_signing_key_secret_ref must reference a PEM private key or a Google service account JSON key matching jwt_signing_algorithm"
        );
        let (status, response) = update(&state, id, json!({"jwt_signing_key_secret_ref": " "})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_signing_key_secret_ref is required for this provider type");
        let (status, response) = update(&state, id, json!({"name": "Renamed"})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["jwt_certificate_secret_ref"], "CERT");
        let (status, response) = update(&state, id, json!({"jwt_certificate_secret_ref": " "})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert!(
            response
                .get("jwt_certificate_secret_ref")
                .is_none(),
            "a blank certificate reference clears it: {response}"
        );
    }

    fn with_token_endpoint(
        mut body: Value,
        provider_id: &str,
        token_endpoint: &str,
    ) -> Value {
        body["provider_id"] = json!(provider_id);
        body["token_endpoint"] = json!(token_endpoint);
        body
    }

    fn client_credentials(provider_type: &str) -> Value {
        json!({
            "name": "Provider", "provider_id": "p", "provider_type": provider_type,
            "authorization_endpoint": "https://192.0.2.1/authorize",
            "token_endpoint": "https://192.0.2.1/token",
            "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn creating_an_oauth_provider_with_an_http_token_endpoint_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        for (index, body) in [
            client_credentials("oauth2_authorization_code"),
            client_credentials("oauth2_client_credentials"),
            jwt_bearer("p"),
            jwt_auth("p"),
        ]
        .into_iter()
        .enumerate()
        {
            let (status, response) =
                create(&state, with_token_endpoint(body.clone(), &format!("http-{index}"), "http://192.0.2.1/token"))
                    .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(response["error"], "token_endpoint must be an https URL");
            let (status, response) =
                create(&state, with_token_endpoint(body, &format!("https-{index}"), "https://192.0.2.1/token")).await;
            assert_eq!(status, StatusCode::CREATED, "{response}");
        }
        let stored: Vec<String> = state
            .store
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|provider| provider.provider_id)
            .collect();
        assert_eq!(stored.len(), 4);
        assert!(
            stored
                .iter()
                .all(|provider_id| provider_id.starts_with("https-")),
            "{stored:?}"
        );

        let (status, response) = create(
            &state,
            json!({"name": "Key", "provider_id": "key", "provider_type": "api_key",
                   "api_key_secret_ref": "CLIENT_SECRET", "token_endpoint": "http://192.0.2.1/token"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "an API key provider sends nothing to a token endpoint: {response}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_update_to_an_http_token_endpoint_is_refused_and_a_stored_one_is_kept_in_warn_mode() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (status, created) = create(&state, client_credentials("oauth2_client_credentials")).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"]
            .as_str()
            .unwrap();
        let (status, response) = update(&state, id, json!({"token_endpoint": "http://192.0.2.1/token"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "token_endpoint must be an https URL");
        let unchanged = state
            .store
            .get(id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged
                .token_endpoint
                .as_deref(),
            Some("https://192.0.2.1/token")
        );

        let mut stored = unchanged;
        stored.id = "stored-http".into();
        stored.provider_id = "stored-http".into();
        stored.token_endpoint = Some("http://192.0.2.1/token".into());
        state
            .store
            .create(stored)
            .await
            .unwrap();
        let (status, response) = update(&state, "stored-http", json!({"name": "Renamed"})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["token_endpoint"], "http://192.0.2.1/token");
        let (status, response) =
            update(&state, "stored-http", json!({"name": "Again", "token_endpoint": "http://192.0.2.1/token"})).await;
        assert_eq!(status, StatusCode::OK, "the same endpoint sent back is unchanged: {response}");
        let (status, response) =
            update(&state, "stored-http", json!({"token_endpoint": "http://192.0.2.1/other"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "token_endpoint must be an https URL");
        let (status, response) =
            update(&state, "stored-http", json!({"token_endpoint": "https://192.0.2.1/token"})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    #[test]
    fn the_save_check_keeps_a_stored_http_endpoint_only_in_warn_mode() {
        use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};

        let egress = |token_endpoint_https, insecure_token_endpoints: Vec<String>| TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: None,
            policy: std::borrow::Cow::Owned(CredentialPolicyConfig {
                token_endpoint_https,
                insecure_token_endpoints,
                ..Default::default()
            }),
        };
        let provider = |provider_type: CredentialProviderType, token_endpoint: &str| {
            let mut provider: CredentialProvider = serde_json::from_value(json!({
                "id": "cp", "name": "Provider", "provider_id": "provider", "token_endpoint": token_endpoint,
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap();
            provider.provider_type = provider_type;
            provider
        };
        let http = provider(CredentialProviderType::OAuth2ClientCredentials, "http://idp.internal/token");
        let https = provider(CredentialProviderType::OAuth2ClientCredentials, "https://idp.internal/token");
        let was_api_key = provider(CredentialProviderType::ApiKey, "http://idp.internal/token");
        let refused = |result: Result<(), ProviderValidationError>| {
            matches!(result, Err(ProviderValidationError::TokenEndpointNotHttps))
        };

        let warn = egress(RuleMode::Warn, vec![]);
        assert!(refused(validate_token_endpoint_scheme(&warn, None, &http)));
        assert!(validate_token_endpoint_scheme(&warn, Some(&http), &http).is_ok());
        assert!(refused(validate_token_endpoint_scheme(&warn, Some(&https), &http)));
        assert!(refused(validate_token_endpoint_scheme(&warn, Some(&was_api_key), &http)));
        assert!(validate_token_endpoint_scheme(&warn, None, &https).is_ok());
        assert!(validate_token_endpoint_scheme(&warn, None, &was_api_key).is_ok());

        let enforce = egress(RuleMode::Enforce, vec![]);
        assert!(refused(validate_token_endpoint_scheme(&enforce, Some(&http), &http)));
        assert!(validate_token_endpoint_scheme(&enforce, Some(&http), &https).is_ok());

        let listed = egress(RuleMode::Enforce, vec!["http://idp.internal/token".into()]);
        assert!(validate_token_endpoint_scheme(&listed, None, &http).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validate_refuses_an_http_token_endpoint_without_contacting_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (http, requests, _server) = token_endpoint_answering_get().await;
        let production = TokenEgress {
            policy: Default::default(),
            ..listed_http_egress()
        };
        let (status, response) = validate_with(
            &state,
            &http,
            &production,
            None,
            json!({"provider_type": "oauth2_client_credentials", "token_endpoint": "http://192.0.2.1/token"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "token_endpoint must be an https URL");
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);

        let (status, response) = validate(
            &state,
            &http,
            None,
            json!({"provider_type": "oauth2_client_credentials", "token_endpoint": "http://192.0.2.1/token"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "an endpoint insecure_token_endpoints lists is checked: {response}");
        assert_eq!(response["reachable"], true);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A client whose every request reaches a local server that answers GET with 405, as a
    /// token endpoint does, and the number of requests it received.
    async fn token_endpoint_answering_get()
    -> (reqwest::Client, Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinSet<()>) {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = requests.clone();
        let app = axum::Router::new().fallback(axum::routing::get(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { StatusCode::METHOD_NOT_ALLOWED }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::http(format!("http://{}", listener.local_addr().unwrap())).unwrap())
            .build()
            .unwrap();
        let mut server = tokio::task::JoinSet::new();
        server.spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        (client, requests, server)
    }

    /// The egress of an appliance whose credential policy allows the documentation address
    /// the validate tests use as an http token endpoint.
    fn listed_http_egress() -> TokenEgress {
        TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: None,
            policy: std::borrow::Cow::Owned(crate::config::credential_policy::CredentialPolicyConfig {
                insecure_token_endpoints: vec!["http://192.0.2.1/token".into()],
                ..Default::default()
            }),
        }
    }

    async fn validate(
        state: &CredentialProviderState,
        http: &reqwest::Client,
        context: Option<Extension<PatTenantContext>>,
        body: Value,
    ) -> (StatusCode, Value) {
        validate_with(state, http, &listed_http_egress(), context, body).await
    }

    async fn validate_with(
        state: &CredentialProviderState,
        http: &reqwest::Client,
        egress: &TokenEgress,
        context: Option<Extension<PatTenantContext>>,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = validate_provider_with(
            state,
            http,
            egress,
            context.is_some(),
            &context,
            &None,
            serde_json::from_value(body).unwrap(),
        )
        .await;
        body_of(response).await
    }

    fn validate_jwt_bearer(signing_key: &str) -> Value {
        json!({
            "provider_type": "oauth2_jwt_bearer", "token_endpoint": "http://192.0.2.1/token",
            "jwt_subject": "admin@example.com", "jwt_signing_key_secret_ref": signing_key
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validate_checks_reachability_and_the_key_material_of_a_jwt_provider() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (http, _requests, _server) = token_endpoint_answering_get().await;
        let (status, response) = validate(&state, &http, None, validate_jwt_bearer("SA_KEY")).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["reachable"], true);
        assert_eq!(response["http_status"], 405);
        assert_eq!(response["token_endpoint"], "http://192.0.2.1/token");
        assert_eq!(response["key_material"], "ok");

        let (status, response) = validate(
            &state,
            &http,
            None,
            json!({"provider_type": "oauth2_client_credentials", "token_endpoint": "http://192.0.2.1/token"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["reachable"], true);
        assert!(
            response
                .get("key_material")
                .is_none(),
            "{response}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validate_refuses_a_jwt_bearer_provider_without_a_subject_before_any_request() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (http, requests, _server) = token_endpoint_answering_get().await;
        let mut body = validate_jwt_bearer("SA_KEY");
        body.as_object_mut()
            .unwrap()
            .remove("jwt_subject");
        let (status, response) = validate(&state, &http, None, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_subject is required for this provider type");
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        let (status, response) = validate(&state, &http, None, validate_jwt_bearer("SA_KEY")).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validate_refuses_key_material_in_the_wrong_format_without_echoing_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        let (http, _requests, _server) = token_endpoint_answering_get().await;
        let (status, response) = validate(&state, &http, None, validate_jwt_bearer("NOT_A_KEY")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response["error"],
            "jwt_signing_key_secret_ref must reference a PEM private key or a Google service account JSON key matching jwt_signing_algorithm"
        );
        assert!(
            !response
                .to_string()
                .contains("key-secret-marker")
        );
        let mut pss_bearer = validate_jwt_bearer("SA_KEY");
        pss_bearer["jwt_signing_algorithm"] = json!("PS256");
        let (status, response) = validate(&state, &http, None, pss_bearer).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "jwt_signing_algorithm is not supported for this provider type");
    }

    fn tenant_a_context() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    async fn add_tenant_a_secret(
        state: &CredentialProviderState,
        secret_id: &str,
    ) {
        state
            .secrets_store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: Some("tenant-a".into()),
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: "tenant-value".into(),
                secret_type: "general".into(),
                tags: vec![],
            })
            .await
            .unwrap();
    }

    async fn create_as_tenant_a(
        state: &CredentialProviderState,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = create_provider(
            State(state.clone()),
            None,
            tenant_a_context(),
            None,
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        .into_response();
        body_of(response).await
    }

    fn api_key_provider(
        provider_id: &str,
        secret_ref: &str,
    ) -> Value {
        json!({"name": "Key", "provider_id": provider_id, "provider_type": "api_key", "api_key_secret_ref": secret_ref})
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_new_tenant_provider_must_reference_its_own_tenants_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        add_tenant_a_secret(&state, "TENANT_KEY").await;

        let (status, response) = create_as_tenant_a(&state, api_key_provider("wide", "CLIENT_SECRET")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "Secret reference is not accessible");
        let mut client = client_credentials("oauth2_client_credentials");
        client["client_secret_secret_ref"] = json!("TENANT_KEY");
        let (status, response) = create_as_tenant_a(&state, client).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "the client id is appliance-wide: {response}");
        let (status, response) = create_as_tenant_a(&state, api_key_provider("own", "TENANT_KEY")).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        assert_eq!(response["tenant_id"], "tenant-a");

        let stored = state
            .store
            .list()
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);

        let (status, response) = create(&state, api_key_provider("operator", "CLIENT_SECRET")).await;
        assert_eq!(status, StatusCode::CREATED, "an appliance-wide provider keeps appliance-wide secrets: {response}");
        add_tenant_a_secret(&state, "TENANT_ONLY").await;
        let (status, response) = create(&state, api_key_provider("operator-2", "TENANT_ONLY")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stored_cross_tenant_reference_is_kept_in_warn_mode_and_a_changed_one_is_refused() {
        use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};

        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        add_tenant_a_secret(&state, "TENANT_KEY").await;
        let stored: CredentialProvider = serde_json::from_value(json!({
            "id": "stored", "name": "Key", "provider_id": "stored", "provider_type": "api_key",
            "api_key_secret_ref": "CLIENT_SECRET", "tenant_id": "tenant-a",
            "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
        }))
        .unwrap();
        state
            .store
            .create(stored.clone())
            .await
            .unwrap();

        let response = update_provider(
            State(state.clone()),
            Path("stored".into()),
            tenant_a_context(),
            None,
            None,
            None,
            Json(serde_json::from_value(json!({"name": "Renamed"})).unwrap()),
        )
        .await
        .into_response();
        let (status, response) = body_of(response).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["api_key_secret_ref"], "CLIENT_SECRET");

        let reassign = |secret_ref: &'static str| {
            update_provider(
                State(state.clone()),
                Path("stored".into()),
                tenant_a_context(),
                None,
                None,
                None,
                Json(serde_json::from_value(json!({"api_key_secret_ref": secret_ref})).unwrap()),
            )
        };
        let (status, response) = body_of(
            reassign("NOT_A_KEY")
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a changed appliance-wide reference is refused: {response}");
        let (status, response) = body_of(
            reassign("TENANT_KEY")
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");

        let egress = |mode| TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: None,
            policy: std::borrow::Cow::Owned(CredentialPolicyConfig {
                tenant_credential_isolation: mode,
                ..Default::default()
            }),
        };
        let check = |mode| {
            let state = state.clone();
            let stored = stored.clone();
            async move {
                validate_provider_settings(&state, &stored, Some(&stored), &egress(mode), &tenant_a_context(), &None)
                    .await
            }
        };
        assert!(
            check(RuleMode::Warn)
                .await
                .is_ok()
        );
        assert!(matches!(check(RuleMode::Enforce).await, Err(ProviderValidationError::SecretNotAccessible)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_with_an_issuer_never_keeps_a_secret_outside_its_tenant_even_in_warn_mode() {
        use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};

        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        state
            .secrets_store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: Some("tenant-b".into()),
                name: "B_KEY".into(),
                secret_id: "B_KEY".into(),
                description: None,
                value: "tenant-b-value".into(),
                secret_type: "general".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        let stored = |issuer: Option<&str>, secret_ref: &str| -> CredentialProvider {
            serde_json::from_value(json!({
                "id": "stored", "name": "Key", "provider_id": "stored", "provider_type": "api_key",
                "api_key_secret_ref": secret_ref, "tenant_id": "tenant-a", "issuer": issuer,
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap()
        };
        let warn = TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: None,
            policy: std::borrow::Cow::Owned(CredentialPolicyConfig {
                tenant_credential_isolation: RuleMode::Warn,
                ..Default::default()
            }),
        };
        let check = |provider: CredentialProvider| {
            let state = state.clone();
            let warn = warn.clone();
            async move {
                validate_provider_settings(&state, &provider, Some(&provider), &warn, &tenant_a_context(), &None).await
            }
        };
        let issuer = Some("https://issuer.example");
        assert!(matches!(
            check(stored(issuer, "CLIENT_SECRET")).await,
            Err(ProviderValidationError::SecretNotAccessible)
        ));
        assert!(matches!(check(stored(issuer, "B_KEY")).await, Err(ProviderValidationError::SecretNotAccessible)));
        assert!(
            check(stored(None, "CLIENT_SECRET"))
                .await
                .is_ok()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validate_refuses_an_appliance_wide_key_for_a_tenant_provider() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        add_tenant_a_secret(&state, "TENANT_KEY").await;
        let (http, requests, _server) = token_endpoint_answering_get().await;
        let (status, response) = validate(&state, &http, tenant_a_context(), validate_jwt_bearer("SA_KEY")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "Secret reference is not accessible");
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        let (status, response) = validate(&state, &http, None, validate_jwt_bearer("SA_KEY")).await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validate_refuses_another_tenants_secret_before_reading_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = with_key_material(&directory).await;
        // Not a key: reading it would answer "must reference a PEM private key" instead.
        state
            .secrets_store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: Some("tenant-b".into()),
                name: "B_KEY".into(),
                secret_id: "B_KEY".into(),
                description: None,
                value: "key-secret-marker".into(),
                secret_type: "general".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        let (http, _requests, _server) = token_endpoint_answering_get().await;
        let tenant_a = Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }));
        let (status, response) = validate(&state, &http, tenant_a, validate_jwt_bearer("B_KEY")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "Secret reference is not accessible");
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
            resource_origins: Default::default(),
            issuers: Default::default(),
            references: Default::default(),
            rbac: None,
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
        let invalid = |result: Result<(), ProviderValidationError>| {
            matches!(result, Err(ProviderValidationError::InvalidConsentStrategy))
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
                ProviderValidationError::InvalidConsentStrategy,
                StatusCode::BAD_REQUEST,
                r#"{"error":"Consent identity strategy is invalid or not accessible"}"#,
            ),
            (
                ProviderValidationError::IdentityConfigurationUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity verification configuration unavailable",
            ),
            (
                ProviderValidationError::SecretNotAccessible,
                StatusCode::BAD_REQUEST,
                r#"{"error":"Secret reference is not accessible"}"#,
            ),
            (
                ProviderValidationError::SecretLookupFailed,
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
            resource_origins: Default::default(),
            issuers: Default::default(),
            references: Default::default(),
            rbac: None,
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

        let update =
            update_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, None, None, rename())
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

        let update =
            update_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, None, None, rename())
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

        let update =
            update_provider(State(state.clone()), Path("provider".into()), tenant_a(), None, None, None, rename())
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
            resource_origins: Default::default(),
            issuers: Arc::new(Some(std::collections::HashMap::from([(
                crate::credential_providers::external::tests::ISSUER.to_string(),
                Vec::new(),
            )]))),
            references: Default::default(),
            rbac: None,
        }
    }

    /// While the operator lists no `external_consent_issuers`, a tenant's
    /// token cannot create an external consent provider, whose endpoints the
    /// tenant would choose: the answer tells the operator to set the list. An
    /// operator still can, and a tenant can once the list names the issuer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tenant_creates_an_external_provider_only_once_the_operator_lists_its_issuers() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = state(&directory, Ok(metadata())).await;
        state.issuers = Arc::new(None);
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "external_consent_issuers_required");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("external_consent_issuers") && error.contains("gateway.json")),
            "{body}"
        );
        assert!(
            stored(&state)
                .await
                .is_empty()
        );

        let operator = create_provider(State(state.clone()), None, None, None, create_request(|_| {}))
            .await
            .into_response();
        assert_eq!(operator.status(), StatusCode::CREATED, "an operator's own provider needs no list");

        state.issuers = Arc::new(Some(std::collections::HashMap::from([(
            crate::credential_providers::external::tests::ISSUER.to_string(),
            Vec::new(),
        )])));
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    /// With `external_consent_issuers` set, a provider is created only for a
    /// listed issuer whose endpoints and `jwks_uri` are on its host or listed
    /// for it; an unlisted issuer's metadata is never fetched. The metadata's
    /// RFC 9207 flag is recorded on the provider, never taken from the request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_an_issuer_the_operator_lists_is_created_and_its_iss_support_is_recorded() {
        let directory = tempfile::tempdir().unwrap();
        let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut state = state(&directory, Ok(metadata())).await;
        let counted = Arc::clone(&fetched);
        state.issuer_metadata = Arc::new(move |_issuer| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(metadata()) })
        });
        state.issuers =
            Arc::new(Some(std::collections::HashMap::from([("https://issuer.example".to_string(), Vec::new())])));
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "provider_issuer_not_permitted");
        assert_eq!(body["field"], "issuer");
        assert_eq!(fetched.load(std::sync::atomic::Ordering::SeqCst), 0, "an unlisted issuer is never fetched");
        assert!(
            stored(&state)
                .await
                .is_empty()
        );

        state.issuers =
            Arc::new(Some(std::collections::HashMap::from([("https://203.0.113.10".to_string(), Vec::new())])));
        let mut jwks_elsewhere = metadata();
        jwks_elsewhere.jwks_uri = Some("https://203.0.113.66/jwks".into());
        state.issuer_metadata = answering(Ok(jwks_elsewhere));
        let (status, body) = create(&state, "tenant-a", create_request(|_| {})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "provider_issuer_not_permitted");
        assert_eq!(body["field"], "jwks_uri");

        state.issuer_metadata = answering(Ok(metadata()));
        let (status, body) = create(
            &state,
            "tenant-a",
            create_request(|body| body["authorization_response_iss_parameter_supported"] = json!(false)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(stored(&state).await[0].authorization_response_iss_parameter_supported, Some(true));
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

    /// A provider's resource must be permitted for its issuer when it is
    /// created: on the issuer's host or a subdomain, or an origin the operator
    /// lists for the issuer in gateway.json. A request cannot widen the list.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_whose_resource_is_not_permitted_for_its_issuer_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = state(&directory, Ok(metadata())).await;
        for resource in
            ["https://collector.example/mcp", "https://203.0.113.10.evil.example/mcp", "https://203.0.113.66/mcp"]
        {
            let (status, body) = create(
                &state,
                "tenant-a",
                create_request(|body| {
                    body["resource"] = json!(resource);
                    body["external_consent_resource_origins"] =
                        json!({"https://203.0.113.10": ["https://collector.example"]});
                    body["resource_origins"] = json!(["https://collector.example"]);
                }),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{resource}: {body}");
            assert_eq!(body["code"], "provider_resource_not_permitted", "{resource}");
        }
        assert!(
            stored(&state)
                .await
                .is_empty()
        );

        state.resource_origins = Arc::new(std::collections::HashMap::from([(
            "https://203.0.113.10".to_string(),
            vec!["https://collector.example".to_string()],
        )]));
        let (status, body) = create(
            &state,
            "tenant-a",
            create_request(|body| body["resource"] = json!("https://collector.example/mcp")),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "the operator's entry permits it: {body}");
        assert_eq!(body["resource_origin"], "https://collector.example");
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
    async fn a_providers_slug_is_logged_escaped() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        let directory = tempfile::tempdir().unwrap();
        let mut moved = metadata();
        moved.token_endpoint = "https://203.0.113.66/token".into();
        for answer in [Err(DiscoveryFailure::Blocked), Ok(moved)] {
            let state = state(&directory, answer).await;
            let logs = FormattedLogs::capture();
            let (status, _) = create(
                &state,
                "tenant-a",
                create_request(|body| body["provider_id"] = json!("slug\nWARN forged line")),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let text = logs.text();
            assert!(text.contains("Refused a credential provider"), "{text}");
            assert!(!text.contains("\nwarn forged line"), "the slug starts a log line of its own: {text}");
        }
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

    /// An external consent provider uses its own tenant's secrets only, for
    /// its client secret and its signing key: never an untenanted operator
    /// secret, nor another tenant's. An untenanted provider uses untenanted
    /// ones only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_external_provider_references_only_its_own_tenants_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let mut metadata = metadata();
        metadata
            .token_endpoint_auth_methods_supported
            .as_mut()
            .unwrap()
            .push("private_key_jwt".into());
        let state = state(&directory, Ok(metadata)).await;
        let key = crate::delegation_vault::jwt_assertion::test_keys::rsa_pkcs8();
        for (secret_id, tenant) in
            [("tenant-a-secret", Some("tenant-a")), ("operator-secret", None), ("tenant-b-secret", Some("tenant-b"))]
        {
            state
                .secrets_store
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: tenant.map(str::to_string),
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: key.private_pem.clone(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let request = |slug: &str, method: &str, secret: &str| {
            create_request(|body| {
                body["provider_id"] = json!(slug);
                body["token_endpoint_auth_method"] = json!(method);
                if method == "private_key_jwt" {
                    body["jwt_signing_key_secret_ref"] = json!(secret);
                } else {
                    body["client_secret_secret_ref"] = json!(secret);
                }
            })
        };
        for method in ["client_secret_post", "private_key_jwt"] {
            for secret in ["operator-secret", "tenant-b-secret"] {
                let (status, body) = create(&state, "tenant-a", request("refused", method, secret)).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{method} with {secret}: {body}");
                assert_eq!(body["error"], "Secret reference is not accessible", "{method} with {secret}");
            }
            let (status, body) =
                create(&state, "tenant-a", request(&format!("own-{method}"), method, "tenant-a-secret")).await;
            assert_eq!(status, StatusCode::CREATED, "{method} with its own tenant's secret: {body}");

            let operator = |secret: &str| {
                create_provider(
                    State(state.clone()),
                    None,
                    None,
                    None,
                    request(&format!("operator-{method}-{secret}"), method, secret),
                )
            };
            let refused = operator("tenant-a-secret")
                .await
                .into_response();
            assert_eq!(
                refused.status(),
                StatusCode::BAD_REQUEST,
                "an operator provider with a tenant's {method} secret"
            );
            let created = operator("operator-secret")
                .await
                .into_response();
            assert_eq!(created.status(), StatusCode::CREATED, "an operator provider with an operator {method} secret");
        }
        assert_eq!(stored(&state).await.len(), 4);
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
                    None,
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
                Some("target_auth") => {
                    surface.target.auth = Some(serde_json::from_value(binding["binding"].clone()).unwrap());
                }
                Some("transit_point_target_auth") => {
                    surface
                        .transit
                        .as_mut()
                        .unwrap()
                        .points[0]
                        .target_auth = Some(serde_json::from_value(binding["binding"].clone()).unwrap());
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
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
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

    /// The answer of a provider delete, once the revocations it started
    /// have ended.
    async fn answer_once_revoked(
        (response, revocations): (Response, Option<tokio::task::JoinHandle<()>>)
    ) -> (StatusCode, serde_json::Value) {
        if let Some(revocations) = revocations {
            tokio::time::timeout(std::time::Duration::from_secs(60), revocations)
                .await
                .expect("the revocations end")
                .unwrap();
        }
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    async fn delete(
        state: &CredentialProviderState,
        id: &str,
    ) -> (StatusCode, serde_json::Value) {
        answer_once_revoked(remove_provider(state, id, &tenant("tenant-a"), &None, None).await).await
    }

    /// The `DELETE` route itself, answering without waiting for the
    /// revocations it starts.
    async fn delete_route(
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
            (
                "the Target's authentication",
                json!({"where": "target_auth", "binding": {"method": {"credential_provider":
                    {"provider_id": "provider"}}}}),
            ),
            (
                "a Transit Point's target authentication",
                json!({"where": "transit_point_target_auth", "binding": {"method": {"credential_provider":
                    {"provider_id": "provider"}}}}),
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

    /// A provider delete holds the provider lock only while it checks the
    /// bindings and deletes the grants and the provider; the grants are
    /// revoked afterwards, on a task of their own, so a vendor that hangs keeps
    /// neither the delete nor another tenant's surface write or connect
    /// completion waiting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_hung_vendor_never_holds_the_provider_lock_of_a_provider_delete() {
        use crate::delegation_vault::grants::GrantKey;
        use crate::identity::handlers::surface_grants::{GrantRemoval, Stored, write_surface};
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start_with_delay(
            200,
            std::time::Duration::from_secs(60),
        )
        .await;
        let state = delete_state(&directory, &server).await;
        let vault = state.vault.clone().unwrap();
        let keys: Vec<GrantKey> = (0..3)
            .map(|index| {
                GrantKey::caller(Some("tenant-a"), "surface", "tp-1", "provider", &format!("{index:064x}")).unwrap()
            })
            .collect();
        for key in &keys {
            vault
                .store_grant(crate::delegation_vault::grants::tests::grant(key, "access"))
                .await
                .unwrap();
        }

        let quick = std::time::Duration::from_secs(5);
        let (status, body) = tokio::time::timeout(quick, delete_route(&state, "provider"))
            .await
            .expect("the delete never waits on the vendor");
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert!(
            state
                .store
                .get("provider")
                .await
                .unwrap()
                .is_none()
        );
        for key in &keys {
            assert!(
                vault
                    .grant(key)
                    .await
                    .unwrap()
                    .is_none(),
                "{key:?} is released no more"
            );
        }

        let surfaces = state
            .surfaces
            .clone()
            .unwrap();
        let mut other = bound_surface(json!({"where": "none"}));
        other.surface_id = "tenant-b-surface".into();
        other.tenant_id = Some("tenant-b".into());
        other.variants = vec![];
        let removal = GrantRemoval {
            vault: Some(&vault),
            providers: Some(&state.store),
            secrets: None,
            exact_allowlist: None,
            actor: None,
        };
        tokio::time::timeout(
            quick,
            write_surface(&removal, surfaces.clone(), "tenant-b-surface", Stored::Absent, Some(&other), || async {
                surfaces
                    .save(&other)
                    .await
                    .map_err(|error| {
                        crate::identity::handlers::surfaces::SurfaceApiError::InternalError(error.to_string())
                    })
            }),
        )
        .await
        .expect("another tenant's surface write never waits on the vendor")
        .expect("and is saved");

        let mut connected = bound_surface(json!({"where": "transit_point", "binding": {
            "credential_provider_id": "provider-b", "consent_mode": "external", "subject": "owner"}}));
        connected.surface_id = "tenant-b-connected".into();
        connected.tenant_id = Some("tenant-b".into());
        surfaces
            .save(&connected)
            .await
            .unwrap();
        let key = GrantKey::owner(Some("tenant-b"), "tenant-b-connected", "tp-1", "provider-b");
        tokio::time::timeout(
            quick,
            crate::identity::handlers::surface_grants::store_grant_while_bound(
                &vault,
                surfaces.as_ref(),
                crate::delegation_vault::grants::tests::grant(&key, "tenant-b-access"),
                &["read".to_string()],
            ),
        )
        .await
        .expect("another tenant's connect completion never waits on the vendor")
        .expect("and its grant is stored");

        let reached = async {
            while server.requests().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(quick, reached)
            .await
            .expect("the revocations still go to the vendor");
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

    /// Deleting a provider reads only its own grants: another provider's
    /// unreadable grant never blocks it, and its own is named in the refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_providers_own_unreadable_grant_keeps_it() {
        use crate::delegation_vault::grants::GrantKey;
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let state = delete_state(&directory, &server).await;
        let vault = state.vault.clone().unwrap();
        let own = GrantKey::owner(Some("tenant-a"), "surface", "tp-1", "provider");
        let other = GrantKey::owner(Some("tenant-a"), "surface", "tp-2", "other-provider");
        for key in [&own, &other] {
            vault
                .store_grant(crate::delegation_vault::grants::tests::grant(key, "access"))
                .await
                .unwrap();
        }
        let file = |key: &GrantKey| {
            directory
                .path()
                .join("vault/delegated_grants")
                .join(format!("{}.json.enc", key.record_id()))
        };
        std::fs::write(file(&own), "not a grant").unwrap();
        let (status, body) = delete(&state, "provider").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let error = body["error"]
            .as_str()
            .unwrap_or_default();
        assert!(error.contains(&own.record_id()), "{body}");
        assert!(error.contains("DELETE /api/v1/delegation-vault/grants/"), "{body}");
        assert!(file(&own).exists());

        std::fs::remove_file(file(&own)).unwrap();
        std::fs::write(file(&other), "not a grant").unwrap();
        let (status, body) = delete(&state, "provider").await;
        assert_eq!(status, StatusCode::NO_CONTENT, "another provider's unreadable grant blocks nothing: {body}");
    }

    /// A provider whose bindings or grants cannot be checked is kept: without
    /// the surface store, or without the delegation vault, its delete answers
    /// `503`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_whose_bindings_or_grants_cannot_be_checked_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let server = crate::delegation_vault::revocation::tests::RecordingServer::start(200).await;
        let state = delete_state(&directory, &server).await;
        for (case, state, error) in [
            (
                "no surface store",
                CredentialProviderState {
                    surfaces: None,
                    ..state.clone()
                },
                "Agent surfaces are unavailable, so the provider's bindings cannot be checked",
            ),
            (
                "no delegation vault",
                CredentialProviderState {
                    vault: None,
                    ..state.clone()
                },
                "The delegation vault is unavailable, so the provider's grants cannot be removed",
            ),
        ] {
            let (status, body) = delete(&state, "provider").await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{case}: {body}");
            assert_eq!(body, serde_json::json!({ "error": error }), "{case}");
            assert!(
                state
                    .store
                    .get("provider")
                    .await
                    .unwrap()
                    .is_some(),
                "{case}: the provider is kept"
            );
        }
        assert!(server.requests().is_empty());
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
        let ((status, _), events) = crate::audit::producer::capture(async {
            let answer = delete_as(&state, tenant("tenant-a"), None).await;
            let revoked = async {
                while server.requests().len() < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), revoked)
                .await
                .expect("the grant is revoked after the answer");
            answer
        })
        .await;
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
