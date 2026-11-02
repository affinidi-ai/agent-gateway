//! Credential Providers module for OAuth 2.0 provider configuration
//!
//! A managed resource that describes an OAuth 2.0 / OIDC provider
//! (Google, GitHub, Microsoft, Okta, etc.) for outbound credential delegation.
//!
//! Credential providers are standalone resources — like JWT verification strategies
//! or secrets — configured once and referenced by channels via `outbound_credentials`.
//!
//! Client secrets are never stored directly; they reference the secrets store
//! via secret_id (e.g. "GOOGLE_CLIENT_SECRET").
//!
//! A provider with an `issuer` is an external consent provider: checked against
//! its issuer's metadata when it is created, its endpoints and client fields
//! fixed for life, and bound only by `consent_mode: external` (see [`external`]).

pub mod external;
pub mod handlers;
pub mod router;
pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::storage::filesystem::StorableEntity;

/// The type of credential flow this provider supports
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CredentialProviderType {
    /// Authorization Code flow (3-legged OAuth) — requires user consent
    #[default]
    #[serde(rename = "oauth2_authorization_code")]
    OAuth2AuthorizationCode,
    /// Client Credentials flow (2-legged OAuth) — machine-to-machine
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials,
    /// Static API key — resolved directly from the secrets store, no OAuth
    #[serde(rename = "api_key")]
    ApiKey,
    /// JWT Bearer grant (RFC 7523 section 2.1): a signed JWT is the grant, no client
    /// credentials. Google service accounts use it.
    #[serde(rename = "oauth2_jwt_bearer")]
    OAuth2JwtBearer,
    /// Client Credentials grant with `private_key_jwt` client authentication (RFC 7523
    /// section 2.2). Entra certificate credentials use it.
    #[serde(rename = "oauth2_client_credentials_jwt_auth")]
    OAuth2ClientCredentialsJwtAuth,
}

impl CredentialProviderType {
    /// The signing algorithm used when the provider names none; `None` for types
    /// that sign nothing.
    pub fn default_jwt_algorithm(&self) -> Option<JwtSigningAlgorithm> {
        match self {
            Self::OAuth2JwtBearer => Some(JwtSigningAlgorithm::RS256),
            Self::OAuth2ClientCredentialsJwtAuth => Some(JwtSigningAlgorithm::PS256),
            Self::OAuth2AuthorizationCode | Self::OAuth2ClientCredentials | Self::ApiKey => None,
        }
    }

    /// Does a request authenticated by a provider of this type carry the gateway's own
    /// credential (an API key, or a token granted to the gateway's own client)? An
    /// authorization code provider sends the end user's token instead.
    pub fn sends_gateway_credential(&self) -> bool {
        match self {
            Self::OAuth2ClientCredentials
            | Self::ApiKey
            | Self::OAuth2JwtBearer
            | Self::OAuth2ClientCredentialsJwtAuth => true,
            Self::OAuth2AuthorizationCode => false,
        }
    }

    /// The algorithm a provider of this type signs with: `configured`, else the default.
    pub fn jwt_signing_algorithm(
        &self,
        configured: Option<JwtSigningAlgorithm>,
    ) -> Option<JwtSigningAlgorithm> {
        self.default_jwt_algorithm()
            .map(|default| configured.unwrap_or(default))
    }

    pub fn allows_jwt_algorithm(
        &self,
        algorithm: JwtSigningAlgorithm,
    ) -> bool {
        match self {
            Self::OAuth2JwtBearer => matches!(algorithm, JwtSigningAlgorithm::RS256 | JwtSigningAlgorithm::ES256),
            Self::OAuth2ClientCredentialsJwtAuth => {
                matches!(algorithm, JwtSigningAlgorithm::PS256 | JwtSigningAlgorithm::RS256)
            }
            Self::OAuth2AuthorizationCode | Self::OAuth2ClientCredentials | Self::ApiKey => false,
        }
    }
}

/// Algorithm of the JWT a provider signs with its private key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum JwtSigningAlgorithm {
    RS256,
    PS256,
    ES256,
}

/// The signed-JWT settings of the `oauth2_jwt_bearer` and
/// `oauth2_client_credentials_jwt_auth` types. Key and certificate are secret
/// references; the PEM values never leave the secrets store except to sign.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwtAssertionSettings {
    /// Secret holding the PEM private key (PKCS#1 or PKCS#8 for RSA, PKCS#8 for EC) or a
    /// Google service account JSON key file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_signing_key_secret_ref: Option<String>,
    /// Secret holding the PEM certificate whose SHA-256 thumbprint goes in `x5t#S256`;
    /// optional, for issuers such as Entra that identify the key by certificate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_certificate_secret_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_signing_algorithm: Option<JwtSigningAlgorithm>,
    /// `aud` claim; the token endpoint when unset
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_audience: Option<String>,
    /// `kid` header
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_key_id: Option<String>,
    /// `iss` claim of a JWT Bearer grant (a Google service account's `client_email`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_issuer: Option<String>,
    /// `sub` claim of a JWT Bearer grant (domain-wide delegation)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_subject: Option<String>,
}

impl JwtAssertionSettings {
    /// These settings with every field that `self` leaves unset taken from `existing`.
    pub fn or(
        self,
        existing: Self,
    ) -> Self {
        Self {
            jwt_signing_key_secret_ref: self
                .jwt_signing_key_secret_ref
                .or(existing.jwt_signing_key_secret_ref),
            jwt_certificate_secret_ref: self
                .jwt_certificate_secret_ref
                .or(existing.jwt_certificate_secret_ref),
            jwt_signing_algorithm: self
                .jwt_signing_algorithm
                .or(existing.jwt_signing_algorithm),
            jwt_audience: self
                .jwt_audience
                .or(existing.jwt_audience),
            jwt_key_id: self
                .jwt_key_id
                .or(existing.jwt_key_id),
            jwt_issuer: self
                .jwt_issuer
                .or(existing.jwt_issuer),
            jwt_subject: self
                .jwt_subject
                .or(existing.jwt_subject),
        }
    }

    /// The same settings with blank values removed and the rest trimmed, so a field
    /// sent empty clears it.
    pub fn normalized(self) -> Self {
        fn clean(value: Option<String>) -> Option<String> {
            value
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        }
        Self {
            jwt_signing_key_secret_ref: clean(self.jwt_signing_key_secret_ref),
            jwt_certificate_secret_ref: clean(self.jwt_certificate_secret_ref),
            jwt_signing_algorithm: self.jwt_signing_algorithm,
            jwt_audience: clean(self.jwt_audience),
            jwt_key_id: clean(self.jwt_key_id),
            jwt_issuer: clean(self.jwt_issuer),
            jwt_subject: clean(self.jwt_subject),
        }
    }
}

/// How an external consent provider's client authenticates at the token and
/// revocation endpoints (RFC 6749 section 2.3, RFC 8414).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// A public client: `client_id` in the body, no secret.
    None,
    /// HTTP Basic with the client id and secret.
    ClientSecretBasic,
    /// The client id and secret in the form body.
    ClientSecretPost,
    /// A JWT the client signs with its private key (RFC 7523 section 2.2), as
    /// an `oauth2_client_credentials_jwt_auth` provider authenticates.
    PrivateKeyJwt,
}

impl TokenEndpointAuthMethod {
    /// The method's name in RFC 8414 `token_endpoint_auth_methods_supported`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }

    /// Whether the client authenticates with a secret.
    pub fn uses_secret(self) -> bool {
        matches!(self, Self::ClientSecretBasic | Self::ClientSecretPost)
    }
}

/// A configured OAuth 2.0 credential provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProvider {
    /// Unique identifier (UUID), immutable after creation
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Human-readable display name (e.g. "Google Calendar", "GitHub")
    pub name: String,

    /// Machine-readable identifier derived from name (e.g. "google-calendar", "github")
    /// Used in callback URLs and vault lookups
    pub provider_id: String,

    /// The type of OAuth 2.0 flow
    #[serde(default)]
    pub provider_type: CredentialProviderType,

    /// OAuth 2.0 authorization endpoint (e.g. "https://accounts.google.com/o/oauth2/v2/auth")
    /// Required for authorization_code flow, unused for client_credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,

    /// OAuth 2.0 token endpoint (e.g. "https://oauth2.googleapis.com/token")
    /// Required for OAuth flows, unused for ApiKey
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,

    /// Secret ID for the OAuth client_id (references secrets store via secret_id field)
    /// Required for OAuth flows, unused for ApiKey
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_secret_ref: Option<String>,

    /// Secret ID for the OAuth client_secret (references secrets store via secret_id field)
    /// Required for OAuth flows, unused for ApiKey
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_secret_ref: Option<String>,

    /// Default scopes to request if not overridden by channel binding
    #[serde(default)]
    pub default_scopes: Vec<String>,

    /// Auto-generated callback path for authorization code flow
    /// Format: /v1/identity/oauth/callback/{provider_id}
    #[serde(default)]
    pub callback_path: String,

    /// Full callback URL including host (e.g. "https://gw.example.com/v1/identity/oauth/callback/github")
    /// User-configurable; used as redirect_uri in OAuth authorization requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_identity_strategy_id: Option<String>,

    /// Whether to attempt token refresh using refresh_token when access_token expires
    #[serde(default = "default_true")]
    pub token_refresh_enabled: bool,

    /// Additional parameters to include in the authorization request
    /// (e.g. {"access_type": "offline", "prompt": "consent"})
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub additional_params: HashMap<String, String>,

    /// Secret ID for the API key (only used when provider_type = ApiKey)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_secret_ref: Option<String>,

    #[serde(flatten)]
    pub jwt: JwtAssertionSettings,

    /// Optional description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The authorization server's issuer. Makes this an external consent
    /// provider, checked against the issuer's metadata at create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// RFC 7009 revocation endpoint of an external consent provider: the one
    /// its issuer's metadata names, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// How an external consent provider's client authenticates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,

    /// An external consent provider's client id, a plain value: a client id is
    /// not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Admit an issuer whose metadata does not list
    /// `code_challenge_methods_supported`, which MCP clients refuse. Set only for
    /// an authorization server known to enforce S256 PKCE without saying so,
    /// such as Microsoft Entra ID. An external consent provider only, fixed for
    /// its life.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_unadvertised_pkce: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

impl StorableEntity for CredentialProvider {
    fn id(&self) -> &str {
        &self.id
    }
}

impl CredentialProvider {
    /// The secret ids this provider reads: client, API key, signing key and certificate.
    pub fn secret_refs(&self) -> Vec<&str> {
        self.secret_ref_fields()
            .into_iter()
            .flatten()
            .collect()
    }

    /// The secret ids a service token of this provider's type reads: the API key; the client
    /// ID and secret; a JWT Bearer grant's signing key and certificate; or the client ID,
    /// signing key and certificate of a client authenticating with a JWT. A reference left
    /// from another type is not among them, and an authorization code provider issues no
    /// service token.
    pub fn service_token_secret_refs(&self) -> Vec<&str> {
        let [client_id, client_secret, api_key, signing_key, certificate] = self.secret_ref_fields();
        match self.provider_type {
            CredentialProviderType::ApiKey => vec![api_key],
            CredentialProviderType::OAuth2ClientCredentials => vec![client_id, client_secret],
            CredentialProviderType::OAuth2JwtBearer => vec![signing_key, certificate],
            CredentialProviderType::OAuth2ClientCredentialsJwtAuth => vec![client_id, signing_key, certificate],
            CredentialProviderType::OAuth2AuthorizationCode => Vec::new(),
        }
        .into_iter()
        .flatten()
        .collect()
    }

    /// The secret reference of each field, in the order of [`Self::secret_refs`].
    fn secret_ref_fields(&self) -> [Option<&str>; 5] {
        [
            self.client_id_secret_ref
                .as_deref(),
            self.client_secret_secret_ref
                .as_deref(),
            self.api_key_secret_ref
                .as_deref(),
            self.jwt
                .jwt_signing_key_secret_ref
                .as_deref(),
            self.jwt
                .jwt_certificate_secret_ref
                .as_deref(),
        ]
    }

    /// Each secret reference, paired with whether `previous` held it in the same field while
    /// this provider keeps the type and sends it to the same place: the token and
    /// authorization endpoints, resource, additional parameters, default scopes and JWT issuer,
    /// subject and audience.
    fn secret_refs_kept_from(
        &self,
        previous: Option<&Self>,
    ) -> Vec<(&str, bool)> {
        let stored = previous
            .filter(|previous| {
                self.provider_type == previous.provider_type
                    && self.token_endpoint == previous.token_endpoint
                    && self.authorization_endpoint == previous.authorization_endpoint
                    && self.resource == previous.resource
                    && self.additional_params == previous.additional_params
                    && self.default_scopes == previous.default_scopes
                    && self.jwt.jwt_issuer == previous.jwt.jwt_issuer
                    && self.jwt.jwt_subject == previous.jwt.jwt_subject
                    && self.jwt.jwt_audience == previous.jwt.jwt_audience
            })
            .map(Self::secret_ref_fields)
            .unwrap_or_default();
        self.secret_ref_fields()
            .into_iter()
            .zip(stored)
            .filter_map(|(reference, stored)| reference.map(|reference| (reference, stored == Some(reference))))
            .collect()
    }

    /// Is a secret of `secret_tenant` outside this provider's own tenant? A tenant provider
    /// may use only its own tenant's secrets and an appliance-wide provider only appliance-wide
    /// ones.
    pub fn secret_is_outside_tenant(
        &self,
        secret_tenant: Option<&str>,
    ) -> bool {
        self.tenant_id.as_deref() != secret_tenant
    }

    /// Does the provider name a secret outside its own tenant? `secret_tenants` maps a secret id
    /// to its tenant; a secret missing from it no longer exists and does not count.
    pub fn uses_secret_outside_tenant(
        &self,
        secret_tenants: &std::collections::HashMap<&str, Option<&str>>,
    ) -> bool {
        self.secret_refs()
            .into_iter()
            .any(|secret_ref| {
                secret_tenants
                    .get(secret_ref)
                    .is_some_and(|tenant| self.secret_is_outside_tenant(*tenant))
            })
    }

    /// Does the provider send the gateway's own credential on a tenant surface from an
    /// appliance-wide provider? Only that credential is held to tenant isolation.
    pub fn breaks_tenant_isolation_for(
        &self,
        surface_tenant_id: Option<&str>,
    ) -> bool {
        self.provider_type
            .sends_gateway_credential()
            && crate::tenancy::breaks_tenant_isolation(surface_tenant_id, self.tenant_id.as_deref())
    }

    /// May a surface use this provider? A provider of another tenant never; an
    /// appliance-wide one that sends the gateway's own credential only while the surface's
    /// mode is `Warn`.
    pub fn usable_by(
        &self,
        surface_tenancy: crate::tenancy::SurfaceTenancy<'_>,
    ) -> bool {
        if self
            .provider_type
            .sends_gateway_credential()
        {
            crate::tenancy::can_reference_with_rule(
                surface_tenancy.tenant_id,
                self.tenant_id.as_deref(),
                surface_tenancy.mode,
            )
        } else {
            crate::tenancy::can_reference(surface_tenancy.tenant_id, self.tenant_id.as_deref())
        }
    }

    /// The algorithm this provider signs its JWT with: the configured one, or its
    /// type's default, or for an external consent provider whose client
    /// authenticates with `private_key_jwt` the default of
    /// `oauth2_client_credentials_jwt_auth`. `None` for providers that sign nothing.
    pub fn jwt_signing_algorithm(&self) -> Option<JwtSigningAlgorithm> {
        if self.token_endpoint_auth_method == Some(TokenEndpointAuthMethod::PrivateKeyJwt) {
            return CredentialProviderType::OAuth2ClientCredentialsJwtAuth
                .jwt_signing_algorithm(self.jwt.jwt_signing_algorithm);
        }
        self.provider_type
            .jwt_signing_algorithm(self.jwt.jwt_signing_algorithm)
    }

    /// Whether this is an external consent provider: one with an `issuer`,
    /// whose grants are made through external consent and kept in the
    /// delegation vault by binding.
    pub fn is_external_consent(&self) -> bool {
        self.issuer.is_some()
    }

    /// Whether this provider may use a secret of `secret_tenant_id`. An
    /// external consent provider uses its own tenant's secrets only, an
    /// untenanted one untenanted secrets only, since its client authenticates
    /// at endpoints its tenant chose; any other provider its own tenant's or
    /// an untenanted one. This is the runtime and kept-reference check: a save
    /// also needs an exact tenant match unless the reference is kept in warn
    /// mode.
    pub fn may_use_secret(
        &self,
        secret_tenant_id: Option<&str>,
    ) -> bool {
        if self.is_external_consent() {
            return self.tenant_id.as_deref() == secret_tenant_id;
        }
        crate::tenancy::can_reference(self.tenant_id.as_deref(), secret_tenant_id)
    }
}

/// Request to create a new credential provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCredentialProviderRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub provider_id: String,
    #[serde(default)]
    pub provider_type: CredentialProviderType,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub client_id_secret_ref: Option<String>,
    #[serde(default)]
    pub client_secret_secret_ref: Option<String>,
    #[serde(default)]
    pub default_scopes: Vec<String>,
    #[serde(default = "default_true")]
    pub token_refresh_enabled: bool,
    #[serde(default)]
    pub additional_params: HashMap<String, String>,
    #[serde(default)]
    pub api_key_secret_ref: Option<String>,
    #[serde(flatten)]
    pub jwt: JwtAssertionSettings,
    #[serde(default)]
    pub description: Option<String>,
    /// Full callback URL (host + path) — overrides auto-generated callback URL
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub consent_identity_strategy_id: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub allow_unadvertised_pkce: bool,
}

/// Request to update an existing credential provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCredentialProviderRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub provider_type: Option<CredentialProviderType>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub client_id_secret_ref: Option<String>,
    #[serde(default)]
    pub client_secret_secret_ref: Option<String>,
    #[serde(default)]
    pub default_scopes: Option<Vec<String>>,
    #[serde(default)]
    pub token_refresh_enabled: Option<bool>,
    #[serde(default)]
    pub additional_params: Option<HashMap<String, String>>,
    #[serde(default)]
    pub api_key_secret_ref: Option<String>,
    #[serde(flatten)]
    pub jwt: JwtAssertionSettings,
    #[serde(default)]
    pub description: Option<String>,
    /// Full callback URL (host + path) — overrides auto-generated callback URL
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub consent_identity_strategy_id: Option<String>,
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub allow_unadvertised_pkce: Option<bool>,
}

/// Request to check a provider before it is saved: the token endpoint's reachability and,
/// for a type that signs a JWT, the key material its secret references hold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateCredentialProviderRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub provider_type: Option<CredentialProviderType>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(flatten)]
    pub jwt: JwtAssertionSettings,
}

/// List response item (no sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProviderListItem {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub provider_id: String,
    pub provider_type: CredentialProviderType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    pub default_scopes: Vec<String>,
    pub token_refresh_enabled: bool,
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// The origin of `resource`, for a provider with an issuer: the only origin
    /// its grants are sent to, so a connect page can show the person where.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_identity_strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_signing_algorithm: Option<JwtSigningAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_unadvertised_pkce: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&CredentialProvider> for CredentialProviderListItem {
    fn from(p: &CredentialProvider) -> Self {
        Self {
            id: p.id.clone(),
            tenant_id: p.tenant_id.clone(),
            name: p.name.clone(),
            provider_id: p.provider_id.clone(),
            provider_type: p.provider_type.clone(),
            authorization_endpoint: p
                .authorization_endpoint
                .clone(),
            token_endpoint: p.token_endpoint.clone(),
            default_scopes: p.default_scopes.clone(),
            token_refresh_enabled: p.token_refresh_enabled,
            description: p.description.clone(),
            callback_url: p.callback_url.clone(),
            resource: p.resource.clone(),
            resource_origin: p
                .is_external_consent()
                .then(|| external::resource_origin(p))
                .flatten(),
            consent_identity_strategy_id: p
                .consent_identity_strategy_id
                .clone(),
            jwt_signing_algorithm: p.jwt.jwt_signing_algorithm,
            jwt_audience: p.jwt.jwt_audience.clone(),
            jwt_key_id: p.jwt.jwt_key_id.clone(),
            jwt_issuer: p.jwt.jwt_issuer.clone(),
            jwt_subject: p.jwt.jwt_subject.clone(),
            issuer: p.issuer.clone(),
            revocation_endpoint: p.revocation_endpoint.clone(),
            token_endpoint_auth_method: p.token_endpoint_auth_method,
            client_id: p.client_id.clone(),
            allow_unadvertised_pkce: p.allow_unadvertised_pkce,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_token_reads_only_the_secrets_its_provider_type_uses() {
        let provider = |provider_type: &str, certificate: Option<&str>| -> CredentialProvider {
            serde_json::from_value(serde_json::json!({
                "id": "p", "name": "p", "provider_id": "p", "provider_type": provider_type,
                "client_id_secret_ref": "ID", "client_secret_secret_ref": "SECRET", "api_key_secret_ref": "KEY",
                "jwt_signing_key_secret_ref": "SIGNING", "jwt_certificate_secret_ref": certificate,
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap()
        };
        for (provider_type, certificate, expected) in [
            ("api_key", Some("CERT"), vec!["KEY"]),
            ("oauth2_client_credentials", Some("CERT"), vec!["ID", "SECRET"]),
            ("oauth2_jwt_bearer", Some("CERT"), vec!["SIGNING", "CERT"]),
            ("oauth2_jwt_bearer", None, vec!["SIGNING"]),
            ("oauth2_client_credentials_jwt_auth", Some("CERT"), vec!["ID", "SIGNING", "CERT"]),
            ("oauth2_authorization_code", Some("CERT"), vec![]),
        ] {
            let provider = provider(provider_type, certificate);
            assert_eq!(provider.service_token_secret_refs(), expected, "{provider_type}");
            assert_eq!(provider.secret_refs().len(), 4 + usize::from(certificate.is_some()), "{provider_type}");
        }
    }

    #[test]
    fn an_external_provider_uses_its_own_tenants_secrets_only_and_any_other_may_also_use_untenanted_ones() {
        let provider = |tenant: Option<&str>, issuer: Option<&str>| -> CredentialProvider {
            serde_json::from_value(serde_json::json!({
                "id": "p", "name": "p", "provider_id": "p", "provider_type": "api_key",
                "api_key_secret_ref": "KEY", "tenant_id": tenant, "issuer": issuer,
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap()
        };
        let issuer = Some("https://issuer.example");

        let external = provider(Some("tenant-a"), issuer);
        assert!(external.may_use_secret(Some("tenant-a")));
        assert!(!external.may_use_secret(None));
        assert!(!external.may_use_secret(Some("tenant-b")));

        let untenanted_external = provider(None, issuer);
        assert!(untenanted_external.may_use_secret(None));
        assert!(!untenanted_external.may_use_secret(Some("tenant-a")));

        let tenant = provider(Some("tenant-a"), None);
        assert!(tenant.may_use_secret(Some("tenant-a")));
        assert!(tenant.may_use_secret(None));
        assert!(!tenant.may_use_secret(Some("tenant-b")));

        let untenanted = provider(None, None);
        assert!(untenanted.may_use_secret(None));
        assert!(!untenanted.may_use_secret(Some("tenant-a")));
    }

    #[test]
    fn a_reference_is_kept_only_in_its_own_field_while_the_destination_is_unchanged() {
        let stored: CredentialProvider = serde_json::from_value(serde_json::json!({
            "id": "p", "name": "p", "provider_id": "p", "provider_type": "oauth2_jwt_bearer",
            "token_endpoint": "https://idp.example/token", "jwt_signing_key_secret_ref": "KEY",
            "jwt_certificate_secret_ref": "CERT", "jwt_issuer": "iss", "jwt_subject": "sub",
            "jwt_audience": "https://idp.example/token",
            "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
        }))
        .unwrap();

        assert_eq!(stored.secret_refs_kept_from(None), vec![("KEY", false), ("CERT", false)]);
        let mut renamed = stored.clone();
        renamed.name = "renamed".into();
        renamed.jwt.jwt_key_id = Some("kid".into());
        assert_eq!(renamed.secret_refs_kept_from(Some(&stored)), vec![("KEY", true), ("CERT", true)]);

        let mut swapped = stored.clone();
        swapped
            .jwt
            .jwt_signing_key_secret_ref = Some("CERT".into());
        swapped
            .jwt
            .jwt_certificate_secret_ref = Some("KEY".into());
        assert_eq!(swapped.secret_refs_kept_from(Some(&stored)), vec![("CERT", false), ("KEY", false)]);

        let redirected: [fn(&mut CredentialProvider); 9] = [
            |p| p.provider_type = CredentialProviderType::OAuth2ClientCredentialsJwtAuth,
            |p| p.token_endpoint = Some("https://tenant.example/token".into()),
            |p| p.authorization_endpoint = Some("https://tenant.example/authorize".into()),
            |p| p.resource = Some("https://tenant.example/".into()),
            |p| {
                p.additional_params
                    .insert("audience".into(), "tenant".into());
            },
            |p| p.jwt.jwt_issuer = Some("tenant".into()),
            |p| p.jwt.jwt_subject = None,
            |p| p.jwt.jwt_audience = Some("https://tenant.example/token".into()),
            |p| p.default_scopes = vec!["admin".into()],
        ];
        for change in redirected {
            let mut changed = stored.clone();
            change(&mut changed);
            assert_eq!(changed.secret_refs_kept_from(Some(&stored)), vec![("KEY", false), ("CERT", false)]);
        }
    }

    #[test]
    fn a_provider_is_usable_by_a_surface_according_to_type_tenant_and_mode() {
        use crate::config::credential_policy::RuleMode::{Enforce, Warn};
        use crate::tenancy::SurfaceTenancy;

        let types = [
            (CredentialProviderType::OAuth2AuthorizationCode, false),
            (CredentialProviderType::OAuth2ClientCredentials, true),
            (CredentialProviderType::OAuth2ClientCredentialsJwtAuth, true),
            (CredentialProviderType::OAuth2JwtBearer, true),
            (CredentialProviderType::ApiKey, true),
        ];
        for (provider_type, sends_gateway_credential) in types {
            assert_eq!(provider_type.sends_gateway_credential(), sends_gateway_credential, "{provider_type:?}");
            let provider = |tenant: Option<&str>| {
                let mut provider = make_provider("p", "p");
                provider.provider_type = provider_type.clone();
                provider.tenant_id = tenant.map(String::from);
                provider
            };
            for mode in [Warn, Enforce] {
                let surface = |tenant: Option<&'static str>| SurfaceTenancy { tenant_id: tenant, mode };
                assert!(provider(Some("a")).usable_by(surface(Some("a"))));
                assert!(!provider(Some("b")).usable_by(surface(Some("a"))));
                assert!(!provider(Some("a")).usable_by(surface(None)));
                assert!(provider(None).usable_by(surface(None)));
            }
            let wide = provider(None);
            assert!(wide.usable_by(SurfaceTenancy {
                tenant_id: Some("a"),
                mode: Warn
            }));
            assert_eq!(
                wide.usable_by(SurfaceTenancy {
                    tenant_id: Some("a"),
                    mode: Enforce
                }),
                !sends_gateway_credential,
                "{provider_type:?}"
            );
            assert_eq!(wide.breaks_tenant_isolation_for(Some("a")), sends_gateway_credential);
            assert!(!wide.breaks_tenant_isolation_for(None));
        }
    }

    #[test]
    fn a_provider_uses_a_secret_outside_its_tenant_only_when_a_secret_it_names_lies_elsewhere() {
        let secret_tenants: std::collections::HashMap<&str, Option<&str>> =
            [("WIDE", None), ("OWN", Some("a")), ("OTHER", Some("b"))]
                .into_iter()
                .collect();
        let provider = |tenant: Option<&str>, client_secret: &str| {
            let mut provider = make_provider("p", "p");
            provider.tenant_id = tenant.map(String::from);
            provider.client_secret_secret_ref = Some(client_secret.into());
            provider
        };
        assert!(provider(Some("a"), "WIDE").uses_secret_outside_tenant(&secret_tenants));
        assert!(provider(Some("a"), "OTHER").uses_secret_outside_tenant(&secret_tenants));
        assert!(provider(None, "OWN").uses_secret_outside_tenant(&secret_tenants));
        assert!(!provider(Some("a"), "OWN").uses_secret_outside_tenant(&secret_tenants));
        assert!(!provider(None, "WIDE").uses_secret_outside_tenant(&secret_tenants));
        assert!(!provider(Some("a"), "GONE").uses_secret_outside_tenant(&secret_tenants));
    }

    #[test]
    fn a_secret_is_outside_a_provider_tenant_unless_both_name_the_same_one() {
        let mut provider = make_provider("p", "p");
        assert!(!provider.secret_is_outside_tenant(None));
        assert!(provider.secret_is_outside_tenant(Some("a")));
        provider.tenant_id = Some("a".into());
        assert!(!provider.secret_is_outside_tenant(Some("a")));
        assert!(provider.secret_is_outside_tenant(Some("b")));
        assert!(provider.secret_is_outside_tenant(None));
    }

    fn make_provider(
        name: &str,
        provider_id: &str,
    ) -> CredentialProvider {
        let now = Utc::now();
        CredentialProvider {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: None,
            name: name.to_string(),
            provider_id: provider_id.to_string(),
            provider_type: CredentialProviderType::OAuth2AuthorizationCode,
            authorization_endpoint: Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            token_endpoint: Some("https://oauth2.googleapis.com/token".to_string()),
            client_id_secret_ref: Some("GOOGLE_CLIENT_ID".to_string()),
            client_secret_secret_ref: Some("GOOGLE_CLIENT_SECRET".to_string()),
            default_scopes: vec!["openid".to_string(), "email".to_string()],
            callback_path: format!("/oauth/callback/{}", provider_id),
            token_refresh_enabled: true,
            additional_params: HashMap::new(),
            api_key_secret_ref: None,
            jwt: Default::default(),
            description: Some("Test provider".to_string()),
            created_at: now,
            updated_at: now,
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
            issuer: None,
            revocation_endpoint: None,
            token_endpoint_auth_method: None,
            client_id: None,
            allow_unadvertised_pkce: false,
        }
    }

    #[test]
    fn test_storable_entity_id() {
        let provider = make_provider("Google", "google");
        assert_eq!(provider.id(), provider.id.as_str());
    }

    #[test]
    fn test_credential_provider_serialization_roundtrip() {
        let provider = make_provider("GitHub", "github");
        let json = serde_json::to_string(&provider).unwrap();
        let deserialized: CredentialProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "GitHub");
        assert_eq!(deserialized.provider_id, "github");
        assert_eq!(deserialized.provider_type, CredentialProviderType::OAuth2AuthorizationCode);
        assert_eq!(deserialized.default_scopes, vec!["openid", "email"]);
        assert!(deserialized.token_refresh_enabled);
    }

    #[test]
    fn test_provider_type_default() {
        let pt: CredentialProviderType = Default::default();
        assert_eq!(pt, CredentialProviderType::OAuth2AuthorizationCode);
    }

    #[test]
    fn test_list_item_from_provider() {
        let provider = make_provider("GitHub", "github");
        let list_item = CredentialProviderListItem::from(&provider);
        assert_eq!(list_item.id, provider.id);
        assert_eq!(list_item.name, "GitHub");
        assert_eq!(list_item.provider_id, "github");
        // Secret refs should NOT be in list item
        let json = serde_json::to_string(&list_item).unwrap();
        assert!(!json.contains("client_id_secret_ref"));
        assert!(!json.contains("client_secret_secret_ref"));
    }

    #[test]
    fn test_create_request_deserialization() {
        let json = r#"{
            "name": "GitHub",
            "provider_id": "github",
            "token_endpoint": "https://github.com/login/oauth/access_token",
            "client_id_secret_ref": "GH_ID",
            "client_secret_secret_ref": "GH_SECRET",
            "default_scopes": ["repo", "read:user"]
        }"#;
        let req: CreateCredentialProviderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "GitHub");
        assert_eq!(req.provider_type, CredentialProviderType::OAuth2AuthorizationCode);
        assert_eq!(req.default_scopes, vec!["repo", "read:user"]);
        assert!(req.token_refresh_enabled);
    }

    #[test]
    fn test_client_credentials_type() {
        let json = r#"{
            "name": "Service Account",
            "provider_id": "service-account",
            "provider_type": "oauth2_client_credentials",
            "token_endpoint": "https://auth.example.com/token",
            "client_id_secret_ref": "SA_ID",
            "client_secret_secret_ref": "SA_SECRET"
        }"#;
        let req: CreateCredentialProviderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.provider_type, CredentialProviderType::OAuth2ClientCredentials);
    }

    #[test]
    fn test_callback_path_format() {
        let provider = make_provider("GitHub", "github");
        assert_eq!(provider.callback_path, "/oauth/callback/github");
    }

    #[test]
    fn test_api_key_type_deserialization() {
        let json = r#"{
            "name": "External Service",
            "provider_id": "ext-svc",
            "provider_type": "api_key",
            "api_key_secret_ref": "EXT_API_KEY"
        }"#;
        let req: CreateCredentialProviderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.provider_type, CredentialProviderType::ApiKey);
        assert_eq!(
            req.api_key_secret_ref
                .as_deref(),
            Some("EXT_API_KEY")
        );
        assert!(req.token_endpoint.is_none());
        assert!(
            req.client_id_secret_ref
                .is_none()
        );
        assert!(
            req.client_secret_secret_ref
                .is_none()
        );
    }

    #[test]
    fn test_api_key_provider_no_oauth_fields() {
        let now = Utc::now();
        let provider = CredentialProvider {
            id: "cp-api".to_string(),
            tenant_id: None,
            name: "API Key Provider".to_string(),
            provider_id: "api-svc".to_string(),
            provider_type: CredentialProviderType::ApiKey,
            authorization_endpoint: None,
            token_endpoint: None,
            client_id_secret_ref: None,
            client_secret_secret_ref: None,
            default_scopes: vec![],
            callback_path: "/oauth/callback/api-svc".to_string(),
            token_refresh_enabled: false,
            additional_params: HashMap::new(),
            api_key_secret_ref: Some("MY_API_KEY".to_string()),
            jwt: Default::default(),
            description: None,
            created_at: now,
            updated_at: now,
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
            issuer: None,
            revocation_endpoint: None,
            token_endpoint_auth_method: None,
            client_id: None,
            allow_unadvertised_pkce: false,
        };
        let json = serde_json::to_string(&provider).unwrap();
        assert!(json.contains("api_key"));
        assert!(json.contains("MY_API_KEY"));
    }

    #[test]
    fn test_provider_type_default_is_authorization_code() {
        assert_eq!(CredentialProviderType::default(), CredentialProviderType::OAuth2AuthorizationCode);
    }

    #[test]
    fn jwt_bearer_provider_round_trips_its_signed_jwt_settings() {
        let json = r#"{
            "id": "cp-vertex", "name": "Vertex", "provider_id": "vertex",
            "provider_type": "oauth2_jwt_bearer",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwt_signing_key_secret_ref": "VERTEX_SA_KEY",
            "jwt_signing_algorithm": "ES256",
            "jwt_audience": "https://oauth2.googleapis.com/token",
            "jwt_key_id": "key-1",
            "jwt_issuer": "agent@project.iam.gserviceaccount.com",
            "jwt_subject": "user@example.com",
            "default_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
        }"#;
        let provider: CredentialProvider = serde_json::from_str(json).unwrap();
        assert_eq!(provider.provider_type, CredentialProviderType::OAuth2JwtBearer);
        assert_eq!(
            provider.jwt,
            JwtAssertionSettings {
                jwt_signing_key_secret_ref: Some("VERTEX_SA_KEY".into()),
                jwt_certificate_secret_ref: None,
                jwt_signing_algorithm: Some(JwtSigningAlgorithm::ES256),
                jwt_audience: Some("https://oauth2.googleapis.com/token".into()),
                jwt_key_id: Some("key-1".into()),
                jwt_issuer: Some("agent@project.iam.gserviceaccount.com".into()),
                jwt_subject: Some("user@example.com".into()),
            }
        );
        let value = serde_json::to_value(&provider).unwrap();
        assert_eq!(value["provider_type"], "oauth2_jwt_bearer");
        assert_eq!(value["jwt_signing_key_secret_ref"], "VERTEX_SA_KEY");
        assert_eq!(value["jwt_signing_algorithm"], "ES256");
        assert!(value.get("jwt").is_none());
        assert!(
            value
                .get("jwt_certificate_secret_ref")
                .is_none()
        );
        let again: CredentialProvider = serde_json::from_value(value).unwrap();
        assert_eq!(again.jwt, provider.jwt);
    }

    #[test]
    fn client_credentials_jwt_auth_request_reads_its_certificate_reference() {
        let json = r#"{
            "name": "Foundry", "provider_id": "foundry",
            "provider_type": "oauth2_client_credentials_jwt_auth",
            "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "client_id_secret_ref": "FOUNDRY_CLIENT_ID",
            "jwt_signing_key_secret_ref": "FOUNDRY_KEY",
            "jwt_certificate_secret_ref": "FOUNDRY_CERT",
            "jwt_signing_algorithm": "PS256"
        }"#;
        let request: CreateCredentialProviderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.provider_type, CredentialProviderType::OAuth2ClientCredentialsJwtAuth);
        assert_eq!(
            request
                .jwt
                .jwt_certificate_secret_ref
                .as_deref(),
            Some("FOUNDRY_CERT")
        );
        assert_eq!(
            request
                .jwt
                .jwt_signing_algorithm,
            Some(JwtSigningAlgorithm::PS256)
        );
        let update: UpdateCredentialProviderRequest =
            serde_json::from_str(r#"{"jwt_key_id": "thumb", "jwt_signing_algorithm": "RS256"}"#).unwrap();
        assert_eq!(
            update
                .jwt
                .jwt_key_id
                .as_deref(),
            Some("thumb")
        );
        assert_eq!(
            update
                .jwt
                .jwt_signing_algorithm,
            Some(JwtSigningAlgorithm::RS256)
        );
        assert!(
            serde_json::from_str::<UpdateCredentialProviderRequest>(r#"{"jwt_signing_algorithm": "HS256"}"#).is_err()
        );
    }

    #[test]
    fn list_item_shows_jwt_settings_but_never_the_key_or_certificate_reference() {
        let mut provider = make_provider("Vertex", "vertex");
        provider.provider_type = CredentialProviderType::OAuth2JwtBearer;
        provider.jwt = JwtAssertionSettings {
            jwt_signing_key_secret_ref: Some("KEY_REF_MARKER".into()),
            jwt_certificate_secret_ref: Some("CERT_REF_MARKER".into()),
            jwt_signing_algorithm: Some(JwtSigningAlgorithm::RS256),
            jwt_audience: Some("https://aud.example".into()),
            jwt_key_id: Some("kid-1".into()),
            jwt_issuer: Some("sa@example.iam".into()),
            jwt_subject: Some("user@example.com".into()),
        };
        let item = serde_json::to_value(CredentialProviderListItem::from(&provider)).unwrap();
        assert_eq!(item["provider_type"], "oauth2_jwt_bearer");
        assert_eq!(item["jwt_signing_algorithm"], "RS256");
        assert_eq!(item["jwt_audience"], "https://aud.example");
        assert_eq!(item["jwt_key_id"], "kid-1");
        assert_eq!(item["jwt_issuer"], "sa@example.iam");
        assert_eq!(item["jwt_subject"], "user@example.com");
        let text = item.to_string();
        assert!(!text.contains("KEY_REF_MARKER"));
        assert!(!text.contains("CERT_REF_MARKER"));
    }

    #[test]
    fn jwt_settings_merge_onto_existing_and_blank_values_clear_them() {
        let existing = JwtAssertionSettings {
            jwt_signing_key_secret_ref: Some("OLD_KEY".into()),
            jwt_issuer: Some("old@example".into()),
            jwt_key_id: Some("old-kid".into()),
            ..Default::default()
        };
        let update = JwtAssertionSettings {
            jwt_issuer: Some(" new@example ".into()),
            jwt_key_id: Some("  ".into()),
            ..Default::default()
        };
        let merged = update
            .or(existing)
            .normalized();
        assert_eq!(
            merged
                .jwt_signing_key_secret_ref
                .as_deref(),
            Some("OLD_KEY")
        );
        assert_eq!(merged.jwt_issuer.as_deref(), Some("new@example"));
        assert_eq!(merged.jwt_key_id, None);
    }

    #[test]
    fn jwt_algorithms_follow_the_provider_type() {
        use CredentialProviderType::*;
        use JwtSigningAlgorithm::*;
        assert_eq!(OAuth2JwtBearer.default_jwt_algorithm(), Some(RS256));
        assert_eq!(OAuth2ClientCredentialsJwtAuth.default_jwt_algorithm(), Some(PS256));
        assert_eq!(OAuth2ClientCredentials.default_jwt_algorithm(), None);
        assert!(OAuth2JwtBearer.allows_jwt_algorithm(RS256));
        assert!(OAuth2JwtBearer.allows_jwt_algorithm(ES256));
        assert!(!OAuth2JwtBearer.allows_jwt_algorithm(PS256));
        assert!(OAuth2ClientCredentialsJwtAuth.allows_jwt_algorithm(PS256));
        assert!(OAuth2ClientCredentialsJwtAuth.allows_jwt_algorithm(RS256));
        assert!(!OAuth2ClientCredentialsJwtAuth.allows_jwt_algorithm(ES256));
        assert!(!ApiKey.allows_jwt_algorithm(RS256));
    }

    #[test]
    fn test_client_credentials_no_authorization_endpoint() {
        let json = r#"{
            "name": "M2M Service",
            "provider_id": "m2m",
            "provider_type": "oauth2_client_credentials",
            "token_endpoint": "https://auth.example.com/token",
            "client_id_secret_ref": "M2M_ID",
            "client_secret_secret_ref": "M2M_SECRET"
        }"#;
        let req: CreateCredentialProviderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.provider_type, CredentialProviderType::OAuth2ClientCredentials);
        assert!(
            req.authorization_endpoint
                .is_none()
        );
        assert_eq!(req.token_endpoint.as_deref(), Some("https://auth.example.com/token"));
    }
}
