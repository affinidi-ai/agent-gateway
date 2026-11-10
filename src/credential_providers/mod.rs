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
pub mod references;
pub mod router;
pub mod scope_comparison;
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

/// How the client of an `oauth2_jwt_bearer` grant identifies itself to the token endpoint
/// (RFC 6749 section 2.3). A provider that sets no client authentication sends no client
/// identity with its grant, as a Google service account does. `Unset` is what an empty string
/// in a request means: it clears the stored setting and is never stored. It is separate from
/// [`TokenEndpointAuthMethod`], which an external consent provider's metadata names and which
/// includes `private_key_jwt`: a JWT Bearer grant's client never signs a second JWT, and this
/// setting needs the empty string that clears it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrantClientAuthentication {
    #[serde(rename = "")]
    Unset,
    /// A public client: its `client_id` in the form body, no secret.
    #[serde(rename = "none")]
    PublicClient,
    /// HTTP Basic with the client id and secret.
    #[serde(rename = "client_secret_basic")]
    ClientSecretBasic,
    /// The client id and secret in the form body.
    #[serde(rename = "client_secret_post")]
    ClientSecretPost,
}

impl GrantClientAuthentication {
    /// The method's name in a request, empty for `Unset`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unset => "",
            Self::PublicClient => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }

    /// Whether the client authenticates with a secret.
    pub fn uses_secret(self) -> bool {
        matches!(self, Self::ClientSecretBasic | Self::ClientSecretPost)
    }
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
    /// `sub` claim of a JWT Bearer grant: required for a JWT Bearer provider (domain-wide delegation)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_subject: Option<String>,
    /// How the client of a JWT Bearer grant identifies itself; unset sends no client identity
    /// and leaves the client references unread. `oauth2_jwt_bearer` only, cleared by an empty
    /// string in an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_authentication: Option<GrantClientAuthentication>,
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
            client_authentication: self
                .client_authentication
                .or(existing.client_authentication),
        }
    }

    /// The client authentication these settings set, `None` when they set none.
    pub fn client_authentication_method(&self) -> Option<GrantClientAuthentication> {
        self.client_authentication
            .filter(|method| *method != GrantClientAuthentication::Unset)
    }

    /// Does a provider of `provider_type` need a `jwt_subject` these settings leave blank?
    /// Only a JWT Bearer grant does: its assertion names the subject the token is for.
    pub fn lacks_subject_for(
        &self,
        provider_type: &CredentialProviderType,
    ) -> bool {
        *provider_type == CredentialProviderType::OAuth2JwtBearer
            && self
                .jwt_subject
                .as_deref()
                .is_none_or(|subject| subject.trim().is_empty())
    }

    /// The same settings with blank values removed and the rest trimmed, so a field
    /// sent empty clears it.
    pub fn normalized(self) -> Self {
        fn clean(value: Option<String>) -> Option<String> {
            value
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        }
        let client_authentication = self.client_authentication_method();
        Self {
            jwt_signing_key_secret_ref: clean(self.jwt_signing_key_secret_ref),
            jwt_certificate_secret_ref: clean(self.jwt_certificate_secret_ref),
            jwt_signing_algorithm: self.jwt_signing_algorithm,
            jwt_audience: clean(self.jwt_audience),
            jwt_key_id: clean(self.jwt_key_id),
            jwt_issuer: clean(self.jwt_issuer),
            jwt_subject: clean(self.jwt_subject),
            client_authentication,
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

/// The gateway's login client at the callers' identity provider, with which a
/// legacy consent provider confirms the person at the consent start before
/// sending them to the vendor. The ID token it gets is verified by
/// `jwt_verification_strategy_id`, and names the caller by
/// `id_token_principal_claim`, or by that strategy's principal claim when unset.
///
/// The caller's vault key hashes a principal value under the strategy's own
/// principal claim name, and its confirmation is recomputed under that same
/// name: `id_token_principal_claim` only chooses which ID-token claim supplies
/// the value, never the name the value is hashed under.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentConfirmation {
    /// The login client's id, a plain value: a client id is not a secret.
    pub client_id: String,
    /// Secret ID for the login client's secret.
    pub client_secret_secret_ref: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwt_verification_strategy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_principal_claim: Option<String>,
}

/// The path the identity provider redirects back to after a consent
/// confirmation sign-in, appended to the provider's redirect URI.
pub const CONSENT_CONFIRMATION_PATH: &str = "/confirm";

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

    /// Auto-generated callback path for authorization code flow:
    /// `{oauth_callback_route}/{id}`, or `{oauth_callback_route}/{provider_id}`
    /// for a provider created before paths ended in its id.
    #[serde(default)]
    pub callback_path: String,

    /// Full callback URL including host, ending in `callback_path` (e.g.
    /// "https://gw.example.com/v1/identity/oauth/callback/{id}").
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

    /// Whether the issuer's metadata says its authorization responses carry
    /// `iss` (RFC 9207), recorded from the metadata when an external consent
    /// provider is created and never set by a request: a connect completed
    /// without `iss` is then refused. `None` for a provider created before it
    /// was recorded, whose connects need `iss` as well, since nothing says its
    /// issuer omits it: recreate such a provider for an issuer that does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,

    /// The `iss` (RFC 9207) the authorization server of an authorization code
    /// provider without an `issuer` puts on its authorization responses, set by
    /// the operator. When set, a consent callback without this exact `iss` is
    /// refused; when unset, `iss` is ignored. It does not make the provider an
    /// external consent provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_response_issuer: Option<String>,

    /// How the scopes an external consent provider's token endpoint grants are
    /// compared with those asked for: exactly by default. An external consent
    /// provider only, fixed for its life.
    #[serde(default, skip_serializing_if = "scope_comparison::ScopeComparison::is_exact")]
    pub scope_comparison: scope_comparison::ScopeComparison,

    /// Whether revoking any one token at the provider's revocation endpoint
    /// ends the whole authorization of the person and the client, every
    /// other grant of theirs included, as Google's does. The gateway then
    /// revokes no grant while the same person holds another grant of the
    /// provider: it would end that one too. Unset, every grant removed is
    /// revoked. An external consent provider only, fixed for its life.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revocation_ends_authorization: bool,

    /// Whether an external consent provider's code exchange and refresh send
    /// its `resource` (RFC 8707) to the token endpoint. Off for a token
    /// endpoint that refuses the parameter, such as the Microsoft identity
    /// platform v2.0 one; the resource still decides where the grants may
    /// go. An external consent provider only, fixed for its life.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub send_resource: bool,

    /// Confirms the person at their identity provider before the vendor. An
    /// authorization code provider without an `issuer` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_confirmation: Option<ConsentConfirmation>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

impl StorableEntity for CredentialProvider {
    fn id(&self) -> &str {
        &self.id
    }
}

impl CredentialProvider {
    /// The secret ids this provider reads: client, API key, signing key, certificate and
    /// consent confirmation client secret.
    pub fn secret_refs(&self) -> Vec<&str> {
        self.secret_ref_fields()
            .into_iter()
            .chain([self.consent_confirmation_secret_ref()])
            .flatten()
            .collect()
    }

    fn consent_confirmation_secret_ref(&self) -> Option<&str> {
        self.consent_confirmation
            .as_ref()
            .map(|confirmation| {
                confirmation
                    .client_secret_secret_ref
                    .as_str()
            })
    }

    /// The secret ids a service token of this provider's type reads: the API key; the client
    /// ID and secret; a JWT Bearer grant's signing key and certificate, preceded by the client
    /// ID, and the client secret too when its client authentication uses one; or the client ID,
    /// signing key and certificate of a client authenticating with a JWT. A reference left
    /// from another type, or a client reference of a JWT Bearer provider that sets no client
    /// authentication, is not among them, and an authorization code provider issues no service
    /// token.
    pub fn service_token_secret_refs(&self) -> Vec<&str> {
        let [client_id, client_secret, api_key, signing_key, certificate] = self.secret_ref_fields();
        match self.provider_type {
            CredentialProviderType::ApiKey => vec![api_key],
            CredentialProviderType::OAuth2ClientCredentials => vec![client_id, client_secret],
            CredentialProviderType::OAuth2JwtBearer => match self
                .jwt
                .client_authentication_method()
            {
                None => vec![signing_key, certificate],
                Some(method) if method.uses_secret() => vec![client_id, client_secret, signing_key, certificate],
                Some(_) => vec![client_id, signing_key, certificate],
            },
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
    /// authorization endpoints, resource, additional parameters, default scopes, JWT issuer,
    /// subject and audience, and client authentication. The consent confirmation client
    /// secret is never kept.
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
                    && self
                        .jwt
                        .client_authentication_method()
                        == previous
                            .jwt
                            .client_authentication_method()
            })
            .map(Self::secret_ref_fields)
            .unwrap_or_default();
        self.secret_ref_fields()
            .into_iter()
            .zip(stored)
            .filter_map(|(reference, stored)| reference.map(|reference| (reference, stored == Some(reference))))
            .chain(
                self.consent_confirmation_secret_ref()
                    .map(|reference| (reference, false)),
            )
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

    /// Is this a JWT Bearer provider without a `jwt_subject`? A save refuses one; a stored
    /// one still signs its grant without `sub`.
    pub fn lacks_jwt_subject(&self) -> bool {
        self.jwt
            .lacks_subject_for(&self.provider_type)
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

    /// Whether a person grants this provider's credential through the gateway's
    /// consent start page and OAuth callback: an authorization code provider
    /// without an `issuer`.
    pub fn uses_legacy_consent(&self) -> bool {
        self.provider_type == CredentialProviderType::OAuth2AuthorizationCode && self.issuer.is_none()
    }

    /// The redirect URI of the gateway's consent flow: `callback_url`, or
    /// `gateway_base_url` followed by `callback_path`.
    pub fn redirect_uri(
        &self,
        gateway_base_url: &str,
    ) -> String {
        self.callback_url
            .clone()
            .unwrap_or_else(|| format!("{gateway_base_url}{}", self.callback_path))
    }

    /// The redirect URI of the consent confirmation sign-in: the redirect URI
    /// followed by [`CONSENT_CONFIRMATION_PATH`].
    pub fn consent_confirmation_redirect_uri(
        &self,
        gateway_base_url: &str,
    ) -> String {
        format!("{}{CONSENT_CONFIRMATION_PATH}", self.redirect_uri(gateway_base_url))
    }

    /// The redirect URIs this provider's consent flow answers on: its redirect
    /// URI, and its confirmation redirect URI while it has
    /// `consent_confirmation`.
    fn consent_redirect_uris(
        &self,
        gateway_base_url: &str,
    ) -> Vec<url::Url> {
        let confirmation = self
            .consent_confirmation
            .is_some()
            .then(|| self.consent_confirmation_redirect_uri(gateway_base_url));
        [Some(self.redirect_uri(gateway_base_url)), confirmation]
            .into_iter()
            .flatten()
            .filter_map(|uri| url::Url::parse(&uri).ok())
            .collect()
    }

    /// Whether this provider and `other` answer on a redirect URI in common.
    fn shares_redirect_uri_with(
        &self,
        other: &Self,
        gateway_base_url: &str,
    ) -> bool {
        let others = other.consent_redirect_uris(gateway_base_url);
        self.consent_redirect_uris(gateway_base_url)
            .iter()
            .any(|uri| others.contains(uri))
    }

    /// The redirect URI parsed, when it is one the consent flow may use: an
    /// https URL with a host and no credentials, query or fragment, whose path
    /// ends in `callback_path`, the path the callback route answers on.
    pub fn consent_redirect_uri(
        &self,
        gateway_base_url: &str,
    ) -> Result<url::Url, &'static str> {
        let url = url::Url::parse(&self.redirect_uri(gateway_base_url))
            .map_err(|_| "callback_url must be an https URL with a host")?;
        if !crate::url_validation::is_https_or_bdd_allowed(&url) || url.host().is_none() {
            return Err("callback_url must be an https URL with a host");
        }
        if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            return Err("callback_url must not carry credentials, a query or a fragment");
        }
        if self.callback_path.is_empty()
            || !url
                .path()
                .ends_with(&self.callback_path)
        {
            return Err("callback_url path must end in the provider's callback_path");
        }
        Ok(url)
    }

    /// The authorization endpoint parsed, when the consent flow may build the
    /// vendor's authorization URL from it: an https URL with a host and no
    /// credentials or fragment, whose query and `additional_params` together
    /// hold at most 32 parameters, none reserved or repeated, with names of at
    /// most 128 bytes and values of at most 2048.
    pub fn consent_authorization_endpoint(&self) -> Result<url::Url, &'static str> {
        let url = self
            .authorization_endpoint
            .as_deref()
            .and_then(|endpoint| url::Url::parse(endpoint).ok())
            .ok_or("authorization_endpoint must be an https URL with a host")?;
        if !crate::url_validation::is_https_or_bdd_allowed(&url)
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err("authorization_endpoint must be an https URL with a host and no credentials or fragment");
        }
        let endpoint_params: Vec<_> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let mut names = std::collections::HashSet::new();
        for (count, (name, value)) in endpoint_params
            .iter()
            .map(|(name, value)| (name, value))
            .chain(&self.additional_params)
            .enumerate()
        {
            if count >= MAX_AUTHORIZATION_PARAMS
                || RESERVED_AUTHORIZATION_PARAMS.contains(&name.as_str())
                || name.len() > 128
                || value.len() > 2048
                || !names.insert(name.as_str())
            {
                return Err(
                    "authorization_endpoint query and additional_params must not repeat a reserved or duplicate \
                     parameter or exceed the limits",
                );
            }
        }
        Ok(url)
    }

    /// Why `authorization_response_issuer` may not be stored on this provider:
    /// only an authorization code provider without an `issuer` takes it, and
    /// only as an https URL with a host and no credentials, query or fragment.
    pub fn authorization_response_issuer_error(&self) -> Option<&'static str> {
        let issuer = self
            .authorization_response_issuer
            .as_deref()?;
        if !self.uses_legacy_consent() {
            return Some(
                "authorization_response_issuer is allowed only on an oauth2_authorization_code provider without issuer",
            );
        }
        let valid = url::Url::parse(issuer).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        });
        (!valid).then_some("authorization_response_issuer must be an https URL with a host and no query or fragment")
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

/// The authorization request parameters the gateway sets itself, which neither
/// the endpoint's own query nor `additional_params` may repeat.
const RESERVED_AUTHORIZATION_PARAMS: [&str; 7] =
    ["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"];

/// How many parameters the endpoint's query and `additional_params` may hold together.
const MAX_AUTHORIZATION_PARAMS: usize = 32;

/// Another consent-flow provider, of any tenant, that answers on one of
/// `provider`'s redirect URIs: its redirect URI, or the confirmation redirect
/// URI of a provider with `consent_confirmation`. Each redirect URI names one
/// provider, so the redirect identifies it.
pub async fn redirect_uri_taken_by(
    store: &dyn storage::CredentialProviderStorage,
    provider: &CredentialProvider,
    gateway_base_url: &str,
) -> anyhow::Result<Option<CredentialProvider>> {
    Ok(store
        .list()
        .await?
        .into_iter()
        .find(|other| {
            other.id != provider.id
                && other.uses_legacy_consent()
                && provider.shares_redirect_uri_with(other, gateway_base_url)
        }))
}

/// Logs an ERROR for each pair of consent-flow providers that share a redirect
/// URI, naming both by id only, and returns the pairs. Both providers' consent
/// fails closed at the start page until one of them gets another redirect URI.
pub fn log_redirect_uri_conflicts<'provider>(
    providers: &'provider [CredentialProvider],
    gateway_base_url: &str,
) -> Vec<(&'provider str, &'provider str)> {
    let consent_providers: Vec<_> = providers
        .iter()
        .filter(|provider| provider.uses_legacy_consent())
        .collect();
    let mut conflicts = Vec::new();
    for (index, &provider) in consent_providers
        .iter()
        .enumerate()
    {
        let id = provider.id.as_str();
        for &other in &consent_providers[index + 1..] {
            let other_id = other.id.as_str();
            if provider.shares_redirect_uri_with(other, gateway_base_url) {
                tracing::error!(
                    target: "credential_delegation",
                    provider_id = %id,
                    other_provider_id = %other_id,
                    "Two credential providers share a redirect URI, so consent for both is refused; give one a \
                     callback_url on a distinct host, or recreate it, which gives it a callback path of its own"
                );
                conflicts.push((id, other_id));
            }
        }
    }
    conflicts
}

/// Logs an ERROR for each consent-flow provider whose redirect URI or
/// authorization endpoint breaks the consent rules, naming it by id and the
/// rule only, and returns them. Such a provider gets no consent link until it
/// is fixed.
pub fn log_consent_rule_breaches<'provider>(
    providers: &'provider [CredentialProvider],
    gateway_base_url: &str,
) -> Vec<(&'provider str, &'static str)> {
    let breaches: Vec<_> = providers
        .iter()
        .filter(|provider| provider.uses_legacy_consent())
        .filter_map(|provider| {
            provider
                .consent_redirect_uri(gateway_base_url)
                .and_then(|_| provider.consent_authorization_endpoint())
                .err()
                .map(|rule| (provider.id.as_str(), rule))
        })
        .collect();
    for (id, rule) in &breaches {
        tracing::error!(
            target: "credential_delegation",
            provider_id = %id,
            rule = %rule,
            "A credential provider breaks the consent rules, so it gets no consent link until it is fixed"
        );
    }
    breaches
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
    /// Full callback URL (host + path). Refused for an authorization code
    /// provider without an `issuer`, whose `callback_path` is known only once it
    /// is created; an update sets it.
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
    #[serde(default)]
    pub scope_comparison: scope_comparison::ScopeComparison,
    #[serde(default)]
    pub revocation_ends_authorization: bool,
    #[serde(default = "default_true")]
    pub send_resource: bool,
    #[serde(default)]
    pub authorization_response_issuer: Option<String>,
    #[serde(default)]
    pub consent_confirmation: Option<ConsentConfirmation>,
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
    /// Full callback URL (host + path), ending in the stored `callback_path`;
    /// used as the redirect URI in place of the gateway's own URL.
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
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub scope_comparison: Option<scope_comparison::ScopeComparison>,
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub revocation_ends_authorization: Option<bool>,
    /// Never changes a provider: a value other than the stored one is refused.
    #[serde(default)]
    pub send_resource: Option<bool>,
    /// A blank value clears the stored one.
    #[serde(default)]
    pub authorization_response_issuer: Option<String>,
    /// Absent keeps the stored setting, `null` clears it, and a value replaces it.
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub consent_confirmation: Option<Option<ConsentConfirmation>>,
}

/// A field that is present in a request, `null` included.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_authentication: Option<GrantClientAuthentication>,
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
    #[serde(default, skip_serializing_if = "scope_comparison::ScopeComparison::is_exact")]
    pub scope_comparison: scope_comparison::ScopeComparison,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revocation_ends_authorization: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub send_resource: bool,
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
            client_authentication: p
                .jwt
                .client_authentication_method(),
            issuer: p.issuer.clone(),
            revocation_endpoint: p.revocation_endpoint.clone(),
            token_endpoint_auth_method: p.token_endpoint_auth_method,
            client_id: p.client_id.clone(),
            allow_unadvertised_pkce: p.allow_unadvertised_pkce,
            scope_comparison: p.scope_comparison,
            revocation_ends_authorization: p.revocation_ends_authorization,
            send_resource: p.send_resource,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consent_provider(
        id: &str,
        slug: &str,
        callback_url: Option<&str>,
    ) -> CredentialProvider {
        serde_json::from_value(serde_json::json!({
            "id": id, "tenant_id": format!("tenant-of-{id}"), "name": "N", "provider_id": slug,
            "callback_path": format!("/v1/identity/oauth/callback/{slug}"), "callback_url": callback_url,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap()
    }

    fn confirming(mut provider: CredentialProvider) -> CredentialProvider {
        provider.consent_confirmation = Some(ConsentConfirmation {
            client_id: "login-client".into(),
            client_secret_secret_ref: "LOGIN_SECRET".into(),
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            jwt_verification_strategy_id: "strategy".into(),
            id_token_principal_claim: None,
        });
        provider
    }

    /// A provider with `consent_confirmation` also answers on its redirect URI
    /// followed by `/confirm`, so another provider whose redirect URI is that
    /// one shares a redirect URI with it, whichever of the two is checked. A
    /// provider without the setting reserves no such URI.
    #[tokio::test]
    async fn a_confirmation_redirect_uri_is_taken_like_a_redirect_uri() {
        let directory = tempfile::tempdir().unwrap();
        let store = storage::FileSystemCredentialProviderStore::new(directory.path().to_path_buf())
            .await
            .unwrap();
        let confirming_one =
            confirming(consent_provider("a", "a", Some("https://gw.example/v1/identity/oauth/callback/a")));
        let at_its_confirmation_uri =
            consent_provider("b", "confirm", Some("https://gw.example/v1/identity/oauth/callback/a/confirm"));
        use storage::CredentialProviderStorage as _;
        store
            .create(confirming_one.clone())
            .await
            .unwrap();
        store
            .create(at_its_confirmation_uri.clone())
            .await
            .unwrap();

        let taken = |provider: CredentialProvider| {
            let store = &store;
            async move {
                redirect_uri_taken_by(store, &provider, "https://gw.example")
                    .await
                    .unwrap()
                    .map(|other| other.id)
            }
        };
        assert_eq!(
            taken(confirming_one.clone())
                .await
                .as_deref(),
            Some("b")
        );
        assert_eq!(
            taken(at_its_confirmation_uri.clone())
                .await
                .as_deref(),
            Some("a")
        );
        assert_eq!(
            log_redirect_uri_conflicts(
                &[confirming_one.clone(), at_its_confirmation_uri.clone()],
                "https://gw.example"
            ),
            [("a", "b")]
        );

        let mut not_confirming = confirming_one;
        not_confirming.consent_confirmation = None;
        store
            .update(not_confirming.clone())
            .await
            .unwrap();
        assert_eq!(taken(not_confirming.clone()).await, None);
        assert_eq!(taken(at_its_confirmation_uri.clone()).await, None);
        assert!(
            log_redirect_uri_conflicts(&[not_confirming, at_its_confirmation_uri], "https://gw.example").is_empty()
        );
    }

    #[test]
    fn an_update_request_tells_an_absent_consent_confirmation_from_null() {
        let parse = |body: &str| {
            serde_json::from_str::<UpdateCredentialProviderRequest>(body)
                .unwrap()
                .consent_confirmation
        };
        assert_eq!(parse("{}"), None);
        assert_eq!(parse(r#"{"consent_confirmation": null}"#), Some(None));
        let absent: UpdateCredentialProviderRequest = serde_json::from_str("{}").unwrap();
        let round_trip = serde_json::to_string(&absent).unwrap();
        assert_eq!(parse(&round_trip), None, "an absent setting stays absent: {round_trip}");
        let cleared: UpdateCredentialProviderRequest =
            serde_json::from_str(r#"{"consent_confirmation": null}"#).unwrap();
        assert_eq!(parse(&serde_json::to_string(&cleared).unwrap()), Some(None));
    }

    /// Each pair of consent providers sharing a redirect URI is logged once as
    /// an ERROR naming both by id, and nothing else about them; providers with
    /// distinct redirect URIs, or outside the consent flow, are not.
    #[test]
    fn shared_redirect_uris_are_logged_as_errors_by_provider_id() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let mut client_credentials = consent_provider("cc", "github", None);
        client_credentials.provider_type = CredentialProviderType::OAuth2ClientCredentials;
        let distinct = [
            consent_provider("a", "github", None),
            consent_provider("b", "github", Some("https://other.example/v1/identity/oauth/callback/github")),
            consent_provider("c", "gitlab", None),
            client_credentials,
        ];
        assert!(log_redirect_uri_conflicts(&distinct, "https://gw.example").is_empty());
        assert!(
            !logs
                .text()
                .contains("redirect URI"),
            "{}",
            logs.text()
        );

        let shared = [
            consent_provider("a", "github", None),
            consent_provider("b", "github", None),
            consent_provider("c", "github", Some("https://gw.example:443/v1/identity/oauth/callback/github")),
            consent_provider("d", "gitlab", None),
        ];
        assert_eq!(log_redirect_uri_conflicts(&shared, "https://gw.example"), [("a", "b"), ("a", "c"), ("b", "c")]);
        let lines: Vec<_> = logs
            .text()
            .lines()
            .filter(|line| line.contains("share a redirect URI"))
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines
                .iter()
                .all(|line| line.contains("ERROR")),
            "{lines:?}"
        );
        assert!(lines[0].contains("provider_id=a") && lines[0].contains("other_provider_id=b"), "{}", lines[0]);
        assert!(
            !logs
                .text()
                .contains("tenant-of-"),
            "no tenant is named: {}",
            logs.text()
        );
    }

    /// A stored consent provider whose redirect URI or authorization endpoint
    /// breaks the consent rules is logged as an ERROR naming it and the rule,
    /// never its URLs or parameters; conforming providers and providers
    /// outside the consent flow are not.
    #[test]
    fn stored_consent_providers_that_break_the_consent_rules_are_logged_as_errors() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let with = |id: &str, callback_url: Option<&str>, endpoint: &str, params: &[(&str, &str)]| {
            let mut provider = consent_provider(id, id, callback_url);
            provider.authorization_endpoint = Some(endpoint.to_string());
            provider.additional_params = params
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            provider
        };
        let endpoint = "https://idp.example/authorize";
        let mut external = with("external", Some("http://gw.example/cb"), "http://idp.example/authorize", &[]);
        external.issuer = Some("https://idp.example".to_string());
        let mut client_credentials = with("cc", Some("http://gw.example/cb"), endpoint, &[]);
        client_credentials.provider_type = CredentialProviderType::OAuth2ClientCredentials;
        let providers = [
            with("fine", None, endpoint, &[("prompt", "consent")]),
            with("plain-http", Some("http://gw.example/v1/identity/oauth/callback/plain-http"), endpoint, &[]),
            with("query", Some("https://gw.example/v1/identity/oauth/callback/query?x=1"), endpoint, &[]),
            with("http-endpoint", None, "http://idp.example/authorize", &[]),
            with("reserved", None, endpoint, &[("state", "secret-param-value")]),
            external,
            client_credentials,
        ];

        let breaches = log_consent_rule_breaches(&providers, "https://gw.example");

        assert_eq!(
            breaches,
            [
                ("plain-http", "callback_url must be an https URL with a host"),
                ("query", "callback_url must not carry credentials, a query or a fragment"),
                (
                    "http-endpoint",
                    "authorization_endpoint must be an https URL with a host and no credentials or fragment"
                ),
                (
                    "reserved",
                    "authorization_endpoint query and additional_params must not repeat a reserved or duplicate \
                     parameter or exceed the limits"
                ),
            ]
        );
        let text = logs.text();
        let lines: Vec<_> = text
            .lines()
            .filter(|line| line.contains("breaks the consent rules"))
            .collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert!(
            lines
                .iter()
                .all(|line| line.contains("ERROR")),
            "{lines:?}"
        );
        assert!(lines[0].contains("provider_id=plain-http"), "{}", lines[0]);
        for leaked in ["gw.example", "idp.example", "secret-param-value", "tenant-of-"] {
            assert!(!text.contains(leaked), "the log names no URL, parameter or tenant: {text}");
        }
    }

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
    fn a_client_reference_left_on_a_provider_is_not_kept_once_a_client_authentication_sends_it() {
        let stored: CredentialProvider = serde_json::from_value(serde_json::json!({
            "id": "p", "name": "p", "provider_id": "p", "provider_type": "oauth2_jwt_bearer",
            "token_endpoint": "https://idp.example/token", "jwt_signing_key_secret_ref": "KEY",
            "client_id_secret_ref": "ID", "client_secret_secret_ref": "SECRET",
            "jwt_issuer": "iss", "jwt_subject": "sub",
            "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
        }))
        .unwrap();
        let all_kept = vec![("ID", true), ("SECRET", true), ("KEY", true)];
        let none_kept = vec![("ID", false), ("SECRET", false), ("KEY", false)];
        assert_eq!(stored.secret_refs_kept_from(Some(&stored)), all_kept);

        let mut sending = stored.clone();
        sending
            .jwt
            .client_authentication = Some(GrantClientAuthentication::ClientSecretPost);
        assert_eq!(sending.secret_refs_kept_from(Some(&sending)), all_kept);
        assert_eq!(sending.secret_refs_kept_from(Some(&stored)), none_kept);
        assert_eq!(
            stored.secret_refs_kept_from(Some(&sending)),
            none_kept,
            "dropping the client authentication is a change of what the provider sends too"
        );
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
            consent_confirmation: None,
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
            authorization_response_iss_parameter_supported: None,
            authorization_response_issuer: None,
            scope_comparison: Default::default(),
            revocation_ends_authorization: false,
            send_resource: true,
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
            consent_confirmation: None,
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
            authorization_response_iss_parameter_supported: None,
            authorization_response_issuer: None,
            scope_comparison: Default::default(),
            revocation_ends_authorization: false,
            send_resource: true,
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
                client_authentication: None,
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
            client_authentication: None,
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
    fn list_item_shows_the_client_authentication_but_never_the_client_references() {
        let mut provider = make_provider("Vertex", "vertex");
        provider.provider_type = CredentialProviderType::OAuth2JwtBearer;
        provider.client_id_secret_ref = Some("ID_REF_MARKER".into());
        provider.client_secret_secret_ref = Some("SECRET_REF_MARKER".into());
        let unset = serde_json::to_value(CredentialProviderListItem::from(&provider)).unwrap();
        assert!(
            unset
                .get("client_authentication")
                .is_none()
        );

        provider
            .jwt
            .client_authentication = Some(GrantClientAuthentication::ClientSecretBasic);
        let item = serde_json::to_value(CredentialProviderListItem::from(&provider)).unwrap();
        assert_eq!(item["client_authentication"], "client_secret_basic");
        let text = item.to_string();
        assert!(!text.contains("ID_REF_MARKER"));
        assert!(!text.contains("SECRET_REF_MARKER"));
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
    fn a_client_authentication_is_kept_unless_an_update_names_or_clears_it() {
        let stored = JwtAssertionSettings {
            client_authentication: Some(GrantClientAuthentication::ClientSecretBasic),
            ..Default::default()
        };
        let sent = |value: &str| -> JwtAssertionSettings {
            serde_json::from_value(serde_json::json!({ "client_authentication": value })).unwrap()
        };
        let kept = JwtAssertionSettings::default()
            .or(stored.clone())
            .normalized();
        assert_eq!(kept.client_authentication, Some(GrantClientAuthentication::ClientSecretBasic));
        let changed = sent("client_secret_post")
            .or(stored.clone())
            .normalized();
        assert_eq!(changed.client_authentication, Some(GrantClientAuthentication::ClientSecretPost));
        let cleared = sent("")
            .or(stored)
            .normalized();
        assert_eq!(cleared.client_authentication, None);
        assert_eq!(
            sent("")
                .normalized()
                .client_authentication,
            None
        );
    }

    #[test]
    fn client_authentication_uses_the_oauth_method_names_and_is_left_out_when_unset() {
        use GrantClientAuthentication::*;
        for (name, method) in [
            ("none", PublicClient),
            ("client_secret_basic", ClientSecretBasic),
            ("client_secret_post", ClientSecretPost),
        ] {
            let settings: JwtAssertionSettings =
                serde_json::from_value(serde_json::json!({ "client_authentication": name })).unwrap();
            assert_eq!(settings.client_authentication, Some(method), "{name}");
            assert_eq!(serde_json::to_value(&settings).unwrap()["client_authentication"], name);
            assert_eq!(method.as_str(), name);
            assert_eq!(method.uses_secret(), name.starts_with("client_secret"), "{name}");
        }
        assert_eq!(serde_json::to_value(Unset).unwrap(), Unset.as_str());
        let unset = serde_json::to_value(JwtAssertionSettings::default()).unwrap();
        assert!(
            unset
                .get("client_authentication")
                .is_none()
        );
        for refused in ["private_key_jwt", "basic", "NONE"] {
            assert!(
                serde_json::from_value::<JwtAssertionSettings>(serde_json::json!({ "client_authentication": refused }))
                    .is_err(),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_jwt_bearer_service_token_reads_the_client_references_only_for_the_method_that_uses_them() {
        let provider = |method: Option<&str>| -> CredentialProvider {
            serde_json::from_value(serde_json::json!({
                "id": "p", "name": "p", "provider_id": "p", "provider_type": "oauth2_jwt_bearer",
                "client_id_secret_ref": "ID", "client_secret_secret_ref": "SECRET",
                "jwt_signing_key_secret_ref": "SIGNING", "jwt_certificate_secret_ref": "CERT",
                "client_authentication": method,
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap()
        };
        for (method, expected) in [
            (None, vec!["SIGNING", "CERT"]),
            (Some("none"), vec!["ID", "SIGNING", "CERT"]),
            (Some("client_secret_basic"), vec!["ID", "SECRET", "SIGNING", "CERT"]),
            (Some("client_secret_post"), vec!["ID", "SECRET", "SIGNING", "CERT"]),
        ] {
            assert_eq!(provider(method).service_token_secret_refs(), expected, "{method:?}");
        }
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
