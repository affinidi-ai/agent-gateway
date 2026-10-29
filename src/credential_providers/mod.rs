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
    /// Secret holding the PEM private key (PKCS#1 or PKCS#8 for RSA, PKCS#8 for EC)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_signing_key_secret_ref: Option<String>,
    /// Secret holding the PEM certificate whose SHA-256 thumbprint goes in `x5t#S256`
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
    /// The algorithm this provider signs its JWT with: the configured one, or its
    /// type's default. `None` for types that sign nothing.
    pub fn jwt_signing_algorithm(&self) -> Option<JwtSigningAlgorithm> {
        self.provider_type
            .default_jwt_algorithm()
            .map(|default| {
                self.jwt
                    .jwt_signing_algorithm
                    .unwrap_or(default)
            })
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
            consent_identity_strategy_id: p
                .consent_identity_strategy_id
                .clone(),
            jwt_signing_algorithm: p.jwt.jwt_signing_algorithm,
            jwt_audience: p.jwt.jwt_audience.clone(),
            jwt_key_id: p.jwt.jwt_key_id.clone(),
            jwt_issuer: p.jwt.jwt_issuer.clone(),
            jwt_subject: p.jwt.jwt_subject.clone(),
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(value.get("jwt_certificate_secret_ref").is_none());
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
        assert_eq!(request.jwt.jwt_certificate_secret_ref.as_deref(), Some("FOUNDRY_CERT"));
        assert_eq!(request.jwt.jwt_signing_algorithm, Some(JwtSigningAlgorithm::PS256));
        let update: UpdateCredentialProviderRequest =
            serde_json::from_str(r#"{"jwt_key_id": "thumb", "jwt_signing_algorithm": "RS256"}"#).unwrap();
        assert_eq!(update.jwt.jwt_key_id.as_deref(), Some("thumb"));
        assert_eq!(update.jwt.jwt_signing_algorithm, Some(JwtSigningAlgorithm::RS256));
        assert!(serde_json::from_str::<UpdateCredentialProviderRequest>(r#"{"jwt_signing_algorithm": "HS256"}"#).is_err());
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
        assert_eq!(merged.jwt_signing_key_secret_ref.as_deref(), Some("OLD_KEY"));
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
