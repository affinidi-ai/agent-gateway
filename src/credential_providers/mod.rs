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
