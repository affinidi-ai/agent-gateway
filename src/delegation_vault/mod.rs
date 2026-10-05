//! Delegation Vault module for secure token storage and OAuth flow management
//!
//! Stores OAuth tokens keyed by (agent_did, user_identity_hash, provider_id).
//! Tokens are encrypted at rest using the gateway's AES-256-GCM encryption.
//!
//! Also handles:
//! - OAuth authorization URL generation
//! - OAuth callback processing (code → token exchange)
//! - Token refresh flow
//! - DelegationCredential VC issuance

pub mod audit;
pub mod handlers;
pub mod modern_consent;
pub mod notifier;
pub mod oauth;
pub mod router;
pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::StorableEntity;

/// A delegation token stored in the vault — represents a user's consent
/// for an agent to access a specific resource provider on their behalf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Unique identifier (UUID)
    pub id: String,

    /// The agent DID that this delegation is for (e.g. "did:web:gw.example.com:agent:42")
    pub agent_did: String,

    /// SHA256 hash of the user's identity claims (from source_auth JWT)
    pub user_identity_hash: String,

    /// FK to the credential provider that issued the tokens
    pub credential_provider_id: String,

    /// The provider_id (machine-readable) for quick lookups
    pub provider_id: String,

    /// OAuth access token (encrypted at rest)
    // Filesystem is currently the only storage backend and encrypts the whole file at rest.
    // Per-field encryption may be enabled when another storage backend is added.
    pub access_token: String,

    /// OAuth refresh token (encrypted at rest, optional)
    // Filesystem is currently the only storage backend and encrypts the whole file at rest.
    // Per-field encryption may be enabled when another storage backend is added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Token type (typically "Bearer")
    #[serde(default = "default_token_type")]
    pub token_type: String,

    /// Granted OAuth scopes
    #[serde(default)]
    pub scopes: Vec<String>,

    /// When the access token expires (None = no expiry info from provider)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// JSON-serialized DelegationCredential VC proving the delegation chain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_vc: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_identity: Option<modern_consent::identity::VerifiedConsentIdentity>,

    /// When the user granted consent
    pub consent_granted_at: DateTime<Utc>,

    /// When the token was last used to make an outbound request
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl StorableEntity for DelegationToken {
    fn id(&self) -> &str {
        &self.id
    }
}

impl DelegationToken {
    /// Check if the access token has expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() >= exp,
            None => false, // No expiry info — assume valid
        }
    }

    /// Check if a refresh is possible
    pub fn can_refresh(&self) -> bool {
        self.refresh_token.is_some()
    }

    /// Composite lookup key for vault queries
    #[allow(dead_code)]
    pub fn lookup_key(&self) -> String {
        format!("{}:{}:{}", self.agent_did, self.user_identity_hash, self.provider_id)
    }
}

/// OAuth state parameter — encrypted and passed through the OAuth flow
/// to bind the callback to the original request context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// Agent DID that needs the delegation
    pub agent_did: String,
    /// User identity hash (from source_auth)
    pub user_identity_hash: String,
    /// Channel config ID where the request originated
    pub surface_id: String,
    /// Credential provider ID
    pub credential_provider_id: String,
    /// Provider ID (machine-readable)
    pub provider_id: String,
    /// Random nonce for CSRF prevention
    pub nonce: String,
    /// When this state expires
    pub expires_at: DateTime<Utc>,
    /// PKCE code_verifier — stored in encrypted state, sent during token exchange
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
}

/// Token response from OAuth provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Consent-required response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConsentRequired {
    pub provider_id: String,
    pub provider_name: String,
    pub authorization_url: String,
    pub scopes: Vec<String>,
    pub message: String,
}

/// Delegation vault lookup result
#[derive(Clone)]
pub enum VaultLookupResult {
    /// Token found and valid
    Found(DelegationToken),
    /// Token found but expired, refresh token available
    ExpiredRefreshable(DelegationToken),
    /// Token found but expired, no refresh token
    ExpiredNoRefresh(DelegationToken),
    /// No token for this combination
    NotFound,
}

/// Metadata-only view for API listing (no tokens)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationTokenListItem {
    pub id: String,
    pub agent_did: String,
    pub user_identity_hash: String,
    pub credential_provider_id: String,
    pub provider_id: String,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub consent_granted_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_expired: bool,
    pub can_refresh: bool,
}

impl From<&DelegationToken> for DelegationTokenListItem {
    fn from(t: &DelegationToken) -> Self {
        Self {
            id: t.id.clone(),
            agent_did: t.agent_did.clone(),
            user_identity_hash: t.user_identity_hash.clone(),
            credential_provider_id: t
                .credential_provider_id
                .clone(),
            provider_id: t.provider_id.clone(),
            token_type: t.token_type.clone(),
            scopes: t.scopes.clone(),
            expires_at: t.expires_at,
            consent_granted_at: t.consent_granted_at,
            last_used_at: t.last_used_at,
            created_at: t.created_at,
            updated_at: t.updated_at,
            is_expired: t.is_expired(),
            can_refresh: t.can_refresh(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    pub(super) fn make_token(
        expires_in_secs: Option<i64>,
        has_refresh: bool,
    ) -> DelegationToken {
        let now = Utc::now();
        DelegationToken {
            id: "test-token-1".to_string(),
            agent_did: "did:web:agent.example.com".to_string(),
            user_identity_hash: "sha256:abc123".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            access_token: "gho_test_access_token".to_string(),
            refresh_token: if has_refresh {
                Some("gho_test_refresh_token".to_string())
            } else {
                None
            },
            token_type: "bearer".to_string(),
            scopes: vec!["repo".to_string(), "read:user".to_string()],
            expires_at: expires_in_secs.map(|s| now + Duration::seconds(s)),
            delegation_vc: None,
            consent_identity: None,
            consent_granted_at: now,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn legacy_vault_records_do_not_establish_verified_consent_identity() {
        let token = make_token(Some(3600), true);
        let value = serde_json::to_value(&token).unwrap();
        assert!(
            value
                .get("consent_identity")
                .is_none()
        );
        let decoded: DelegationToken = serde_json::from_value(value).unwrap();
        assert!(
            decoded
                .consent_identity
                .is_none()
        );
    }

    #[test]
    fn test_token_not_expired_no_expiry() {
        let token = make_token(None, false);
        assert!(!token.is_expired(), "Token with no expiry should not be expired");
    }

    #[test]
    fn test_token_not_expired_future() {
        let token = make_token(Some(3600), false);
        assert!(!token.is_expired(), "Token expiring in 1h should not be expired");
    }

    #[test]
    fn test_token_expired_past() {
        let token = make_token(Some(-60), false);
        assert!(token.is_expired(), "Token that expired 60s ago should be expired");
    }

    #[test]
    fn test_can_refresh_with_refresh_token() {
        let token = make_token(Some(-60), true);
        assert!(token.can_refresh(), "Expired token with refresh_token should be refreshable");
    }

    #[test]
    fn test_cannot_refresh_without_refresh_token() {
        let token = make_token(Some(-60), false);
        assert!(!token.can_refresh(), "Expired token without refresh_token should not be refreshable");
    }

    #[test]
    fn test_can_refresh_valid_token_with_refresh_token() {
        let token = make_token(Some(3600), true);
        assert!(token.can_refresh(), "Token with refresh_token should report can_refresh regardless of expiry");
    }

    #[test]
    fn test_lookup_key() {
        let token = make_token(Some(3600), false);
        let key = token.lookup_key();
        assert_eq!(key, "did:web:agent.example.com:sha256:abc123:github");
    }

    #[test]
    fn test_storable_entity_id() {
        let token = make_token(None, false);
        assert_eq!(token.id(), "test-token-1");
    }

    #[test]
    fn test_list_item_from_token_does_not_contain_secrets() {
        let token = make_token(Some(3600), true);
        let item = DelegationTokenListItem::from(&token);
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("access_token"), "List item must not contain access_token");
        assert!(!json.contains("refresh_token"), "List item must not contain refresh_token");
        assert!(!item.is_expired);
        assert!(item.can_refresh); // has refresh_token
    }

    #[test]
    fn test_list_item_expired_refreshable() {
        let token = make_token(Some(-60), true);
        let item = DelegationTokenListItem::from(&token);
        assert!(item.is_expired);
        assert!(item.can_refresh);
    }

    #[test]
    fn test_oauth_state_serialization() {
        let state = OAuthState {
            agent_did: "did:web:agent.example.com".to_string(),
            user_identity_hash: "sha256:abc123".to_string(),
            surface_id: "ch-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-123".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: None,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: OAuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_did, "did:web:agent.example.com");
        assert_eq!(deserialized.nonce, "nonce-123");
    }

    #[test]
    fn test_consent_required_serialization() {
        let consent = ConsentRequired {
            provider_id: "github".to_string(),
            provider_name: "GitHub".to_string(),
            authorization_url: "https://github.com/login/oauth/authorize?client_id=test".to_string(),
            scopes: vec!["repo".to_string()],
            message: "Please authorize".to_string(),
        };
        let json = serde_json::to_string(&consent).unwrap();
        assert!(json.contains("authorization_url"));
        assert!(json.contains("github.com"));
    }

    #[test]
    fn test_outbound_credential_binding_types() {
        use crate::config::types::{
            ConsentMode, CredentialInjection, CredentialRequirement, OutboundCredentialBinding,
        };

        let binding = OutboundCredentialBinding {
            credential_provider_id: "cp-1".to_string(),
            scopes: vec!["repo".to_string()],
            required_for: CredentialRequirement::All,
            consent_mode: ConsentMode::OnDemand,
            inject_as: CredentialInjection::BearerHeader,
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::OnDemand,
        };
        let json = serde_json::to_string(&binding).unwrap();
        let deserialized: OutboundCredentialBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.credential_provider_id, "cp-1");
        assert_eq!(deserialized.scopes, vec!["repo"]);
    }

    #[test]
    fn test_credential_injection_custom_header() {
        use crate::config::types::CredentialInjection;

        let inject = CredentialInjection::CustomHeader {
            name: "X-GitHub-Token".to_string(),
            format: "token {value}".to_string(),
        };
        let json = serde_json::to_string(&inject).unwrap();
        assert!(json.contains("custom_header"));
        assert!(json.contains("X-GitHub-Token"));
    }

    #[test]
    fn test_credential_requirement_tools_filter() {
        use crate::config::types::CredentialRequirement;

        let req = CredentialRequirement::Tools(vec!["list_repos".to_string(), "create_issue".to_string()]);
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: CredentialRequirement = serde_json::from_str(&json).unwrap();
        match deserialized {
            CredentialRequirement::Tools(tools) => {
                assert_eq!(tools.len(), 2);
                assert_eq!(tools[0], "list_repos");
            }
            _ => panic!("Expected Tools variant"),
        }
    }
}
