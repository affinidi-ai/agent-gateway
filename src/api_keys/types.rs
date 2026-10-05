//! API Key data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// API key status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum ApiKeyStatus {
    /// Key is active and can be used for authentication
    #[default]
    Active,
    /// Key has been revoked and cannot be used
    Revoked,
}

/// Issuer information for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyIssuer {
    /// Actor who issued the key (user ID, operator ID, or system)
    pub actor: String,
    /// Method used to issue (api, rotation, migration, etc.)
    pub method: String,
}

/// Full API key record stored in backend (includes secret)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    /// Unique key identifier
    pub key_id: String,

    /// Agent this key belongs to
    pub agent_id: String,

    /// External client identifier
    pub client_id: String,

    /// SHA-256 hash of the key secret. The raw secret is returned to the
    /// caller only once at creation/rotation and never persisted — only this
    /// hash is stored, and validation compares against it. `None` for legacy
    /// records created before hashed storage (such keys must be rotated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hash: Option<String>,

    /// Key status (active/revoked)
    #[serde(default)]
    pub status: ApiKeyStatus,

    /// When the key was created
    pub created_at: DateTime<Utc>,

    /// When the key was revoked (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,

    /// Last time the key was used for authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// Optional labels for categorization
    #[serde(default)]
    pub labels: HashMap<String, String>,

    /// Issuer information for audit
    pub issuer: ApiKeyIssuer,

    /// If this key was created by rotating another key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
}

impl crate::storage::filesystem::StorableEntity for ApiKeyRecord {
    fn id(&self) -> &str {
        &self.key_id
    }
}

/// API key metadata (safe for listing, no secret)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyMeta {
    /// Unique key identifier
    pub key_id: String,

    /// Agent this key belongs to
    pub agent_id: String,

    /// External client identifier
    pub client_id: String,

    /// Key status (active/revoked)
    pub status: ApiKeyStatus,

    /// When the key was created
    pub created_at: DateTime<Utc>,

    /// When the key was revoked (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,

    /// Last time the key was used for authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// Optional labels for categorization
    #[serde(default)]
    pub labels: HashMap<String, String>,

    /// Issuer information for audit
    pub issuer: ApiKeyIssuer,

    /// If this key was created by rotating another key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,

    /// `true` when the key predates hashed storage (no `secret_hash`) and is
    /// still active. Such keys can no longer authenticate and must be rotated;
    /// the dashboard surfaces this as a "Rotate required" indicator.
    pub needs_rotation: bool,
}

impl From<ApiKeyRecord> for ApiKeyMeta {
    fn from(record: ApiKeyRecord) -> Self {
        let needs_rotation = record.status == ApiKeyStatus::Active && record.secret_hash.is_none();
        Self {
            key_id: record.key_id,
            agent_id: record.agent_id,
            client_id: record.client_id,
            status: record.status,
            created_at: record.created_at,
            revoked_at: record.revoked_at,
            last_used_at: record.last_used_at,
            labels: record.labels,
            issuer: record.issuer,
            rotated_from: record.rotated_from,
            needs_rotation,
        }
    }
}

/// Response returned when a key is created or rotated (includes one-time secret)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCreated {
    /// Unique key identifier
    pub key_id: String,

    /// The secret value (shown only once!)
    pub secret: String,

    /// Agent this key belongs to
    pub agent_id: String,

    /// External client identifier
    pub client_id: String,

    /// When the key was created
    pub created_at: DateTime<Utc>,

    /// If this was a rotation, the old key_id that was revoked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
}

/// Request to create a new API key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    /// External client identifier
    pub client_id: String,

    /// Optional labels for categorization
    #[serde(default)]
    pub labels: Option<HashMap<String, String>>,
}

/// Request to rotate an API key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct RotateApiKeyRequest {
    /// Actor performing the rotation (for audit)
    #[serde(default)]
    pub actor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_status_default() {
        let status = ApiKeyStatus::default();
        assert_eq!(status, ApiKeyStatus::Active);
    }

    #[test]
    fn test_api_key_meta_from_record() {
        let record = ApiKeyRecord {
            key_id: "key-123".to_string(),
            agent_id: "agent-456".to_string(),
            client_id: "client-789".to_string(),
            secret_hash: Some("deadbeef".to_string()),
            status: ApiKeyStatus::Active,
            created_at: Utc::now(),
            revoked_at: None,
            last_used_at: None,
            labels: HashMap::new(),
            issuer: ApiKeyIssuer {
                actor: "test".to_string(),
                method: "api".to_string(),
            },
            rotated_from: None,
        };

        let meta: ApiKeyMeta = record.into();
        assert_eq!(meta.key_id, "key-123");
        assert_eq!(meta.agent_id, "agent-456");
        assert_eq!(meta.client_id, "client-789");
        assert_eq!(meta.status, ApiKeyStatus::Active);
        assert!(!meta.needs_rotation, "a hashed active key does not need rotation");
    }

    #[test]
    fn test_api_key_meta_needs_rotation_flag() {
        let base = ApiKeyRecord {
            key_id: "key-1".to_string(),
            agent_id: "agent-1".to_string(),
            client_id: "client-1".to_string(),
            secret_hash: None,
            status: ApiKeyStatus::Active,
            created_at: Utc::now(),
            revoked_at: None,
            last_used_at: None,
            labels: HashMap::new(),
            issuer: ApiKeyIssuer {
                actor: "test".to_string(),
                method: "api".to_string(),
            },
            rotated_from: None,
        };

        // Active + no hash (legacy) → needs rotation.
        assert!(ApiKeyMeta::from(base.clone()).needs_rotation);

        // Revoked legacy key → no rotation prompt (nothing to fix).
        let revoked = ApiKeyRecord {
            status: ApiKeyStatus::Revoked,
            ..base.clone()
        };
        assert!(!ApiKeyMeta::from(revoked).needs_rotation);

        // Active + hashed → no rotation prompt.
        let hashed = ApiKeyRecord {
            secret_hash: Some("deadbeef".to_string()),
            ..base
        };
        assert!(!ApiKeyMeta::from(hashed).needs_rotation);
    }

    #[test]
    fn test_api_key_status_serialization() {
        let active = ApiKeyStatus::Active;
        let revoked = ApiKeyStatus::Revoked;

        assert_eq!(serde_json::to_string(&active).unwrap(), "\"active\"");
        assert_eq!(serde_json::to_string(&revoked).unwrap(), "\"revoked\"");
    }
}
