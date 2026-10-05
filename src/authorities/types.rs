use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::StorableEntity;

/// Local record book entry representing an external "authority" — a DID that
/// acts as a trust anchor for policy authoring or Trust Check template
/// subjects. Carries no key material, DID generation, or trust-registry
/// registration; this is pure operator-supplied metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authority {
    /// Unique identifier (UUID v4, server-generated on create).
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Human-readable label (required).
    pub name: String,

    /// Optional free-form description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// External DID (required, user-supplied, must start with `did:`).
    /// Immutable after creation.
    pub did: String,

    /// Optional structured context. When present, must be a JSON object —
    /// arrays / primitives are rejected at the handler boundary so this
    /// stays useful as a bag of properties for Rego / template consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,

    /// Timestamp when this record was created.
    pub created_at: DateTime<Utc>,

    /// Timestamp when this record was last updated.
    pub updated_at: DateTime<Utc>,
}

impl StorableEntity for Authority {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Authority {
    pub fn new(
        id: String,
        name: String,
        did: String,
        description: Option<String>,
        context: Option<serde_json::Value>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            tenant_id: None,
            name,
            description,
            did,
            context,
            created_at: now,
            updated_at: now,
        }
    }
}

/// API response struct — kept identical in shape to `Authority` so a single
/// serialiser round-trip suffices. Exists to leave headroom for future
/// wire/storage divergence (e.g. audit fields we don't want to leak).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityResponse {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Authority> for AuthorityResponse {
    fn from(a: Authority) -> Self {
        Self {
            id: a.id,
            tenant_id: a.tenant_id,
            name: a.name,
            description: a.description,
            did: a.did,
            context: a.context,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}
