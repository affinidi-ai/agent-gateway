use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::StorableEntity;

/// Represents an issuer record with auto-generated DID.
/// New issuers use `did:webvh` (when the `didwebvh` feature is enabled);
/// legacy issuers may still carry a `did:web` identifier, and legacy DIDs
/// minted before the `department` → `issuer` rename retain their
/// `:departments:` path segment for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issuer {
    /// Unique identifier (UUID v4)
    pub id: String,

    /// Management-plane tenant ownership. Missing means appliance-global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Issuer name (user-supplied)
    pub name: String,

    /// Optional description (user-supplied, may be empty)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// DID (auto-generated on create, immutable).
    /// `did:webvh:<scid>:<domain>:issuers:<uuid>` when created with the
    /// `didwebvh` feature; legacy `did:web:<domain>:issuers:<uuid>` for
    /// the non-webvh fallback. Records minted before the rename may carry
    /// `:departments:` in place of `:issuers:` and continue to resolve.
    pub did: String,

    /// Legacy: Private keys (JSON array of Secret JWKs — never returned in API responses).
    /// Retained for backward compatibility with issuers created before the
    /// did:webvh migration. New issuers store keys via `key_pair` instead.
    #[serde(default)]
    pub secrets: serde_json::Value,

    /// Ed25519 signing key pair for did:webvh identities.
    /// Populated when the issuer is created with the `didwebvh` feature.
    #[cfg(feature = "didwebvh")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_pair: Option<crate::identity::didwebvh::types::KeyPair>,

    /// W3C DID document (served via /issuers/{id}/did.json).
    /// For did:webvh issuers this is the parallel did:web document.
    pub did_document: serde_json::Value,

    /// Trust registry DID used when this issuer was registered (stored for deregistration on delete).
    /// Never returned in API responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_registry_did: Option<String>,

    /// Authority DID (company DID) used when this issuer was registered in the trust registry.
    /// Never returned in API responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_did: Option<String>,

    /// Trust registry registration status.
    /// None = no TR registration was requested.
    /// Some(true) = successfully registered via DIDComm.
    /// Some(false) = registration was attempted but failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tr_registered: Option<bool>,

    /// Timestamp when this record was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when this record was last updated
    pub updated_at: DateTime<Utc>,
}

impl StorableEntity for Issuer {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Issuer {
    #[allow(dead_code)] // Used in #[cfg(not(feature = "didwebvh"))] path
    pub fn new(
        id: String,
        name: String,
        did: String,
        secrets: serde_json::Value,
        did_document: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            tenant_id: None,
            name,
            description: None,
            did,
            secrets,
            #[cfg(feature = "didwebvh")]
            key_pair: None,
            did_document,
            trust_registry_did: None,
            authority_did: None,
            tr_registered: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new issuer with a did:webvh key pair.
    #[cfg(feature = "didwebvh")]
    pub fn new_webvh(
        id: String,
        name: String,
        did: String,
        key_pair: crate::identity::didwebvh::types::KeyPair,
        did_document: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            tenant_id: None,
            name,
            description: None,
            did,
            secrets: serde_json::Value::Array(vec![]),
            key_pair: Some(key_pair),
            did_document,
            trust_registry_did: None,
            authority_did: None,
            tr_registered: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// API response struct — excludes secrets and did_document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerResponse {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_registry_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tr_registered: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Issuer> for IssuerResponse {
    fn from(i: Issuer) -> Self {
        Self {
            id: i.id,
            tenant_id: i.tenant_id,
            name: i.name,
            description: i.description,
            did: i.did,
            trust_registry_did: i.trust_registry_did,
            authority_did: i.authority_did,
            tr_registered: i.tr_registered,
            created_at: i.created_at,
            updated_at: i.updated_at,
        }
    }
}
