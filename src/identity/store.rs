//! Identity Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::filesystem;

/// Trait for storing and retrieving agent identity to DID mappings
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Find an existing DID for the given identity hash
    async fn find_by_hash(
        &self,
        identity_hash: &str,
    ) -> Result<Option<filesystem::AgentIdentityRecord>>;

    /// Create a new identity record
    async fn create(
        &self,
        record: filesystem::AgentIdentityRecord,
    ) -> Result<()>;

    /// Create `record` unless a record already exists for its hash. Returns the
    /// existing record when one does, `None` when `record` was created.
    async fn create_if_absent(
        &self,
        record: filesystem::AgentIdentityRecord,
    ) -> Result<Option<filesystem::AgentIdentityRecord>> {
        if let Some(existing) = self
            .find_by_hash(&record.identity_hash)
            .await?
        {
            return Ok(Some(existing));
        }
        self.create(record).await?;
        Ok(None)
    }

    /// List all stored identities
    async fn list_all(&self) -> Result<Vec<filesystem::AgentIdentityRecord>>;

    /// Update usage tracking for an identity
    /// If channel_config_id is provided, updates the last-used channel and records `role`,
    /// whether the identity was the managed agent or a caller there
    async fn update_usage(
        &self,
        identity_hash: &str,
        channel_config_id: Option<String>,
        role: Option<filesystem::IdentityOrigin>,
    ) -> Result<()>;

    /// Find an identity by DID
    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<filesystem::AgentIdentityRecord>>;

    /// Store an external DID reference (from another gateway)
    /// This creates a lightweight record for tracking identities issued by other gateways
    /// verified flag indicates if the VP/VC signature was cryptographically verified
    async fn store_external_did(
        &self,
        did: &str,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        channel_config_id: Option<String>,
        verified: bool,
    ) -> Result<()>;

    /// Record how an identity entered the store, unless it already has an
    /// origin: an origin, once set, never changes. Returns the record's origin
    /// after the call; `None` from stores without origin tracking.
    async fn set_origin(
        &self,
        _identity_hash: &str,
        _origin: filesystem::IdentityOrigin,
    ) -> Result<Option<filesystem::IdentityOrigin>> {
        Ok(None)
    }

    /// Record where a managed identity comes from; see
    /// [`filesystem::AgentIdentityRecord::apply_managed_source`]. Stores without provenance
    /// tracking ignore it.
    async fn apply_managed_source(
        &self,
        _identity_hash: &str,
        _source: &filesystem::ManagedIdentitySource,
        _identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        Ok(())
    }

    /// Every rotation of the identity's credential, oldest first; `None` for an unknown
    /// identity. Stores without a rotation history keep rotations on the record.
    async fn rotations(
        &self,
        identity_hash: &str,
    ) -> Result<Option<Vec<filesystem::CredentialRotation>>> {
        Ok(self
            .find_by_hash(identity_hash)
            .await?
            .map(|record| record.rotations))
    }

    /// Returns the base filesystem storage path, if this is a filesystem-backed store.
    /// Returns `None` for in-memory or mock implementations.
    fn base_path(&self) -> Option<std::path::PathBuf> {
        None
    }
}
