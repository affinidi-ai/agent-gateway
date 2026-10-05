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

    /// List all stored identities
    async fn list_all(&self) -> Result<Vec<filesystem::AgentIdentityRecord>>;

    /// Update usage tracking for an identity
    /// If channel_config_id is provided, updates the last-used channel
    async fn update_usage(
        &self,
        identity_hash: &str,
        channel_config_id: Option<String>,
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

    /// Returns the base filesystem storage path, if this is a filesystem-backed store.
    /// Returns `None` for in-memory or mock implementations.
    fn base_path(&self) -> Option<std::path::PathBuf> {
        None
    }
}
