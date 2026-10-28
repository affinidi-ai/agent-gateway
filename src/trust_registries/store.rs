//! Trust Registry Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::TrustRegistry;

/// Trait for storing trust registry records
#[async_trait]
pub trait TrustRegistryStore: Send + Sync {
    /// Create a trust registry
    async fn create(
        &self,
        trust_registry: &TrustRegistry,
    ) -> Result<()>;

    /// Get a trust registry by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<TrustRegistry>>;

    /// Get a trust registry by DID
    #[allow(dead_code)]
    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<TrustRegistry>>;

    /// List all trust registries
    async fn list_all(&self) -> Result<Vec<TrustRegistry>>;

    /// Delete a trust registry by ID
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Update a trust registry only when its record still exists, returning
    /// whether it was written. A record deleted in the meantime is not recreated,
    /// so implementations must make the existence check and the write atomic
    /// with respect to `delete` for the same id.
    async fn update_if_exists(
        &self,
        trust_registry: &TrustRegistry,
    ) -> Result<bool>;
}
