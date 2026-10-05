use anyhow::Result;
use async_trait::async_trait;

use super::types::Authority;

/// Trait for storing authority records.
#[async_trait]
pub trait AuthorityStore: Send + Sync {
    /// Create an authority.
    async fn create(
        &self,
        authority: &Authority,
    ) -> Result<()>;

    /// Get an authority by ID.
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Authority>>;

    /// List all authorities.
    async fn list_all(&self) -> Result<Vec<Authority>>;

    /// Delete an authority by ID.
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Update an authority.
    async fn update(
        &self,
        authority: &Authority,
    ) -> Result<()>;

    /// Find an authority by its DID.
    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Authority>>;
}
