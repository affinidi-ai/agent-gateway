//! Gateway Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::Gateway;

/// Trait for storing gateway records
#[async_trait]
pub trait GatewayStore: Send + Sync {
    /// Create a gateway
    async fn create(
        &self,
        gateway: &Gateway,
    ) -> Result<()>;

    /// Get a gateway by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Gateway>>;

    /// Get a gateway by DID
    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Gateway>>;

    /// List all gateways
    async fn list_all(&self) -> Result<Vec<Gateway>>;

    /// Delete a gateway by ID
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Update a gateway
    async fn update(
        &self,
        gateway: &Gateway,
    ) -> Result<()>;
}
