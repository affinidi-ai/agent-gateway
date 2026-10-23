//! Connection Point Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::GatewayConnectionPoint;

/// Trait for storing and retrieving gateway connection points
#[async_trait]
pub trait ConnectionPointStore: Send + Sync {
    /// Create a new connection point
    async fn create(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()>;

    /// Get a connection point by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<GatewayConnectionPoint>>;

    /// List all connection points
    async fn list_all(&self) -> Result<Vec<GatewayConnectionPoint>>;

    /// List connection points for a specific gateway
    async fn list_by_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayConnectionPoint>>;

    /// Update a connection point, creating the record when it is absent
    async fn update(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()>;

    /// Update a connection point only when its record still exists, returning
    /// whether it was written. A record deleted in the meantime is not recreated,
    /// so implementations must make the existence check and the write atomic
    /// with respect to `delete` for the same id.
    async fn update_if_exists(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<bool>;

    /// Delete a connection point
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}
