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
    /// whether it was written. A record deleted in the meantime is not recreated.
    /// The default checks then writes; stores that can make the two atomic override it.
    async fn update_if_exists(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<bool> {
        if self
            .get(&connection_point.id)
            .await?
            .is_none()
        {
            return Ok(false);
        }
        self.update(connection_point)
            .await?;
        Ok(true)
    }

    /// Delete a connection point
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}
