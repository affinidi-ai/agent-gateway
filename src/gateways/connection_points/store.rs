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

    /// Store the permanent connection point that the point `reserving_id` reserved, only
    /// while that point is still stored. Deleting the reserving point removes the keys of
    /// a reservation never paired, so a pairing that completes as its point is deleted
    /// fails here instead of storing a point whose keys are gone. Implementations make the
    /// check and the write atomic with respect to `delete` of `reserving_id`.
    async fn create_reserved(
        &self,
        connection_point: &GatewayConnectionPoint,
        reserving_id: &str,
    ) -> Result<()> {
        if self
            .get(reserving_id)
            .await?
            .is_none()
        {
            anyhow::bail!("connection point {reserving_id} that reserved this permanent DID was deleted");
        }
        self.create(connection_point)
            .await
    }

    /// Every connection point, as [`Self::list_all`], except that a record stored but
    /// unreadable (one that cannot be decrypted, say) is an error rather than left out.
    /// For callers that remove what no stored record names.
    async fn list_all_checked(&self) -> Result<Vec<GatewayConnectionPoint>> {
        self.list_all().await
    }

    /// The connection points of a gateway, as [`Self::list_by_gateway`], except that a
    /// record stored but unreadable is an error, since it may belong to this gateway.
    async fn list_by_gateway_checked(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayConnectionPoint>> {
        self.list_by_gateway(gateway_id)
            .await
    }
}
