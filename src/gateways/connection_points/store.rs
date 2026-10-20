//! Connection Point Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::GatewayConnectionPoint;

#[derive(Debug, thiserror::Error)]
#[error("connection point {0} no longer exists")]
pub struct ConnectionPointGone(pub String);

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

    /// Creates the record when absent, except that a recently deleted id fails
    /// with [`ConnectionPointGone`] so a late write cannot resurrect it.
    async fn update(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()>;

    /// Delete a connection point
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}
