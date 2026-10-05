//! Mediator Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::Mediator;

/// Trait for storing mediator records
#[async_trait]
pub trait MediatorStore: Send + Sync {
    /// Create a mediator
    async fn create(
        &self,
        mediator: &Mediator,
    ) -> Result<()>;

    /// Get a mediator by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Mediator>>;

    /// List all mediators
    async fn list_all(&self) -> Result<Vec<Mediator>>;

    /// Delete a mediator by ID
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Update a mediator
    async fn update(
        &self,
        mediator: &Mediator,
    ) -> Result<()>;
}
