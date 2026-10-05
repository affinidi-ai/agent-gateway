use anyhow::Result;
use async_trait::async_trait;

use super::types::Issuer;

/// Trait for storing issuer records
#[async_trait]
pub trait IssuerStore: Send + Sync {
    /// Create an issuer
    async fn create(
        &self,
        issuer: &Issuer,
    ) -> Result<()>;

    /// Get an issuer by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Issuer>>;

    /// List all issuers
    async fn list_all(&self) -> Result<Vec<Issuer>>;

    /// Delete an issuer by ID
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Update an issuer
    async fn update(
        &self,
        issuer: &Issuer,
    ) -> Result<()>;

    /// Find an issuer by its DID
    #[allow(dead_code)]
    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Issuer>>;
}
