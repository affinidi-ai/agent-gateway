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
    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Issuer>>;
}

static ISSUER_LOCKS: std::sync::LazyLock<crate::storage::id_locks::IdLocks> =
    std::sync::LazyLock::new(Default::default);

/// Hold the lock of issuer `id`, which serialises the read-modify-write
/// updates of that issuer, so one never saves over a change made meanwhile.
pub async fn lock_issuer(id: &str) -> crate::storage::id_locks::IdLockGuard<'_> {
    ISSUER_LOCKS.lock(id).await
}
