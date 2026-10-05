pub use super::AuthorityStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use crate::storage::filesystem::{StorageBackend, cached_storage};

use super::types::Authority;

/// Filesystem-based implementation of `AuthorityStore` with in-memory cache.
pub struct FileSystemAuthorityStore {
    storage: Box<dyn StorageBackend<Authority>>,
}

impl FileSystemAuthorityStore {
    /// Create a new `FileSystemAuthorityStore` with in-memory cache.
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "authority").await?;
        Ok(Self { storage })
    }
}

#[async_trait]
impl AuthorityStore for FileSystemAuthorityStore {
    async fn create(
        &self,
        authority: &Authority,
    ) -> Result<()> {
        self.storage
            .save(authority)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Authority>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<Authority>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }

    async fn update(
        &self,
        authority: &Authority,
    ) -> Result<()> {
        self.storage
            .save(authority)
            .await
    }

    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Authority>> {
        let all = self
            .storage
            .list_all()
            .await?;
        Ok(all
            .into_iter()
            .find(|a| a.did == did))
    }
}
