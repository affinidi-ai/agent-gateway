pub use super::IssuerStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use crate::storage::filesystem::{StorageBackend, cached_storage};

use super::types::Issuer;

/// Filesystem-based implementation of IssuerStore with in-memory cache
pub struct FileSystemIssuerStore {
    storage: Box<dyn StorageBackend<Issuer>>,
}

impl FileSystemIssuerStore {
    /// Create a new FileSystemIssuerStore with in-memory cache
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "issuer").await?;
        Ok(Self { storage })
    }
}

#[async_trait]
impl IssuerStore for FileSystemIssuerStore {
    async fn create(
        &self,
        issuer: &Issuer,
    ) -> Result<()> {
        self.storage
            .save(issuer)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Issuer>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<Issuer>> {
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
        issuer: &Issuer,
    ) -> Result<()> {
        self.storage
            .save(issuer)
            .await
    }

    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Issuer>> {
        let all = self
            .storage
            .list_all()
            .await?;
        Ok(all
            .into_iter()
            .find(|i| i.did == did))
    }
}
