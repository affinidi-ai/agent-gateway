pub use super::MediatorStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use crate::storage::filesystem::{StorageBackend, cached_storage};

use super::types::Mediator;

/// Filesystem-based implementation of MediatorStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemMediatorStore {
    storage: Box<dyn StorageBackend<Mediator>>,
}

impl FileSystemMediatorStore {
    /// Create a new FileSystemMediatorStore with in-memory cache
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "mediator").await?;
        Ok(Self { storage })
    }
}

#[async_trait]
impl MediatorStore for FileSystemMediatorStore {
    async fn create(
        &self,
        mediator: &Mediator,
    ) -> Result<()> {
        self.storage
            .save(mediator)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Mediator>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<Mediator>> {
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
        mediator: &Mediator,
    ) -> Result<()> {
        // Update is the same as create for filesystem implementation
        self.storage
            .save(mediator)
            .await
    }
}
