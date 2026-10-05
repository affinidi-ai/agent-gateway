//! Filesystem-backed storage for Agent Surface configurations

use super::AgentSurfaceStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

use crate::config::agent_surface::AgentSurface;
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Filesystem-based implementation of AgentSurfaceStore with in-memory cache
pub struct FileSystemAgentSurfaceStore {
    storage: Box<dyn StorageBackend<AgentSurface>>,
}

impl FileSystemAgentSurfaceStore {
    /// Create a new FileSystemAgentSurfaceStore with in-memory cache
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        info!("Loading agent surfaces from: {}", storage_dir.display());
        let storage = cached_storage(storage_dir, "agent_surface").await?;
        let count = storage
            .list_all()
            .await?
            .len();
        info!("Loaded {} agent surface(s)", count);
        Ok(Self { storage })
    }

    pub fn subscribe(
        &self
    ) -> Option<tokio::sync::broadcast::Receiver<crate::storage::filesystem::StorageEvent<AgentSurface>>> {
        self.storage.subscribe()
    }

    /// Reconcile the in-memory cache with the shared-storage directory, so a
    /// node promoted from standby recompiles surface policies from the active
    /// writer's latest surfaces rather than a stale boot snapshot.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }
}

#[async_trait]
impl AgentSurfaceStore for FileSystemAgentSurfaceStore {
    async fn save(
        &self,
        surface: &AgentSurface,
    ) -> Result<()> {
        self.storage
            .save(surface)
            .await?;
        crate::mcp::subscriptions::invalidate_access();
        Ok(())
    }

    async fn get(
        &self,
        surface_id: &str,
    ) -> Result<Option<AgentSurface>> {
        self.storage
            .get(surface_id)
            .await
    }

    async fn list_all(&self) -> Result<Vec<AgentSurface>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        surface_id: &str,
    ) -> Result<()> {
        self.storage
            .delete(surface_id)
            .await?;
        crate::mcp::subscriptions::invalidate_access();
        Ok(())
    }
}
