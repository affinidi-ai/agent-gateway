pub use super::TrustRegistryStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use super::types::TrustRegistry;
use crate::storage::filesystem::{StorageBackend, cached_storage};
use crate::storage::id_locks::IdLocks;

/// Filesystem-based implementation of TrustRegistryStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemTrustRegistryStore {
    storage: Box<dyn StorageBackend<TrustRegistry>>,
    id_locks: IdLocks,
}

impl FileSystemTrustRegistryStore {
    /// Create a new FileSystemTrustRegistryStore with in-memory cache
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "trust_registry").await?;
        Ok(Self {
            storage,
            id_locks: IdLocks::default(),
        })
    }

    /// Reconcile the in-memory cache with the current on-disk state.
    ///
    /// Picks up registries added to storage while the process was stopped or
    /// restarted.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }
}

#[async_trait]
impl TrustRegistryStore for FileSystemTrustRegistryStore {
    async fn create(
        &self,
        trust_registry: &TrustRegistry,
    ) -> Result<()> {
        let _guard = self
            .id_locks
            .lock(&trust_registry.id)
            .await;
        self.storage
            .save(trust_registry)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<TrustRegistry>> {
        self.storage.get(id).await
    }

    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<TrustRegistry>> {
        let all = self
            .storage
            .list_all()
            .await?;
        Ok(all.into_iter().find(|tr| {
            tr.did.as_deref() == Some(did)
                || tr.registry_did.as_deref() == Some(did)
                || tr.main_did.as_deref() == Some(did)
        }))
    }

    async fn list_all(&self) -> Result<Vec<TrustRegistry>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        let _guard = self.id_locks.lock(id).await;
        self.storage.delete(id).await
    }

    async fn update_if_exists(
        &self,
        trust_registry: &TrustRegistry,
    ) -> Result<bool> {
        let _guard = self
            .id_locks
            .lock(&trust_registry.id)
            .await;
        if self
            .storage
            .get(&trust_registry.id)
            .await?
            .is_none()
        {
            return Ok(false);
        }
        self.storage
            .save(trust_registry)
            .await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_registries::did_manager::DidMethod;
    use tempfile::TempDir;

    #[tokio::test]
    async fn refresh_from_disk_picks_up_registry_added_after_construction() {
        let dir = TempDir::new().unwrap();

        // A node that booted first: its cache is empty.
        let cached_reader = FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        assert!(
            cached_reader
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );

        // Another node (or a later API write) persists a registry to the same storage dir.
        let writer = FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let tr = TrustRegistry::new(
            "TR".to_string(),
            "desc".to_string(),
            "https://oob.example".to_string(),
            DidMethod::Peer,
        );
        let tr_id = tr.id.clone();
        writer
            .create(&tr)
            .await
            .unwrap();

        // The first store's boot cache still does not see it.
        assert!(
            cached_reader
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );

        // After refresh, the first store sees exactly that registry.
        cached_reader
            .refresh_from_disk()
            .await
            .unwrap();
        let seen = cached_reader
            .list_all()
            .await
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].id, tr_id);
    }

    fn sample_registry() -> TrustRegistry {
        TrustRegistry::new("TR".to_string(), "desc".to_string(), "https://oob.example".to_string(), DidMethod::Peer)
    }

    #[tokio::test]
    async fn update_if_exists_writes_an_existing_record() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let mut tr = sample_registry();
        store
            .create(&tr)
            .await
            .unwrap();
        tr.name = "renamed".to_string();

        assert!(
            store
                .update_if_exists(&tr)
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get(&tr.id)
                .await
                .unwrap()
                .unwrap()
                .name,
            "renamed"
        );
    }

    #[tokio::test]
    async fn update_if_exists_after_a_delete_does_not_resurrect_the_record() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let tr = sample_registry();
        store
            .create(&tr)
            .await
            .unwrap();
        store
            .delete(&tr.id)
            .await
            .unwrap();

        assert!(
            !store
                .update_if_exists(&tr)
                .await
                .unwrap(),
            "nothing is written for a deleted record"
        );
        assert!(
            store
                .get(&tr.id)
                .await
                .unwrap()
                .is_none()
        );
        let reloaded = FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        assert!(
            reloaded
                .get(&tr.id)
                .await
                .unwrap()
                .is_none(),
            "nothing was written to disk"
        );
    }

    #[tokio::test]
    async fn concurrent_conditional_updates_and_a_delete_leave_the_record_gone() {
        let dir = TempDir::new().unwrap();
        let store = std::sync::Arc::new(
            FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let tr = sample_registry();
        store
            .create(&tr)
            .await
            .unwrap();
        let mut updaters = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let tr = tr.clone();
            updaters.push(tokio::spawn(async move {
                for _ in 0..20 {
                    let _ = store
                        .update_if_exists(&tr)
                        .await;
                    tokio::task::yield_now().await;
                }
            }));
        }
        store
            .delete(&tr.id)
            .await
            .unwrap();
        for updater in updaters {
            updater.await.unwrap();
        }
        assert!(
            store
                .get(&tr.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
