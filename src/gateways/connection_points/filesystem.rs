pub use super::ConnectionPointStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

use super::types::GatewayConnectionPoint;
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// File system implementation of ConnectionPointStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemConnectionPointStore {
    base_path: PathBuf,
    storage: Box<dyn StorageBackend<GatewayConnectionPoint>>,
}

impl FileSystemConnectionPointStore {
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        let storage = cached_storage(base_path.clone(), "connection_point").await?;
        info!(
            "Loaded {} connection point(s) from {}",
            storage
                .list_all()
                .await?
                .len(),
            base_path.display()
        );
        Ok(Self { base_path, storage })
    }

    /// Reconcile the in-memory cache with the current on-disk state.
    ///
    /// Picks up connection points added to storage while the process was
    /// stopped or restarted.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }

    /// Clean up orphaned connection point key directories — a `{id}/` folder with no
    /// `{id}.json` or `{id}.json.enc` config sibling at the base level. These are leftover
    /// DID secret folders from failed or incomplete connection attempts.
    pub async fn cleanup_orphaned_directories(&self) -> Result<usize> {
        use tracing::{info, warn};

        let mut cleaned = 0;
        let mut dir = tokio::fs::read_dir(&self.base_path).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            let dir_name = entry.file_name();

            // Skip the special "pending" directory and JSON files
            if dir_name == "pending"
                || path
                    .extension()
                    .and_then(|s| s.to_str())
                    == Some("json")
            {
                continue;
            }

            // Only process directories
            if path.is_dir() {
                let dir_name_str = dir_name.to_string_lossy();

                // A connection point's config lives at the base level as `{id}.json`
                // (plaintext) or `{id}.json.enc` (whole-file encryption at rest). Either
                // one proves the sibling `{id}/` key directory is a live connection point,
                // not an orphan. Checking only `{id}.json` would delete every valid key
                // directory once encryption at rest is enabled.
                let config_json = self
                    .base_path
                    .join(format!("{}.json", dir_name_str));
                let config_json_enc = self
                    .base_path
                    .join(format!("{}.json.enc", dir_name_str));

                if !config_json.exists() && !config_json_enc.exists() {
                    info!("Cleaning up orphaned connection point directory: {:?}", dir_name);

                    match tokio::fs::remove_dir_all(&path).await {
                        Ok(_) => {
                            cleaned += 1;
                        }
                        Err(e) => {
                            warn!("Failed to remove orphaned directory {:?}: {}", dir_name, e);
                        }
                    }
                }
            }
        }

        if cleaned > 0 {
            info!(
                "✓ Cleaned up {} orphaned connection point director{}",
                cleaned,
                if cleaned == 1 {
                    "y"
                } else {
                    "ies"
                }
            );
        }

        Ok(cleaned)
    }
}

#[async_trait]
impl ConnectionPointStore for FileSystemConnectionPointStore {
    async fn create(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()> {
        self.storage
            .save(connection_point)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<GatewayConnectionPoint>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<GatewayConnectionPoint>> {
        let mut connection_points = self
            .storage
            .list_all()
            .await?;

        // Sort by creation date (newest first)
        connection_points.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(connection_points)
    }

    async fn list_by_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayConnectionPoint>> {
        let mut connection_points = self
            .storage
            .list_all()
            .await?;
        connection_points.retain(|cp| cp.gateway_id == gateway_id);

        // Sort by creation date (newest first)
        connection_points.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(connection_points)
    }

    async fn update(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()> {
        // Update is the same as store
        self.storage
            .save(connection_point)
            .await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
    use tempfile::TempDir;

    fn sample_cp() -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gw-1".to_string(),
            "did:example:mediator".to_string(),
            "did:example:cp".to_string(),
            "CP".to_string(),
            "desc".to_string(),
            "oob-1".to_string(),
            "https://oob.example".to_string(),
            serde_json::json!({}),
            None,
            ConnectionPointType::User,
            "secret".to_string(),
        )
    }

    #[tokio::test]
    async fn refresh_from_disk_picks_up_connection_point_added_after_construction() {
        let dir = TempDir::new().unwrap();

        // A node that booted first: its cache is empty.
        let cached_reader = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        assert!(
            cached_reader
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );

        // Another node (or a later API write) persists a connection point to the same dir.
        let writer = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let cp = sample_cp();
        let cp_id = cp.id.clone();
        writer
            .create(&cp)
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

        // After refresh, the first store sees exactly that connection point.
        cached_reader
            .refresh_from_disk()
            .await
            .unwrap();
        let seen = cached_reader
            .list_all()
            .await
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].id, cp_id);
    }

    #[tokio::test]
    async fn cleanup_keeps_key_dir_with_encrypted_config_and_removes_true_orphan() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();

        // A live connection point under encryption at rest: config persisted as
        // `{id}.json.enc`, private keys in the sibling `{id}/` directory.
        let live_id = "live-cp";
        let live_keys = dir.path().join(live_id);
        tokio::fs::create_dir_all(&live_keys)
            .await
            .unwrap();
        tokio::fs::write(live_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path()
                .join(format!("{}.json.enc", live_id)),
            b"ciphertext",
        )
        .await
        .unwrap();

        // A live connection point with a plaintext config (encryption disabled).
        let plain_id = "plain-cp";
        let plain_keys = dir.path().join(plain_id);
        tokio::fs::create_dir_all(&plain_keys)
            .await
            .unwrap();
        tokio::fs::write(plain_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path()
                .join(format!("{}.json", plain_id)),
            b"{}",
        )
        .await
        .unwrap();

        // A genuine orphan: a key directory with no config sibling at all.
        let orphan_id = "orphan-cp";
        let orphan_keys = dir.path().join(orphan_id);
        tokio::fs::create_dir_all(&orphan_keys)
            .await
            .unwrap();
        tokio::fs::write(orphan_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();

        let cleaned = store
            .cleanup_orphaned_directories()
            .await
            .unwrap();

        assert_eq!(cleaned, 1, "only the true orphan should be removed");
        assert!(live_keys.exists(), "key dir with an encrypted config must be kept");
        assert!(plain_keys.exists(), "key dir with a plaintext config must be kept");
        assert!(!orphan_keys.exists(), "key dir with no config sibling must be removed");
    }
}
