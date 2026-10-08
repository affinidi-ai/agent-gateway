//! JWT Bearer verification strategy storage
//!
//! Defines the [`JwtVerificationStrategyStorage`] trait and the default
//! [`FileSystemJwtVerificationStrategyStore`] implementation.
//!
//! # Storage layout (filesystem)
//! ```text
//! _storage/
//! └── jwt_verification_strategies/
//!     ├── {uuid}.json
//!     └── ...
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use tracing::info;
use uuid::Uuid;

use crate::jwt_bearer::models::JwtVerificationStrategy;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};

// ── Trait ────────────────────────────────────────────────────────────────────

/// Storage backend for JWT verification strategy configurations.
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait JwtVerificationStrategyStorage: Send + Sync {
    /// Create a new JWT verification strategy.
    ///
    /// The `id`, `created_at`, and `updated_at` fields are populated automatically;
    /// any values supplied for those fields are ignored.
    async fn create(
        &self,
        strategy: JwtVerificationStrategy,
    ) -> Result<JwtVerificationStrategy>;

    /// Retrieve a strategy by its UUID.
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<JwtVerificationStrategy>>;

    /// List all registered strategies.
    async fn list(&self) -> Result<Vec<JwtVerificationStrategy>>;

    /// Update an existing strategy.
    ///
    /// Returns `Err` if the strategy does not exist.
    /// The `id` and `created_at` fields are preserved; `updated_at` is refreshed.
    async fn update(
        &self,
        strategy: JwtVerificationStrategy,
    ) -> Result<JwtVerificationStrategy>;

    /// Delete a strategy by its UUID.
    ///
    /// Silently succeeds if the strategy does not exist.
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}

// ── Filesystem implementation ─────────────────────────────────────────────────

/// JWT verification strategies are keyed on their UUID for filesystem storage.
impl StorableEntity for JwtVerificationStrategy {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Filesystem-backed JWT verification strategy store.
///
/// Each strategy is persisted as `{storage_dir}/{id}.json` through the generic
/// storage backend (inheriting encryption at rest and atomic writes). Reads are
/// served from the backend's in-memory cache for low-latency access.
pub struct FileSystemJwtVerificationStrategyStore {
    storage: Box<dyn StorageBackend<JwtVerificationStrategy>>,
}

impl FileSystemJwtVerificationStrategyStore {
    /// Create (or open) the store at `storage_dir`, loading all existing strategies.
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "jwt_verification_strategy")
            .await
            .context("Failed to open JWT verification strategy storage")?;
        let store = Self { storage };
        info!(
            "Initialised FileSystemJwtVerificationStrategyStore with {} strategy/strategies",
            store
                .storage
                .list_all()
                .await?
                .len()
        );
        Ok(store)
    }

    /// Re-read all strategy files from disk and reconcile the in-memory cache.
    /// Safe to call from a hot-reload watcher.
    #[allow(dead_code)]
    pub async fn reload(&self) -> Result<()> {
        let _access_change =
            crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::Appliance);
        info!("Reloading JWT verification strategy store from disk");
        self.storage
            .refresh_from_disk()
            .await
    }
}

#[async_trait]
impl JwtVerificationStrategyStorage for FileSystemJwtVerificationStrategyStore {
    async fn create(
        &self,
        mut strategy: JwtVerificationStrategy,
    ) -> Result<JwtVerificationStrategy> {
        let now = Utc::now();
        strategy.id = Uuid::new_v4().to_string();
        strategy.created_at = now;
        strategy.updated_at = now;

        let _access_change = crate::mcp::subscriptions::AccessChange::begin(
            crate::mcp::subscriptions::AccessScope::owned_by(strategy.tenant_id.as_deref()),
        );
        self.storage
            .save(&strategy)
            .await?;
        info!("Created JWT verification strategy {} ({})", strategy.name, strategy.id);
        Ok(strategy)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<JwtVerificationStrategy>> {
        self.storage.get(id).await
    }

    async fn list(&self) -> Result<Vec<JwtVerificationStrategy>> {
        let mut strategies = self
            .storage
            .list_all()
            .await?;
        // Deterministic order by creation time for stable API responses
        strategies.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
        });
        Ok(strategies)
    }

    async fn update(
        &self,
        mut strategy: JwtVerificationStrategy,
    ) -> Result<JwtVerificationStrategy> {
        let existing = self
            .storage
            .get(&strategy.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("JWT verification strategy not found: {}", strategy.id))?;

        // Preserve immutable fields
        strategy.created_at = existing.created_at;
        strategy.updated_at = Utc::now();

        let _access_change =
            crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::reowned(
                existing.tenant_id.as_deref(),
                strategy.tenant_id.as_deref(),
            ));
        self.storage
            .save(&strategy)
            .await?;
        info!("Updated JWT verification strategy {} ({})", strategy.name, strategy.id);
        Ok(strategy)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        let existing = self.storage.get(id).await?;
        let _access_change =
            crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::owned_by(
                existing
                    .as_ref()
                    .and_then(|strategy| strategy.tenant_id.as_deref()),
            ));
        self.storage
            .delete(id)
            .await?;
        info!("Deleted JWT verification strategy {}", id);
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt_bearer::models::{JwksSource, JwtVerificationStrategy};
    use tempfile::TempDir;

    async fn make_store() -> (FileSystemJwtVerificationStrategyStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = FileSystemJwtVerificationStrategyStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        (store, tmp)
    }

    fn sample_strategy() -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: String::new(), // populated by create()
            tenant_id: None,
            name: "Test IdP".to_string(),
            expected_issuer: "https://idp.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://idp.example.com/.well-known/jwks.json".to_string(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_create_assigns_uuid() {
        let (store, _tmp) = make_store().await;
        let p = store
            .create(sample_strategy())
            .await
            .unwrap();
        assert!(!p.id.is_empty());
        assert!(Uuid::parse_str(&p.id).is_ok());
    }

    #[tokio::test]
    async fn test_get_returns_created_strategy() {
        let (store, _tmp) = make_store().await;
        let created = store
            .create(sample_strategy())
            .await
            .unwrap();
        let found = store
            .get(&created.id)
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Test IdP");
    }

    #[tokio::test]
    async fn test_get_returns_none_for_missing() {
        let (store, _tmp) = make_store().await;
        let result = store
            .get("non-existent")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_returns_all_strategies() {
        let (store, _tmp) = make_store().await;
        store
            .create(sample_strategy())
            .await
            .unwrap();
        let mut s2 = sample_strategy();
        s2.name = "Second IdP".to_string();
        store
            .create(s2)
            .await
            .unwrap();
        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_update_changes_fields_and_refreshes_updated_at() {
        let (store, _tmp) = make_store().await;
        let created = store
            .create(sample_strategy())
            .await
            .unwrap();
        let original_created_at = created.created_at;

        let mut updated = created.clone();
        updated.name = "Renamed IdP".to_string();
        let result = store
            .update(updated)
            .await
            .unwrap();

        assert_eq!(result.name, "Renamed IdP");
        assert_eq!(result.created_at, original_created_at);
        assert!(result.updated_at >= original_created_at);
    }

    #[tokio::test]
    async fn test_update_non_existent_returns_error() {
        let (store, _tmp) = make_store().await;
        let mut s = sample_strategy();
        s.id = "non-existent".to_string();
        assert!(store.update(s).await.is_err());
    }

    #[tokio::test]
    async fn test_delete_removes_strategy() {
        let (store, _tmp) = make_store().await;
        let created = store
            .create(sample_strategy())
            .await
            .unwrap();
        store
            .delete(&created.id)
            .await
            .unwrap();
        assert!(
            store
                .get(&created.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_non_existent_is_ok() {
        let (store, _tmp) = make_store().await;
        assert!(
            store
                .delete("ghost")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_load_from_disk_on_startup() {
        let tmp = TempDir::new().unwrap();

        let store1 = FileSystemJwtVerificationStrategyStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        let created = store1
            .create(sample_strategy())
            .await
            .unwrap();

        let store2 = FileSystemJwtVerificationStrategyStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();

        let found = store2
            .get(&created.id)
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Test IdP");
    }

    #[tokio::test]
    async fn test_reload_picks_up_new_file() {
        let tmp = TempDir::new().unwrap();
        let store = FileSystemJwtVerificationStrategyStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();

        let mut strategy = sample_strategy();
        strategy.id = Uuid::new_v4().to_string();
        strategy.created_at = Utc::now();
        strategy.updated_at = Utc::now();
        let path = tmp
            .path()
            .join(format!("{}.json", strategy.id));
        std::fs::write(&path, serde_json::to_string(&strategy).unwrap()).unwrap();

        // Cache-backed reads (list) do not see the externally-written file yet.
        assert!(
            store
                .list()
                .await
                .unwrap()
                .iter()
                .all(|s| s.id != strategy.id)
        );

        store.reload().await.unwrap();

        // After reload the cache is reconciled with disk.
        assert!(
            store
                .list()
                .await
                .unwrap()
                .iter()
                .any(|s| s.id == strategy.id)
        );
    }
}
