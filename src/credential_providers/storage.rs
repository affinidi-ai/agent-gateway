//! Filesystem storage for credential providers

use super::CredentialProvider;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Trait for credential provider storage operations
#[async_trait]
pub trait CredentialProviderStorage: Send + Sync {
    async fn create(
        &self,
        provider: CredentialProvider,
    ) -> Result<CredentialProvider>;
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<CredentialProvider>>;
    async fn list(&self) -> Result<Vec<CredentialProvider>>;
    async fn update(
        &self,
        provider: CredentialProvider,
    ) -> Result<CredentialProvider>;
    async fn delete(
        &self,
        id: &str,
    ) -> Result<bool>;
    async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<CredentialProvider>>;

    /// Reconcile any in-memory cache with the backing storage, picking up records
    /// another node wrote. A store without a cache has nothing to reconcile.
    async fn refresh_from_disk(&self) -> Result<()> {
        Ok(())
    }
}

/// Filesystem-backed credential provider storage using DashMap cache
pub struct FileSystemCredentialProviderStore {
    storage: Box<dyn StorageBackend<CredentialProvider>>,
}

impl FileSystemCredentialProviderStore {
    pub async fn new(path: PathBuf) -> Result<Self> {
        let storage = cached_storage(path.clone(), "credential_provider").await?;
        info!(
            target: "credential_delegation",
            path = %path.display(),
            "Credential provider store initialized"
        );
        Ok(Self { storage })
    }
}

#[async_trait]
impl CredentialProviderStorage for FileSystemCredentialProviderStore {
    async fn create(
        &self,
        provider: CredentialProvider,
    ) -> Result<CredentialProvider> {
        let _access_change = crate::mcp::subscriptions::AccessChange::begin(
            crate::mcp::subscriptions::AccessScope::owned_by(provider.tenant_id.as_deref()),
        );
        self.storage
            .save(&provider)
            .await
            .context("Failed to save credential provider")?;
        info!(
            target: "credential_delegation",
            id = %provider.id,
            name = %provider.name,
            provider_id = %provider.provider_id,
            provider_type = ?provider.provider_type,
            "Credential provider created"
        );
        Ok(provider)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<CredentialProvider>> {
        self.storage.get(id).await
    }

    async fn list(&self) -> Result<Vec<CredentialProvider>> {
        self.storage.list_all().await
    }

    async fn update(
        &self,
        provider: CredentialProvider,
    ) -> Result<CredentialProvider> {
        let previous = self
            .storage
            .get(&provider.id)
            .await?;
        let _access_change =
            crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::reowned(
                previous
                    .as_ref()
                    .map_or(provider.tenant_id.as_deref(), |previous| previous.tenant_id.as_deref()),
                provider.tenant_id.as_deref(),
            ));
        self.storage
            .save(&provider)
            .await
            .context("Failed to update credential provider")?;
        info!(
            target: "credential_delegation",
            id = %provider.id,
            name = %provider.name,
            "Credential provider updated"
        );
        Ok(provider)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<bool> {
        // Check existence first since StorageBackend::delete returns ()
        let existing = self.storage.get(id).await?;
        let exists = existing.is_some();
        if let Some(existing) = existing {
            let _access_change = crate::mcp::subscriptions::AccessChange::begin(
                crate::mcp::subscriptions::AccessScope::owned_by(existing.tenant_id.as_deref()),
            );
            self.storage
                .delete(id)
                .await?;
            info!(
                target: "credential_delegation",
                id = %id,
                "Credential provider deleted"
            );
        }
        Ok(exists)
    }

    async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<CredentialProvider>> {
        let all = self
            .storage
            .list_all()
            .await?;
        Ok(all
            .into_iter()
            .find(|p| p.provider_id == provider_id))
    }

    async fn refresh_from_disk(&self) -> Result<()> {
        let _access_change =
            crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::Appliance);
        self.storage
            .refresh_from_disk()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_provider() -> CredentialProvider {
        serde_json::from_value(serde_json::json!({
            "id": "provider-a",
            "name": "Calendar",
            "provider_id": "calendar",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn refresh_from_disk_picks_up_another_nodes_update() {
        let tmp = tempfile::TempDir::new().unwrap();
        let writer = FileSystemCredentialProviderStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        writer
            .create(sample_provider())
            .await
            .unwrap();
        let reader = FileSystemCredentialProviderStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        writer
            .update(CredentialProvider {
                name: "Renamed".to_string(),
                ..sample_provider()
            })
            .await
            .unwrap();

        let before = reader
            .get("provider-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.name, "Calendar");

        reader
            .refresh_from_disk()
            .await
            .unwrap();
        let after = reader
            .get("provider-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.name, "Renamed");
    }

    struct UncachedStore;

    #[async_trait]
    impl CredentialProviderStorage for UncachedStore {
        async fn create(
            &self,
            provider: CredentialProvider,
        ) -> Result<CredentialProvider> {
            Ok(provider)
        }

        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<CredentialProvider>> {
            Ok(None)
        }

        async fn list(&self) -> Result<Vec<CredentialProvider>> {
            Ok(vec![])
        }

        async fn update(
            &self,
            provider: CredentialProvider,
        ) -> Result<CredentialProvider> {
            Ok(provider)
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> Result<bool> {
            Ok(false)
        }

        async fn find_by_provider_id(
            &self,
            _provider_id: &str,
        ) -> Result<Option<CredentialProvider>> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn a_store_without_a_cache_has_nothing_to_reconcile() {
        let store = UncachedStore;
        store
            .refresh_from_disk()
            .await
            .expect("the default reconcile succeeds");
    }
}

#[cfg(test)]
mod unknown_type_tests {
    use super::*;
    use serde_json::json;

    fn provider_json(
        id: &str,
        provider_type: &str,
    ) -> String {
        json!({
            "id": id, "name": id, "provider_id": id, "provider_type": provider_type,
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        })
        .to_string()
    }

    /// A provider record with an unrecognised provider_type is skipped and counted as an
    /// unreadable record, and the other providers still load.
    #[tokio::test]
    async fn a_provider_of_an_unknown_type_is_skipped_alone() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory
                .path()
                .join("known.json"),
            provider_json("known", "oauth2_client_credentials"),
        )
        .unwrap();
        std::fs::write(
            directory
                .path()
                .join("unknown.json"),
            provider_json("unknown", "an_unknown_type"),
        )
        .unwrap();
        let counted = || {
            crate::metrics::backends::prometheus::STORAGE_LOAD_ERRORS
                .with_label_values(&["credential_provider", "unreadable_record"])
                .get()
        };
        let before = counted();

        let store = FileSystemCredentialProviderStore::new(directory.path().to_path_buf())
            .await
            .unwrap();

        assert!(
            store
                .get("known")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get("unknown")
                .await
                .unwrap()
                .is_none()
        );
        assert!(counted() > before);
    }
}
