pub use super::GatewayStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;

use super::types::{Gateway, GatewayType};
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Filesystem-based implementation of GatewayStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemGatewayStore {
    storage: Box<dyn StorageBackend<Gateway>>,
}

impl FileSystemGatewayStore {
    /// Create a new FileSystemGatewayStore with in-memory cache
    pub async fn new(
        storage_dir: PathBuf,
        proxy_did: Option<String>,
    ) -> Result<Self> {
        let storage = cached_storage(storage_dir, "gateway").await?;
        let store = Self { storage };

        let all_gateways = store.list_all().await?;
        if all_gateways.is_empty() {
            // First boot: create the self-gateway with the current proxy DID
            let did = proxy_did.unwrap_or_else(|| "did:web:localhost:8443".to_string());
            let self_gateway = Gateway::new(
                "This Gateway (Local)".to_string(),
                "This local Affinidi Trust Fabric Agent Gateway instance".to_string(),
                did,
                GatewayType::SelfGateway,
            );
            store
                .create(&self_gateway)
                .await?;
        } else if let Some(new_did) = proxy_did {
            // Subsequent boots: sync the self-gateway DID if it was migrated (e.g. did:web → did:webvh)
            if let Some(mut self_gw) = all_gateways
                .into_iter()
                .find(|g| g.gateway_type == GatewayType::SelfGateway)
                && self_gw.did != new_did
            {
                tracing::info!("Updating self-gateway DID: {} → {}", self_gw.did, new_did);
                self_gw.did = new_did;
                store.update(&self_gw).await?;
            }
        }

        Ok(store)
    }

    /// Reconcile the in-memory cache with the shared-storage directory, so a
    /// node promoted from standby recompiles gateway OPA from the active
    /// writer's latest gateway records rather than a stale boot snapshot.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }
}

#[async_trait]
impl GatewayStore for FileSystemGatewayStore {
    async fn create(
        &self,
        gateway: &Gateway,
    ) -> Result<()> {
        self.storage
            .save(gateway)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Gateway>> {
        self.storage.get(id).await
    }

    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Gateway>> {
        let all = self
            .storage
            .list_all()
            .await?;
        Ok(all
            .into_iter()
            .find(|g| g.did == did))
    }

    async fn list_all(&self) -> Result<Vec<Gateway>> {
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
        gateway: &Gateway,
    ) -> Result<()> {
        // Update is the same as create for filesystem implementation
        self.storage
            .save(gateway)
            .await
    }
}

/// Get the ID of the local (self) gateway
pub async fn get_local_gateway_id(store: &Arc<dyn GatewayStore>) -> Option<String> {
    match store.list_all().await {
        Ok(gateways) => gateways
            .into_iter()
            .find(|g| g.gateway_type == GatewayType::SelfGateway)
            .map(|g| g.id),
        Err(e) => {
            tracing::error!("Failed to list gateways to find local gateway ID: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn filesystem_store_get_by_did_returns_issuer_did() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemGatewayStore::new(dir.path().to_path_buf(), Some("did:web:self.example".to_string()))
            .await
            .expect("store");
        let mut remote = Gateway::new(
            "peer".to_string(),
            String::new(),
            "did:web:peer.example:connection-points:1111".to_string(),
            GatewayType::Remote,
        );
        remote.issuer_did = Some("did:web:peer.example".to_string());
        store
            .create(&remote)
            .await
            .expect("create");

        let by_did = store
            .get_by_did("did:web:peer.example:connection-points:1111")
            .await
            .expect("get_by_did")
            .expect("record");
        let reopened = FileSystemGatewayStore::new(dir.path().to_path_buf(), None)
            .await
            .expect("reopen")
            .get(&remote.id)
            .await
            .expect("get")
            .expect("persisted record");

        assert_eq!(by_did.issuer_did, Some("did:web:peer.example".to_string()));
        assert_eq!(reopened.issuer_did, Some("did:web:peer.example".to_string()));
    }
}
