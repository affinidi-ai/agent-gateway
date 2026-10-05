pub use super::A2aProxyStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use super::types::A2aProxy;
use crate::storage::filesystem::{StorageBackend, cached_storage};

pub struct FileSystemA2aProxyStore {
    storage: Box<dyn StorageBackend<A2aProxy>>,
}

impl FileSystemA2aProxyStore {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "a2a_proxy").await?;
        Ok(Self { storage })
    }
}

#[async_trait]
impl A2aProxyStore for FileSystemA2aProxyStore {
    async fn create(
        &self,
        proxy: &A2aProxy,
    ) -> Result<()> {
        proxy
            .validate()
            .map_err(anyhow::Error::msg)?;
        self.storage.save(proxy).await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<A2aProxy>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<A2aProxy>> {
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
        proxy: &A2aProxy,
    ) -> Result<()> {
        proxy
            .validate()
            .map_err(anyhow::Error::msg)?;
        self.storage.save(proxy).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a_proxies::types::{
        A2aProxy, A2aProxyBackend, CopilotDirectLineBackend, DEFAULT_DIRECT_LINE_BASE_URL,
        DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS, DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS, DEFAULT_DIRECT_LINE_TIMEOUT_SECS,
        DirectLineCredentialMode,
    };

    fn proxy() -> A2aProxy {
        A2aProxy::new(
            "worker".to_string(),
            "Copilot worker".to_string(),
            A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
                secret_id: "direct-line-secret".to_string(),
                credential_mode: DirectLineCredentialMode::Secret,
                base_url: DEFAULT_DIRECT_LINE_BASE_URL.to_string(),
                timeout_secs: DEFAULT_DIRECT_LINE_TIMEOUT_SECS,
                poll_interval_ms: DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
                max_poll_attempts: DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
            }),
            None,
        )
    }

    #[tokio::test]
    async fn create_get_update_delete_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemA2aProxyStore::new(dir.path().to_path_buf())
            .await
            .expect("store");
        let mut proxy = proxy();
        let id = proxy.id.clone();

        store
            .create(&proxy)
            .await
            .expect("create");
        assert_eq!(
            store
                .get(&id)
                .await
                .expect("get")
                .expect("stored")
                .name,
            "worker"
        );

        proxy.name = "updated worker".to_string();
        proxy.updated_at = chrono::Utc::now();
        store
            .update(&proxy)
            .await
            .expect("update");
        assert_eq!(
            store
                .get(&id)
                .await
                .expect("get")
                .expect("stored")
                .name,
            "updated worker"
        );

        store
            .delete(&id)
            .await
            .expect("delete");
        assert!(
            store
                .get(&id)
                .await
                .expect("get")
                .is_none()
        );
    }
}
