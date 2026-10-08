pub use super::McpProxyStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use super::types::McpProxy;
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Filesystem-based implementation of McpProxyStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemMcpProxyStore {
    storage: Box<dyn StorageBackend<McpProxy>>,
}

impl FileSystemMcpProxyStore {
    /// Create a new FileSystemMcpProxyStore with in-memory cache
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "mcp_proxy").await?;
        Ok(Self { storage })
    }
}

#[async_trait]
impl McpProxyStore for FileSystemMcpProxyStore {
    async fn create(
        &self,
        proxy: &McpProxy,
    ) -> Result<()> {
        self.storage
            .save(proxy)
            .await?;
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::owned_by(
            proxy.tenant_id.as_deref(),
        ));
        crate::mcp::subscriptions::catalog_subscriptions()
            .publish(&proxy.id, crate::mcp::subscriptions::CatalogChange::Closed);
        Ok(())
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<McpProxy>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<McpProxy>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        let previous = self.storage.get(id).await?;
        self.storage
            .delete(id)
            .await?;
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::owned_by(
            previous
                .as_ref()
                .and_then(|proxy| proxy.tenant_id.as_deref()),
        ));
        crate::mcp::subscriptions::catalog_subscriptions()
            .publish(id, crate::mcp::subscriptions::CatalogChange::Closed);
        Ok(())
    }

    async fn update(
        &self,
        proxy: &McpProxy,
    ) -> Result<()> {
        let previous = self
            .storage
            .get(&proxy.id)
            .await?;
        self.storage
            .save(proxy)
            .await?;
        let scope = crate::mcp::subscriptions::AccessScope::reowned(
            previous
                .as_ref()
                .map_or(proxy.tenant_id.as_deref(), |previous| previous.tenant_id.as_deref()),
            proxy.tenant_id.as_deref(),
        );
        let close = previous.is_none_or(|previous| {
            proxy.status != super::types::McpProxyStatus::Active
                || previous.status != proxy.status
                || previous.tenant_id != proxy.tenant_id
                || previous.base_url != proxy.base_url
                || previous.endpoint_path != proxy.endpoint_path
                || previous.channel_prefix != proxy.channel_prefix
                || previous.mcp_http != proxy.mcp_http
        });
        if close {
            crate::mcp::subscriptions::invalidate_access(scope);
        }
        crate::mcp::subscriptions::catalog_subscriptions().publish(
            &proxy.id,
            if close {
                crate::mcp::subscriptions::CatalogChange::Closed
            } else {
                crate::mcp::subscriptions::CatalogChange::Changed
            },
        );
        Ok(())
    }
}
