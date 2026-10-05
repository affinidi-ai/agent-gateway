//! MCP Proxy Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::McpProxy;

/// Trait for storing MCP Proxy records
#[async_trait]
pub trait McpProxyStore: Send + Sync {
    /// Create an MCP Proxy
    async fn create(
        &self,
        proxy: &McpProxy,
    ) -> Result<()>;

    /// Get an MCP Proxy by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<McpProxy>>;

    /// List all MCP Proxies
    async fn list_all(&self) -> Result<Vec<McpProxy>>;

    /// Delete an MCP Proxy by ID
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Update an MCP Proxy
    async fn update(
        &self,
        proxy: &McpProxy,
    ) -> Result<()>;
}
