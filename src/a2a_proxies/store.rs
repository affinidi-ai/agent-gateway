use anyhow::Result;
use async_trait::async_trait;

use super::types::A2aProxy;

#[async_trait]
pub trait A2aProxyStore: Send + Sync {
    async fn create(
        &self,
        proxy: &A2aProxy,
    ) -> Result<()>;

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<A2aProxy>>;

    async fn list_all(&self) -> Result<Vec<A2aProxy>>;

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    async fn update(
        &self,
        proxy: &A2aProxy,
    ) -> Result<()>;
}
