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
}
