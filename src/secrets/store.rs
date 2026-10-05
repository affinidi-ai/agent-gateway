//! Secrets Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};

/// Secrets storage backend trait
#[async_trait]
pub trait SecretsStore: Send + Sync {
    /// Create a new secret
    async fn create(
        &self,
        request: CreateSecretRequest,
    ) -> Result<Secret>;

    /// Get a secret by internal storage ID (includes sensitive value)
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Secret>>;

    /// Get a secret by its public `secret_id` identifier.
    async fn get_by_secret_id(
        &self,
        secret_id: &str,
    ) -> Result<Option<Secret>> {
        let Some(secret) = self
            .list_all()
            .await?
            .into_iter()
            .find(|secret| secret.secret_id == secret_id)
        else {
            return Ok(None);
        };

        self.get(secret.id.as_str())
            .await
    }

    /// List all secrets (without sensitive values)
    async fn list_all(&self) -> Result<Vec<SecretListItem>>;

    /// Update a secret
    async fn update(
        &self,
        id: &str,
        request: UpdateSecretRequest,
    ) -> Result<Secret>;

    async fn set_tenant_id(
        &self,
        _id: &str,
        _tenant_id: Option<String>,
    ) -> Result<Secret> {
        anyhow::bail!("Tenant reassignment is not supported by this SecretsStore")
    }

    /// Delete a secret
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Search secrets by tag
    async fn find_by_tag(
        &self,
        tag: &str,
    ) -> Result<Vec<SecretListItem>>;
}
