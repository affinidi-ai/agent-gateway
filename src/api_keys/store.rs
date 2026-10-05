//! API Key storage and validation traits

use async_trait::async_trait;
use std::collections::HashMap;

use super::types::ApiKeyRecord;
use super::{ApiKeyCreated, ApiKeyMeta, ApiKeyResult};

/// Storage backend trait for API keys
///
/// Implementations must be thread-safe and support concurrent access.
/// The filesystem implementation uses DashMap for caching.
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Create a new API key for an agent
    ///
    /// # Arguments
    /// * `agent_id` - The agent this key belongs to
    /// * `client_id` - External client identifier
    /// * `labels` - Optional key-value labels
    /// * `actor` - Who is creating this key (for audit)
    ///
    /// # Returns
    /// The created key with its secret (shown only once)
    async fn create_with_material(
        &self,
        agent_id: &str,
        key_id: String,
        secret: String,
        client_id: &str,
        labels: Option<HashMap<String, String>>,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated>;

    #[cfg(test)]
    async fn create(
        &self,
        agent_id: &str,
        client_id: &str,
        labels: Option<HashMap<String, String>>,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated> {
        let (key_id, secret) = super::generator::DefaultKeyGenerator::generate();
        self.create_with_material(agent_id, key_id, secret, client_id, labels, actor)
            .await
    }

    /// List all keys for an agent (metadata only, no secrets)
    async fn list(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<Vec<ApiKeyMeta>>;

    /// List all keys across all agents (metadata only, no secrets)
    async fn list_all(&self) -> ApiKeyResult<Vec<ApiKeyMeta>>;

    /// Get a specific key's full stored record (includes the secret hash, never
    /// the raw secret). Internal use only — backs revoke/rotate/delete.
    async fn get_record(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<Option<ApiKeyRecord>>;

    /// Revoke a key (cannot be undone)
    ///
    /// # Arguments
    /// * `agent_id` - The agent this key belongs to
    /// * `key_id` - The key to revoke
    /// * `actor` - Who is revoking this key (for audit)
    async fn revoke(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<()>;

    /// Rotate a key: issue a fresh secret in place, keeping the same `key_id`
    ///
    /// The `key_id` is preserved so any `from_api_key` managed identity keyed
    /// on it continues to resolve to the same DID after rotation.
    ///
    /// # Arguments
    /// * `agent_id` - The agent this key belongs to
    /// * `key_id` - The key to rotate
    /// * `actor` - Who is rotating this key (for audit)
    ///
    /// # Returns
    /// The rotated key with its new secret (shown only once)
    async fn rotate(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated>;

    /// Delete a key permanently
    ///
    /// # Arguments
    /// * `agent_id` - The agent this key belongs to
    /// * `key_id` - The key to delete
    /// * `actor` - Who is deleting the key (for audit)
    async fn delete(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<()>;

    /// Update last_used_at timestamp (best-effort, non-blocking)
    ///
    /// This is called on successful validation and should not fail loudly.
    #[allow(unused)]
    async fn touch_usage(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<()>;
}

/// Validation trait for API key authentication
///
/// This is a narrower interface used by the auth path to validate
/// presented API keys without exposing full storage operations.
#[async_trait]
pub trait ApiKeyValidator: Send + Sync {
    /// Validate a presented API key
    ///
    /// # Arguments
    /// * `agent_id` - The agent the key should belong to
    /// * `presented_key` - The secret value presented by the client
    ///
    /// # Returns
    /// * `Ok(Some(meta))` - Key is valid and active
    /// * `Ok(None)` - Key not found or revoked
    /// * `Err(_)` - Storage/internal error
    async fn validate(
        &self,
        agent_id: &str,
        presented_key: &str,
    ) -> ApiKeyResult<Option<ApiKeyMeta>>;
}
