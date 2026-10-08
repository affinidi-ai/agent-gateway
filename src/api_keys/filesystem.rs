//! Filesystem-based API key storage
//!
//! Stores API keys as JSON files organized by agent:
//! ```text
//! _storage/api_keys/{agent_id}/{key_id}.json
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use tokio::fs;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::errors::{ApiKeyError, ApiKeyResult};
use super::generator::{DefaultKeyGenerator, constant_time_compare, hash_secret};
use super::store::{ApiKeyStore, ApiKeyValidator};
use super::types::{ApiKeyCreated, ApiKeyIssuer, ApiKeyMeta, ApiKeyRecord, ApiKeyStatus};
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Filesystem-based API key store.
///
/// Each agent's keys live in their own `{storage_dir}/{agent_id}` directory,
/// backed by a generic [`CachedFilesystemStorage`] — the same storage backend
/// used for surfaces, mediators, and every other [`StorableEntity`]. Encryption
/// at rest is therefore inherited from the process-wide storage config: when
/// filesystem encryption is enabled, keys are written as `{key_id}.json.enc`;
/// otherwise as plaintext `{key_id}.json`.
///
/// [`CachedFilesystemStorage`]: crate::storage::filesystem::CachedFilesystemStorage
/// [`StorableEntity`]: crate::storage::filesystem::StorableEntity
pub struct FileSystemApiKeyStore {
    /// Base storage directory (contains one subdirectory per agent).
    storage_dir: PathBuf,
    /// Per-agent generic stores: agent_id -> store.
    stores: Arc<DashMap<String, Arc<dyn StorageBackend<ApiKeyRecord>>>>,
    /// Per-agent secret-hash lookup: agent_id -> (secret_hash -> key_id).
    ///
    /// Lets validation resolve a presented key to its record in O(1) instead of
    /// scanning every key for the agent. Kept in sync on create/rotate/delete
    /// and rebuilt from disk on load. Legacy records without a `secret_hash`
    /// are absent here, so they never validate (rotation required).
    hash_index: Arc<DashMap<String, DashMap<String, String>>>,
    /// Serializes lazy per-agent store creation so two concurrent writers for a
    /// new agent don't build (and leak) two stores for the same directory.
    create_lock: Mutex<()>,
}

impl FileSystemApiKeyStore {
    /// Create a new filesystem API key store
    ///
    /// # Arguments
    /// * `storage_path` - Base directory for API key storage
    pub async fn new(storage_path: &str) -> ApiKeyResult<Self> {
        let storage_dir = PathBuf::from(storage_path);

        // Create storage directory if it doesn't exist
        fs::create_dir_all(&storage_dir).await?;

        let store = Self {
            storage_dir,
            stores: Arc::new(DashMap::new()),
            hash_index: Arc::new(DashMap::new()),
            create_lock: Mutex::new(()),
        };

        // Build per-agent stores and load existing keys into memory
        store
            .load_existing_agents()
            .await?;

        info!("Initialized FileSystemApiKeyStore at: {}", store.storage_dir.display());

        Ok(store)
    }

    /// Get the directory that holds an agent's key files.
    fn agent_dir(
        &self,
        agent_id: &str,
    ) -> PathBuf {
        self.storage_dir
            .join(agent_id)
    }

    /// Scan the storage root and build a per-agent generic store for every
    /// existing agent directory, loading (and, when encryption at rest is on,
    /// transparently migrating) each agent's keys into memory.
    async fn load_existing_agents(&self) -> ApiKeyResult<()> {
        let mut entries = match fs::read_dir(&self.storage_dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir()
                && let Some(agent_id) = path
                    .file_name()
                    .and_then(|n| n.to_str())
                && let Err(e) = self
                    .agent_store(agent_id)
                    .await
            {
                warn!("Failed to load keys for agent {}: {}", agent_id, e);
            }
        }

        Ok(())
    }

    /// Get (or lazily create) the generic filesystem store backing one agent's
    /// keys. Each agent maps to its own `{storage_dir}/{agent_id}` directory,
    /// served by a store that inherits the process-wide storage config — so API
    /// keys are encrypted at rest exactly like every other [`StorableEntity`]
    /// (surfaces, mediators, …) when encryption is enabled.
    ///
    /// [`StorableEntity`]: crate::storage::filesystem::StorableEntity
    async fn agent_store(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<Arc<dyn StorageBackend<ApiKeyRecord>>> {
        if let Some(store) = self
            .stores
            .get(agent_id)
            .map(|s| s.value().clone())
        {
            return Ok(store);
        }

        crate::storage::validate_storage_id(agent_id).map_err(|e| ApiKeyError::validation(e.to_string()))?;

        let _guard = self.create_lock.lock().await;
        if let Some(store) = self
            .stores
            .get(agent_id)
            .map(|s| s.value().clone())
        {
            return Ok(store);
        }

        let agent_dir = self.agent_dir(agent_id);

        // Defense-in-depth: confirm the resolved path stays inside storage_dir
        crate::storage::assert_within_storage_dir(&self.storage_dir, &agent_dir)
            .map_err(|e| ApiKeyError::validation(e.to_string()))?;

        let store: Arc<dyn StorageBackend<ApiKeyRecord>> = cached_storage::<ApiKeyRecord>(agent_dir, "api_key")
            .await?
            .into();
        self.stores
            .insert(agent_id.to_string(), store.clone());

        // Build the secret-hash lookup for this agent from disk. Legacy records
        // without a `secret_hash` are skipped and therefore never validate.
        let index = DashMap::new();
        for record in store.list_all().await? {
            if let Some(ref hash) = record.secret_hash {
                index.insert(hash.clone(), record.key_id.clone());
            }
        }
        self.hash_index
            .insert(agent_id.to_string(), index);

        Ok(store)
    }

    /// Insert or replace this record's `secret_hash -> key_id` entry.
    fn index_secret_hash(
        &self,
        record: &ApiKeyRecord,
    ) {
        if let Some(ref hash) = record.secret_hash {
            self.hash_index
                .entry(record.agent_id.clone())
                .or_default()
                .insert(hash.clone(), record.key_id.clone());
        }
    }

    /// Remove a single `secret_hash` entry from an agent's index.
    fn unindex_secret_hash(
        &self,
        agent_id: &str,
        secret_hash: &str,
    ) {
        if let Some(index) = self.hash_index.get(agent_id) {
            index.remove(secret_hash);
        }
    }

    /// Persist a key record through its agent's generic store (encrypting at
    /// rest when configured) and refresh the store's cache.
    async fn save_record(
        &self,
        record: &ApiKeyRecord,
    ) -> ApiKeyResult<()> {
        let store = self
            .agent_store(&record.agent_id)
            .await?;
        store.save(record).await?;
        Ok(())
    }

    /// Delete a key record from its agent's generic store, if the store exists.
    async fn delete_record(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<()> {
        if let Some(store) = self
            .stores
            .get(agent_id)
            .map(|s| s.value().clone())
        {
            store.delete(key_id).await?;
        }
        Ok(())
    }

    /// Read a full key record (including secret) from its agent's store.
    async fn get_record_internal(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<Option<ApiKeyRecord>> {
        match self
            .stores
            .get(agent_id)
            .map(|s| s.value().clone())
        {
            Some(store) => Ok(store.get(key_id).await?),
            None => Ok(None),
        }
    }

    /// Find a key by presented secret (for validation).
    ///
    /// Hashes the presented key and resolves it through the agent's in-memory
    /// `secret_hash -> key_id` index in O(1), then loads the single matching
    /// record. A final constant-time hash comparison guards against a stale
    /// index entry.
    async fn find_by_secret(
        &self,
        agent_id: &str,
        secret: &str,
    ) -> ApiKeyResult<Option<ApiKeyRecord>> {
        let presented_hash = hash_secret(secret);

        let Some(key_id) = self
            .hash_index
            .get(agent_id)
            .and_then(|index| {
                index
                    .get(&presented_hash)
                    .map(|kv| kv.value().clone())
            })
        else {
            return Ok(None);
        };

        let Some(record) = self
            .get_record_internal(agent_id, &key_id)
            .await?
        else {
            return Ok(None);
        };

        match record.secret_hash {
            Some(ref stored_hash) if constant_time_compare(stored_hash, &presented_hash) => Ok(Some(record)),
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl ApiKeyStore for FileSystemApiKeyStore {
    async fn create_with_material(
        &self,
        agent_id: &str,
        key_id: String,
        secret: String,
        client_id: &str,
        labels: Option<HashMap<String, String>>,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated> {
        // Validate inputs — reject empty, traversal sequences, and multi-component paths
        crate::storage::validate_storage_id(agent_id).map_err(|e| ApiKeyError::validation(e.to_string()))?;
        crate::storage::validate_storage_id(client_id).map_err(|e| ApiKeyError::validation(e.to_string()))?;

        let now = Utc::now();

        let record = ApiKeyRecord {
            key_id: key_id.clone(),
            agent_id: agent_id.to_string(),
            client_id: client_id.to_string(),
            secret_hash: Some(hash_secret(&secret)),
            status: ApiKeyStatus::Active,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
            labels: labels.unwrap_or_default(),
            issuer: ApiKeyIssuer {
                actor: actor.to_string(),
                method: "api".to_string(),
            },
            rotated_from: None,
        };

        self.save_record(&record)
            .await?;
        self.index_secret_hash(&record);

        info!(
            agent_id = %agent_id,
            key_id = %key_id,
            client_id = %client_id,
            actor = %actor,
            "Created API key"
        );

        Ok(ApiKeyCreated {
            key_id,
            secret,
            agent_id: agent_id.to_string(),
            client_id: client_id.to_string(),
            created_at: now,
            rotated_from: None,
        })
    }

    async fn list(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        let keys = match self
            .stores
            .get(agent_id)
            .map(|s| s.value().clone())
        {
            Some(store) => store
                .list_all()
                .await?
                .into_iter()
                .map(ApiKeyMeta::from)
                .collect(),
            None => Vec::new(),
        };

        Ok(keys)
    }

    async fn get_record(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<Option<ApiKeyRecord>> {
        let record = self
            .get_record_internal(agent_id, key_id)
            .await?;
        if record.is_some() {
            info!(
                agent_id = %agent_id,
                key_id = %key_id,
                "API key record retrieved"
            );
        }
        Ok(record)
    }

    async fn revoke(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<()> {
        let mut record = self
            .get_record_internal(agent_id, key_id)
            .await?
            .ok_or_else(|| ApiKeyError::not_found(key_id))?;

        if record.status == ApiKeyStatus::Revoked {
            return Err(ApiKeyError::AlreadyRevoked { key_id: key_id.to_string() });
        }

        record.status = ApiKeyStatus::Revoked;
        record.revoked_at = Some(Utc::now());

        self.save_record(&record)
            .await?;
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::Appliance);

        info!(
            agent_id = %agent_id,
            key_id = %key_id,
            actor = %actor,
            "Revoked API key"
        );

        Ok(())
    }

    async fn rotate(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated> {
        let mut record = self
            .get_record_internal(agent_id, key_id)
            .await?
            .ok_or_else(|| ApiKeyError::not_found(key_id))?;

        if record.status == ApiKeyStatus::Revoked {
            return Err(ApiKeyError::AlreadyRevoked { key_id: key_id.to_string() });
        }

        // Rotate the secret in place — the key_id is preserved so any
        // `from_api_key` managed identity keyed on it keeps the same DID.
        let new_secret = DefaultKeyGenerator::generate_secret();
        let old_hash = record.secret_hash.take();
        record.secret_hash = Some(hash_secret(&new_secret));
        record.status = ApiKeyStatus::Active;
        record.revoked_at = None;
        record.last_used_at = None;
        record.issuer = ApiKeyIssuer {
            actor: actor.to_string(),
            method: "rotation".to_string(),
        };

        self.save_record(&record)
            .await?;

        // Swap the index entry: drop the superseded hash, add the new one.
        if let Some(ref old) = old_hash {
            self.unindex_secret_hash(agent_id, old);
        }
        self.index_secret_hash(&record);
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::Appliance);

        info!(
            agent_id = %agent_id,
            key_id = %key_id,
            actor = %actor,
            "Rotated API key secret in place"
        );

        Ok(ApiKeyCreated {
            key_id: record.key_id.clone(),
            secret: new_secret,
            agent_id: agent_id.to_string(),
            client_id: record.client_id.clone(),
            created_at: record.created_at,
            rotated_from: None,
        })
    }

    async fn delete(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<()> {
        let record = self
            .get_record_internal(agent_id, key_id)
            .await?
            .ok_or_else(|| ApiKeyError::not_found(key_id))?;

        self.delete_record(agent_id, key_id)
            .await?;

        if let Some(ref hash) = record.secret_hash {
            self.unindex_secret_hash(agent_id, hash);
        }
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::Appliance);

        info!(
            actor = %actor,
            agent_id = %agent_id,
            key_id = %key_id,
            "Deleted API key"
        );

        Ok(())
    }

    async fn touch_usage(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<()> {
        if let Some(mut record) = self
            .get_record_internal(agent_id, key_id)
            .await?
        {
            record.last_used_at = Some(Utc::now());
            // Best-effort update, don't fail on error
            if let Err(e) = self
                .save_record(&record)
                .await
            {
                debug!("Failed to update last_used_at for {}: {}", key_id, e);
            }
        }
        Ok(())
    }

    async fn list_all(&self) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        let stores: Vec<_> = self
            .stores
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        let mut all = Vec::new();
        for store in stores {
            for record in store.list_all().await? {
                all.push(ApiKeyMeta::from(record));
            }
        }
        all.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });
        Ok(all)
    }
}

#[async_trait]
impl ApiKeyValidator for FileSystemApiKeyStore {
    async fn validate(
        &self,
        agent_id: &str,
        presented_key: &str,
    ) -> ApiKeyResult<Option<ApiKeyMeta>> {
        match self
            .find_by_secret(agent_id, presented_key)
            .await?
        {
            Some(mut record) if record.status == ApiKeyStatus::Active => {
                debug!(
                    agent_id = %agent_id,
                    key_id = %record.key_id,
                    "API key validated"
                );

                // Record usage so the list/detail pages reflect real activity.
                // Best-effort and persisted through the store; a write failure
                // must not fail an otherwise-valid authentication.
                record.last_used_at = Some(Utc::now());
                if let Err(e) = self
                    .save_record(&record)
                    .await
                {
                    debug!(
                        agent_id = %agent_id,
                        key_id = %record.key_id,
                        error = %e,
                        "Failed to persist last_used_at on validation"
                    );
                }

                Ok(Some(ApiKeyMeta::from(record)))
            }
            Some(record) => {
                warn!(
                    agent_id = %agent_id,
                    key_id = %record.key_id,
                    "Rejected revoked API key presented for authentication"
                );
                Ok(None)
            }
            None => {
                debug!(
                    agent_id = %agent_id,
                    "API key authentication failed: no matching active key"
                );
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_store() -> (FileSystemApiKeyStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        (store, temp_dir)
    }

    #[tokio::test]
    async fn test_create_and_list_keys() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        assert!(!created.key_id.is_empty());
        assert!(!created.secret.is_empty());
        assert_eq!(created.agent_id, "agent-1");
        assert_eq!(created.client_id, "client-1");

        let keys = store
            .list("agent-1")
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, created.key_id);
        assert_eq!(keys[0].status, ApiKeyStatus::Active);
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        store
            .revoke("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        let key = store
            .get_record("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.status, ApiKeyStatus::Revoked);
        assert!(key.revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_rotate_key() {
        let (store, _temp_dir) = create_test_store().await;

        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let created = store
            .create("agent-1", "client-1", Some(labels.clone()), "test-actor")
            .await
            .unwrap();

        let rotated = store
            .rotate("agent-1", &created.key_id, "rotator")
            .await
            .unwrap();

        // Rotation preserves the key_id (and thus any DID derived from it)
        // while issuing a fresh secret.
        assert_eq!(rotated.key_id, created.key_id);
        assert_ne!(rotated.secret, created.secret);
        assert_eq!(rotated.client_id, created.client_id);
        assert_eq!(rotated.rotated_from, None);

        // The key remains active and usable under the same key_id, and its
        // metadata (labels, created_at) is preserved. Only the secret and the
        // rotation issuer change.
        let key = store
            .get_record("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.status, ApiKeyStatus::Active);
        assert!(key.revoked_at.is_none());
        assert_eq!(key.secret_hash.as_deref(), Some(hash_secret(&rotated.secret).as_str()));
        assert_eq!(key.labels, labels);
        assert_eq!(key.issuer.actor, "rotator");
        assert_eq!(key.issuer.method, "rotation");

        // The new secret authenticates; the old secret is rejected.
        let ok = store
            .validate("agent-1", &rotated.secret)
            .await
            .unwrap();
        assert_eq!(ok.map(|m| m.key_id), Some(created.key_id.clone()));
        assert!(
            store
                .validate("agent-1", &created.secret)
                .await
                .unwrap()
                .is_none(),
            "old secret must no longer authenticate after rotation"
        );
    }

    #[tokio::test]
    async fn test_rotate_persists_and_survives_reload() {
        let (store, temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let rotated = store
            .rotate("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        // Reload from disk — the rotated secret must be persisted under the
        // same key_id.
        let reloaded = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        let key = reloaded
            .get_record("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.key_id, created.key_id);
        assert_eq!(key.secret_hash.as_deref(), Some(hash_secret(&rotated.secret).as_str()));
        assert_eq!(key.status, ApiKeyStatus::Active);
    }

    #[tokio::test]
    async fn test_rotate_revoked_key_errors() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        store
            .revoke("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        let err = store
            .rotate("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap_err();
        assert!(matches!(err, ApiKeyError::AlreadyRevoked { .. }));
    }

    #[tokio::test]
    async fn test_rotate_missing_key_errors() {
        let (store, _temp_dir) = create_test_store().await;

        let err = store
            .rotate("agent-1", "atgk_does_not_exist", "test-actor")
            .await
            .unwrap_err();
        assert!(matches!(err, ApiKeyError::KeyNotFound { .. }));
    }

    #[tokio::test]
    async fn test_validate_key() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        // Valid key
        let result = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().key_id, created.key_id);

        // Invalid key
        let result = store
            .validate("agent-1", "invalid-secret")
            .await
            .unwrap();
        assert!(result.is_none());

        // Revoked key
        store
            .revoke("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();
        let result = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_validate_updates_last_used_at() {
        let (store, temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        // Freshly created keys have never been used.
        assert!(
            store
                .get_record("agent-1", &created.key_id)
                .await
                .unwrap()
                .unwrap()
                .last_used_at
                .is_none()
        );

        // A successful validation stamps last_used_at and surfaces it on the meta.
        let meta = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap()
            .expect("valid key");
        assert!(meta.last_used_at.is_some(), "validate must surface last_used_at on the meta");

        // The timestamp is persisted through the store and survives a reload.
        let reloaded = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(
            reloaded
                .get_record("agent-1", &created.key_id)
                .await
                .unwrap()
                .unwrap()
                .last_used_at
                .is_some(),
            "last_used_at must be persisted, not just cached"
        );
    }

    #[tokio::test]
    async fn test_delete_key() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        store
            .delete("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        let key = store
            .get_record("agent-1", &created.key_id)
            .await
            .unwrap();
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create store and add a key
        {
            let store = FileSystemApiKeyStore::new(path)
                .await
                .unwrap();
            store
                .create("agent-1", "client-1", None, "test-actor")
                .await
                .unwrap();
        }

        // Create new store instance and verify key exists
        {
            let store = FileSystemApiKeyStore::new(path)
                .await
                .unwrap();
            let keys = store
                .list("agent-1")
                .await
                .unwrap();
            assert_eq!(keys.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_corrupted_json_file_skipped() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write a corrupted JSON file
        let corrupted_file = agent_dir.join("corrupted-key.json");
        std::fs::write(&corrupted_file, "{ invalid json }").unwrap();

        // Write a valid JSON file
        let valid_record = ApiKeyRecord {
            key_id: "valid-key".to_string(),
            agent_id: "agent-1".to_string(),
            client_id: "client-1".to_string(),
            secret_hash: Some(hash_secret("secret")),
            status: ApiKeyStatus::Active,
            created_at: Utc::now(),
            revoked_at: None,
            last_used_at: None,
            labels: HashMap::new(),
            issuer: ApiKeyIssuer {
                actor: "test".to_string(),
                method: "api".to_string(),
            },
            rotated_from: None,
        };
        let valid_file = agent_dir.join("valid-key.json");
        std::fs::write(&valid_file, serde_json::to_string_pretty(&valid_record).unwrap()).unwrap();

        // Store should load successfully, skipping corrupted file
        let store = FileSystemApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // Only the valid key should be loaded
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "valid-key");
    }

    #[tokio::test]
    async fn test_empty_file_skipped() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write an empty file
        let empty_file = agent_dir.join("empty-key.json");
        std::fs::write(&empty_file, "").unwrap();

        // Store should load successfully, skipping empty file
        let store = FileSystemApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // No keys should be loaded from empty file
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_missing_required_fields_skipped() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write JSON with missing required fields
        let partial_json = r#"{"key_id": "partial", "agent_id": "agent-1"}"#;
        let partial_file = agent_dir.join("partial-key.json");
        std::fs::write(&partial_file, partial_json).unwrap();

        // Store should load successfully, skipping invalid file
        let store = FileSystemApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // No keys should be loaded
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_non_json_files_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write files with different extensions
        std::fs::write(agent_dir.join("key.txt"), "not json").unwrap();
        std::fs::write(agent_dir.join(".hidden"), "hidden file").unwrap();
        std::fs::write(agent_dir.join("readme.md"), "# readme").unwrap();

        // Store should load successfully, ignoring non-json files
        let store = FileSystemApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // No keys should be loaded
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let (store, _temp_dir) = create_test_store().await;
        let store = Arc::new(store);

        // Create multiple keys concurrently
        let mut handles = Vec::new();
        for i in 0..10 {
            let store_clone = store.clone();
            let client_id = format!("client-{}", i);
            handles.push(tokio::spawn(async move {
                store_clone
                    .create("agent-1", &client_id, None, "test-actor")
                    .await
            }));
        }

        // Wait for all to complete
        let results: Vec<_> = futures::future::join_all(handles).await;
        for result in results {
            assert!(result.unwrap().is_ok());
        }

        // Verify all keys were created
        let keys = store
            .list("agent-1")
            .await
            .unwrap();
        assert_eq!(keys.len(), 10);
    }

    #[tokio::test]
    async fn test_validation_empty_inputs() {
        let (store, _temp_dir) = create_test_store().await;

        // Empty agent_id should fail
        let result = store
            .create("", "client-1", None, "test-actor")
            .await;
        assert!(result.is_err());

        // Empty client_id should fail
        let result = store
            .create("agent-1", "", None, "test-actor")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_record_returns_hash_not_raw_secret() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        // get_record is an internal path (revoke/rotate/delete). It returns the
        // stored record, which holds only the SHA-256 hash of the secret — never
        // the raw secret, which is disclosed to the caller once at creation.
        let record = store
            .get_record("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.secret_hash.as_deref(), Some(hash_secret(&created.secret).as_str()));
        assert_ne!(record.secret_hash.as_deref(), Some(created.secret.as_str()));

        // A missing key returns None (no record, nothing logged).
        assert!(
            store
                .get_record("agent-1", "atgk_missing")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_legacy_record_without_hash_never_validates() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Simulate a pre-hashing record persisted with a cleartext `secret`
        // field (now unknown to the struct) and no `secret_hash`.
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let legacy = serde_json::json!({
            "key_id": "atgk_legacy",
            "agent_id": "agent-1",
            "client_id": "client-1",
            "secret": "atgs_cleartext_legacy_secret",
            "status": "active",
            "created_at": Utc::now(),
            "labels": {},
            "issuer": { "actor": "test", "method": "api" }
        });
        std::fs::write(agent_dir.join("atgk_legacy.json"), serde_json::to_string_pretty(&legacy).unwrap()).unwrap();

        let store = FileSystemApiKeyStore::new(path)
            .await
            .unwrap();

        // The record still lists (metadata survives) but the legacy cleartext
        // secret must not authenticate — the key requires rotation.
        assert_eq!(
            store
                .list("agent-1")
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .validate("agent-1", "atgs_cleartext_legacy_secret")
                .await
                .unwrap()
                .is_none(),
            "legacy cleartext secret must not validate after the hashing change"
        );
    }

    #[tokio::test]
    async fn test_validate_is_scoped_per_agent() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        // The same secret must not authenticate under a different agent scope.
        assert!(
            store
                .validate("agent-2", &created.secret)
                .await
                .unwrap()
                .is_none(),
            "a key's secret must only validate within its own agent scope"
        );

        // It still authenticates under its own agent.
        let ok = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap();
        assert_eq!(ok.map(|m| m.key_id), Some(created.key_id));
    }

    #[tokio::test]
    async fn test_repeated_rotation_only_latest_secret_valid() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        let first = store
            .rotate("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();
        let second = store
            .rotate("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        // Every rotation stays on the same key_id.
        assert_eq!(first.key_id, created.key_id);
        assert_eq!(second.key_id, created.key_id);

        // Only the newest secret authenticates; both prior secrets are rejected.
        assert_eq!(
            store
                .validate("agent-1", &second.secret)
                .await
                .unwrap()
                .map(|m| m.key_id),
            Some(created.key_id.clone())
        );
        assert!(
            store
                .validate("agent-1", &first.secret)
                .await
                .unwrap()
                .is_none(),
            "the intermediate rotated secret must no longer authenticate"
        );
        assert!(
            store
                .validate("agent-1", &created.secret)
                .await
                .unwrap()
                .is_none(),
            "the original secret must no longer authenticate"
        );
    }
}
