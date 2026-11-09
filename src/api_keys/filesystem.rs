//! Filesystem-based API key storage
//!
//! Stores API keys as JSON files organized by agent:
//! ```text
//! _storage/api_keys/{agent_id}/{key_id}.json
//! _storage/api_keys/{agent_id}/.{key_id}.last_used
//! ```
//!
//! The `.last_used` file holds the key's last use, kept apart from the record so a usage
//! write never rewrites the key's status.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
    /// Per-agent locks held across the read, status check and write of a key record, so a
    /// revoke, rotation or delete on this node never undoes another on this node.
    record_locks: DashMap<String, Arc<Mutex<()>>>,
    /// When this node last recorded each key's use: (agent_id, key_id) -> time.
    last_uses: DashMap<(String, String), DateTime<Utc>>,
    usage_write_interval: chrono::TimeDelta,
}

/// The shortest time between two usage writes of one key on a node; validations in between
/// write nothing.
const USAGE_WRITE_INTERVAL: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// Suffix of the file beside a key record that holds the key's last use. It is neither
/// `.json` nor `.json.enc`, so the record loader and the key-record check skip it.
const USAGE_FILE_SUFFIX: &str = ".last_used";

/// Replaces a usage file through a temporary file in the same folder, so a reader never sees a
/// partial time. The folder is never created: a missing folder fails the write.
async fn write_usage_file(
    path: &std::path::Path,
    used_at: &str,
) -> std::io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let temporary = PathBuf::from(temporary);
    let written = async {
        fs::write(&temporary, used_at).await?;
        fs::rename(&temporary, path).await
    }
    .await;
    if written.is_err() {
        let _ = fs::remove_file(&temporary).await;
    }
    written
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
            record_locks: DashMap::new(),
            last_uses: DashMap::new(),
            usage_write_interval: USAGE_WRITE_INTERVAL,
        };

        // Build per-agent stores and load existing keys into memory
        store
            .load_new_agents()
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
    /// agent directory that has none yet, loading (and, when encryption at rest
    /// is on, transparently migrating) its keys into memory: at startup every
    /// directory, later those another node sharing the storage created since. A
    /// symlink to a directory counts as one; an entry whose type cannot be read is
    /// skipped. A name that is not a valid storage id is no agent's and is
    /// skipped; an agent whose keys cannot be loaded is logged, skipped, and
    /// returned. A root that cannot be read is an error.
    async fn load_new_agents(&self) -> ApiKeyResult<Vec<String>> {
        let mut skipped = Vec::new();
        let mut entries = fs::read_dir(&self.storage_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let Some(agent_id) = file_name.to_str() else {
                continue;
            };
            if self
                .stores
                .contains_key(agent_id)
                || crate::storage::validate_storage_id(agent_id).is_err()
                || !fs::metadata(entry.path())
                    .await
                    .is_ok_and(|metadata| metadata.is_dir())
            {
                continue;
            }
            if let Err(e) = self
                .agent_store(agent_id)
                .await
            {
                warn!("Failed to load keys for agent {}: {}", agent_id, e);
                skipped.push(agent_id.to_string());
            }
        }

        Ok(skipped)
    }

    /// Every key of the agents loaded so far, from the cache; with `last_use`, each key's
    /// latest use is read from its usage file.
    async fn list_loaded(
        &self,
        last_use: bool,
    ) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        let stores: Vec<_> = self
            .stores
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        let mut all = Vec::new();
        for (agent_id, store) in stores {
            for record in store.list_all().await? {
                let record = if last_use {
                    self.with_last_use(&agent_id, record)
                        .await
                } else {
                    record
                };
                all.push(ApiKeyMeta::from(record));
            }
        }
        all.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });
        Ok(all)
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
        self.index_agent(agent_id, store.as_ref())
            .await?;

        Ok(store)
    }

    /// Build, or rebuild, the secret-hash lookup of one agent from its store's records.
    /// Legacy records without a `secret_hash` are skipped and therefore never validate.
    async fn index_agent(
        &self,
        agent_id: &str,
        store: &dyn StorageBackend<ApiKeyRecord>,
    ) -> ApiKeyResult<()> {
        let index = DashMap::new();
        for record in store.list_all().await? {
            if let Some(ref hash) = record.secret_hash {
                index.insert(hash.clone(), record.key_id.clone());
            }
        }
        self.hash_index
            .insert(agent_id.to_string(), index);
        Ok(())
    }

    /// Reconcile every agent's keys with disk, as another node sharing the storage wrote
    /// them: load agent folders created since, re-read each loaded agent's records, so a key
    /// created, rotated or revoked elsewhere takes effect, rebuild its secret-hash lookup, and
    /// drop an agent whose folder is gone. An agent that cannot be refreshed keeps what it
    /// held and is logged.
    pub async fn refresh_from_disk(&self) -> ApiKeyResult<()> {
        self.load_new_agents().await?;
        let agents: Vec<(String, Arc<dyn StorageBackend<ApiKeyRecord>>)> = self
            .stores
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        for (agent_id, store) in agents {
            if !fs::try_exists(self.agent_dir(&agent_id)).await? {
                self.forget_agent(&agent_id);
                continue;
            }
            if let Err(error) = self
                .refresh_agent(&agent_id, store.as_ref())
                .await
            {
                warn!("Failed to refresh keys for agent {}: {}", agent_id, error);
            }
        }
        Ok(())
    }

    /// Drop an agent whose folder is gone from memory.
    fn forget_agent(
        &self,
        agent_id: &str,
    ) {
        self.stores.remove(agent_id);
        self.hash_index
            .remove(agent_id);
    }

    /// Re-read one loaded agent's records from disk and rebuild its secret-hash lookup.
    async fn refresh_agent(
        &self,
        agent_id: &str,
        store: &dyn StorageBackend<ApiKeyRecord>,
    ) -> ApiKeyResult<()> {
        store
            .refresh_from_disk()
            .await?;
        self.index_agent(agent_id, store)
            .await
    }

    /// One key record read from disk, bypassing the cache, so a rotation starts from the key
    /// as stored. Only that record is read; a folder that is gone holds no record. The
    /// secret-hash lookup is left as is: a stale entry resolves to the cached record, whose
    /// hash is checked.
    async fn record_on_disk(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<Option<ApiKeyRecord>> {
        if crate::storage::validate_storage_id(agent_id).is_err() || !fs::try_exists(self.agent_dir(agent_id)).await? {
            return Ok(None);
        }
        Ok(crate::storage::filesystem::uncached_storage::<ApiKeyRecord>(self.agent_dir(agent_id), "api_key")
            .await?
            .get(key_id)
            .await?)
    }

    #[cfg(test)]
    fn with_usage_write_interval(
        mut self,
        interval: chrono::TimeDelta,
    ) -> Self {
        self.usage_write_interval = interval;
        self
    }

    /// The file in the agent's key folder that holds a key's last use; `None`, logged, when
    /// either id is not a valid storage id.
    fn usage_path(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> Option<PathBuf> {
        if let Err(error) =
            crate::storage::validate_storage_id(agent_id).and_then(|()| crate::storage::validate_storage_id(key_id))
        {
            warn!(%error, "Skipped the usage file of an API key with an invalid id");
            return None;
        }
        Some(
            self.agent_dir(agent_id)
                .join(format!(".{key_id}{USAGE_FILE_SUFFIX}")),
        )
    }

    /// Records a key's use in its usage file, at most once per usage write interval on this
    /// node, and returns the last use this node knows of. Only the usage file is written, never
    /// the key record, so a usage write cannot undo a revocation, and the agent's folder is
    /// never created. When the key was deleted or rotated while the file was written, the file
    /// is removed again. A failed write is logged and the use is still returned.
    async fn record_use(
        &self,
        agent_id: &str,
        key_id: &str,
        secret_hash: Option<&str>,
    ) -> DateTime<Utc> {
        let now = Utc::now();
        {
            let mut last = self
                .last_uses
                .entry((agent_id.to_string(), key_id.to_string()))
                .or_insert(now - self.usage_write_interval);
            if now - *last < self.usage_write_interval {
                return *last;
            }
            *last = now;
        }
        let Some(path) = self.usage_path(agent_id, key_id) else {
            return now;
        };
        if let Err(error) = write_usage_file(&path, &now.to_rfc3339()).await {
            warn!(agent_id = %agent_id, key_id = %key_id, %error, "Failed to record an API key's last use");
            return now;
        }
        let still_held = self
            .get_record_internal(agent_id, key_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|record| record.secret_hash.as_deref() == secret_hash);
        if !still_held {
            self.forget_use(agent_id, key_id)
                .await;
        }
        now
    }

    /// The key's last use read from its usage file, `None` when it has none or it cannot be read.
    async fn stored_last_use(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> Option<DateTime<Utc>> {
        let stored = fs::read_to_string(self.usage_path(agent_id, key_id)?)
            .await
            .ok()?;
        DateTime::parse_from_rfc3339(stored.trim())
            .ok()
            .map(|used| used.with_timezone(&Utc))
    }

    /// The record of a key in `agent_id`'s folder with `last_used_at` taken from its usage
    /// file. A record written before usage files existed keeps its own `last_used_at` until its
    /// key is used again.
    async fn with_last_use(
        &self,
        agent_id: &str,
        mut record: ApiKeyRecord,
    ) -> ApiKeyRecord {
        if let Some(used) = self
            .stored_last_use(agent_id, &record.key_id)
            .await
        {
            record.last_used_at = Some(used);
        }
        record
    }

    /// Removes a key's usage file and this node's record of its last use.
    async fn forget_use(
        &self,
        agent_id: &str,
        key_id: &str,
    ) {
        self.last_uses
            .remove(&(agent_id.to_string(), key_id.to_string()));
        let Some(path) = self.usage_path(agent_id, key_id) else {
            return;
        };
        match fs::remove_file(path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(agent_id = %agent_id, key_id = %key_id, %error, "Failed to remove an API key's usage file")
            }
        }
    }

    /// The lock serializing the read, status check and write of one agent's key records.
    fn record_lock(
        &self,
        agent_id: &str,
    ) -> Arc<Mutex<()>> {
        self.record_locks
            .entry(agent_id.to_string())
            .or_default()
            .clone()
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
    /// rest when configured) and refresh the store's cache. The file is replaced
    /// atomically, so a concurrent writer or reader never sees a partial record.
    async fn save_record(
        &self,
        record: &ApiKeyRecord,
    ) -> ApiKeyResult<()> {
        let store = self
            .agent_store(&record.agent_id)
            .await?;
        store
            .save_atomic(record)
            .await?;
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
        let Some(store) = self
            .stores
            .get(agent_id)
            .map(|s| s.value().clone())
        else {
            return Ok(Vec::new());
        };
        let mut keys = Vec::new();
        for record in store.list_all().await? {
            keys.push(ApiKeyMeta::from(
                self.with_last_use(agent_id, record)
                    .await,
            ));
        }
        Ok(keys)
    }

    /// Loads the agent's folder when another node created it, or re-reads it when loaded. A
    /// folder that does not exist holds no keys and is not created.
    async fn list_from_disk(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        if crate::storage::validate_storage_id(agent_id).is_err() {
            return Ok(Vec::new());
        }
        if !fs::try_exists(self.agent_dir(agent_id)).await? {
            self.forget_agent(agent_id);
            return Ok(Vec::new());
        }
        let loaded = self
            .stores
            .get(agent_id)
            .map(|s| s.value().clone());
        match loaded {
            Some(store) => {
                self.refresh_agent(agent_id, store.as_ref())
                    .await?
            }
            None => {
                self.agent_store(agent_id)
                    .await?;
            }
        }
        self.list(agent_id).await
    }

    /// Reads the agent folder's entries without parsing them, so a record that cannot be
    /// parsed or decrypted counts too.
    async fn holds_key_records(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<bool> {
        if crate::storage::validate_storage_id(agent_id).is_err() {
            return Ok(false);
        }
        let mut entries = match fs::read_dir(self.agent_dir(agent_id)).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".json") || name.ends_with(".json.enc") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn get_record(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<Option<ApiKeyRecord>> {
        let Some(record) = self
            .get_record_internal(agent_id, key_id)
            .await?
        else {
            return Ok(None);
        };
        info!(
            agent_id = %agent_id,
            key_id = %key_id,
            "API key record retrieved"
        );
        Ok(Some(
            self.with_last_use(agent_id, record)
                .await,
        ))
    }

    async fn revoke(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<()> {
        let lock = self.record_lock(agent_id);
        let _guard = lock.lock().await;
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
        let lock = self.record_lock(agent_id);
        let _guard = lock.lock().await;
        self.get_record_internal(agent_id, key_id)
            .await?
            .ok_or_else(|| ApiKeyError::not_found(key_id))?;
        let mut record = self
            .record_on_disk(agent_id, key_id)
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
        self.forget_use(agent_id, key_id)
            .await;

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
        let lock = self.record_lock(agent_id);
        let _guard = lock.lock().await;
        let record = self
            .get_record_internal(agent_id, key_id)
            .await?
            .ok_or_else(|| ApiKeyError::not_found(key_id))?;

        self.delete_record(agent_id, key_id)
            .await?;
        self.forget_use(agent_id, key_id)
            .await;

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
        if let Some(record) = self
            .get_record_internal(agent_id, key_id)
            .await?
            .filter(|record| record.status == ApiKeyStatus::Active)
        {
            self.record_use(agent_id, key_id, record.secret_hash.as_deref())
                .await;
        }
        Ok(())
    }

    async fn refresh_from_disk(&self) -> ApiKeyResult<()> {
        FileSystemApiKeyStore::refresh_from_disk(self).await
    }

    async fn list_all(&self) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        self.load_new_agents().await?;
        self.list_loaded(false).await
    }

    async fn list_all_with_last_use(&self) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        self.load_new_agents().await?;
        self.list_loaded(true).await
    }

    async fn list_all_with_skipped(&self) -> ApiKeyResult<(Vec<ApiKeyMeta>, Vec<String>)> {
        let skipped = self.load_new_agents().await?;
        Ok((
            self.list_loaded(false)
                .await?,
            skipped,
        ))
    }

    async fn list_all_complete(&self) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        let skipped = self.load_new_agents().await?;
        if !skipped.is_empty() {
            return Err(ApiKeyError::Storage(anyhow::anyhow!(
                "the keys of {} agent(s) could not be loaded",
                skipped.len()
            )));
        }
        self.list_loaded(false).await
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
                record.last_used_at = Some(
                    self.record_use(agent_id, &record.key_id, record.secret_hash.as_deref())
                        .await,
                );
                debug!(
                    agent_id = %agent_id,
                    key_id = %record.key_id,
                    "API key validated"
                );
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
    async fn list_all_sees_keys_another_store_on_the_same_directory_created_for_a_new_agent() {
        let (first, temp_dir) = create_test_store().await;
        let second = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(
            second
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );

        let created = first
            .create("agent-later", "client-1", None, "test-actor")
            .await
            .unwrap();
        std::fs::create_dir(
            temp_dir
                .path()
                .join(".not-an-agent"),
        )
        .unwrap();

        let seen = second
            .list_all()
            .await
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].key_id, created.key_id);
        assert_eq!(seen[0].agent_id, "agent-later");
    }

    #[tokio::test]
    async fn refresh_from_disk_takes_in_keys_another_store_created_rotated_or_revoked() {
        let (first, temp_dir) = create_test_store().await;
        let rotated = first
            .create("agent-x", "client-1", None, "test-actor")
            .await
            .unwrap();
        let revoked = first
            .create("agent-x", "client-2", None, "test-actor")
            .await
            .unwrap();
        let second = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();

        let created = first
            .create("agent-x", "client-3", None, "test-actor")
            .await
            .unwrap();
        let rotation = first
            .rotate("agent-x", &rotated.key_id, "test-actor")
            .await
            .unwrap();
        first
            .revoke("agent-x", &revoked.key_id, "test-actor")
            .await
            .unwrap();
        let validates = |secret: String| {
            let second = &second;
            async move {
                second
                    .validate("agent-x", &secret)
                    .await
                    .unwrap()
                    .map(|meta| meta.key_id)
            }
        };
        assert_eq!(validates(created.secret.clone()).await, None, "not seen before the refresh");

        ApiKeyStore::refresh_from_disk(&second)
            .await
            .unwrap();

        let listed: Vec<String> = second
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .map(|meta| meta.key_id)
            .collect();
        assert!(listed.contains(&created.key_id), "{listed:?}");
        assert_eq!(validates(created.secret.clone()).await, Some(created.key_id.clone()));
        assert_eq!(validates(rotation.secret.clone()).await, Some(rotated.key_id.clone()));
        assert_eq!(validates(rotated.secret.clone()).await, None, "the rotated-out secret no longer validates");
        assert_eq!(validates(revoked.secret.clone()).await, None, "a revoked key no longer validates");

        std::fs::remove_dir_all(
            temp_dir
                .path()
                .join("agent-x"),
        )
        .unwrap();
        ApiKeyStore::refresh_from_disk(&second)
            .await
            .unwrap();
        assert!(
            second
                .list_all()
                .await
                .unwrap()
                .is_empty(),
            "a deleted agent folder is dropped"
        );
        assert_eq!(validates(created.secret.clone()).await, None);
    }

    #[tokio::test]
    async fn only_a_complete_listing_fails_when_an_agents_keys_cannot_be_loaded() {
        use std::os::unix::fs::PermissionsExt as _;
        let (first, temp_dir) = create_test_store().await;
        let readable = first
            .create("agent-readable", "client-1", None, "test-actor")
            .await
            .unwrap();
        first
            .create("agent-locked", "client-1", None, "test-actor")
            .await
            .unwrap();
        let locked = temp_dir
            .path()
            .join("agent-locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            // Running as root: no read fails, so there is no folder to skip.
            return;
        }

        let second = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .expect("a folder that cannot be loaded does not stop the store from starting");
        let listed: Vec<String> = second
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .map(|key| key.key_id)
            .collect();
        assert_eq!(listed, vec![readable.key_id], "a plain listing leaves the folder out");
        assert!(
            second
                .list_all_complete()
                .await
                .is_err(),
            "a complete listing fails"
        );

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            second
                .list_all_complete()
                .await
                .unwrap()
                .len(),
            2,
            "the folder is loaded once it can be read"
        );
    }

    #[tokio::test]
    async fn a_listing_with_skipped_names_the_agents_whose_keys_cannot_be_loaded() {
        use std::os::unix::fs::PermissionsExt as _;
        let (first, temp_dir) = create_test_store().await;
        let readable = first
            .create("agent-readable", "client-1", None, "test-actor")
            .await
            .unwrap();
        first
            .create("agent-locked", "client-1", None, "test-actor")
            .await
            .unwrap();
        let locked = temp_dir
            .path()
            .join("agent-locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let root_locked = std::fs::read_dir(&locked).is_err();
        let second = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        let partial = second
            .list_all_with_skipped()
            .await
            .map(|(keys, skipped)| (key_ids(keys), skipped));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let recovered = second
            .list_all_with_skipped()
            .await
            .map(|(keys, skipped)| (keys.len(), skipped));
        std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable_root = second
            .list_all_with_skipped()
            .await;
        std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        if !root_locked {
            // Running as root: no read fails.
            return;
        }

        assert_eq!(partial.unwrap(), (vec![readable.key_id], vec!["agent-locked".to_string()]));
        assert_eq!(recovered.unwrap(), (2, Vec::new()), "the folder is loaded once it can be read");
        assert!(unreadable_root.is_err(), "a root that cannot be read is an error");
    }

    fn key_ids(keys: Vec<ApiKeyMeta>) -> Vec<String> {
        let mut ids: Vec<String> = keys
            .into_iter()
            .map(|key| key.key_id)
            .collect();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn listing_one_agent_from_disk_sees_keys_another_store_on_the_same_directory_created() {
        let (first, temp_dir) = create_test_store().await;
        let known = first
            .create("agent-known", "client-1", None, "test-actor")
            .await
            .unwrap();
        let second = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        let in_new_folder = second
            .create("agent-new", "client-1", None, "test-actor")
            .await
            .unwrap();
        let in_known_folder = second
            .create("agent-known", "client-1", None, "test-actor")
            .await
            .unwrap();

        assert!(
            first
                .list("agent-new")
                .await
                .unwrap()
                .is_empty(),
            "a plain listing reads only loaded folders"
        );
        assert_eq!(
            key_ids(
                first
                    .list_from_disk("agent-new")
                    .await
                    .unwrap()
            ),
            vec![in_new_folder.key_id]
        );
        let mut both = vec![known.key_id, in_known_folder.key_id];
        both.sort();
        assert_eq!(
            key_ids(
                first
                    .list_from_disk("agent-known")
                    .await
                    .unwrap()
            ),
            both
        );
        assert!(
            first
                .revoke(
                    "agent-new",
                    &key_ids(
                        first
                            .list("agent-new")
                            .await
                            .unwrap()
                    )[0],
                    "test-actor"
                )
                .await
                .is_ok(),
            "a folder read from disk is loaded, so its keys can be revoked"
        );
    }

    #[tokio::test]
    async fn listing_one_agent_from_disk_without_a_folder_is_empty_and_creates_none() {
        let (store, temp_dir) = create_test_store().await;

        assert!(
            store
                .list_from_disk("agent-none")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .list_from_disk("../escape")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !temp_dir
                .path()
                .join("agent-none")
                .exists()
        );

        store
            .create("agent-gone", "client-1", None, "test-actor")
            .await
            .unwrap();
        std::fs::remove_dir_all(
            temp_dir
                .path()
                .join("agent-gone"),
        )
        .unwrap();
        assert!(
            store
                .list_from_disk("agent-gone")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .list_all()
                .await
                .unwrap()
                .is_empty(),
            "a folder found gone is dropped from memory"
        );
    }

    #[tokio::test]
    async fn listing_one_agent_from_disk_fails_only_for_that_agents_unreadable_folder() {
        use std::os::unix::fs::PermissionsExt as _;
        let (first, temp_dir) = create_test_store().await;
        let readable = first
            .create("agent-readable", "client-1", None, "test-actor")
            .await
            .unwrap();
        first
            .create("agent-locked", "client-1", None, "test-actor")
            .await
            .unwrap();
        let locked = temp_dir
            .path()
            .join("agent-locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            // Running as root: no read fails.
            return;
        }

        let second = FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        let unreadable = second
            .list_from_disk("agent-locked")
            .await;
        let readable_keys = second
            .list_from_disk("agent-readable")
            .await;
        let loaded_unreadable = first
            .list_from_disk("agent-locked")
            .await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(unreadable.is_err(), "a folder that is not loaded yet cannot be read");
        assert!(loaded_unreadable.is_err(), "a loaded folder cannot be re-read");
        assert_eq!(key_ids(readable_keys.unwrap()), vec![readable.key_id]);
        assert_eq!(
            second
                .list_from_disk("agent-locked")
                .await
                .unwrap()
                .len(),
            1,
            "the folder is read once it can be"
        );
    }

    #[tokio::test]
    async fn list_all_fails_when_the_storage_root_cannot_be_read() {
        let (store, temp_dir) = create_test_store().await;
        std::fs::remove_dir_all(temp_dir.path()).unwrap();

        assert!(
            store
                .list_all()
                .await
                .is_err()
        );
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

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_agent_folder_is_loaded_and_a_dangling_link_is_skipped() {
        let elsewhere = TempDir::new().unwrap();
        let created = FileSystemApiKeyStore::new(
            elsewhere
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap()
        .create("agent-linked", "client-1", None, "test-actor")
        .await
        .unwrap();
        let root = TempDir::new().unwrap();
        std::os::unix::fs::symlink(
            elsewhere
                .path()
                .join("agent-linked"),
            root.path()
                .join("agent-linked"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            root.path()
                .join("no-such-folder"),
            root.path()
                .join("agent-dangling"),
        )
        .unwrap();

        let store = FileSystemApiKeyStore::new(root.path().to_str().unwrap())
            .await
            .unwrap();

        let validated = store
            .validate("agent-linked", &created.secret)
            .await
            .unwrap()
            .expect("a key in a symlinked agent folder validates");
        assert_eq!(validated.key_id, created.key_id);
        let listed = store
            .list_all()
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent_id, "agent-linked");
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

    async fn open_store(temp_dir: &TempDir) -> FileSystemApiKeyStore {
        FileSystemApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn stored_record(
        temp_dir: &TempDir,
        key_id: &str,
    ) -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(
                temp_dir
                    .path()
                    .join("agent-1")
                    .join(format!("{key_id}.json")),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn usage_file(
        temp_dir: &TempDir,
        key_id: &str,
    ) -> std::path::PathBuf {
        temp_dir
            .path()
            .join("agent-1")
            .join(format!(".{key_id}{USAGE_FILE_SUFFIX}"))
    }

    #[tokio::test]
    async fn usage_writes_after_a_revoke_through_another_store_leave_it_revoked() {
        let (first, temp_dir) = create_test_store().await;
        let created = first
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let second = open_store(&temp_dir)
            .await
            .with_usage_write_interval(chrono::TimeDelta::zero());
        assert!(
            second
                .validate("agent-1", &created.secret)
                .await
                .unwrap()
                .is_some()
        );
        first
            .revoke("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        let before_refresh = second
            .validate("agent-1", &created.secret)
            .await
            .unwrap();
        second
            .touch_usage("agent-1", &created.key_id)
            .await
            .unwrap();
        second
            .refresh_from_disk()
            .await
            .unwrap();
        let after_refresh = second
            .validate("agent-1", &created.secret)
            .await
            .unwrap();

        assert!(before_refresh.is_some(), "this node holds the key as active until its cache is refreshed");
        assert!(after_refresh.is_none());
        let record = stored_record(&temp_dir, &created.key_id);
        assert_eq!(record["status"], "revoked", "{record}");
        assert!(record["revoked_at"].is_string(), "{record}");
        assert!(record["last_used_at"].is_null(), "usage never goes into the record: {record}");
        assert!(usage_file(&temp_dir, &created.key_id).exists());
    }

    #[tokio::test]
    async fn a_failed_usage_write_still_accepts_the_caller() {
        use std::os::unix::fs::PermissionsExt as _;
        let (store, temp_dir) = create_test_store().await;
        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let folder = temp_dir
            .path()
            .join("agent-1");
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::write(folder.join("writable"), b"").is_ok() {
            std::fs::remove_file(folder.join("writable")).unwrap();
            std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let validated = store
            .validate("agent-1", &created.secret)
            .await;
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();

        let meta = validated
            .unwrap()
            .expect("the caller is accepted");
        assert_eq!(meta.key_id, created.key_id);
        assert!(!usage_file(&temp_dir, &created.key_id).exists());
        assert_eq!(stored_record(&temp_dir, &created.key_id)["status"], "active");
    }

    #[tokio::test]
    async fn key_meta_shows_the_usage_file_time_and_falls_back_to_a_legacy_record() {
        let (store, temp_dir) = create_test_store().await;
        let used = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let legacy = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let used_at = store
            .validate("agent-1", &used.secret)
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .unwrap();
        let mut legacy_record = stored_record(&temp_dir, &legacy.key_id);
        legacy_record["last_used_at"] = serde_json::json!("2026-01-01T00:00:00Z");
        std::fs::write(
            temp_dir
                .path()
                .join("agent-1")
                .join(format!("{}.json", legacy.key_id)),
            serde_json::to_vec(&legacy_record).unwrap(),
        )
        .unwrap();

        let fresh = open_store(&temp_dir).await;
        let listed = fresh
            .list("agent-1")
            .await
            .unwrap();
        let last_use = |key_id: &str| {
            listed
                .iter()
                .find(|key| key.key_id == key_id)
                .unwrap()
                .last_used_at
        };

        assert_eq!(last_use(&used.key_id), Some(used_at));
        assert_eq!(
            last_use(&legacy.key_id),
            Some(
                "2026-01-01T00:00:00Z"
                    .parse()
                    .unwrap()
            )
        );
        assert_eq!(
            fresh
                .get_record("agent-1", &used.key_id)
                .await
                .unwrap()
                .unwrap()
                .last_used_at,
            Some(used_at)
        );
        assert!(stored_record(&temp_dir, &used.key_id)["last_used_at"].is_null());
    }

    #[tokio::test]
    async fn deleting_or_rotating_a_key_removes_its_usage_file() {
        let (store, temp_dir) = create_test_store().await;
        let deleted = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let rotated = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        for key in [&deleted, &rotated] {
            store
                .validate("agent-1", &key.secret)
                .await
                .unwrap()
                .unwrap();
            assert!(usage_file(&temp_dir, &key.key_id).exists());
        }

        store
            .delete("agent-1", &deleted.key_id, "test-actor")
            .await
            .unwrap();
        store
            .rotate("agent-1", &rotated.key_id, "test-actor")
            .await
            .unwrap();

        assert!(!usage_file(&temp_dir, &deleted.key_id).exists());
        assert!(!usage_file(&temp_dir, &rotated.key_id).exists());
        assert!(
            store
                .get_record("agent-1", &rotated.key_id)
                .await
                .unwrap()
                .unwrap()
                .last_used_at
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_record_with_a_traversing_key_id_writes_no_usage_file_outside_its_folder() {
        let (first, temp_dir) = create_test_store().await;
        let created = first
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let mut tampered = stored_record(&temp_dir, &created.key_id);
        tampered["key_id"] = serde_json::json!("/../escape");
        std::fs::write(
            temp_dir
                .path()
                .join("agent-1")
                .join(format!("{}.json", created.key_id)),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        let store = open_store(&temp_dir).await;

        let validated = store
            .validate("agent-1", &created.secret)
            .await;
        let listed = store.list("agent-1").await;

        assert!(validated.is_ok(), "{validated:?}");
        assert!(listed.is_ok(), "{listed:?}");
        let root: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(root, vec![std::ffi::OsString::from("agent-1")]);
        let usage_files: Vec<_> = std::fs::read_dir(
            temp_dir
                .path()
                .join("agent-1"),
        )
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| {
            name.to_string_lossy()
                .contains(USAGE_FILE_SUFFIX)
        })
        .collect();
        assert!(usage_files.is_empty(), "{usage_files:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_delete_racing_a_validation_leaves_no_usage_file() {
        for _ in 0..50 {
            let (store, temp_dir) = create_test_store().await;
            let store = Arc::new(store.with_usage_write_interval(chrono::TimeDelta::zero()));
            let created = store
                .create("agent-1", "client-1", None, "test-actor")
                .await
                .unwrap();
            let validator = store.clone();
            let secret = created.secret.clone();
            let validations = tokio::spawn(async move {
                for _ in 0..5 {
                    validator
                        .validate("agent-1", &secret)
                        .await
                        .unwrap();
                }
            });
            let deleter = store.clone();
            let key_id = created.key_id.clone();
            let delete = tokio::spawn(async move {
                tokio::task::yield_now().await;
                deleter
                    .delete("agent-1", &key_id, "test-actor")
                    .await
                    .unwrap();
            });
            validations.await.unwrap();
            delete.await.unwrap();

            assert!(!usage_file(&temp_dir, &created.key_id).exists());
            assert!(
                !store
                    .last_uses
                    .contains_key(&("agent-1".to_string(), created.key_id.clone()))
            );
        }
    }

    #[tokio::test]
    async fn rotating_a_key_reads_only_its_own_record_from_disk() {
        use std::os::unix::fs::PermissionsExt as _;
        let (store, temp_dir) = create_test_store().await;
        let rotated = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let sibling = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let sibling_file = temp_dir
            .path()
            .join("agent-1")
            .join(format!("{}.json", sibling.key_id));
        std::fs::set_permissions(&sibling_file, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&sibling_file).is_ok() {
            std::fs::set_permissions(&sibling_file, std::fs::Permissions::from_mode(0o600)).unwrap();
            return;
        }

        let rotation = store
            .rotate("agent-1", &rotated.key_id, "test-actor")
            .await;
        let sibling_validated = store
            .validate("agent-1", &sibling.secret)
            .await;
        std::fs::set_permissions(&sibling_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        rotation.unwrap();
        assert!(
            sibling_validated
                .unwrap()
                .is_some(),
            "an unreadable sibling stays cached"
        );
    }

    #[tokio::test]
    async fn usage_within_the_interval_writes_nothing() {
        let (store, temp_dir) = create_test_store().await;
        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let first_use = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap()
            .unwrap()
            .last_used_at;
        let written = std::fs::read(usage_file(&temp_dir, &created.key_id)).unwrap();

        let again = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap()
            .unwrap()
            .last_used_at;
        store
            .touch_usage("agent-1", &created.key_id)
            .await
            .unwrap();

        assert!(first_use.is_some());
        assert_eq!(again, first_use);
        assert_eq!(std::fs::read(usage_file(&temp_dir, &created.key_id)).unwrap(), written);
    }

    #[tokio::test]
    async fn rotating_on_a_stale_store_refuses_a_key_another_store_revoked() {
        let (first, temp_dir) = create_test_store().await;
        let created = first
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let second = open_store(&temp_dir).await;
        first
            .revoke("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        let rotated = second
            .rotate("agent-1", &created.key_id, "test-actor")
            .await;

        assert!(matches!(rotated, Err(ApiKeyError::AlreadyRevoked { .. })), "{rotated:?}");
        let on_disk = open_store(&temp_dir)
            .await
            .get_record("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(on_disk.status, ApiKeyStatus::Revoked);
    }

    #[tokio::test]
    async fn rotating_an_active_key_on_another_store_still_rotates_it() {
        let (first, temp_dir) = create_test_store().await;
        let created = first
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let second = open_store(&temp_dir).await;

        let rotated = second
            .rotate("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        assert_eq!(rotated.key_id, created.key_id);
        let fresh = open_store(&temp_dir).await;
        assert!(
            fresh
                .validate("agent-1", &rotated.secret)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            fresh
                .validate("agent-1", &created.secret)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_usage_write_racing_a_revoke_on_the_same_store_never_undoes_it() {
        for _ in 0..100 {
            let (store, temp_dir) = create_test_store().await;
            let store = Arc::new(store.with_usage_write_interval(chrono::TimeDelta::zero()));
            let created = store
                .create("agent-1", "client-1", None, "test-actor")
                .await
                .unwrap();
            let validator = store.clone();
            let secret = created.secret.clone();
            let validations = tokio::spawn(async move {
                for _ in 0..5 {
                    validator
                        .validate("agent-1", &secret)
                        .await
                        .unwrap();
                }
            });
            let revoker = store.clone();
            let key_id = created.key_id.clone();
            let revoke = tokio::spawn(async move {
                tokio::task::yield_now().await;
                revoker
                    .revoke("agent-1", &key_id, "test-actor")
                    .await
                    .unwrap();
            });
            validations.await.unwrap();
            revoke.await.unwrap();

            let on_disk = open_store(&temp_dir)
                .await
                .get_record("agent-1", &created.key_id)
                .await
                .unwrap()
                .expect("the record stays readable");
            assert_eq!(on_disk.status, ApiKeyStatus::Revoked);
        }
    }

    #[tokio::test]
    async fn an_agent_folder_holds_key_records_whether_or_not_they_load() {
        let (store, temp_dir) = create_test_store().await;
        for (agent, file) in [("bad-json", "atgk_a.json"), ("bad-enc", "atgk_b.json.enc")] {
            std::fs::create_dir_all(temp_dir.path().join(agent)).unwrap();
            std::fs::write(
                temp_dir
                    .path()
                    .join(agent)
                    .join(file),
                b"{not a record",
            )
            .unwrap();
        }
        std::fs::create_dir_all(temp_dir.path().join("empty")).unwrap();
        std::fs::create_dir_all(
            temp_dir
                .path()
                .join("only-temp"),
        )
        .unwrap();
        std::fs::write(
            temp_dir
                .path()
                .join("only-temp")
                .join(".atgk_c.json.1.tmp"),
            b"{",
        )
        .unwrap();
        std::fs::create_dir_all(
            temp_dir
                .path()
                .join("only-usage"),
        )
        .unwrap();
        std::fs::write(
            temp_dir
                .path()
                .join("only-usage")
                .join(format!(".atgk_d{USAGE_FILE_SUFFIX}")),
            b"2026-01-01T00:00:00Z",
        )
        .unwrap();

        assert!(
            !store
                .holds_key_records("only-usage")
                .await
                .unwrap()
        );
        assert!(
            store
                .list_from_disk("only-usage")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .holds_key_records("bad-json")
                .await
                .unwrap()
        );
        assert!(
            store
                .holds_key_records("bad-enc")
                .await
                .unwrap()
        );
        assert!(
            store
                .list_from_disk("bad-json")
                .await
                .unwrap()
                .is_empty(),
            "the record does not load"
        );
        assert!(
            !store
                .holds_key_records("empty")
                .await
                .unwrap()
        );
        assert!(
            !store
                .holds_key_records("only-temp")
                .await
                .unwrap()
        );
        assert!(
            !store
                .holds_key_records("missing")
                .await
                .unwrap()
        );
        assert!(
            !temp_dir
                .path()
                .join("missing")
                .exists()
        );
    }

    #[tokio::test]
    async fn an_unreadable_agent_folder_fails_the_key_record_check() {
        use std::os::unix::fs::PermissionsExt as _;
        let (store, temp_dir) = create_test_store().await;
        let folder = temp_dir.path().join("locked");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&folder).is_ok() {
            std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let held = store
            .holds_key_records("locked")
            .await;
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(held.is_err());
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
