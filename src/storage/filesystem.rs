//! Generic filesystem storage for JSON-serializable entities
//!
//! Provides both cached and non-cached storage implementations with
//! common CRUD operations for any type that implements `StorableEntity`.
//!
//! # Optional Encryption at Rest
//!
//! All storage implementations support optional encryption using AES-GCM
//! AEAD. When enabled, data is encrypted before writing to disk and decrypted
//! when reading from disk.

use crate::encryption::{EncryptionService, fingerprint, init::init_encryption_service};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

// ============================================================================
// Global Encryption Configuration
// ============================================================================

use once_cell::sync::Lazy;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global encryption service for serde operations
/// This is initialized by the application and used throughout serialization
static GLOBAL_STORAGE_CONFIG: Lazy<RwLock<Option<StorageConfig>>> = Lazy::new(|| RwLock::new(None));

/// Interval, in seconds, at which every cached filesystem store reconciles its
/// in-memory cache with disk. `0` (the default) disables periodic refresh, so a
/// single-node deployment that owns its storage pays no polling cost. A positive
/// value is set once at startup for shared-storage deployments, where a standby
/// node must tail the active writer's changes to serve fresh state on promotion.
static CACHE_REFRESH_INTERVAL_SECS: AtomicU64 = AtomicU64::new(0);

/// Configure the periodic cache-refresh interval (seconds); `0` disables it.
///
/// Must be called before any cached store is constructed — each store reads the
/// interval once when it spawns its refresh loop.
pub fn set_cache_refresh_interval_secs(secs: u64) {
    CACHE_REFRESH_INTERVAL_SECS.store(secs, Ordering::Relaxed);
}

fn cache_refresh_interval_secs() -> u64 {
    CACHE_REFRESH_INTERVAL_SECS.load(Ordering::Relaxed)
}

// Test-only isolation — see the matching note in `encryption::global`. Production
// uses the process-wide `GLOBAL_STORAGE_CONFIG` below; concurrent unit tests each get their
// own thread-local so one test's storage config can't clobber another's.
#[cfg(test)]
thread_local! {
    static TEST_STORAGE_CONFIG: std::cell::RefCell<Option<StorageConfig>> = const { std::cell::RefCell::new(None) };
}

/// Initialize the global encryption service
///
/// Constructs the `EncryptionService` internally from the given config
/// via `init_encryption_service`. Must be called before any encrypted
/// structs are serialized/deserialized.
pub fn init_global_encryption(encryption_config: crate::config::EncryptionConfig) -> anyhow::Result<()> {
    let storage_config = storage_config_from_encryption_config(&encryption_config)?;

    #[cfg(test)]
    {
        TEST_STORAGE_CONFIG.with(|global_storage_config| {
            *global_storage_config.borrow_mut() = Some(storage_config);
        });

        debug!("Thread-local test storage config initialized for storage operations");
        Ok(())
    }

    #[cfg(not(test))]
    {
        let mut global_storage_config = GLOBAL_STORAGE_CONFIG
            .write()
            .unwrap();
        *global_storage_config = Some(storage_config);

        debug!("Global storage config initialized for all storage operations");
        Ok(())
    }
}

/// Get the global storage config, falling back to default if not initialized
fn get_global_storage_config() -> StorageConfig {
    #[cfg(test)]
    {
        if let Some(config) = TEST_STORAGE_CONFIG.with(|global_storage_config| {
            global_storage_config
                .borrow()
                .clone()
        }) {
            return config;
        }
    }

    GLOBAL_STORAGE_CONFIG
        .read()
        .unwrap()
        .clone()
        .unwrap_or_default()
}

// ============================================================================
// Core Traits
// ============================================================================

/// Trait for entities that can be stored in filesystem storage
///
/// Types implementing this trait must be serializable to JSON and provide
/// an ID for filesystem naming.
pub trait StorableEntity: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    /// Get the unique identifier for this entity
    ///
    /// This ID will be used as the filename (with .json extension)
    fn id(&self) -> &str;

    /// Optional hook called after loading from disk
    ///
    /// Use this for data normalization, migrations, or validation
    /// after deserialization.
    fn on_load(&mut self) {
        // Default: no-op
    }

    /// Pre-deserialization migration hook for raw JSON.
    ///
    /// Called on the raw `serde_json::Value` before deserializing into the typed entity.
    /// Returns `Ok(true)` if the JSON was modified (indicating the file should be re-persisted),
    /// `Ok(false)` if no changes were made, or `Err` if the migration encountered an error.
    ///
    /// Use this for schema migrations that must run before deserialization — e.g. renaming
    /// or transforming fields that no longer exist on the Rust struct.
    fn migrate_raw_json(_value: &mut serde_json::Value) -> Result<bool> {
        Ok(false)
    }
}

/// Type alias for the RwLock-based cache used by `RwLockFilesystemStorage`
///
/// Callers that need direct mutable access to the cache (e.g. session cleanup)
/// should use `raw_cache()` which returns this type.
pub type StorageCache<T> = Arc<tokio::sync::RwLock<std::collections::HashMap<String, T>>>;

/// Type alias for the DashMap-based cache used by `CachedFilesystemStorage`
///
/// DashMap provides lock-free concurrent reads and fine-grained per-shard
/// locking for writes, making it ideal for high-concurrency read-heavy workloads.
/// Each id maps to one [`CacheEntry`] holding the record together with the
/// bookkeeping the Active/Standby refresh scan needs, so every check-and-update for an
/// id happens under that id's single entry lock.
pub type DashMapCache<T> = Arc<DashMap<String, CacheEntry<T>>>;

/// How long a tombstone left by a local delete survives when no refresh scan prunes it
/// (periodic refresh disabled). Any scan that started before the delete has long finished by then.
const TOMBSTONE_TTL: Duration = Duration::from_secs(60);

/// One cached record plus what the disk refresh scan needs to reconcile it safely.
pub struct CacheEntry<T> {
    /// `None` is a tombstone left by a local delete, so a scan that read the file
    /// before the delete cannot bring the record back. The first scan that starts
    /// after the delete removes the tombstone.
    entity: Option<T>,
    /// SHA-256 of the on-disk bytes this record was last decrypted and parsed from.
    /// `None` after a local write until the next scan sees the new bytes.
    fingerprint: Option<[u8; 32]>,
    /// When this process last saved or deleted the record. A scan that started
    /// earlier leaves the entry alone; a scan that started later clears the mark.
    local_write_at: Option<Instant>,
}

impl<T> Default for CacheEntry<T> {
    fn default() -> Self {
        Self {
            entity: None,
            fingerprint: None,
            local_write_at: None,
        }
    }
}

impl<T> CacheEntry<T> {
    fn scanned(scanned: ScannedEntity<T>) -> Self {
        Self {
            entity: Some(scanned.entity),
            fingerprint: Some(scanned.fingerprint),
            local_write_at: None,
        }
    }

    fn written_locally_since(
        &self,
        scan_started: Instant,
    ) -> bool {
        self.local_write_at
            .is_some_and(|written_at| written_at >= scan_started)
    }

    fn is_expired_tombstone(
        &self,
        now: Instant,
    ) -> bool {
        self.entity.is_none()
            && self
                .local_write_at
                .is_none_or(|written_at| now.duration_since(written_at) > TOMBSTONE_TTL)
    }
}

/// One record as a scan read it: the parsed entity plus the fingerprint of the bytes it
/// came from. A file whose bytes still match the cached fingerprint is reused without
/// being decrypted again, so a quiet store costs no KMS calls per refresh tick.
struct ScannedEntity<T> {
    entity: T,
    fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageEventSource {
    // Event originated from a local write operation (create/update/delete)
    LocalWrite,
    // Event originated from an external change (second instance)
    RemoteWrite,
}

#[derive(Clone)]
pub enum StorageEvent<T: StorableEntity> {
    Upsert {
        #[allow(dead_code)]
        id: String,
        entity: T,
        source: StorageEventSource,
    },
    Delete {
        id: String,
        source: StorageEventSource,
    },
}

/// Trait for filesystem storage operations
///
/// Provides a common interface for CRUD operations that can be
/// implemented by different storage backends.
#[async_trait]
pub trait StorageBackend<T: StorableEntity>: Send + Sync {
    /// Create or update an entity
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()>;

    async fn save_atomic(
        &self,
        entity: &T,
    ) -> Result<()> {
        self.save(entity).await
    }

    /// Get an entity by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>>;

    /// List all entities
    async fn list_all(&self) -> Result<Vec<T>>;

    /// Delete an entity by ID
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Check if an entity exists
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }

    /// Return a snapshot of all entities as a HashMap.
    ///
    /// Cached backends read from the in-memory cache; the uncached
    /// backend loads from disk.  The RwLock is acquired (and released)
    /// internally so callers never see the lock.
    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        let entities = self.list_all().await?;
        Ok(entities
            .into_iter()
            .map(|e| (e.id().to_string(), e))
            .collect())
    }

    /// Get a direct reference to the underlying RwLock cache.
    ///
    /// Returns `Some` for RwLock-based backends (`RwLockFilesystemStorage`,
    /// `InMemoryStorage`), `None` for DashMap-backed and uncached backends.
    /// Use this only when you need mutable (write) access to the
    /// cache, e.g. during initialisation fixups.  For read-only
    /// snapshots prefer `hash_map()`.
    fn raw_cache(&self) -> Option<&StorageCache<T>> {
        None
    }

    fn subscribe(&self) -> Option<broadcast::Receiver<StorageEvent<T>>> {
        None
    }

    /// Reconcile the in-memory cache with the current on-disk state.
    ///
    /// Cached backends re-read the storage directory and upsert/evict entries so
    /// the cache matches disk, emitting a `RemoteWrite` event per change.
    /// Unreadable files are skipped and treated as absent (their cache entry is
    /// evicted). The default is a no-op for backends that always read from disk.
    async fn refresh_from_disk(&self) -> Result<()> {
        Ok(())
    }

    /// Encrypt any plaintext records left on disk when encryption at rest is enabled.
    ///
    /// Cached backends migrate plaintext to `.json.enc` as a side effect of loading
    /// every record into their cache at construction. Backends that never scan their
    /// directory at boot (the uncached backend used for secrets) override this to run
    /// the same sweep explicitly, so plaintext records do not linger unencrypted at
    /// rest. Returns the number of records migrated. The default is a no-op.
    async fn migrate_plaintext_at_rest(&self) -> Result<usize> {
        Ok(0)
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for filesystem storage
///
/// Controls how data is stored on disk, including optional encryption.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Enable encryption at rest
    pub encryption_service: Option<EncryptionService>,
}

impl StorageConfig {
    /// Create a new config without encryption
    pub fn new() -> Self {
        Self { encryption_service: None }
    }

    /// Add encryption to the config
    pub fn with_encryption_service(
        mut self,
        service: EncryptionService,
    ) -> Self {
        self.encryption_service = Some(service);
        self
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions for EncryptionConfig Integration
// ============================================================================

/// Create StorageConfig from EncryptionConfig
///
/// This bridges the on-disk TOML configuration (EncryptionConfig) to runtime
/// storage configuration (StorageConfig). If filesystem encryption is enabled,
/// it loads the key from the configured source and creates an Encryptor.
///
/// # Arguments
/// * `encryption_config` - EncryptionConfig from BootstrapConfig
///
/// # Errors
/// Returns an error if:
/// - Key loading fails
/// - Key has invalid format or encoding
/// - EncryptionService creation fails
pub fn storage_config_from_encryption_config(
    encryption_config: &crate::config::EncryptionConfig
) -> Result<StorageConfig> {
    let mut config = StorageConfig::default();
    if encryption_config.enabled {
        let encryption_service =
            init_encryption_service(encryption_config).context("Failed to initialize encryption service")?;
        config = config.with_encryption_service(encryption_service);
    }

    Ok(config)
}

// ============================================================================
// Convenience Functions for Storage Creation
// ============================================================================

// ============================================================================
// Helper Functions for Raw/Encrypted File Management
// ============================================================================

/// Get the encrypted file path for an entity
fn get_encrypted_path(
    storage_dir: &Path,
    id: &str,
) -> PathBuf {
    storage_dir.join(format!("{}.json.enc", id))
}

/// Get the raw (unencrypted) file path for an entity
fn get_raw_path(
    storage_dir: &Path,
    id: &str,
) -> PathBuf {
    storage_dir.join(format!("{}.json", id))
}

/// Deserialize a stored entity after running its [`StorableEntity::migrate_raw_json`]
/// hook, as every load path must. Returns the entity and whether the migration
/// changed it, in which case the caller persists the migrated entity.
fn deserialize_migrated<T: StorableEntity>(json: &[u8]) -> std::result::Result<(T, bool), String> {
    let mut value: serde_json::Value = serde_json::from_slice(json).map_err(|e| e.to_string())?;
    let migrated = T::migrate_raw_json(&mut value).map_err(|e| format!("migration failed: {e}"))?;
    let entity = serde_json::from_value(value).map_err(|e| e.to_string())?;
    Ok((entity, migrated))
}

/// Persist an entity whose stored JSON [`deserialize_migrated`] changed. A
/// failed write is logged, not fatal: the next load migrates it again.
async fn persist_migrated_entity<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    config: &StorageConfig,
    entity: &T,
) {
    match save_entity_to_disk(storage_dir, entity_name, config, entity).await {
        Ok(()) => info!("Schema-migrated {} {}, persisted the updated record", entity_name, entity.id()),
        Err(e) => warn!("Failed to persist schema-migrated {} {}: {}", entity_name, entity.id(), e),
    }
}

/// Load a raw (unencrypted) JSON file, deserialize it, and auto-encrypt it
///
/// This helper is used during startup when only raw JSON files exist but
/// encryption is enabled. It loads the JSON, deserializes it, calls on_load(),
/// and encrypts the content before saving.
async fn load_and_encrypt_raw_entity<T: StorableEntity>(
    storage_dir: &Path,
    id: &str,
    raw_path: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
) -> Result<ScannedEntity<T>> {
    let content = fs::read(raw_path)
        .await
        .context("Failed to read raw entity file")?;

    // Parse JSON
    let (mut entity, migrated): (T, bool) = deserialize_migrated(&content).map_err(|serde_err| {
        error!(
            "Deserialization error for entity {}: {}. File: {:?}, Content length: {} bytes",
            id,
            serde_err,
            raw_path,
            content.len()
        );
        anyhow::anyhow!("Failed to deserialize entity {} from {:?}: {}", id, raw_path, serde_err)
    })?;

    entity.on_load(); // Allow post-load processing

    // Encrypt and save the JSON content if encryption is enabled
    if let Some(encryption_service) = config
        .encryption_service
        .as_ref()
    {
        let json_str =
            String::from_utf8(content.clone()).context("Failed to convert JSON content to string for encryption")?;
        let encrypted_path = get_encrypted_path(storage_dir, id);
        let encrypted_content = encryption_service
            .encrypt_file(&encrypted_path, &json_str)
            .context("Failed to encrypt entity for auto-migration")?;
        atomic_write_file(&encrypted_path, encrypted_content.as_bytes())
            .await
            .context("Failed to write encrypted entity during auto-migration")?;
        info!("Auto-migrated entity {} from unencrypted to encrypted storage", id);
        // Encrypt-then-delete: the ciphertext is durably written, so the plaintext
        // original can be removed (no-op when raw-file retention is on).
        remove_plaintext_sibling(storage_dir, entity_name, id, config).await;
    }
    if migrated {
        persist_migrated_entity(storage_dir, entity_name, config, &entity).await;
    }

    Ok(ScannedEntity {
        entity,
        fingerprint: fingerprint(&content),
    })
}

/// Rename an entity's file on disk when the filename doesn't match `entity.id()`.
///
/// Saves the entity under its canonical id and removes the old mismatched file.
/// Returns `true` on success, `false` if either the save or delete failed.
async fn rename_mismatched_entity_file<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    config: &StorageConfig,
    entity: &T,
    old_file_id: &str,
) -> bool {
    let entity_id = entity.id();
    warn!(
        "Filename mismatch for {}: file '{}' has id '{}'. Renaming to '{}.json'",
        entity_name, old_file_id, entity_id, entity_id
    );
    if let Err(e) = save_entity_to_disk(storage_dir, entity_name, config, entity).await {
        error!("Failed to save renamed {} {}: {}", entity_name, entity_id, e);
        return false;
    }
    if let Err(e) = delete_entity_from_disk(storage_dir, entity_name, old_file_id).await {
        error!("Failed to remove old {} file '{}': {}", entity_name, old_file_id, e);
        return false;
    }
    true
}

/// Load all entities from disk, performing decryption and auto-migration as needed.
///
/// Returns a map of entity ID → scanned entity, ready to be used as a cache.
/// This is the shared implementation used by both CachedFilesystemStorage and
/// RwLockFilesystemStorage. When `cache` holds records an earlier scan of the same
/// directory decrypted, a file whose bytes still match the cached fingerprint is
/// taken from the cache instead of being decrypted and parsed again.
async fn load_all_entities_from_disk<T: StorableEntity>(
    storage_dir: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
    cache: Option<&DashMapCache<T>>,
    strict: bool,
) -> Result<std::collections::HashMap<String, ScannedEntity<T>>> {
    let mut entries = fs::read_dir(storage_dir)
        .await
        .context("Failed to read storage directory")?;

    let mut entities = std::collections::HashMap::new();
    let mut error_count = 0;
    let mut decrypt_error_count = 0;
    let mut processed_ids = std::collections::HashSet::new();

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str());

        if let Some(file_name) = file_name {
            let processed = if file_name.ends_with(".json") {
                // Raw file
                let id = file_name
                    .trim_end_matches(".json")
                    .to_string();

                // When encryption is active and raw files are not retained, a
                // plaintext .json must not remain on disk. A stale plaintext beside
                // an authoritative ciphertext is dropped here (the .json.enc entry
                // loads separately in this same scan); a plaintext-only record falls
                // through to load + encrypt + delete via the auto-migration path below.
                if config
                    .encryption_service
                    .is_some()
                    && get_encrypted_path(storage_dir, &id).exists()
                {
                    remove_plaintext_sibling(storage_dir, entity_name, &id, config).await;
                    continue;
                }

                if processed_ids.contains(&id) {
                    continue;
                }

                Some(id)
            } else if file_name.ends_with(".json.enc") {
                // Encrypted file
                let id = file_name
                    .trim_end_matches(".json.enc")
                    .to_string();

                if processed_ids.contains(&id) {
                    continue;
                }

                Some(id)
            } else {
                None
            };

            if let Some(id) = processed {
                // Determine which file to load from
                let file_to_load = if config
                    .encryption_service
                    .is_some()
                {
                    get_encrypted_path(storage_dir, &id)
                } else {
                    get_raw_path(storage_dir, &id)
                };

                // If the primary file doesn't exist and encryption is enabled,
                // check if only the raw file exists and auto-migrate it
                if !file_to_load.exists() {
                    if config
                        .encryption_service
                        .is_some()
                    {
                        let raw_path = get_raw_path(storage_dir, &id);
                        if raw_path.exists() {
                            // Found only the raw file during startup, load and encrypt it
                            match load_and_encrypt_raw_entity::<T>(storage_dir, &id, &raw_path, entity_name, config)
                                .await
                            {
                                Ok(entity) => {
                                    entities.insert(id.clone(), entity);
                                    processed_ids.insert(id);
                                    continue;
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to auto-migrate raw {} {} from {:?}: {}",
                                        entity_name, id, raw_path, e
                                    );
                                    error_count += 1;
                                    continue;
                                }
                            }
                        }
                    } else {
                        // Encryption is off but an encrypted file exists with no
                        // readable plaintext sibling. It cannot be decrypted (no storage
                        // encryptor is configured), so surface it loudly instead of silently
                        // dropping the record.
                        let encrypted_path = get_encrypted_path(storage_dir, &id);
                        if encrypted_path.exists() {
                            error!(
                                "{} {} exists only as an encrypted file ({:?}) but encryption at rest is \
                                 disabled; record skipped. Re-enable encryption or migrate this record \
                                 to plaintext JSON.",
                                entity_name, id, encrypted_path
                            );
                            error_count += 1;
                            crate::metrics::backends::prometheus::track_storage_load_error(
                                entity_name,
                                "encrypted_but_encryption_disabled",
                            );
                        }
                    }
                    continue;
                }

                match fs::read(&file_to_load).await {
                    Ok(content) => {
                        let content_fingerprint = fingerprint(&content);
                        if let Some(cache) = cache
                            && let Some(entry) = cache.get(&id)
                            && entry.fingerprint == Some(content_fingerprint)
                            && let Some(cached) = entry.entity.clone()
                        {
                            drop(entry);
                            entities.insert(
                                id.clone(),
                                ScannedEntity {
                                    entity: cached,
                                    fingerprint: content_fingerprint,
                                },
                            );
                            processed_ids.insert(id);
                            continue;
                        }

                        // Track whether we loaded from a raw (unencrypted) file
                        let loaded_from_raw = !file_to_load
                            .as_path()
                            .to_str()
                            .map(|s| s.ends_with(".json.enc"))
                            .unwrap_or(false);

                        // Decrypt if needed
                        let json_content = if file_to_load
                            .as_path()
                            .to_str()
                            .map(|s| s.ends_with(".json.enc"))
                            .unwrap_or(false)
                        {
                            let encryption_service = config
                                .encryption_service
                                .as_ref()
                                .context("File is encrypted but no encryptor available")?;
                            {
                                let encrypted_str = match String::from_utf8(content.clone()) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to convert encrypted {} {} to UTF-8: {}", entity_name, id, e);
                                        error_count += 1;
                                        decrypt_error_count += 1;
                                        crate::metrics::backends::prometheus::track_storage_load_error(
                                            entity_name,
                                            "decrypt_failed",
                                        );
                                        continue;
                                    }
                                };
                                match encryption_service.decrypt_file(&file_to_load, &encrypted_str) {
                                    Ok(decrypted) => decrypted.into_bytes(),
                                    Err(e) => {
                                        error!("Failed to decrypt {} from {:?}: {}", entity_name, file_to_load, e);
                                        error_count += 1;
                                        decrypt_error_count += 1;
                                        crate::metrics::backends::prometheus::track_storage_load_error(
                                            entity_name,
                                            "decrypt_failed",
                                        );
                                        continue;
                                    }
                                }
                            }
                        } else {
                            content
                        };

                        // Parse JSON — two-step: Value → migrate → deserialize
                        // Step 1: Parse into raw Value
                        let mut json_value: serde_json::Value = match serde_json::from_slice(&json_content) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Failed to parse {} from {:?}: {}", entity_name, file_to_load, e);
                                error_count += 1;
                                processed_ids.insert(id);
                                continue;
                            }
                        };

                        // Step 2: Run pre-deserialization migration on raw JSON
                        let schema_migrated = match T::migrate_raw_json(&mut json_value) {
                            Ok(migrated) => migrated,
                            Err(e) => {
                                error!("Failed to migrate {} from {:?}: {}", entity_name, file_to_load, e);
                                error_count += 1;
                                processed_ids.insert(id);
                                continue;
                            }
                        };

                        // Step 3: Deserialize from (possibly migrated) Value into typed entity
                        match serde_json::from_value::<T>(json_value) {
                            Ok(mut entity) => {
                                entity.on_load(); // Allow post-load processing

                                // Use entity.id() (config_id) as the canonical cache key,
                                // not the filename-derived id which may be stale/mismatched.
                                let entity_id = entity.id().to_string();
                                let filename_mismatch = entity_id != id;
                                entities.insert(
                                    entity_id.clone(),
                                    ScannedEntity {
                                        entity: entity.clone(),
                                        fingerprint: content_fingerprint,
                                    },
                                );
                                debug!("Loaded {} from {:?}", entity_name, file_to_load);

                                // If the filename doesn't match the entity's canonical id,
                                // re-save under the correct name and remove the old file.
                                if filename_mismatch {
                                    if !rename_mismatched_entity_file(storage_dir, entity_name, config, &entity, &id)
                                        .await
                                    {
                                        error_count += 1;
                                    }
                                    // Mark the new id as processed to avoid double-loading
                                    processed_ids.insert(entity_id);
                                } else {
                                    // If schema migration changed the JSON, persist the migrated version
                                    if schema_migrated {
                                        info!("Schema-migrated {} {}, persisting updated config", entity_name, id);
                                        if let Err(e) =
                                            save_entity_to_disk(storage_dir, entity_name, config, &entity).await
                                        {
                                            error!("Failed to persist schema-migrated {} {}: {}", entity_name, id, e);
                                            error_count += 1;
                                        }
                                    }

                                    // If encryption is enabled and we loaded from an unencrypted file,
                                    // encrypt and save it (auto-migration)
                                    if loaded_from_raw
                                        && let Some(encryption_service) = config
                                            .encryption_service
                                            .as_ref()
                                    {
                                        let json_str = match serde_json::to_string_pretty(&entity) {
                                            Ok(s) => s,
                                            Err(e) => {
                                                error!(
                                                    "Failed to convert {} {} content to string for encryption: {}",
                                                    entity_name, id, e
                                                );
                                                error_count += 1;
                                                processed_ids.insert(id);
                                                continue;
                                            }
                                        };
                                        let encrypted_path = get_encrypted_path(storage_dir, &id);
                                        match encryption_service.encrypt_file(&encrypted_path, &json_str) {
                                            Ok(encrypted_content) => {
                                                if let Err(e) = fs::write(&encrypted_path, encrypted_content).await {
                                                    error!(
                                                        "Failed to write encrypted {} {} during auto-migration: {}",
                                                        entity_name, id, e
                                                    );
                                                    error_count += 1;
                                                } else {
                                                    info!(
                                                        "Auto-migrated {} {} from unencrypted to encrypted storage",
                                                        entity_name, id
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to encrypt {} {} for auto-migration: {}",
                                                    entity_name, id, e
                                                );
                                                error_count += 1;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to parse {} from {:?}: {}", entity_name, file_to_load, e);
                                error_count += 1;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read {} from {:?}: {}", entity_name, file_to_load, e);
                        error_count += 1;
                    }
                }

                processed_ids.insert(id);
            }
        }
    }

    if error_count > 0 {
        error!("Encountered {} error(s) loading {}(s)", error_count, entity_name);
    }

    // Fail open on a decryption failure: an unreadable encrypted record (KMS outage,
    // wrong key source, tampered/corrupt envelope) is logged and skipped rather than
    // aborting the whole load, so a transient failure can't brick startup or a refresh.
    // The skipped record stays absent from the returned map until it can be read again.
    //
    // Deliberate tradeoff (availability over strict fail-closed): a `key_source` swap or
    // envelope-version mismatch is already caught before load by the boot preflight
    // (`encryption::preflight::check_envelope_versions`), so this path only fires on a
    // genuine transient outage or true corruption. The cost is that a skipped record
    // for a security-control store (policy, certificate, trust-registry config) is
    // absent rather than enforced — every skip is therefore logged at `error` and
    // metered (`agent_gateway_storage_load_errors_total`) so the degraded state is
    // loud and alertable, not silent. Callers that need strict fail-closed semantics for
    // a specific store should treat a non-zero counter as a hard alert.
    if decrypt_error_count > 0 {
        error!(
            "Skipped {} undecryptable encrypted {}(s) during load; check the encryption key_source and KMS availability",
            decrypt_error_count, entity_name
        );
    }

    if strict && error_count > 0 {
        bail!("encountered {error_count} load error(s) loading {entity_name}(s)");
    }

    Ok(entities)
}

/// Log encryption status, create storage dir, and load entities from disk.
///
/// Returns the loaded entity map. Used by both DashMap and RwLock init helpers.
async fn load_storage_dir<T: StorableEntity>(
    storage_dir: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
    cache: Option<&DashMapCache<T>>,
    strict: bool,
) -> Result<std::collections::HashMap<String, ScannedEntity<T>>> {
    let encryption_status = if config
        .encryption_service
        .is_some()
    {
        "with encryption"
    } else {
        "without encryption"
    };
    info!("Initializing {} storage {} at: {}", entity_name, encryption_status, storage_dir.display());

    // Create storage directory if it doesn't exist
    fs::create_dir_all(storage_dir)
        .await
        .context("Failed to create storage directory")?;

    // Load existing entities from disk
    let entities = load_all_entities_from_disk(storage_dir, entity_name, config, cache, strict).await?;
    info!("Loaded {} {}(s) from {}", entities.len(), entity_name, storage_dir.display());

    Ok(entities)
}

/// Initialize a DashMap-backed cached storage directory.
///
/// Used by `CachedFilesystemStorage::new_with_config`.
async fn init_dashmap_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    strict: bool,
) -> Result<(PathBuf, DashMapCache<T>, StorageConfig)> {
    let cache: DashMapCache<T> = Arc::new(DashMap::new());
    let scanned = load_storage_dir::<T>(&storage_dir, entity_name, &config, None, strict).await?;
    for (id, scanned) in scanned {
        cache.insert(id, CacheEntry::scanned(scanned));
    }
    Ok((storage_dir, cache, config))
}

/// Loads latest state on disk and reconciles the DashMap cache with it.
///
/// Ids saved or deleted locally after the scan started are left untouched: the scan
/// may have read their files before that write landed, so what it holds is older
/// than the cache, not newer.
async fn refresh_dashmap_cache<T: StorableEntity>(
    storage_dir: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
    cache: &DashMapCache<T>,
    event_tx: &broadcast::Sender<StorageEvent<T>>,
    strict: bool,
    refresh_lock: &tokio::sync::Mutex<()>,
) -> Result<()> {
    // Serialize scans for this store: two overlapping refreshes could otherwise apply
    // out of order and revert a record to an older on-disk snapshot (F5). The lock is
    // shared across every clone and the periodic loop, so only one scan runs at a time.
    let _scan_guard = refresh_lock.lock().await;
    let scan_started = Instant::now();
    let latest = load_all_entities_from_disk(storage_dir, entity_name, config, Some(cache), strict).await?;
    apply_disk_snapshot(cache, event_tx, latest, scan_started);
    Ok(())
}

/// Spawn a background task that reconciles the cache with disk every `interval_secs`
/// seconds, emitting a `RemoteWrite` event for every record another process sharing
/// the storage directory has written, updated, or removed. Returns `None` (spawning
/// nothing) when `interval_secs` is `0`, so single-node deployments keep the
/// default behaviour of never polling their own storage.
///
/// The returned guard aborts the task when the last handle to it drops, tying the
/// loop's lifetime to the store: a transiently constructed store (e.g. the throwaway
/// surface store built on a config reload) stops tailing as soon as it is dropped,
/// instead of leaking a scanning task for the life of the process.
fn spawn_dashmap_refresh_loop<T: StorableEntity>(
    interval_secs: u64,
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    cache: DashMapCache<T>,
    event_tx: broadcast::Sender<StorageEvent<T>>,
    strict: bool,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
) -> Option<Arc<RefreshLoopGuard>> {
    if interval_secs == 0 {
        return None;
    }
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The cache was loaded fresh at construction, so skip the immediate first tick.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) =
                refresh_dashmap_cache(&storage_dir, entity_name, &config, &cache, &event_tx, strict, &refresh_lock)
                    .await
            {
                warn!("Failed to refresh '{}' cache from disk: {}", entity_name, e);
            }
        }
    });
    Some(Arc::new(RefreshLoopGuard(handle)))
}

/// Aborts a store's background refresh loop when the last store handle drops.
///
/// Shared across [`CachedFilesystemStorage`] clones via `Arc`, so the loop runs as
/// long as any clone lives and stops once they are all gone. The task only reads
/// disk and updates the in-memory cache under per-id entry locks, so aborting it
/// mid-scan cannot corrupt state.
struct RefreshLoopGuard(tokio::task::JoinHandle<()>);

impl Drop for RefreshLoopGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Applies a directory snapshot taken at `scan_started` to the cache, emitting a
/// `RemoteWrite` event per change. Every decision and update for an id happens under
/// that id's entry lock, so a concurrent local save or delete can never be undone.
///
/// An entry saved or deleted locally after `scan_started` is left alone, because the
/// scan may have read its file before that write. Every other entry is reconciled
/// with disk: its local-write mark is cleared, a record missing on disk is evicted
/// with a `Delete` event, and a tombstone missing on disk is dropped silently.
fn apply_disk_snapshot<T: StorableEntity>(
    cache: &DashMapCache<T>,
    event_tx: &broadcast::Sender<StorageEvent<T>>,
    latest: std::collections::HashMap<String, ScannedEntity<T>>,
    scan_started: Instant,
) {
    let latest_keys: std::collections::HashSet<String> = latest
        .keys()
        .cloned()
        .collect();

    for (id, scanned) in latest {
        let changed = match cache.entry(id.clone()) {
            Entry::Occupied(mut occupied) => {
                let current = occupied.get_mut();
                if current.written_locally_since(scan_started) {
                    continue;
                }
                let changed = current
                    .entity
                    .as_ref()
                    .is_none_or(|cached| serde_json::to_vec(cached).ok() != serde_json::to_vec(&scanned.entity).ok());
                *current = CacheEntry::scanned(ScannedEntity {
                    entity: scanned.entity.clone(),
                    fingerprint: scanned.fingerprint,
                });
                changed
            }
            Entry::Vacant(vacant) => {
                vacant.insert(CacheEntry::scanned(ScannedEntity {
                    entity: scanned.entity.clone(),
                    fingerprint: scanned.fingerprint,
                }));
                true
            }
        };
        if changed {
            let _ = event_tx.send(StorageEvent::Upsert {
                id,
                entity: scanned.entity,
                source: StorageEventSource::RemoteWrite,
            });
        }
    }

    let missing_on_disk: Vec<String> = cache
        .iter()
        .map(|entry| entry.key().clone())
        .filter(|key| !latest_keys.contains(key))
        .collect();
    for key in missing_on_disk {
        let evicted_record = match cache.entry(key.clone()) {
            Entry::Occupied(occupied)
                if !occupied
                    .get()
                    .written_locally_since(scan_started) =>
            {
                occupied
                    .remove()
                    .entity
                    .is_some()
            }
            _ => false,
        };
        if evicted_record {
            let _ = event_tx.send(StorageEvent::Delete {
                id: key,
                source: StorageEventSource::RemoteWrite,
            });
        }
    }
}

/// Initialize an RwLock-backed cached storage directory.
///
/// Used by `RwLockFilesystemStorage::new_with_config`.
async fn init_rwlock_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<(PathBuf, StorageCache<T>, StorageConfig)> {
    let entities = load_storage_dir::<T>(&storage_dir, entity_name, &config, None, false)
        .await?
        .into_iter()
        .map(|(id, scanned)| (id, scanned.entity))
        .collect();
    let cache = Arc::new(tokio::sync::RwLock::new(entities));
    Ok((storage_dir, cache, config))
}

/// Save an entity to disk, handling serialization, encryption, and raw file storage.
///
/// Shared by all three storage backends.
async fn save_entity_to_disk<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    config: &StorageConfig,
    entity: &T,
) -> Result<()> {
    let id = entity.id();
    super::validate_storage_id(id)?;

    // Serialize to JSON
    let json_content = serde_json::to_string_pretty(entity).context("Failed to serialize entity")?;

    // Store based on config
    if let Some(ref encryption_service) = config.encryption_service {
        // Encrypted storage
        let encrypted_path = get_encrypted_path(storage_dir, id);
        let encrypted_content = encryption_service
            .encrypt_file(&encrypted_path, &json_content)
            .context("Failed to encrypt entity")?;
        fs::write(&encrypted_path, encrypted_content)
            .await
            .context("Failed to write encrypted entity to disk")?;
        debug!("Saved encrypted {} {} to {:?}", entity_name, id, encrypted_path);

        // Remove any stale plaintext sibling left from before encryption was enabled.
        remove_plaintext_sibling(storage_dir, entity_name, id, config).await;
    } else {
        // Plain storage
        let raw_path = get_raw_path(storage_dir, id);
        fs::write(&raw_path, json_content.as_bytes())
            .await
            .context("Failed to write entity to disk")?;
        debug!("Saved {} {} to {:?}", entity_name, id, raw_path);
    }

    Ok(())
}

/// Save an entity to disk atomically, ensuring that the file is fully written.
/// This function writes the entity to a temporary file first and then renames (atomic) it
async fn save_entity_to_disk_atomic<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    config: &StorageConfig,
    entity: &T,
) -> Result<()> {
    let id = entity.id();
    super::validate_storage_id(id)?;

    let json_content = serde_json::to_string_pretty(entity).context("Failed to serialize entity")?;

    if let Some(ref encryption_service) = config.encryption_service {
        let encrypted_path = get_encrypted_path(storage_dir, id);
        let encrypted_content = encryption_service
            .encrypt_file(&encrypted_path, &json_content)
            .context("Failed to encrypt entity")?;
        atomic_write_file(&encrypted_path, encrypted_content.as_bytes())
            .await
            .context("Failed to write encrypted entity to disk")?;
        debug!("Atomically saved encrypted {} {} to {:?}", entity_name, id, encrypted_path);

        // Remove any stale plaintext sibling left from before encryption was enabled.
        remove_plaintext_sibling(storage_dir, entity_name, id, config).await;
    } else {
        let raw_path = get_raw_path(storage_dir, id);
        atomic_write_file(&raw_path, json_content.as_bytes())
            .await
            .context("Failed to write entity to disk")?;
        debug!("Atomically saved {} {} to {:?}", entity_name, id, raw_path);
    }

    Ok(())
}

async fn atomic_write_file(
    target_path: &Path,
    content: &[u8],
) -> Result<()> {
    let parent = target_path
        .parent()
        .context("Target path has no parent directory")?;
    fs::create_dir_all(parent)
        .await
        .context("Failed to create parent directory for atomic write")?;

    let file_name = target_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Target path has invalid file name")?;
    let tmp_name = format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4());
    let tmp_path = parent.join(tmp_name);

    let result = async {
        let mut temporary = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await
            .context("Failed to create atomic temporary file")?;
        temporary
            .write_all(content)
            .await
            .context("Failed to write atomic temporary file")?;
        temporary
            .flush()
            .await
            .context("Failed to flush atomic temporary file")?;
        temporary
            .sync_all()
            .await
            .context("Failed to sync atomic temporary file")?;
        drop(temporary);
        fs::rename(&tmp_path, target_path)
            .await
            .context("Failed to atomically replace entity file")?;
        #[cfg(unix)]
        sync_directory(parent).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path).await;
    }
    result
}

#[cfg(unix)]
pub(crate) async fn sync_directory(directory: &Path) -> Result<()> {
    static UNSUPPORTED_LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    let handle = fs::File::open(directory)
        .await
        .context("Failed to open storage directory for sync")?;
    match handle.sync_all().await {
        Ok(()) => Ok(()),
        Err(error) if directory_sync_unsupported(&error) => {
            if UNSUPPORTED_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                debug!("Skipped unsupported sync of storage directory {:?}: {}", directory, error);
            } else {
                warn!(
                    "Storage directory {:?} does not support directory sync ({}); continuing without it, so \
                     renamed or deleted entries rely on the filesystem's own durability",
                    directory, error
                );
            }
            Ok(())
        }
        Err(error) => Err(error).context("Failed to sync storage directory"),
    }
}

#[cfg(unix)]
fn directory_sync_unsupported(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput)
        || error
            .raw_os_error()
            .is_some_and(|code| [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS].contains(&code))
}

/// Remove a plaintext `id.json` once its encrypted `id.json.enc` sibling is
/// authoritative, so decrypted key material does not linger on disk.
///
/// No-op unless encryption is active. Failure is logged, not propagated: a
/// read-only filesystem or a permissions error must not abort startup or a
/// save — the record is already durably encrypted and loadable.
async fn remove_plaintext_sibling(
    storage_dir: &Path,
    entity_name: &str,
    id: &str,
    config: &StorageConfig,
) {
    if config
        .encryption_service
        .is_none()
    {
        return;
    }

    let raw_path = get_raw_path(storage_dir, id);
    if raw_path.exists() {
        // Enforce the encrypt-then-delete invariant defensively: never remove the
        // plaintext unless its authoritative ciphertext sibling is actually on disk.
        // A missing `.enc` means the plaintext is the only readable copy, so keep it.
        let encrypted_path = get_encrypted_path(storage_dir, id);
        if !encrypted_path.exists() {
            crate::metrics::backends::prometheus::track_storage_plaintext_removal_failed(entity_name);
            error!(
                "Refusing to delete plaintext {} file {:?}: its encrypted sibling {:?} is missing, so \
                 this is the only readable copy",
                entity_name, raw_path, encrypted_path
            );
            return;
        }
        match fs::remove_file(&raw_path).await {
            Ok(()) => info!("Removed plaintext {} file {:?} after encryption", entity_name, raw_path),
            Err(e) => {
                crate::metrics::backends::prometheus::track_storage_plaintext_removal_failed(entity_name);
                error!(
                    "Failed to delete plaintext {} file {:?} after encryption; plaintext key material may \
                     remain on disk: {}",
                    entity_name, raw_path, e
                );
            }
        }
    }
}

/// Delete an entity's files from disk (encrypted and/or raw).
///
/// Shared by all three storage backends.
async fn delete_entity_from_disk(
    storage_dir: &Path,
    entity_name: &str,
    id: &str,
) -> Result<()> {
    super::validate_storage_id(id)?;
    let mut removed = false;

    // Delete encrypted file if exists
    let encrypted_path = get_encrypted_path(storage_dir, id);
    if encrypted_path.exists() {
        fs::remove_file(&encrypted_path)
            .await
            .context("Failed to delete encrypted entity file")?;
        removed = true;
        debug!("Deleted encrypted {} file {:?}", entity_name, encrypted_path);
    }

    // Delete raw file if exists
    let raw_path = get_raw_path(storage_dir, id);
    if raw_path.exists() {
        fs::remove_file(&raw_path)
            .await
            .context("Failed to delete raw entity file")?;
        removed = true;
        debug!("Deleted raw {} file {:?}", entity_name, raw_path);
    }

    if removed {
        #[cfg(unix)]
        sync_directory(storage_dir).await?;
    }
    debug!("Deleted {} {}", entity_name, id);
    Ok(())
}

// ============================================================================
// Cached Implementation (DashMap)
// ============================================================================

/// Filesystem storage with lock-free in-memory cache backed by DashMap
///
/// This implementation maintains a DashMap cache of all entities for fast,
/// concurrent access. Reads are lock-free and writes use fine-grained
/// per-shard locking so they never block unrelated reads.
///
/// # When to use
/// - Frequently accessed data with concurrent readers
/// - Data that fits comfortably in memory
/// - When read performance is critical
/// - When you do **not** need whole-map locked access (use
///   `RwLockFilesystemStorage` for that)
///
/// # Example
/// ```rust,no_run
/// use crate::storage::filesystem::{CachedFilesystemStorage, StorableEntity};
///
/// #[derive(Clone, serde::Serialize, serde::Deserialize)]
/// struct MyEntity {
///     id: String,
///     data: String,
/// }
///
/// impl StorableEntity for MyEntity {
///     fn id(&self) -> &str {
///         &self.id
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = CachedFilesystemStorage::new(
///     "/path/to/storage".into(),
///     "my_entity"
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct CachedFilesystemStorage<T: StorableEntity> {
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    cache: DashMapCache<T>,
    event_tx: broadcast::Sender<StorageEvent<T>>,
    strict_loading: bool,
    /// Aborts the background refresh loop when the last store handle drops.
    /// `None` when periodic refresh is disabled (`cache_refresh_interval_secs == 0`).
    refresh_loop: Option<Arc<RefreshLoopGuard>>,
    /// Serializes disk-refresh scans (periodic loop + explicit refreshes + cache-miss
    /// reloads) so two overlapping scans cannot apply out of order and revert a record
    /// to a stale snapshot (F5). Shared across all clones via `Arc`.
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl<T: StorableEntity> Clone for CachedFilesystemStorage<T> {
    fn clone(&self) -> Self {
        Self {
            storage_dir: self.storage_dir.clone(),
            entity_name: self.entity_name,
            config: self.config.clone(),
            cache: self.cache.clone(),
            event_tx: self.event_tx.clone(),
            strict_loading: self.strict_loading,
            refresh_loop: self.refresh_loop.clone(),
            refresh_lock: self.refresh_lock.clone(),
        }
    }
}

impl<T: StorableEntity> CachedFilesystemStorage<T> {
    /// Create a new cached filesystem storage without encryption
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store JSON files
    /// * `entity_name` - Human-readable name for logging (e.g., "channel", "gateway")
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read or parsed
    #[allow(dead_code)]
    pub async fn new(
        storage_dir: PathBuf,
        entity_name: &'static str,
    ) -> Result<Self> {
        Self::new_with_config(storage_dir, entity_name, StorageConfig::default()).await
    }

    /// Create a new cached filesystem storage with custom config
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store files
    /// * `entity_name` - Human-readable name for logging
    /// * `config` - Storage configuration (encryption, raw files, etc.)
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read, decrypted, or parsed
    pub async fn new_with_config(
        storage_dir: PathBuf,
        entity_name: &'static str,
        config: StorageConfig,
    ) -> Result<Self> {
        Self::new_with_config_and_loading(storage_dir, entity_name, config, false).await
    }

    async fn new_with_config_and_loading(
        storage_dir: PathBuf,
        entity_name: &'static str,
        config: StorageConfig,
        strict_loading: bool,
    ) -> Result<Self> {
        let (storage_dir, cache, config) =
            init_dashmap_storage(storage_dir, entity_name, config, strict_loading).await?;
        let (event_tx, _) = broadcast::channel(1024);
        let refresh_lock = Arc::new(tokio::sync::Mutex::new(()));

        let refresh_loop = spawn_dashmap_refresh_loop(
            cache_refresh_interval_secs(),
            storage_dir.clone(),
            entity_name,
            config.clone(),
            cache.clone(),
            event_tx.clone(),
            strict_loading,
            refresh_lock.clone(),
        );

        Ok(Self {
            storage_dir,
            entity_name,
            config,
            cache,
            event_tx,
            strict_loading,
            refresh_loop,
            refresh_lock,
        })
    }

    /// Create or update an entity
    pub async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk(&self.storage_dir, self.entity_name, &self.config, entity).await?;
        self.commit_local_write(entity);
        Ok(())
    }

    /// Create or update an entity, writing to disk atomically (temp file + rename).
    pub async fn atomic_save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk_atomic(&self.storage_dir, self.entity_name, &self.config, entity).await?;
        self.commit_local_write(entity);
        Ok(())
    }

    /// Publishes a completed on-disk write to the cache under the id's entry lock, so
    /// a refresh scan that read the file before this write skips the id instead of
    /// reverting it. The fingerprint is dropped because the bytes on disk changed.
    fn commit_local_write(
        &self,
        entity: &T,
    ) {
        let id = entity.id().to_string();
        {
            let mut entry = self
                .cache
                .entry(id.clone())
                .or_default();
            entry.entity = Some(entity.clone());
            entry.fingerprint = None;
            entry.local_write_at = Some(Instant::now());
        }
        let _ = self
            .event_tx
            .send(StorageEvent::Upsert {
                id,
                entity: entity.clone(),
                source: StorageEventSource::LocalWrite,
            });
    }

    fn cached_entity(
        &self,
        id: &str,
    ) -> Option<T> {
        self.cache
            .get(id)
            .and_then(|entry| entry.entity.clone())
    }

    /// Get an entity by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        if let Some(entity) = self.cached_entity(id) {
            return Ok(Some(entity));
        }

        refresh_dashmap_cache(
            &self.storage_dir,
            self.entity_name,
            &self.config,
            &self.cache,
            &self.event_tx,
            self.strict_loading,
            &self.refresh_lock,
        )
        .await?;

        Ok(self.cached_entity(id))
    }

    /// List all entities
    pub async fn list_all(&self) -> Result<Vec<T>> {
        Ok(self
            .cache
            .iter()
            .filter_map(|entry| entry.entity.clone())
            .collect())
    }

    /// Reconcile the in-memory cache with the current on-disk state.
    ///
    /// Re-reads the storage directory and upserts/evicts cache entries to match
    /// disk, emitting a `RemoteWrite` event per change. Entities saved or deleted
    /// locally while the scan was running keep their in-memory state. Unreadable
    /// files are skipped and treated as absent (their cache entry is evicted). If
    /// the storage directory itself cannot be read the cache is left unchanged and
    /// the error is returned to the caller.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        refresh_dashmap_cache(
            &self.storage_dir,
            self.entity_name,
            &self.config,
            &self.cache,
            &self.event_tx,
            self.strict_loading,
            &self.refresh_lock,
        )
        .await
    }

    /// Delete an entity by ID
    ///
    /// The cache keeps a tombstone for the id so a refresh scan that read the file
    /// before the delete cannot bring the record back. The next scan removes the
    /// tombstone. Without periodic refresh there may be no scan, so tombstones older than
    /// [`TOMBSTONE_TTL`] are swept here instead.
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        delete_entity_from_disk(&self.storage_dir, self.entity_name, id).await?;
        let now = Instant::now();
        self.sweep_expired_tombstones(now);
        {
            let mut entry = self
                .cache
                .entry(id.to_string())
                .or_default();
            entry.entity = None;
            entry.fingerprint = None;
            entry.local_write_at = Some(now);
        }
        let _ = self
            .event_tx
            .send(StorageEvent::Delete {
                id: id.to_string(),
                source: StorageEventSource::LocalWrite,
            });
        Ok(())
    }

    fn sweep_expired_tombstones(
        &self,
        now: Instant,
    ) {
        self.cache
            .retain(|_, entry| !entry.is_expired_tombstone(now));
    }

    /// Check if an entity exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self
            .cache
            .get(id)
            .is_some_and(|entry| entry.entity.is_some()))
    }

    /// Create a new cached filesystem storage with encryption
    ///
    /// Convenience method for creating storage with encryption enabled.
    #[allow(dead_code)]
    pub async fn new_with_encryption(
        storage_dir: PathBuf,
        entity_name: &'static str,
        encryption_service: EncryptionService,
    ) -> Result<Self> {
        let config = StorageConfig::default().with_encryption_service(encryption_service);
        Self::new_with_config(storage_dir, entity_name, config).await
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for CachedFilesystemStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        CachedFilesystemStorage::save(self, entity).await
    }
    async fn save_atomic(
        &self,
        entity: &T,
    ) -> Result<()> {
        CachedFilesystemStorage::atomic_save(self, entity).await
    }
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        CachedFilesystemStorage::get(self, id).await
    }
    async fn list_all(&self) -> Result<Vec<T>> {
        CachedFilesystemStorage::list_all(self).await
    }
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        CachedFilesystemStorage::delete(self, id).await
    }
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        CachedFilesystemStorage::exists(self, id).await
    }

    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        Ok(self
            .cache
            .iter()
            .filter_map(|entry| {
                entry
                    .entity
                    .clone()
                    .map(|entity| (entry.key().clone(), entity))
            })
            .collect())
    }

    fn subscribe(&self) -> Option<broadcast::Receiver<StorageEvent<T>>> {
        Some(self.event_tx.subscribe())
    }

    async fn refresh_from_disk(&self) -> Result<()> {
        CachedFilesystemStorage::refresh_from_disk(self).await
    }
}

// ============================================================================
// Non-Cached Implementation (Always Read from Disk)
// ============================================================================

/// Filesystem storage without caching - always reads from disk
///
/// This implementation does not maintain an in-memory cache and reads
/// from disk on every access. Use this for sensitive data or when
/// memory is constrained.
///
/// # When to use
/// - Sensitive data (secrets, credentials)
/// - Large entities that don't fit well in memory
/// - Infrequently accessed data
/// - When memory is constrained
///
/// # Example
/// ```rust,no_run
/// use crate::storage::filesystem::{UncachedFilesystemStorage, StorableEntity};
///
/// #[derive(Clone, serde::Serialize, serde::Deserialize)]
/// struct Secret {
///     id: String,
///     encrypted_value: Vec<u8>,
/// }
///
/// impl StorableEntity for Secret {
///     fn id(&self) -> &str {
///         &self.id
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = UncachedFilesystemStorage::new(
///     "/path/to/secrets".into(),
///     "secret"
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct UncachedFilesystemStorage<T: StorableEntity> {
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: StorableEntity> Clone for UncachedFilesystemStorage<T> {
    fn clone(&self) -> Self {
        Self {
            storage_dir: self.storage_dir.clone(),
            entity_name: self.entity_name,
            config: self.config.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: StorableEntity> UncachedFilesystemStorage<T> {
    /// Create a new uncached filesystem storage without encryption
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store JSON files
    /// * `entity_name` - Human-readable name for logging
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created
    #[allow(dead_code)]
    pub async fn new(
        storage_dir: PathBuf,
        entity_name: &'static str,
    ) -> Result<Self> {
        Self::new_with_config(storage_dir, entity_name, StorageConfig::default()).await
    }

    /// Create a new uncached filesystem storage with custom config
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store files
    /// * `entity_name` - Human-readable name for logging
    /// * `config` - Storage configuration
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created
    pub async fn new_with_config(
        storage_dir: PathBuf,
        entity_name: &'static str,
        config: StorageConfig,
    ) -> Result<Self> {
        let encryption_status = if config
            .encryption_service
            .is_some()
        {
            "with encryption"
        } else {
            "without encryption"
        };
        info!("Initializing uncached {} storage {} at: {}", entity_name, encryption_status, storage_dir.display());

        // Create storage directory if it doesn't exist
        fs::create_dir_all(&storage_dir)
            .await
            .context("Failed to create storage directory")?;

        Ok(Self {
            storage_dir,
            entity_name,
            config,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Create a new uncached filesystem storage with encryption
    ///
    /// Convenience method for creating storage with encryption enabled.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store encrypted files
    /// * `entity_name` - Human-readable name for logging
    /// * `encryption_service` - EncryptionService for data at rest
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created
    #[allow(dead_code)]
    pub async fn new_with_encryption(
        storage_dir: PathBuf,
        entity_name: &'static str,
        encryption_service: EncryptionService,
    ) -> Result<Self> {
        let config = StorageConfig::default().with_encryption_service(encryption_service);
        Self::new_with_config(storage_dir, entity_name, config).await
    }

    /// Get the encrypted file path for an entity
    fn get_encrypted_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_encrypted_path(&self.storage_dir, id)
    }

    /// Get the raw file path for an entity
    fn get_raw_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_raw_path(&self.storage_dir, id)
    }

    /// Load an entity from disk
    ///
    /// If encryption is enabled and only a raw (unencrypted) JSON file is found,
    /// it will be automatically encrypted and saved as .json.enc for future loads.
    async fn load_from_disk(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        super::validate_storage_id(id)?;

        // Determine which file to load from
        let file_to_load = if self
            .config
            .encryption_service
            .is_some()
        {
            self.get_encrypted_path(id)
        } else {
            self.get_raw_path(id)
        };

        // If the primary file doesn't exist and encryption is enabled,
        // check if only the raw file exists and auto-migrate it
        if !file_to_load.exists() {
            if self
                .config
                .encryption_service
                .is_some()
            {
                let raw_path = self.get_raw_path(id);
                if raw_path.exists() {
                    // Found only the raw file, use it for loading instead
                    return self
                        .load_and_encrypt_raw(id, &raw_path)
                        .await;
                }
            } else {
                // Encryption is off but an encrypted file exists with no
                // readable plaintext sibling. It cannot be decrypted, so fail loudly
                // instead of reporting the record as absent.
                let encrypted_path = self.get_encrypted_path(id);
                if encrypted_path.exists() {
                    crate::metrics::backends::prometheus::track_storage_load_error(
                        self.entity_name,
                        "encrypted_but_encryption_disabled",
                    );
                    anyhow::bail!(
                        "{} {} exists only as an encrypted file but encryption at rest is disabled; \
                         re-enable encryption or migrate this record to plaintext JSON",
                        self.entity_name,
                        id
                    );
                }
            }
            return Ok(None);
        }

        let content = fs::read(&file_to_load)
            .await
            .context("Failed to read entity file")?;

        // Track whether we loaded from a raw (unencrypted) file
        let loaded_from_raw = !file_to_load
            .as_path()
            .to_str()
            .map(|s| s.ends_with(".json.enc"))
            .unwrap_or(false);

        // Decrypt if needed
        let json_content = if file_to_load
            .as_path()
            .to_str()
            .map(|s| s.ends_with(".json.enc"))
            .unwrap_or(false)
        {
            let encryption_service = self
                .config
                .encryption_service
                .as_ref()
                .context("File is encrypted but no encryptor available")?;
            {
                // File was encrypted with encrypt_string, so read as UTF-8 string
                let encrypted_str = String::from_utf8(content.clone()).context("Encrypted data is not valid UTF-8")?;
                encryption_service
                    .decrypt_file(&file_to_load, &encrypted_str)
                    .map_err(|err| {
                        error!(
                            "Decryption error for {} {}: {}. File: {:?}, Content length: {} bytes",
                            self.entity_name,
                            id,
                            err,
                            file_to_load,
                            content.len(),
                        );
                        anyhow::anyhow!(
                            "Failed to decrypt entity {} {} from {:?}: {}",
                            self.entity_name,
                            id,
                            file_to_load,
                            err
                        )
                    })?
                    .into_bytes()
            }
        } else {
            content
        };

        let (mut entity, migrated): (T, bool) = deserialize_migrated(&json_content).map_err(|serde_err| {
            error!(
                "Deserialization error for {} {}: {}. File: {:?}, Content length: {} bytes",
                self.entity_name,
                id,
                serde_err,
                file_to_load,
                json_content.len(),
            );
            anyhow::anyhow!("Failed to deserialize {} {} from {:?}: {}", self.entity_name, id, file_to_load, serde_err)
        })?;

        entity.on_load(); // Allow post-load processing

        // If encryption is enabled and we loaded from an unencrypted file, encrypt and save it
        // This provides automatic migration of existing unencrypted files to encrypted storage
        if loaded_from_raw
            && let Some(encryption_service) = self
                .config
                .encryption_service
                .as_ref()
        {
            // Preserve the original JSON content for encryption
            let json_str = String::from_utf8(json_content.clone())
                .context("Failed to convert JSON content to string for encryption")?;
            let encrypted_path = self.get_encrypted_path(id);
            let encrypted_content = encryption_service
                .encrypt_file(&encrypted_path, &json_str)
                .context("Failed to encrypt entity for auto-migration")?;
            atomic_write_file(&encrypted_path, encrypted_content.as_bytes())
                .await
                .context("Failed to write encrypted entity during auto-migration")?;
            info!("Auto-migrated {} {} from unencrypted to encrypted storage", self.entity_name, id);
            remove_plaintext_sibling(&self.storage_dir, self.entity_name, id, &self.config).await;
        }
        if migrated {
            persist_migrated_entity(&self.storage_dir, self.entity_name, &self.config, &entity).await;
        }

        Ok(Some(entity))
    }

    /// Load a raw (unencrypted) JSON file and encrypt it
    async fn load_and_encrypt_raw(
        &self,
        id: &str,
        raw_path: &PathBuf,
    ) -> Result<Option<T>> {
        let content = fs::read(raw_path)
            .await
            .context("Failed to read raw entity file")?;

        // Parse JSON
        let (mut entity, migrated): (T, bool) = deserialize_migrated(&content).map_err(|serde_err| {
            error!(
                "Deserialization error for {} {}: {}. File: {:?}, Content length: {} bytes",
                self.entity_name,
                id,
                serde_err,
                raw_path,
                content.len()
            );
            anyhow::anyhow!("Failed to deserialize {} {} from {:?}: {}", self.entity_name, id, raw_path, serde_err)
        })?;

        entity.on_load(); // Allow post-load processing

        // Encrypt and save the JSON content if encryption is enabled
        if let Some(encryption_service) = self
            .config
            .encryption_service
            .as_ref()
        {
            let json_str = String::from_utf8(content.clone())
                .context("Failed to convert JSON content to string for encryption")?;
            let encrypted_path = self.get_encrypted_path(id);
            let encrypted_content = encryption_service
                .encrypt_file(&encrypted_path, &json_str)
                .context("Failed to encrypt entity for auto-migration")?;
            atomic_write_file(&encrypted_path, encrypted_content.as_bytes())
                .await
                .context("Failed to write encrypted entity during auto-migration")?;
            info!("Auto-migrated {} {} from unencrypted to encrypted storage", self.entity_name, id);
            remove_plaintext_sibling(&self.storage_dir, self.entity_name, id, &self.config).await;
        }
        if migrated {
            persist_migrated_entity(&self.storage_dir, self.entity_name, &self.config, &entity).await;
        }

        Ok(Some(entity))
    }

    /// List all entity IDs from disk
    async fn list_all_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut processed_ids = std::collections::HashSet::new();
        let mut entries = fs::read_dir(&self.storage_dir)
            .await
            .context("Failed to read storage directory")?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str());

            if let Some(file_name) = file_name
                && let Some(id) = if file_name.ends_with(".json") {
                    Some(
                        file_name
                            .trim_end_matches(".json")
                            .to_string(),
                    )
                } else if file_name.ends_with(".json.enc") {
                    Some(
                        file_name
                            .trim_end_matches(".json.enc")
                            .to_string(),
                    )
                } else {
                    None
                }
                && !processed_ids.contains(&id)
            {
                ids.push(id.clone());
                processed_ids.insert(id);
            }
        }

        Ok(ids)
    }

    /// Create or update an entity
    pub async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk(&self.storage_dir, self.entity_name, &self.config, entity).await
    }

    pub async fn atomic_save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk_atomic(&self.storage_dir, self.entity_name, &self.config, entity).await
    }

    /// Get an entity by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        self.load_from_disk(id).await
    }

    /// List all entities
    pub async fn list_all(&self) -> Result<Vec<T>> {
        let ids = self.list_all_ids().await?;
        let mut entities = Vec::new();

        for id in ids {
            if let Some(entity) = self
                .load_from_disk(&id)
                .await?
            {
                entities.push(entity);
            }
        }

        Ok(entities)
    }

    /// Encrypt any plaintext records left on disk when encryption at rest is enabled.
    ///
    /// The uncached backend never scans its directory at construction, so — unlike the
    /// cached backends — it never runs the boot-time plaintext -> `.json.enc` sweep. This
    /// walks the directory once and migrates every plaintext record: a plaintext-only
    /// record is loaded (which encrypts it and removes the plaintext), and a stale
    /// plaintext sibling left beside an existing `.json.enc` is removed. Each record is
    /// loaded transiently and dropped, so no values are retained in memory. Returns the
    /// number of records migrated.
    pub async fn migrate_plaintext_at_rest(&self) -> Result<usize> {
        if self
            .config
            .encryption_service
            .is_none()
        {
            return Ok(0);
        }

        let mut migrated = 0usize;
        for id in self.list_all_ids().await? {
            if !self
                .get_raw_path(&id)
                .exists()
            {
                continue;
            }

            if self
                .get_encrypted_path(&id)
                .exists()
            {
                remove_plaintext_sibling(&self.storage_dir, self.entity_name, &id, &self.config).await;
                migrated += 1;
            } else {
                match self.load_from_disk(&id).await {
                    Ok(_) => migrated += 1,
                    Err(e) => warn!(
                        "Failed to encrypt plaintext {} {} at rest during startup migration: {}",
                        self.entity_name, id, e
                    ),
                }
            }
        }

        if migrated > 0 {
            info!("Encrypted {} plaintext {} record(s) at rest during startup migration", migrated, self.entity_name);
        }

        Ok(migrated)
    }

    /// Delete an entity by ID
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        delete_entity_from_disk(&self.storage_dir, self.entity_name, id).await
    }

    /// Check if an entity exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for UncachedFilesystemStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        UncachedFilesystemStorage::save(self, entity).await
    }
    async fn save_atomic(
        &self,
        entity: &T,
    ) -> Result<()> {
        UncachedFilesystemStorage::atomic_save(self, entity).await
    }
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        UncachedFilesystemStorage::get(self, id).await
    }
    async fn list_all(&self) -> Result<Vec<T>> {
        UncachedFilesystemStorage::list_all(self).await
    }
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        UncachedFilesystemStorage::delete(self, id).await
    }
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        UncachedFilesystemStorage::exists(self, id).await
    }
    async fn migrate_plaintext_at_rest(&self) -> Result<usize> {
        UncachedFilesystemStorage::migrate_plaintext_at_rest(self).await
    }
}

// ============================================================================
// RwLock-based Cached Implementation (For Async-Heavy Workloads)
// ============================================================================

/// Filesystem storage with in-memory cache using RwLock
///
/// This implementation maintains an in-memory cache of all entities for fast
/// read access, using tokio's async RwLock for synchronization. All operations
/// are synchronized between disk and cache.
///
/// # When to use
/// - When you need async lock guards (can hold across .await points)
/// - Workloads with long-held read locks during async operations
/// - When DashMap's lock-free nature isn't required
/// - Legacy code that already uses RwLock pattern
///
/// # Performance Considerations
/// - **Lock contention**: Multiple concurrent writes will serialize
/// - **Async overhead**: Slightly higher overhead than DashMap
/// - **Better for**: Long-running read operations with .await
/// - **Worse for**: High-frequency writes
///
/// # Example
/// ```rust,no_run
/// use crate::storage::filesystem::{RwLockFilesystemStorage, StorableEntity};
///
/// #[derive(Clone, serde::Serialize, serde::Deserialize)]
/// struct MyEntity {
///     id: String,
///     data: String,
/// }
///
/// impl StorableEntity for MyEntity {
///     fn id(&self) -> &str {
///         &self.id
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = RwLockFilesystemStorage::new(
///     "/path/to/storage".into(),
///     "my_entity"
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct RwLockFilesystemStorage<T: StorableEntity> {
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    cache: StorageCache<T>,
}

impl<T: StorableEntity> Clone for RwLockFilesystemStorage<T> {
    fn clone(&self) -> Self {
        Self {
            storage_dir: self.storage_dir.clone(),
            entity_name: self.entity_name,
            config: self.config.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl<T: StorableEntity> RwLockFilesystemStorage<T> {
    /// Create a new RwLock-based cached filesystem storage without encryption
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store JSON files
    /// * `entity_name` - Human-readable name for logging (e.g., "pipe", "config")
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read or parsed
    #[allow(dead_code)]
    pub async fn new(
        storage_dir: PathBuf,
        entity_name: &'static str,
    ) -> Result<Self> {
        Self::new_with_config(storage_dir, entity_name, StorageConfig::default()).await
    }

    /// Create a new RwLock-based cached filesystem storage with custom config
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store files
    /// * `entity_name` - Human-readable name for logging
    /// * `config` - Storage configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read, decrypted, or parsed
    pub async fn new_with_config(
        storage_dir: PathBuf,
        entity_name: &'static str,
        config: StorageConfig,
    ) -> Result<Self> {
        let (storage_dir, cache, config) = init_rwlock_storage(storage_dir, entity_name, config).await?;
        Ok(Self {
            storage_dir,
            entity_name,
            config,
            cache,
        })
    }

    /// Create a new RwLock-based cached filesystem storage with encryption
    ///
    /// Convenience method for creating storage with encryption enabled.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store encrypted files
    /// * `entity_name` - Human-readable name for logging
    /// * `encryption_service` - EncryptionService for data at rest
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read, decrypted, or parsed
    #[allow(dead_code)]
    pub async fn new_with_encryption(
        storage_dir: PathBuf,
        entity_name: &'static str,
        encryption_service: EncryptionService,
    ) -> Result<Self> {
        let config = StorageConfig::default().with_encryption_service(encryption_service);
        Self::new_with_config(storage_dir, entity_name, config).await
    }

    /// Get the encrypted file path for an entity
    #[allow(dead_code)]
    fn get_encrypted_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_encrypted_path(&self.storage_dir, id)
    }

    /// Get the raw file path for an entity
    #[allow(dead_code)]
    fn get_raw_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_raw_path(&self.storage_dir, id)
    }

    /// Create or update an entity
    pub async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk(&self.storage_dir, self.entity_name, &self.config, entity).await?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(entity.id().to_string(), entity.clone());

        Ok(())
    }

    /// Get an entity by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        let cache = self.cache.read().await;
        Ok(cache.get(id).cloned())
    }

    /// List all entities
    pub async fn list_all(&self) -> Result<Vec<T>> {
        let cache = self.cache.read().await;
        Ok(cache
            .values()
            .cloned()
            .collect())
    }

    /// Delete an entity by ID
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        delete_entity_from_disk(&self.storage_dir, self.entity_name, id).await?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(id);

        Ok(())
    }

    /// Check if an entity exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }

    /// Reconcile the in-memory cache with the current on-disk state.
    ///
    /// Acquires the write lock *before* scanning the directory and holds it across
    /// the replacement, so a concurrent local `save`/`delete` can never be clobbered
    /// by a snapshot read taken before the lock. Re-reads the storage directory and
    /// replaces the cache wholesale, so a shared-storage node picks up another
    /// writer's changes (e.g. on promotion from standby). Unlike the DashMap backend
    /// this store has no periodic refresh loop, so this is the only way its cache
    /// tracks cross-node writes.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        let mut cache = self.cache.write().await;
        let entities: std::collections::HashMap<String, T> =
            load_storage_dir::<T>(&self.storage_dir, self.entity_name, &self.config, None, false)
                .await?
                .into_iter()
                .map(|(id, scanned)| (id, scanned.entity))
                .collect();
        *cache = entities;
        Ok(())
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for RwLockFilesystemStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        RwLockFilesystemStorage::save(self, entity).await
    }
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        RwLockFilesystemStorage::get(self, id).await
    }
    async fn list_all(&self) -> Result<Vec<T>> {
        RwLockFilesystemStorage::list_all(self).await
    }
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        RwLockFilesystemStorage::delete(self, id).await
    }
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        RwLockFilesystemStorage::exists(self, id).await
    }
    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        Ok(self
            .cache
            .read()
            .await
            .clone())
    }
    fn raw_cache(&self) -> Option<&StorageCache<T>> {
        Some(&self.cache)
    }
    async fn refresh_from_disk(&self) -> Result<()> {
        RwLockFilesystemStorage::refresh_from_disk(self).await
    }
}

// ============================================================================
// In-Memory Storage (no filesystem)
// ============================================================================

/// Pure in-memory storage backend using `Arc<RwLock<HashMap>>`.
///
/// This provides the same `StorageBackend` interface as the filesystem
/// implementations but stores everything in memory only.  Useful for
/// session-style data that does not need to survive restarts or for
/// testing.
///
/// When `timeout_minutes` is set, entries are lazily evicted on read
/// operations once they exceed the configured age.
pub struct InMemoryStorage<T: StorableEntity> {
    cache: StorageCache<T>,
    /// Per-entry insertion timestamps for timeout-based eviction
    timestamps: Arc<tokio::sync::RwLock<std::collections::HashMap<String, std::time::Instant>>>,
    /// Optional TTL – entries older than this are evicted on access
    timeout: Option<std::time::Duration>,
}

impl<T: StorableEntity> Clone for InMemoryStorage<T> {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
            timestamps: self.timestamps.clone(),
            timeout: self.timeout,
        }
    }
}

impl<T: StorableEntity> InMemoryStorage<T> {
    /// Create a new, empty in-memory storage (no timeout).
    pub fn new() -> Self {
        Self {
            cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timestamps: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timeout: None,
        }
    }

    /// Create a new, empty in-memory storage with a timeout.
    ///
    /// Entries that have not been saved/updated for longer than
    /// `timeout_minutes` will be lazily evicted on the next read.
    pub fn with_timeout(timeout_minutes: u64) -> Self {
        Self {
            cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timestamps: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timeout: Some(std::time::Duration::from_secs(timeout_minutes * 60)),
        }
    }

    /// Evict entries whose insertion timestamp exceeds the configured timeout.
    ///
    /// This is a no-op when no timeout is configured.
    async fn evict_expired(&self) {
        let timeout = match self.timeout {
            Some(t) => t,
            None => return,
        };

        let now = std::time::Instant::now();
        let expired_keys: Vec<String> = {
            let ts = self.timestamps.read().await;
            ts.iter()
                .filter_map(|(k, inserted)| {
                    if now.duration_since(*inserted) > timeout {
                        Some(k.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        if expired_keys.is_empty() {
            return;
        }

        let mut cache = self.cache.write().await;
        let mut ts = self.timestamps.write().await;
        for key in &expired_keys {
            cache.remove(key);
            ts.remove(key);
        }
        debug!("InMemoryStorage: evicted {} expired entries (timeout {}s)", expired_keys.len(), timeout.as_secs());
    }
}

impl<T: StorableEntity> Default for InMemoryStorage<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for InMemoryStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        let mut cache = self.cache.write().await;
        let id = entity.id().to_string();
        cache.insert(id.clone(), entity.clone());
        if self.timeout.is_some() {
            let mut ts = self.timestamps.write().await;
            ts.insert(id, std::time::Instant::now());
        }
        Ok(())
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        self.evict_expired().await;
        let cache = self.cache.read().await;
        Ok(cache.get(id).cloned())
    }

    async fn list_all(&self) -> Result<Vec<T>> {
        self.evict_expired().await;
        let cache = self.cache.read().await;
        Ok(cache
            .values()
            .cloned()
            .collect())
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.remove(id);
        if self.timeout.is_some() {
            let mut ts = self.timestamps.write().await;
            ts.remove(id);
        }
        Ok(())
    }

    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        self.evict_expired().await;
        let cache = self.cache.read().await;
        Ok(cache.contains_key(id))
    }

    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        self.evict_expired().await;
        Ok(self
            .cache
            .read()
            .await
            .clone())
    }

    fn raw_cache(&self) -> Option<&StorageCache<T>> {
        Some(&self.cache)
    }
}

/// Create a pure in-memory storage (no filesystem, no timeout).
///
/// Returns a trait object for generic storage access.
#[allow(dead_code)]
pub fn in_memory_storage<T: StorableEntity>() -> Box<dyn StorageBackend<T>> {
    Box::new(InMemoryStorage::<T>::new())
}

/// Create a pure in-memory storage with a timeout (no filesystem).
///
/// Entries are lazily evicted after `timeout_minutes` minutes.
/// Returns a trait object for generic storage access.
pub fn in_memory_storage_with_timeout<T: StorableEntity>(timeout_minutes: u64) -> Box<dyn StorageBackend<T>> {
    Box::new(InMemoryStorage::<T>::with_timeout(timeout_minutes))
}

// ============================================================================
// Convenience Functions for Storage Creation
// ============================================================================

/// Create a cached filesystem storage with type inference
///
/// Returns a trait object for generic storage access.
/// If a global encryption config is set, it will be applied to this storage instance.
pub async fn cached_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config();
    Ok(Box::new(CachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await?))
}

/// Create cached storage that rejects any unreadable entity candidate.
pub async fn cached_storage_strict<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config();
    Ok(Box::new(CachedFilesystemStorage::new_with_config_and_loading(storage_dir, entity_name, config, true).await?))
}

/// Create an uncached filesystem storage with type inference
///
/// Returns a trait object for generic storage access.
/// If a global encryption config is set, it will be applied to this storage instance.
pub async fn uncached_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config();
    Ok(Box::new(UncachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await?))
}

/// Create a RwLock-based cached filesystem storage with type inference
///
/// Returns a trait object for generic storage access.
/// If a global encryption config is set, it will be applied to this storage instance.
pub async fn rwlock_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config();
    Ok(Box::new(RwLockFilesystemStorage::new_with_config(storage_dir, entity_name, config).await?))
}

/// Create a cached filesystem storage with custom StorageConfig
///
/// Use this when you need to specify encryption or other storage options.
/// For basic usage without configuration, use [cached_storage] instead.
///
/// # Arguments
/// * `storage_dir` - Directory to store files
/// * `entity_name` - Name for logging/identification
/// * `config` - StorageConfig for encryption options
///
/// # Example
/// ```no_run
/// # use std::path::PathBuf;
/// # use crate::storage::filesystem::{cached_storage_with_config, StorageConfig};
/// # async fn example() -> anyhow::Result<()> {
/// let config = StorageConfig::default();
///
/// let storage = cached_storage_with_config::<MyEntity>(
///     PathBuf::from("./storage"),
///     "my_entity",
///     config,
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[allow(dead_code)]
pub async fn cached_storage_with_config<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<CachedFilesystemStorage<T>> {
    CachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await
}

/// Create an uncached filesystem storage with custom StorageConfig
///
/// Use this when you need to specify encryption or other storage options.
/// For basic usage without configuration, use [uncached_storage] instead.
#[allow(dead_code)]
pub async fn uncached_storage_with_config<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<UncachedFilesystemStorage<T>> {
    UncachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await
}

/// Create a RwLock-based cached filesystem storage with custom StorageConfig
///
/// Use this when you need to specify encryption or other storage options.
/// For basic usage without configuration, use [rwlock_storage] instead.
#[allow(dead_code)]
pub async fn rwlock_storage_with_config<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<RwLockFilesystemStorage<T>> {
    RwLockFilesystemStorage::new_with_config(storage_dir, entity_name, config).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{KeyManager, KeySource};
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    /// Helper to create an EncryptionService from a random key for tests
    fn test_encryption_service() -> (EncryptionService, [u8; 32]) {
        let key_manager = KeyManager::from_raw_key(&rand::random::<[u8; 32]>()).unwrap();
        let key = *key_manager.master_key();
        let service = EncryptionService::new(KeySource::Raw { key }).unwrap();
        (service, key)
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestEntity {
        id: String,
        name: String,
        value: i32,
    }

    impl StorableEntity for TestEntity {
        fn id(&self) -> &str {
            &self.id
        }
    }

    #[tokio::test]
    async fn test_cached_storage_crud() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // Create
        let entity = TestEntity {
            id: "test-1".to_string(),
            name: "Test".to_string(),
            value: 42,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity.clone()));

        // List
        let all = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], entity);

        // Update
        let entity2 = TestEntity {
            id: "test-1".to_string(),
            name: "Updated".to_string(),
            value: 99,
        };
        storage
            .save(&entity2)
            .await
            .unwrap();
        let loaded = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity2));

        // Delete
        storage
            .delete("test-1")
            .await
            .unwrap();
        let deleted = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    async fn atomic_file_replacements_are_complete_and_failed_writes_clean_up() {
        let directory = TempDir::new().unwrap();
        let target = directory
            .path()
            .join("record.json");
        let mut writers = tokio::task::JoinSet::new();
        for index in 0..16 {
            let target = target.clone();
            writers.spawn(async move {
                let content = serde_json::to_vec(&serde_json::json!({
                    "writer": index, "payload": index.to_string().repeat(4096)
                }))
                .unwrap();
                atomic_write_file(&target, &content)
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = writers.join_next().await {
            result.unwrap();
        }
        let value: serde_json::Value = serde_json::from_slice(
            &fs::read(&target)
                .await
                .unwrap(),
        )
        .unwrap();
        let index = value["writer"]
            .as_u64()
            .unwrap();
        assert!(index < 16);
        assert_eq!(value["payload"], index.to_string().repeat(4096));
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .count(),
            1
        );
        let blocked = directory
            .path()
            .join("existing-directory");
        fs::create_dir(&blocked)
            .await
            .unwrap();
        assert!(
            atomic_write_file(&blocked, b"replacement")
                .await
                .is_err()
        );
        assert!(blocked.is_dir());
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .count(),
            2
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(&target)
                    .await
                    .unwrap()
            )
            .unwrap(),
            value
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_sync_unsupported_accepts_only_unsupported_errors() {
        use std::io::{Error, ErrorKind};

        for code in [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS] {
            assert!(directory_sync_unsupported(&Error::from_raw_os_error(code)), "errno {code}");
        }
        assert!(directory_sync_unsupported(&Error::from(ErrorKind::Unsupported)));
        assert!(directory_sync_unsupported(&Error::from(ErrorKind::InvalidInput)));

        for code in [libc::EIO, libc::EACCES, libc::ENOSPC, libc::EROFS] {
            assert!(!directory_sync_unsupported(&Error::from_raw_os_error(code)), "errno {code}");
        }
        assert!(!directory_sync_unsupported(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!directory_sync_unsupported(&Error::other("device failure")));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_directory_succeeds_on_real_directories_and_propagates_open_failures() {
        let directory = TempDir::new().unwrap();
        sync_directory(directory.path())
            .await
            .unwrap();

        let error = sync_directory(
            &directory
                .path()
                .join("missing"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotFound)
        );
    }

    #[tokio::test]
    async fn test_cached_storage_atomic_save_updates_cache_and_leaves_no_temp_file() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();
        let entity = TestEntity {
            id: "atomic-1".to_string(),
            name: "Atomic".to_string(),
            value: 7,
        };

        StorageBackend::save_atomic(&storage, &entity)
            .await
            .unwrap();

        assert_eq!(
            storage
                .get("atomic-1")
                .await
                .unwrap(),
            Some(entity)
        );
        let files = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0]
                .path()
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("json")
        );
    }

    #[tokio::test]
    async fn test_cached_storage_save_emits_localwrite_upsert_event() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        let entity = TestEntity {
            id: "evt-1".to_string(),
            name: "Event".to_string(),
            value: 1,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for local event")
            .expect("channel closed unexpectedly");

        match event {
            StorageEvent::Upsert { id, entity: observed, source } => {
                assert_eq!(id, "evt-1");
                assert_eq!(observed, entity);
                assert_eq!(source, StorageEventSource::LocalWrite);
            }
            _ => panic!("expected local upsert event"),
        }
    }

    #[tokio::test]
    async fn test_refresh_dashmap_cache_emits_remotewrite_upsert_event_on_external_update() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        let initial = TestEntity {
            id: "evt-2".to_string(),
            name: "Before".to_string(),
            value: 10,
        };
        storage
            .save(&initial)
            .await
            .unwrap();

        // Drain the expected LocalWrite event from save() so we can assert on the refresh event.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for local event")
            .expect("channel closed unexpectedly");

        let external_update = TestEntity {
            id: "evt-2".to_string(),
            name: "After".to_string(),
            value: 99,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external_update)
            .await
            .unwrap();

        refresh_dashmap_cache(
            &storage.storage_dir,
            storage.entity_name,
            &storage.config,
            &storage.cache,
            &storage.event_tx,
            false,
            &storage.refresh_lock,
        )
        .await
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for remote event")
            .expect("channel closed unexpectedly");

        match event {
            StorageEvent::Upsert { id, entity: observed, source } => {
                assert_eq!(id, "evt-2");
                assert_eq!(observed, external_update);
                assert_eq!(source, StorageEventSource::RemoteWrite);
            }
            _ => panic!("expected remote upsert event"),
        }
    }

    #[tokio::test]
    async fn test_spawn_dashmap_refresh_loop_tails_external_writes() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        // Retain the guard so the loop keeps running for the duration of the test.
        let _refresh_guard = spawn_dashmap_refresh_loop(
            1,
            storage.storage_dir.clone(),
            storage.entity_name,
            storage.config.clone(),
            storage.cache.clone(),
            storage.event_tx.clone(),
            false,
            storage.refresh_lock.clone(),
        );

        // A record written straight to disk by another process sharing the directory.
        let external = TestEntity {
            id: "tail-1".to_string(),
            name: "Tailed".to_string(),
            value: 42,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external)
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("refresh loop did not emit within timeout")
            .expect("channel closed unexpectedly");

        match event {
            StorageEvent::Upsert { id, entity: observed, source } => {
                assert_eq!(id, "tail-1");
                assert_eq!(observed, external);
                assert_eq!(source, StorageEventSource::RemoteWrite);
            }
            _ => panic!("expected remote upsert event from refresh loop"),
        }

        // The tailed record is now visible through the cache without an explicit refresh.
        assert_eq!(storage.cached_entity("tail-1"), Some(external));
    }

    #[tokio::test]
    async fn test_spawn_dashmap_refresh_loop_disabled_when_interval_zero() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        spawn_dashmap_refresh_loop(
            0,
            storage.storage_dir.clone(),
            storage.entity_name,
            storage.config.clone(),
            storage.cache.clone(),
            storage.event_tx.clone(),
            false,
            storage.refresh_lock.clone(),
        );

        let external = TestEntity {
            id: "no-tail".to_string(),
            name: "Ignored".to_string(),
            value: 1,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external)
            .await
            .unwrap();

        // With the loop disabled no scan runs, so no RemoteWrite event ever arrives.
        let outcome = tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await;
        assert!(outcome.is_err(), "no refresh event must fire when the interval is zero");
        assert_eq!(storage.cached_entity("no-tail"), None);
    }

    #[tokio::test]
    async fn test_dropping_refresh_guard_aborts_the_loop() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        // A transiently constructed store: spawn the loop, then drop the only guard,
        // mirroring a throwaway store built for a single read on config reload.
        let guard = spawn_dashmap_refresh_loop(
            1,
            storage.storage_dir.clone(),
            storage.entity_name,
            storage.config.clone(),
            storage.cache.clone(),
            storage.event_tx.clone(),
            false,
            storage.refresh_lock.clone(),
        );
        assert!(guard.is_some(), "a positive interval must spawn a loop");
        drop(guard);

        let external = TestEntity {
            id: "aborted".to_string(),
            name: "NeverSeen".to_string(),
            value: 5,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external)
            .await
            .unwrap();

        // The aborted loop never scans, so no RemoteWrite event fires and the cache stays stale.
        let outcome = tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await;
        assert!(outcome.is_err(), "a dropped guard must stop the refresh loop");
        assert_eq!(storage.cached_entity("aborted"), None);
    }

    /// Concurrency guard for F5: a refresh scan cannot begin while the shared
    /// per-store lock is held, so two scans never overlap and revert each other.
    #[tokio::test]
    async fn refresh_scan_waits_for_the_shared_refresh_lock() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // An entity is on disk but not yet in the (stale) cache.
        let external = TestEntity {
            id: "gated".to_string(),
            name: "Gated".to_string(),
            value: 9,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external)
            .await
            .unwrap();

        // Hold the store's refresh lock, then start a concurrent refresh.
        let held = storage
            .refresh_lock
            .clone()
            .lock_owned()
            .await;
        let refresher = storage.clone();
        let scan = tokio::spawn(async move {
            refresher
                .refresh_from_disk()
                .await
        });

        // While the lock is held the scan cannot run, so the cache stays stale.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!scan.is_finished(), "a scan must block while the refresh lock is held");
        assert_eq!(storage.cached_entity("gated"), None, "no scan may apply while the lock is held");

        // Releasing the lock lets the queued scan proceed and reconcile the cache.
        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(5), scan)
            .await
            .expect("scan did not complete after the lock was released")
            .expect("scan task panicked")
            .expect("refresh returned an error");
        assert_eq!(storage.cached_entity("gated"), Some(external));
    }

    #[tokio::test]
    async fn test_refresh_from_disk_picks_up_externally_added_entity() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // An entity written straight to disk after construction bypasses the cache.
        let external = TestEntity {
            id: "ext-1".to_string(),
            name: "External".to_string(),
            value: 7,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external)
            .await
            .unwrap();

        // Before refresh the stale cache does not see it.
        let before = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(before, Vec::<TestEntity>::new());

        // After refresh the cache reflects exactly the on-disk set.
        storage
            .refresh_from_disk()
            .await
            .unwrap();
        let after = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(after, vec![external]);
    }

    #[tokio::test]
    async fn test_refresh_from_disk_reflects_external_update_and_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // Seed two entities through the store (cache + disk).
        let a = TestEntity {
            id: "a".to_string(),
            name: "A".to_string(),
            value: 1,
        };
        let b = TestEntity {
            id: "b".to_string(),
            name: "B".to_string(),
            value: 2,
        };
        storage
            .save(&a)
            .await
            .unwrap();
        storage
            .save(&b)
            .await
            .unwrap();

        // Externally update `a` and delete `b` on disk, bypassing the cache.
        let a_updated = TestEntity {
            id: "a".to_string(),
            name: "A-updated".to_string(),
            value: 99,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &a_updated)
            .await
            .unwrap();
        delete_entity_from_disk(&storage.storage_dir, storage.entity_name, "b")
            .await
            .unwrap();

        // The stale cache still shows the original pair.
        let mut before = storage
            .list_all()
            .await
            .unwrap();
        before.sort_by(|x, y| x.id.cmp(&y.id));
        assert_eq!(before, vec![a.clone(), b.clone()]);

        // After refresh the cache matches disk: `a` updated, `b` evicted.
        storage
            .refresh_from_disk()
            .await
            .unwrap();
        let after = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(after, vec![a_updated]);
    }

    #[tokio::test]
    async fn test_refresh_from_disk_errors_and_keeps_cache_when_directory_missing() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();
        let seeded = TestEntity {
            id: "x".to_string(),
            name: "X".to_string(),
            value: 5,
        };
        storage
            .save(&seeded)
            .await
            .unwrap();

        // Remove the storage directory out from under the store.
        temp_dir.close().unwrap();

        // Refresh surfaces the error and leaves the cache unchanged (non-fatal for callers).
        assert!(
            storage
                .refresh_from_disk()
                .await
                .is_err()
        );
        assert_eq!(
            storage
                .list_all()
                .await
                .unwrap(),
            vec![seeded]
        );
    }

    #[tokio::test]
    async fn test_rwlock_refresh_from_disk_reflects_external_add_update_and_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RwLockFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // Seed one entity through the store (cache + disk).
        let a = TestEntity {
            id: "a".to_string(),
            name: "A".to_string(),
            value: 1,
        };
        storage
            .save(&a)
            .await
            .unwrap();

        // Externally add `b` and update `a`, both bypassing the RwLock cache.
        let a_updated = TestEntity {
            id: "a".to_string(),
            name: "A-updated".to_string(),
            value: 99,
        };
        let b = TestEntity {
            id: "b".to_string(),
            name: "B".to_string(),
            value: 2,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &a_updated)
            .await
            .unwrap();
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &b)
            .await
            .unwrap();

        // The RwLock backend has no refresh loop, so the stale cache still
        // shows only the original `a`.
        let before = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(before, vec![a.clone()]);

        // After refresh the cache matches disk exactly: `a` updated, `b` added.
        RwLockFilesystemStorage::refresh_from_disk(&storage)
            .await
            .unwrap();
        let mut after = storage
            .list_all()
            .await
            .unwrap();
        after.sort_by(|x, y| x.id.cmp(&y.id));
        assert_eq!(after, vec![a_updated.clone(), b]);

        // Externally delete `b`; a further refresh evicts it from the cache.
        delete_entity_from_disk(&storage.storage_dir, storage.entity_name, "b")
            .await
            .unwrap();
        RwLockFilesystemStorage::refresh_from_disk(&storage)
            .await
            .unwrap();
        let after_delete = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(after_delete, vec![a_updated]);
    }

    fn snapshot_entity(
        id: &str,
        name: &str,
        value: i32,
    ) -> TestEntity {
        TestEntity {
            id: id.to_string(),
            name: name.to_string(),
            value,
        }
    }

    async fn subscribed_storage()
    -> (TempDir, CachedFilesystemStorage<TestEntity>, broadcast::Receiver<StorageEvent<TestEntity>>) {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();
        let rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");
        (temp_dir, storage, rx)
    }

    async fn snapshot_of(
        storage: &CachedFilesystemStorage<TestEntity>
    ) -> std::collections::HashMap<String, ScannedEntity<TestEntity>> {
        load_all_entities_from_disk(&storage.storage_dir, storage.entity_name, &storage.config, None, false)
            .await
            .unwrap()
    }

    fn has_tombstone(
        storage: &CachedFilesystemStorage<TestEntity>,
        id: &str,
    ) -> bool {
        storage
            .cache
            .get(id)
            .is_some_and(|entry| entry.entity.is_none())
    }

    fn drain_events(rx: &mut broadcast::Receiver<StorageEvent<TestEntity>>) {
        while rx.try_recv().is_ok() {}
    }

    #[tokio::test]
    async fn test_disk_snapshot_keeps_entity_saved_after_scan_started() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;
        let stale = snapshot_entity("r", "stale", 1);
        storage
            .save(&stale)
            .await
            .unwrap();
        let _ = rx.recv().await;

        let scan_started = Instant::now();
        let snapshot = snapshot_of(&storage).await;
        let fresh = snapshot_entity("r", "fresh", 2);
        storage
            .save(&fresh)
            .await
            .unwrap();
        let _ = rx.recv().await;

        apply_disk_snapshot(&storage.cache, &storage.event_tx, snapshot, scan_started);

        assert_eq!(
            storage
                .get("r")
                .await
                .unwrap(),
            Some(fresh)
        );
        assert!(rx.try_recv().is_err(), "a skipped stale snapshot must not emit a RemoteWrite event");
    }

    #[tokio::test]
    async fn test_disk_snapshot_keeps_entity_created_after_scan_started() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;

        let scan_started = Instant::now();
        let snapshot = snapshot_of(&storage).await;
        assert!(snapshot.is_empty());
        let created = snapshot_entity("c", "created", 3);
        storage
            .save(&created)
            .await
            .unwrap();
        let _ = rx.recv().await;

        apply_disk_snapshot(&storage.cache, &storage.event_tx, snapshot, scan_started);

        assert_eq!(
            storage
                .list_all()
                .await
                .unwrap(),
            vec![created]
        );
        assert!(rx.try_recv().is_err(), "an entity created during the scan must not be evicted");
    }

    #[tokio::test]
    async fn test_disk_snapshot_does_not_resurrect_entity_deleted_after_scan_started() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;
        let doomed = snapshot_entity("d", "doomed", 4);
        storage
            .save(&doomed)
            .await
            .unwrap();
        let _ = rx.recv().await;

        let scan_started = Instant::now();
        let snapshot = snapshot_of(&storage).await;
        assert!(snapshot.contains_key("d"));
        storage
            .delete("d")
            .await
            .unwrap();
        let _ = rx.recv().await;

        apply_disk_snapshot(&storage.cache, &storage.event_tx, snapshot, scan_started);

        assert!(
            !storage
                .exists("d")
                .await
                .unwrap()
        );
        assert!(has_tombstone(&storage, "d"), "the tombstone must outlive a scan that started before the delete");
        assert!(rx.try_recv().is_err(), "a deleted entity must not come back from a stale snapshot");
    }

    #[tokio::test]
    async fn test_delete_of_uncached_record_still_blocks_stale_snapshot() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;
        let external = snapshot_entity("x", "external", 1);
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external)
            .await
            .unwrap();
        assert!(
            !storage
                .exists("x")
                .await
                .unwrap()
        );

        let scan_started = Instant::now();
        let snapshot = snapshot_of(&storage).await;
        assert!(snapshot.contains_key("x"));
        storage
            .delete("x")
            .await
            .unwrap();
        let _ = rx.recv().await;

        apply_disk_snapshot(&storage.cache, &storage.event_tx, snapshot, scan_started);

        assert!(
            !storage
                .exists("x")
                .await
                .unwrap()
        );
        assert!(
            !storage
                .storage_dir
                .join("x.json")
                .exists()
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_local_delete_hides_record_from_every_read_path() {
        let (_temp_dir, storage, _rx) = subscribed_storage().await;
        let keep = snapshot_entity("keep", "K", 1);
        storage
            .save(&keep)
            .await
            .unwrap();
        storage
            .save(&snapshot_entity("gone", "G", 2))
            .await
            .unwrap();

        storage
            .delete("gone")
            .await
            .unwrap();

        assert!(has_tombstone(&storage, "gone"));
        assert!(
            !storage
                .exists("gone")
                .await
                .unwrap()
        );
        assert_eq!(
            storage
                .list_all()
                .await
                .unwrap(),
            vec![keep.clone()]
        );
        let map = storage
            .hash_map()
            .await
            .unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("keep"), Some(&keep));
        assert_eq!(
            storage
                .get("gone")
                .await
                .unwrap(),
            None
        );
        assert!(
            !storage
                .storage_dir
                .join("gone.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn test_next_scan_drops_tombstone_silently() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;
        storage
            .save(&snapshot_entity("d", "D", 1))
            .await
            .unwrap();
        storage
            .delete("d")
            .await
            .unwrap();
        drain_events(&mut rx);
        assert!(has_tombstone(&storage, "d"), "a fresh tombstone is kept");

        tokio::time::sleep(Duration::from_millis(2)).await;
        storage
            .refresh_from_disk()
            .await
            .unwrap();

        assert!(
            !storage
                .cache
                .contains_key("d"),
            "a scan that started after the delete removes the tombstone"
        );
        assert!(rx.try_recv().is_err(), "dropping a tombstone is not a remote delete");
    }

    #[tokio::test]
    async fn test_save_after_local_delete_replaces_tombstone() {
        let (_temp_dir, storage, _rx) = subscribed_storage().await;
        storage
            .save(&snapshot_entity("r", "first", 1))
            .await
            .unwrap();
        storage
            .delete("r")
            .await
            .unwrap();
        assert!(has_tombstone(&storage, "r"));

        let again = snapshot_entity("r", "again", 2);
        storage
            .save(&again)
            .await
            .unwrap();

        assert!(
            storage
                .exists("r")
                .await
                .unwrap()
        );
        assert_eq!(
            storage
                .get("r")
                .await
                .unwrap(),
            Some(again.clone())
        );
        assert_eq!(
            storage
                .list_all()
                .await
                .unwrap(),
            vec![again]
        );
    }

    #[tokio::test]
    async fn test_remote_recreate_after_local_delete_is_applied_by_a_later_scan() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;
        storage
            .save(&snapshot_entity("r", "local", 1))
            .await
            .unwrap();
        storage
            .delete("r")
            .await
            .unwrap();
        drain_events(&mut rx);

        tokio::time::sleep(Duration::from_millis(2)).await;
        let remote = snapshot_entity("r", "remote", 2);
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &remote)
            .await
            .unwrap();
        storage
            .refresh_from_disk()
            .await
            .unwrap();

        assert_eq!(
            storage
                .get("r")
                .await
                .unwrap(),
            Some(remote.clone())
        );
        let Ok(StorageEvent::Upsert { entity, source, .. }) = rx.try_recv() else {
            panic!("expected a RemoteWrite upsert event");
        };
        assert_eq!(entity, remote);
        assert_eq!(source, StorageEventSource::RemoteWrite);
    }

    #[tokio::test]
    async fn test_delete_sweeps_only_tombstones_older_than_the_ttl() {
        let (_temp_dir, storage, _rx) = subscribed_storage().await;
        storage
            .save(&snapshot_entity("live", "L", 1))
            .await
            .unwrap();
        storage
            .save(&snapshot_entity("old", "O", 2))
            .await
            .unwrap();
        storage
            .save(&snapshot_entity("new", "N", 3))
            .await
            .unwrap();
        storage
            .delete("old")
            .await
            .unwrap();
        storage
            .delete("new")
            .await
            .unwrap();
        assert!(
            has_tombstone(&storage, "old") && has_tombstone(&storage, "new"),
            "a delete keeps tombstones younger than the TTL"
        );

        storage.sweep_expired_tombstones(Instant::now() + TOMBSTONE_TTL + Duration::from_secs(1));

        assert!(
            !storage
                .cache
                .contains_key("old")
        );
        assert!(
            !storage
                .cache
                .contains_key("new")
        );
        assert!(
            storage
                .exists("live")
                .await
                .unwrap(),
            "records are never swept"
        );
    }

    #[tokio::test]
    async fn test_refresh_applies_external_change_made_after_last_local_write_and_clears_mark() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;
        let local = snapshot_entity("e", "local", 1);
        storage
            .save(&local)
            .await
            .unwrap();
        let _ = rx.recv().await;
        assert!(
            storage
                .cache
                .get("e")
                .unwrap()
                .local_write_at
                .is_some()
        );

        tokio::time::sleep(Duration::from_millis(5)).await;
        let external = snapshot_entity("e", "external", 2);
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external)
            .await
            .unwrap();

        storage
            .refresh_from_disk()
            .await
            .unwrap();

        assert_eq!(
            storage
                .get("e")
                .await
                .unwrap(),
            Some(external.clone())
        );
        let Ok(StorageEvent::Upsert { entity, source, .. }) = rx.try_recv() else {
            panic!("expected a RemoteWrite upsert event");
        };
        assert_eq!(entity, external);
        assert_eq!(source, StorageEventSource::RemoteWrite);
        assert!(
            storage
                .cache
                .get("e")
                .unwrap()
                .local_write_at
                .is_none(),
            "a scan that started after the write clears its mark"
        );
    }

    #[tokio::test]
    async fn test_refresh_serves_unchanged_files_from_cache_without_decrypting() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _) = test_encryption_service();
        let mut storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();
        let kept = snapshot_entity("k", "kept", 1);
        storage
            .save(&kept)
            .await
            .unwrap();
        assert!(
            storage
                .cache
                .get("k")
                .unwrap()
                .fingerprint
                .is_none(),
            "a local write invalidates the fingerprint"
        );
        storage
            .refresh_from_disk()
            .await
            .unwrap();
        assert!(
            storage
                .cache
                .get("k")
                .unwrap()
                .fingerprint
                .is_some(),
            "a scan records the fingerprint of what it decrypted"
        );

        let writer_config = storage.config.clone();
        let (other_service, _) = test_encryption_service();
        storage.config = StorageConfig::default().with_encryption_service(other_service);

        storage
            .refresh_from_disk()
            .await
            .unwrap();
        assert_eq!(
            storage
                .get("k")
                .await
                .unwrap(),
            Some(kept),
            "an unchanged file is served from the cache, so the key is never used"
        );

        save_entity_to_disk(
            &storage.storage_dir,
            storage.entity_name,
            &writer_config,
            &snapshot_entity("k", "changed", 2),
        )
        .await
        .unwrap();
        storage
            .refresh_from_disk()
            .await
            .unwrap();
        assert!(
            !storage
                .exists("k")
                .await
                .unwrap(),
            "a changed file is decrypted again, which this key cannot do"
        );
    }

    #[tokio::test]
    async fn test_refresh_evicts_record_whose_file_was_removed_remotely() {
        let (_temp_dir, storage, mut rx) = subscribed_storage().await;
        storage
            .save(&snapshot_entity("a", "A", 1))
            .await
            .unwrap();
        storage
            .save(&snapshot_entity("b", "B", 2))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        storage
            .refresh_from_disk()
            .await
            .unwrap();
        drain_events(&mut rx);

        delete_entity_from_disk(&storage.storage_dir, storage.entity_name, "b")
            .await
            .unwrap();
        storage
            .refresh_from_disk()
            .await
            .unwrap();

        assert!(
            storage
                .cache
                .get("a")
                .unwrap()
                .fingerprint
                .is_some()
        );
        assert!(
            !storage
                .cache
                .contains_key("b"),
            "a remote delete leaves no entry behind, not even a tombstone"
        );
        let Ok(StorageEvent::Delete { id, source }) = rx.try_recv() else {
            panic!("expected a RemoteWrite delete event");
        };
        assert_eq!(id, "b");
        assert_eq!(source, StorageEventSource::RemoteWrite);
    }

    #[tokio::test]
    async fn test_strict_cached_storage_rejects_malformed_candidate_without_replacing_cache() {
        let temp_dir = TempDir::new().unwrap();
        let storage = cached_storage_strict::<TestEntity>(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();
        let seeded = TestEntity {
            id: "valid".to_string(),
            name: "Valid".to_string(),
            value: 1,
        };
        storage
            .save(&seeded)
            .await
            .unwrap();
        tokio::fs::write(
            temp_dir
                .path()
                .join("broken.json"),
            b"not json",
        )
        .await
        .unwrap();

        assert!(
            storage
                .refresh_from_disk()
                .await
                .is_err()
        );
        assert_eq!(
            storage
                .list_all()
                .await
                .unwrap(),
            vec![seeded]
        );
    }

    #[tokio::test]
    async fn test_strict_cached_storage_rejects_undecryptable_candidate() {
        let temp_dir = TempDir::new().unwrap();
        let (write_service, _write_key) = test_encryption_service();
        let writer = CachedFilesystemStorage::<TestEntity>::new_with_config(
            temp_dir.path().to_path_buf(),
            "test_entity",
            StorageConfig::default().with_encryption_service(write_service),
        )
        .await
        .unwrap();
        writer
            .save(&TestEntity {
                id: "encrypted".to_string(),
                name: "Encrypted".to_string(),
                value: 1,
            })
            .await
            .unwrap();
        drop(writer);

        let (wrong_service, _wrong_key) = test_encryption_service();
        let result = CachedFilesystemStorage::<TestEntity>::new_with_config_and_loading(
            temp_dir.path().to_path_buf(),
            "test_entity",
            StorageConfig::default().with_encryption_service(wrong_service),
            true,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_default_cached_storage_still_skips_malformed_candidate() {
        let temp_dir = TempDir::new().unwrap();
        tokio::fs::write(
            temp_dir
                .path()
                .join("broken.json"),
            b"not json",
        )
        .await
        .unwrap();

        let storage = cached_storage::<TestEntity>(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();
        assert!(
            storage
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_uncached_storage_crud() {
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // Create
        let entity = TestEntity {
            id: "test-1".to_string(),
            name: "Test".to_string(),
            value: 42,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity.clone()));

        // List
        let all = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        storage
            .delete("test-1")
            .await
            .unwrap();
        let deleted = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    async fn test_uncached_trait_object_save_atomic_persists_entity() {
        let temp_dir = TempDir::new().unwrap();
        let storage: Box<dyn StorageBackend<TestEntity>> =
            uncached_storage(temp_dir.path().to_path_buf(), "test_entity")
                .await
                .unwrap();

        let entity = TestEntity {
            id: "atomic-1".to_string(),
            name: "Atomic".to_string(),
            value: 7,
        };

        storage
            .save_atomic(&entity)
            .await
            .unwrap();

        let loaded = storage
            .get("atomic-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity));

        let has_tmp = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .any(|name| name.ends_with(".tmp"));
        assert!(!has_tmp);
    }

    #[tokio::test]
    async fn test_cached_trait_object_save_atomic_persists_and_leaves_no_temp() {
        let temp_dir = TempDir::new().unwrap();
        let storage: Box<dyn StorageBackend<TestEntity>> = cached_storage(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let entity = TestEntity {
            id: "atomic-default-1".to_string(),
            name: "Default".to_string(),
            value: 11,
        };

        storage
            .save_atomic(&entity)
            .await
            .unwrap();

        let loaded = storage
            .get("atomic-default-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity));

        let has_tmp = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .any(|name| name.ends_with(".tmp"));
        assert!(!has_tmp);
    }

    #[tokio::test]
    async fn test_persistence_between_instances() {
        let temp_dir = TempDir::new().unwrap();

        // Create and save with first instance
        {
            let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
                .await
                .unwrap();

            let entity = TestEntity {
                id: "test-persist".to_string(),
                name: "Persistent".to_string(),
                value: 123,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Load with second instance
        {
            let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
                .await
                .unwrap();

            let loaded = storage
                .get("test-persist")
                .await
                .unwrap();
            assert!(loaded.is_some());
            assert_eq!(loaded.unwrap().value, 123);
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct NormalizableEntity {
        id: String,
        #[serde(default)]
        normalized: bool,
    }

    impl StorableEntity for NormalizableEntity {
        fn id(&self) -> &str {
            &self.id
        }

        fn on_load(&mut self) {
            self.normalized = true;
        }
    }

    #[tokio::test]
    async fn test_on_load_hook() {
        let temp_dir = TempDir::new().unwrap();

        // Save entity without normalized flag
        {
            let storage =
                CachedFilesystemStorage::<NormalizableEntity>::new(temp_dir.path().to_path_buf(), "normalizable")
                    .await
                    .unwrap();

            let entity = NormalizableEntity {
                id: "test-1".to_string(),
                normalized: false,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Load should trigger on_load which sets normalized=true
        {
            let storage =
                CachedFilesystemStorage::<NormalizableEntity>::new(temp_dir.path().to_path_buf(), "normalizable")
                    .await
                    .unwrap();

            let loaded = storage
                .get("test-1")
                .await
                .unwrap()
                .unwrap();
            assert!(loaded.normalized);
        }
    }

    // ============================================================================
    // Encryption Tests
    // ============================================================================

    #[tokio::test]
    async fn test_uncached_storage_with_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();

        // Create
        let entity = TestEntity {
            id: "encrypted-2".to_string(),
            name: "Confidential".to_string(),
            value: 99,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("encrypted-2")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity));

        // Verify encryption (encrypted files use .json.enc extension)
        let file_path = temp_dir
            .path()
            .join("encrypted-2.json.enc");
        let file_content = std::fs::read(&file_path).unwrap();
        let file_str = String::from_utf8_lossy(&file_content);
        assert!(!file_str.contains("Confidential"));
    }

    #[tokio::test]
    async fn test_local_trace_source_stores_pass_through_envelopes_that_load_back() {
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            EncryptionService::local_trace(),
        )
        .await
        .unwrap();

        let entity = TestEntity {
            id: "dev-1".to_string(),
            name: "Visible".to_string(),
            value: 1,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(
            temp_dir
                .path()
                .join("dev-1.json.enc"),
        )
        .unwrap();
        assert!(on_disk.starts_with("ENC[0::"), "{on_disk}");
        assert!(
            !temp_dir
                .path()
                .join("dev-1.json")
                .exists(),
            "the local source must still write the encrypted-file layout"
        );
        assert_eq!(
            storage
                .get("dev-1")
                .await
                .unwrap(),
            Some(entity)
        );
    }

    #[tokio::test]
    async fn test_uncached_migrate_plaintext_at_rest_encrypts_lingering_plaintext() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        // Simulate a record written while encryption was disabled: a plaintext .json on disk.
        let entity = TestEntity {
            id: "legacy-plain".to_string(),
            name: "eeee".to_string(),
            value: 42,
        };
        let raw_path = temp_dir
            .path()
            .join("legacy-plain.json");
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();

        let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();

        let migrated = storage
            .migrate_plaintext_at_rest()
            .await
            .unwrap();
        assert_eq!(migrated, 1);

        // Plaintext is gone; the encrypted blob exists and does not leak the value.
        assert!(!raw_path.exists());
        let enc_path = temp_dir
            .path()
            .join("legacy-plain.json.enc");
        assert!(enc_path.exists());
        let enc_bytes = std::fs::read(&enc_path).unwrap();
        assert!(!String::from_utf8_lossy(&enc_bytes).contains("eeee"));

        // The record still decrypts back to the original.
        let loaded = storage
            .get("legacy-plain")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity));
    }

    #[tokio::test]
    async fn test_uncached_migrate_plaintext_at_rest_removes_stale_plaintext_sibling() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();

        // Save encrypts and produces only a .json.enc, then plant a stale plaintext sibling.
        let entity = TestEntity {
            id: "stale".to_string(),
            name: "secret".to_string(),
            value: 1,
        };
        storage
            .save(&entity)
            .await
            .unwrap();
        let raw_path = temp_dir
            .path()
            .join("stale.json");
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();

        let migrated = storage
            .migrate_plaintext_at_rest()
            .await
            .unwrap();
        assert_eq!(migrated, 1);
        assert!(!raw_path.exists());
        assert!(
            temp_dir
                .path()
                .join("stale.json.enc")
                .exists()
        );
    }

    #[tokio::test]
    async fn test_uncached_migrate_plaintext_at_rest_noop_without_encryption() {
        let temp_dir = TempDir::new().unwrap();

        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let entity = TestEntity {
            id: "plain".to_string(),
            name: "kept".to_string(),
            value: 3,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // With encryption disabled the sweep is a no-op and the plaintext file stays.
        let migrated = storage
            .migrate_plaintext_at_rest()
            .await
            .unwrap();
        assert_eq!(migrated, 0);
        assert!(
            temp_dir
                .path()
                .join("plain.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn test_encrypted_only_record_fails_loud_when_encryption_off() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        // Save a record while whole-file encryption is on, producing only a .json.enc file.
        let encrypted_storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();
        let entity = TestEntity {
            id: "enc-only-1".to_string(),
            name: "Confidential".to_string(),
            value: 7,
        };
        encrypted_storage
            .save(&entity)
            .await
            .unwrap();
        drop(encrypted_storage);

        assert!(
            temp_dir
                .path()
                .join("enc-only-1.json.enc")
                .exists()
        );
        assert!(
            !temp_dir
                .path()
                .join("enc-only-1.json")
                .exists()
        );

        // Reopen the same directory with encryption disabled (no encryptor).
        let plain_storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // The encrypted-only record must fail loudly rather than silently reporting as absent.
        let result = plain_storage
            .get("enc-only-1")
            .await;
        assert!(result.is_err(), "expected a loud error, got: {:?}", result);
        let message = result
            .unwrap_err()
            .to_string();
        assert!(message.contains("encryption at rest is disabled"), "unexpected error message: {message}");
    }

    #[tokio::test]
    async fn test_encrypted_only_record_increments_load_error_metric() {
        // Unique entity label so the absolute counter value is deterministic regardless of
        // other tests touching the shared process-wide Prometheus registry.
        let entity_name = "metric_probe_entity_enc_only";
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        let encrypted_storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            entity_name,
            encryption_service,
        )
        .await
        .unwrap();
        encrypted_storage
            .save(&TestEntity {
                id: "enc-only-metric-1".to_string(),
                name: "Confidential".to_string(),
                value: 1,
            })
            .await
            .unwrap();
        drop(encrypted_storage);

        let plain_storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), entity_name)
            .await
            .unwrap();
        let _ = plain_storage
            .get("enc-only-metric-1")
            .await;

        let count = crate::metrics::backends::prometheus::STORAGE_LOAD_ERRORS
            .with_label_values(&[entity_name, "encrypted_but_encryption_disabled"])
            .get();
        assert_eq!(count, 1, "expected exactly one load-error metric increment, got {count}");
    }

    #[tokio::test]
    async fn test_rwlock_storage_with_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        let storage = RwLockFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();

        // Create
        let entity = TestEntity {
            id: "encrypted-3".to_string(),
            name: "Sensitive".to_string(),
            value: 123,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("encrypted-3")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity));
    }

    #[tokio::test]
    async fn test_wrong_key_fails_to_load() {
        let temp_dir = TempDir::new().unwrap();

        // Save with one key
        {
            let (encryption_service1, _key1) = test_encryption_service();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service1,
            )
            .await
            .unwrap();

            let entity = TestEntity {
                id: "test-key".to_string(),
                name: "Secret".to_string(),
                value: 42,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Try to load with different key
        {
            let (encryption_service2, _key2) = test_encryption_service();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service2,
            )
            .await;

            // Fail open: an undecryptable record is skipped, so the store still constructs
            // but the record it could not decrypt is absent from the loaded map.
            let storage = storage.expect("fail-open load must still construct the store");
            assert!(
                storage
                    .get("test-key")
                    .await
                    .unwrap()
                    .is_none(),
                "a record that cannot be decrypted must not appear in the loaded store"
            );
        }
    }

    #[tokio::test]
    async fn test_encryption_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let key_manager = KeyManager::from_raw_key(&rand::random::<[u8; 32]>()).unwrap();
        let raw_key = *key_manager.master_key();

        // Save with encryption
        {
            let encryption_service = EncryptionService::new(KeySource::Raw { key: raw_key }).unwrap();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service,
            )
            .await
            .unwrap();

            let entity = TestEntity {
                id: "persist".to_string(),
                name: "Persistent Secret".to_string(),
                value: 777,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Load with same key in new instance
        {
            let encryption_service = EncryptionService::new(KeySource::Raw { key: raw_key }).unwrap();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service,
            )
            .await
            .unwrap();

            let loaded = storage
                .get("persist")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(loaded.name, "Persistent Secret");
            assert_eq!(loaded.value, 777);
        }
    }

    // ============================================================================
    // Startup migration: encrypt plaintext storage files and delete originals.
    // ============================================================================

    /// A plaintext-only record is encrypted, the plaintext is deleted, and
    /// the record loads with its original value.
    #[tokio::test]
    async fn test_startup_migrates_plaintext_only_and_deletes_original() {
        let temp_dir = TempDir::new().unwrap();
        let key = rand::random::<[u8; 32]>();
        let id = "plain-1";
        let entity = TestEntity {
            id: id.to_string(),
            name: "Plain".to_string(),
            value: 7,
        };

        let raw_path = get_raw_path(temp_dir.path(), id);
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();

        let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            EncryptionService::new(KeySource::Raw { key }).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(storage.get(id).await.unwrap(), Some(entity.clone()));

        let enc_path = get_encrypted_path(temp_dir.path(), id);
        assert!(!raw_path.exists(), "plaintext must be deleted after migration");
        assert!(enc_path.exists(), "ciphertext must be written");

        // The ciphertext decrypts back to the original content.
        let cipher = std::fs::read_to_string(&enc_path).unwrap();
        let decrypted = EncryptionService::new(KeySource::Raw { key })
            .unwrap()
            .decrypt_string(cipher)
            .unwrap();
        let round_tripped: TestEntity = serde_json::from_str(&decrypted).unwrap();
        assert_eq!(round_tripped, entity);
    }

    /// A stale plaintext beside an authoritative ciphertext is deleted, and
    /// the record loads from the ciphertext (not the stale plaintext).
    #[tokio::test]
    async fn test_startup_deletes_stale_plaintext_beside_ciphertext() {
        let temp_dir = TempDir::new().unwrap();
        let key = rand::random::<[u8; 32]>();
        let id = "both-1";
        let enc_entity = TestEntity {
            id: id.to_string(),
            name: "FromCiphertext".to_string(),
            value: 100,
        };
        let stale_plain = TestEntity {
            id: id.to_string(),
            name: "StalePlaintext".to_string(),
            value: 1,
        };

        let svc = EncryptionService::new(KeySource::Raw { key }).unwrap();
        let enc_path = get_encrypted_path(temp_dir.path(), id);
        std::fs::write(
            &enc_path,
            svc.encrypt_string(serde_json::to_string_pretty(&enc_entity).unwrap())
                .unwrap(),
        )
        .unwrap();
        let raw_path = get_raw_path(temp_dir.path(), id);
        std::fs::write(&raw_path, serde_json::to_string_pretty(&stale_plain).unwrap()).unwrap();

        let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            EncryptionService::new(KeySource::Raw { key }).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(storage.get(id).await.unwrap(), Some(enc_entity), "ciphertext is authoritative");
        assert!(!raw_path.exists(), "stale plaintext must be deleted");
        assert!(enc_path.exists());
    }

    /// Plaintext that fails to deserialize is preserved, not deleted, and no
    /// ciphertext is written for it.
    #[tokio::test]
    async fn test_startup_preserves_invalid_plaintext() {
        let temp_dir = TempDir::new().unwrap();
        let key = rand::random::<[u8; 32]>();
        let id = "bad-1";
        let raw_path = get_raw_path(temp_dir.path(), id);
        std::fs::write(&raw_path, b"{ this is not valid json").unwrap();

        let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            EncryptionService::new(KeySource::Raw { key }).unwrap(),
        )
        .await
        .unwrap();

        assert!(raw_path.exists(), "invalid plaintext must be preserved");
        assert!(!get_encrypted_path(temp_dir.path(), id).exists(), "no ciphertext for undeserializable plaintext");
        assert!(
            storage
                .get(id)
                .await
                .unwrap()
                .is_none(),
            "invalid record must not load"
        );
    }

    /// With encryption disabled, plaintext is left untouched (no encryption,
    /// no deletion).
    #[tokio::test]
    async fn test_startup_encryption_disabled_leaves_plaintext_untouched() {
        let temp_dir = TempDir::new().unwrap();
        let id = "plain-off";
        let entity = TestEntity {
            id: id.to_string(),
            name: "Plain".to_string(),
            value: 3,
        };
        let raw_path = get_raw_path(temp_dir.path(), id);
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();

        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        assert_eq!(storage.get(id).await.unwrap(), Some(entity));
        assert!(raw_path.exists(), "plaintext must be untouched when encryption is disabled");
        assert!(!get_encrypted_path(temp_dir.path(), id).exists());
    }

    /// Running the migration twice leaves the same on-disk state; the second
    /// boot does not rewrite the ciphertext.
    #[tokio::test]
    async fn test_startup_migration_is_idempotent() {
        let temp_dir = TempDir::new().unwrap();
        let key = rand::random::<[u8; 32]>();
        let id = "idem-1";
        let entity = TestEntity {
            id: id.to_string(),
            name: "Idem".to_string(),
            value: 9,
        };
        let raw_path = get_raw_path(temp_dir.path(), id);
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();

        {
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                EncryptionService::new(KeySource::Raw { key }).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(storage.get(id).await.unwrap(), Some(entity.clone()));
        }

        let enc_path = get_encrypted_path(temp_dir.path(), id);
        assert!(!raw_path.exists());
        assert!(enc_path.exists());
        let cipher_after_first = std::fs::read(&enc_path).unwrap();

        {
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                EncryptionService::new(KeySource::Raw { key }).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(storage.get(id).await.unwrap(), Some(entity));
        }

        assert!(!raw_path.exists(), "still no plaintext after second boot");
        assert_eq!(
            std::fs::read(&enc_path).unwrap(),
            cipher_after_first,
            "idempotent re-open must not rewrite the ciphertext"
        );
    }

    /// Saving an entity while encryption is active removes any stale plaintext
    /// sibling left on disk.
    #[tokio::test]
    async fn test_save_removes_stale_plaintext_sibling() {
        let temp_dir = TempDir::new().unwrap();
        let key = rand::random::<[u8; 32]>();
        let id = "save-1";

        let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            EncryptionService::new(KeySource::Raw { key }).unwrap(),
        )
        .await
        .unwrap();

        let raw_path = get_raw_path(temp_dir.path(), id);
        std::fs::write(&raw_path, br#"{"id":"save-1","name":"stale","value":0}"#).unwrap();

        let entity = TestEntity {
            id: id.to_string(),
            name: "Fresh".to_string(),
            value: 11,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        assert!(!raw_path.exists(), "save must remove the stale plaintext sibling");
        assert!(get_encrypted_path(temp_dir.path(), id).exists());
        assert_eq!(storage.get(id).await.unwrap(), Some(entity));
    }

    #[test]
    fn test_storage_config_from_encryption_disabled() {
        // Test that StorageConfig is created without encryption when disabled
        let encryption_config = crate::config::EncryptionConfig {
            enabled: false,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: "TEST_KEY".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
        };

        let config = storage_config_from_encryption_config(&encryption_config).unwrap();
        assert!(
            config
                .encryption_service
                .is_none()
        );
    }

    #[test]
    fn test_storage_config_from_missing_env_var() {
        // Test that error is returned when environment variable is missing
        let encryption_config = crate::config::EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: "MISSING_ENV_VAR".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
        };

        // This should fail because the env var doesn't exist
        let result = storage_config_from_encryption_config(&encryption_config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to initialize encryption service")
        );
    }

    #[test]
    fn test_storage_config_with_valid_key() {
        // Test creating StorageConfig with a valid encryption key from environment
        use std::env;

        // Generate a valid 32-byte key
        let key: [u8; 32] = rand::random();
        let key_str = base64::engine::general_purpose::STANDARD.encode(key);

        unsafe { env::set_var("TEST_VALID_ENCRYPTION_KEY", &key_str) };

        let encryption_config = crate::config::EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: "TEST_VALID_ENCRYPTION_KEY".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
        };

        let config = storage_config_from_encryption_config(&encryption_config).unwrap();
        assert!(
            config
                .encryption_service
                .is_some()
        );

        unsafe { env::remove_var("TEST_VALID_ENCRYPTION_KEY") };
    }

    #[test]
    fn test_storage_config_encryption_toggle() {
        use std::env;

        let key: [u8; 32] = rand::random();
        let key_str = base64::engine::general_purpose::STANDARD.encode(key);
        unsafe { env::set_var("TEST_MATRIX_ENCRYPTION_KEY", &key_str) };

        let cases = [(false, false), (true, true)];

        for (enabled, should_encrypt_filesystem) in cases {
            let encryption_config = crate::config::EncryptionConfig {
                enabled,
                key_source: crate::config::KeySourceConfig::Environment,
                key_env_var: "TEST_MATRIX_ENCRYPTION_KEY".to_string(),
                key_file: None,
                kms_key_id: None,
                kms_max_concurrent_ops: 16,
                field_encryption_enabled: false,
            };

            let config = storage_config_from_encryption_config(&encryption_config).unwrap();
            assert_eq!(
                config
                    .encryption_service
                    .is_some(),
                should_encrypt_filesystem,
                "enabled={enabled}"
            );
        }

        unsafe { env::remove_var("TEST_MATRIX_ENCRYPTION_KEY") };
    }

    // ============================================================================
    // Path traversal prevention tests
    // ============================================================================

    #[tokio::test]
    async fn test_path_traversal_rejected_on_get() {
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let result = storage
            .get("../../etc/passwd")
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid storage id")
        );
    }

    #[tokio::test]
    async fn test_path_traversal_rejected_on_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let result = storage
            .delete("../../etc/passwd")
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid storage id")
        );
    }

    #[tokio::test]
    async fn test_path_traversal_rejected_on_save() {
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let malicious_entity = TestEntity {
            id: "../../etc/passwd".to_string(),
            name: "pwned".to_string(),
            value: 0,
        };
        let result = storage
            .save(&malicious_entity)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid storage id")
        );
    }

    #[tokio::test]
    async fn test_path_traversal_rejected_on_cached_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let result = storage
            .delete("../secret")
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid storage id")
        );
    }

    #[tokio::test]
    async fn test_path_traversal_rejected_on_rwlock_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RwLockFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let result = storage
            .delete("../secret")
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid storage id")
        );
    }

    #[tokio::test]
    async fn test_url_decoded_traversal_rejected() {
        // Axum decodes %2F to / before the handler runs, so this simulates
        // what arrives at the store after percent-decoding.
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // Simulate what Axum hands the handler after decoding "..%2F..%2Fetc%2Fpasswd"
        let result = storage
            .get("../../etc/passwd")
            .await;
        assert!(result.is_err());

        // Also test slash-encoded variant
        let result2 = storage
            .get("../etc/shadow")
            .await;
        assert!(result2.is_err());
    }
}
