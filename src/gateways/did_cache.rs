use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::storage::filesystem::{StorableEntity, StorageBackend, uncached_storage};

// ============================================================================
// Shared DID Resolver Client (process-wide singleton)
// ============================================================================

use affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy;
use std::sync::OnceLock;
use tokio::sync::OnceCell;

/// Which hosts did:web and did:webvh resolution may contact, set once at
/// startup from `[did_cache] allow_private_hosts`.
static DID_HOST_POLICY: OnceLock<HostPolicy> = OnceLock::new();

/// Record the process-wide DID host policy. Call once during startup, before
/// [`init_shared_resolver`]; later calls are ignored.
pub fn init_did_host_policy(allow_private_hosts: bool) {
    let _ = DID_HOST_POLICY.set(host_policy_for(allow_private_hosts));
}

fn host_policy_for(allow_private_hosts: bool) -> HostPolicy {
    if allow_private_hosts {
        HostPolicy::AllowPrivate
    } else {
        HostPolicy::PublicOnly
    }
}

/// The recorded DID host policy; `PublicOnly` when startup has not set one.
fn did_host_policy() -> HostPolicy {
    DID_HOST_POLICY
        .get()
        .copied()
        .unwrap_or(HostPolicy::PublicOnly)
}

/// Headless TDK config whose own DID resolver follows the process-wide host
/// policy. Each TDK state keeps its own resolver cache, separate from
/// [`shared_resolver`].
pub fn headless_tdk_config() -> Result<affinidi_tdk_common::config::TDKConfig, affinidi_tdk_common::errors::TDKError> {
    headless_tdk_config_for(did_host_policy())
}

fn headless_tdk_config_for(
    host_policy: HostPolicy
) -> Result<affinidi_tdk_common::config::TDKConfig, affinidi_tdk_common::errors::TDKError> {
    affinidi_tdk_common::config::TDKConfig::builder()
        .with_load_environment(false)
        .with_use_atm(false)
        .with_did_resolver_config(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default()
                .with_host_policy(host_policy)
                .build(),
        )
        .build()
}

/// Process-wide shared DID resolver client.
///
/// Avoids creating multiple `DIDCacheClient` instances (each ~40-80 MB for
/// TLS context + connection pool + internal cache). Initialise once at
/// startup via [`init_shared_resolver`], then obtain a clone-cheap `Arc`
/// handle via [`shared_resolver`] anywhere in the codebase.
static SHARED_DID_RESOLVER: OnceCell<Arc<affinidi_did_resolver_cache_sdk::DIDCacheClient>> = OnceCell::const_new();

/// Initialise the shared DID resolver client.  Call once during startup.
///
/// Silently succeeds if already initialised (safe for parallel tests in the
/// same process).
pub async fn init_shared_resolver() -> Result<()> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    // Already initialised — nothing to do.
    if SHARED_DID_RESOLVER
        .get()
        .is_some()
    {
        return Ok(());
    }

    let config = DIDCacheConfigBuilder::default()
        .with_cache_capacity(100)
        .with_cache_ttl(3600) // 1 hour
        .with_host_policy(did_host_policy())
        .build();

    let client = DIDCacheClient::new(config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create shared DID resolver: {}", e))?;

    // Use `get_or_init` pattern: if a concurrent caller raced us, that's fine.
    let _ = SHARED_DID_RESOLVER.set(Arc::new(client));

    info!("✓ Shared DID resolver client initialised (100 entries, 1 h TTL)");
    Ok(())
}

/// Obtain the shared DID resolver client.
///
/// Panics if [`init_shared_resolver`] has not been called yet (programming
/// error — should always be initialised during startup).
pub fn shared_resolver() -> &'static Arc<affinidi_did_resolver_cache_sdk::DIDCacheClient> {
    SHARED_DID_RESOLVER
        .get()
        .expect("shared DID resolver not initialised — call init_shared_resolver() at startup")
}

/// Serializable version of a cached DID document for persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SerializableCachedDID {
    did: String,
    document: serde_json::Value,
    cached_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    is_fresh: bool,
    /// Filesystem key (sanitized DID). Derived from `did`; never serialized.
    #[serde(skip)]
    storage_key: String,
}

impl SerializableCachedDID {
    /// Build the filesystem-safe storage key for a DID (`:` and `/` → `_`).
    fn storage_key_for(did: &str) -> String {
        did.replace([':', '/'], "_")
    }
}

impl StorableEntity for SerializableCachedDID {
    fn id(&self) -> &str {
        &self.storage_key
    }

    fn on_load(&mut self) {
        self.storage_key = Self::storage_key_for(&self.did);
    }
}

/// A cached DID document with metadata
#[derive(Clone, Debug)]
pub struct CachedDIDDocument {
    /// The DID being cached
    #[allow(dead_code)]
    pub did: String,
    /// The DID document in affinidi_did_common::Document format
    pub document: affinidi_did_common::Document,
    /// When this document was cached
    pub cached_at: DateTime<Utc>,
    /// When this cache entry expires
    pub expires_at: DateTime<Utc>,
    /// Whether this was cached from a successful resolution (true) or as a fallback (false)
    pub is_fresh: bool,
}

/// Configuration for the DID cache
#[derive(Clone, Debug)]
pub struct DIDCacheConfig {
    /// Time-to-live for cache entries in seconds (default: 3600 = 1 hour)
    pub ttl_seconds: i64,
    /// Maximum number of entries in the cache (default: 1000)
    pub max_entries: usize,
    /// Whether to mark entries as stale (but still usable) after a percentage of TTL
    pub stale_threshold_percent: u8, // e.g., 80 means entries are "stale" after 80% of TTL
    /// Path to store cached DID documents
    pub storage_path: String,
    /// Local domain for detecting self-referential DIDs (e.g., "agent-gateway-1.example.com")
    pub local_domain: Option<String>,
    /// Path to VC keys storage for loading the gateway's own DID document
    pub vc_keys_path: Option<String>,
    /// Path to connection points storage for loading local DID documents
    pub connection_points_storage_path: Option<String>,
}

impl Default for DIDCacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 3600, // 1 hour
            max_entries: 1000,
            stale_threshold_percent: 80,
            storage_path: "_storage/cache/did".to_string(),
            local_domain: None,
            vc_keys_path: None,
            connection_points_storage_path: None,
        }
    }
}

/// DID document cache for resilient gateway communication
///
/// This cache stores DID documents after successful resolution to avoid
/// repeated network requests and to provide fallback when remote gateways
/// are temporarily unavailable.
pub struct DIDCache {
    config: DIDCacheConfig,
    cache: Arc<RwLock<HashMap<String, CachedDIDDocument>>>,
    /// Generic storage backend for durable cache entries (encryption at rest, atomic writes)
    storage: Box<dyn StorageBackend<SerializableCachedDID>>,
    /// Persistent DID resolver client (reused across resolutions for connection pooling)
    resolver_client: Arc<affinidi_did_resolver_cache_sdk::DIDCacheClient>,
}

impl DIDCache {
    /// Create a new DID cache with the given configuration
    ///
    /// Reuses the process-wide shared DID resolver client (initialised via
    /// [`init_shared_resolver`]) to avoid duplicating TLS contexts and
    /// connection pools.
    pub async fn new(config: DIDCacheConfig) -> Result<Self> {
        let storage = uncached_storage(PathBuf::from(&config.storage_path), "did_cache_document").await?;

        // Reuse the shared resolver instead of creating a new one
        let resolver_client = shared_resolver().clone();

        info!("✓ DID cache created – reusing shared DID resolver client");

        let cache = Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            storage,
            resolver_client,
        };

        Ok(cache)
    }

    /// Load cached DIDs from disk on startup
    pub async fn load_from_disk(&self) -> Result<usize> {
        let mut loaded = 0;

        let records = match self.storage.list_all().await {
            Ok(records) => records,
            Err(e) => {
                warn!("Failed to read DID cache storage: {}", e);
                return Ok(0);
            }
        };

        for cached_did in records {
            // Check if entry has expired
            if cached_did.expires_at > Utc::now() {
                // Convert JSON document back to affinidi_did_common::Document
                if let Ok(document) = serde_json::from_value(cached_did.document.clone()) {
                    let entry = CachedDIDDocument {
                        did: cached_did.did.clone(),
                        document,
                        cached_at: cached_did.cached_at,
                        expires_at: cached_did.expires_at,
                        is_fresh: cached_did.is_fresh,
                    };

                    let mut cache = self.cache.write().await;
                    cache.insert(cached_did.did.clone(), entry);
                    loaded += 1;
                    debug!("Loaded cached DID from disk: {}", cached_did.did);
                }
            } else {
                // Remove expired cache entry
                let key = SerializableCachedDID::storage_key_for(&cached_did.did);
                let _ = self
                    .storage
                    .delete(&key)
                    .await;
                debug!("Removed expired cache entry: {}", cached_did.did);
            }
        }

        if loaded > 0 {
            info!("✓ Loaded {} cached DID documents from disk", loaded);
        }

        Ok(loaded)
    }

    /// Save a cached DID to disk
    async fn save_to_disk(
        &self,
        did: &str,
        entry: &CachedDIDDocument,
    ) {
        // Convert to serializable format
        let document_json = match serde_json::to_value(&entry.document) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize DID document for {}: {}", did, e);
                return;
            }
        };

        let serializable = SerializableCachedDID {
            did: entry.did.clone(),
            document: document_json,
            cached_at: entry.cached_at,
            expires_at: entry.expires_at,
            is_fresh: entry.is_fresh,
            storage_key: SerializableCachedDID::storage_key_for(did),
        };

        if let Err(e) = self
            .storage
            .save(&serializable)
            .await
        {
            error!("Failed to write DID cache entry for {}: {}", did, e);
        } else {
            debug!("Saved DID cache to disk: {}", did);
        }
    }

    /// Store a DID document in the cache
    ///
    /// # Arguments
    /// * `did` - The DID string
    /// * `document` - The DID document
    /// * `is_fresh` - Whether this is from a successful network resolution (true) or a fallback (false)
    pub async fn store(
        &self,
        did: String,
        document: affinidi_did_common::Document,
        is_fresh: bool,
    ) -> Result<()> {
        let mut cache = self.cache.write().await;

        // Check if we need to evict entries (simple LRU-like: remove oldest)
        if cache.len() >= self.config.max_entries {
            // Find and remove the oldest entry
            if let Some(oldest_did) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(did, _)| did.clone())
            {
                cache.remove(&oldest_did);
                debug!("Evicted oldest DID from cache to make room: {}", oldest_did);
            }
        }

        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.ttl_seconds);

        let cached_entry = CachedDIDDocument {
            did: did.clone(),
            document,
            cached_at: now,
            expires_at,
            is_fresh,
        };

        cache.insert(did.clone(), cached_entry.clone());
        drop(cache); // Release lock before disk I/O

        // Save to disk asynchronously
        self.save_to_disk(&did, &cached_entry)
            .await;

        let freshness = if is_fresh {
            "fresh"
        } else {
            "fallback"
        };
        info!("✓ Cached DID document for {} ({}, expires in {}s)", did, freshness, self.config.ttl_seconds);

        Ok(())
    }

    /// Get a DID document from the cache
    ///
    /// Returns Some((document, is_stale)) if found and not expired
    /// The is_stale flag indicates if the entry should be refreshed soon
    pub async fn get(
        &self,
        did: &str,
    ) -> Option<(affinidi_did_common::Document, bool)> {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(did) {
            let now = Utc::now();

            // Check if expired
            if now > entry.expires_at {
                debug!(
                    "Cache entry for {} has expired (cached at {}, expired at {})",
                    did, entry.cached_at, entry.expires_at
                );
                return None;
            }

            // Check if stale (approaching expiration)
            let ttl_duration = Duration::seconds(self.config.ttl_seconds);
            let stale_threshold = ttl_duration.num_seconds()
                * (self
                    .config
                    .stale_threshold_percent as i64)
                / 100;
            let age = (now - entry.cached_at).num_seconds();
            let is_stale = age > stale_threshold;

            if is_stale {
                debug!("Cache entry for {} is stale (age: {}s, threshold: {}s)", did, age, stale_threshold);
            } else {
                debug!("Cache hit for {} (age: {}s, fresh: {})", did, age, entry.is_fresh);
            }

            Some((entry.document.clone(), is_stale))
        } else {
            debug!("Cache miss for {}", did);
            None
        }
    }

    /// Get a DID document from the cache even if expired
    /// This is used as a last-resort fallback when network resolution fails
    pub async fn get_expired(
        &self,
        did: &str,
    ) -> Option<affinidi_did_common::Document> {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(did) {
            let now = Utc::now();
            let age = (now - entry.cached_at).num_seconds();

            warn!(
                "Using EXPIRED cache entry for {} (expired {}s ago) as fallback",
                did,
                (now - entry.expires_at).num_seconds()
            );
            warn!("  Cache age: {}s, was cached at: {}", age, entry.cached_at);

            Some(entry.document.clone())
        } else {
            None
        }
    }

    /// Remove expired entries from the cache
    pub async fn evict_expired(&self) -> usize {
        let mut cache = self.cache.write().await;
        let now = Utc::now();
        let initial_size = cache.len();

        cache.retain(|did, entry| {
            let keep = now <= entry.expires_at;
            if !keep {
                debug!("Evicting expired DID cache entry: {}", did);
            }
            keep
        });

        let evicted = initial_size - cache.len();
        if evicted > 0 {
            info!("Evicted {} expired DID cache entries", evicted);
        }
        evicted
    }

    /// Get all DIDs that are stale and should be refreshed
    pub async fn get_stale_dids(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        let now = Utc::now();

        let ttl_duration = Duration::seconds(self.config.ttl_seconds);
        let stale_threshold = ttl_duration.num_seconds()
            * (self
                .config
                .stale_threshold_percent as i64)
            / 100;

        cache
            .iter()
            .filter(|(_, entry)| {
                let age = (now - entry.cached_at).num_seconds();
                let is_expired = now > entry.expires_at;
                age > stale_threshold && !is_expired
            })
            .map(|(did, _)| did.clone())
            .collect()
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let now = Utc::now();

        let mut fresh_count = 0;
        let mut stale_count = 0;
        let mut expired_count = 0;

        let ttl_duration = Duration::seconds(self.config.ttl_seconds);
        let stale_threshold = ttl_duration.num_seconds()
            * (self
                .config
                .stale_threshold_percent as i64)
            / 100;

        for entry in cache.values() {
            if now > entry.expires_at {
                expired_count += 1;
            } else {
                let age = (now - entry.cached_at).num_seconds();
                if age > stale_threshold {
                    stale_count += 1;
                } else {
                    fresh_count += 1;
                }
            }
        }

        CacheStats {
            total_entries: cache.len(),
            fresh_entries: fresh_count,
            stale_entries: stale_count,
            expired_entries: expired_count,
        }
    }

    /// Clear all cache entries
    #[allow(dead_code)]
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("DID cache cleared");
    }
}

/// Statistics about the DID cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub fresh_entries: usize,
    pub stale_entries: usize,
    pub expired_entries: usize,
}

/// Helper functions for DID resolution with caching and fallback
impl DIDCache {
    /// Resolve a DID document with caching and fallback logic
    ///
    /// This function tries to:
    /// 1. Check the cache for a valid (non-expired) entry
    /// 2. If cache miss or stale, attempt network resolution
    /// 3. On network failure, fall back to expired cache entry if available
    /// 4. Cache the result for future use
    ///
    /// Returns (document, was_cached) where was_cached indicates if served from cache
    pub async fn resolve_with_fallback(
        &self,
        did: &str,
    ) -> Result<(affinidi_did_common::Document, bool)> {
        // First check our cache
        if let Some((document, is_stale)) = self.get(did).await {
            if !is_stale {
                debug!("Serving DID {} from cache (fresh)", did);
                return Ok((document, true));
            }
            // Cache entry is stale - try to refresh below
            debug!("Cache entry for {} is stale, attempting refresh", did);
        }

        // Try to resolve from network
        match self
            .resolve_from_network(did)
            .await
        {
            Ok(document) => {
                // Successfully resolved - cache it
                if let Err(e) = self
                    .store(did.to_string(), document.clone(), true)
                    .await
                {
                    warn!("Failed to cache DID document for {}: {}", did, e);
                }
                Ok((document, false))
            }
            Err(e) => {
                // Network resolution failed - try expired cache as fallback
                warn!("DID resolution failed for {}: {}", did, e);

                if let Some(document) = self.get_expired(did).await {
                    warn!("✓ Using expired cache entry as fallback for {}", did);
                    // Re-cache with current timestamp but mark as non-fresh
                    if let Err(cache_err) = self
                        .store(did.to_string(), document.clone(), false)
                        .await
                    {
                        warn!("Failed to re-cache fallback DID: {}", cache_err);
                    }
                    Ok((document, true))
                } else {
                    Err(anyhow::anyhow!("DID resolution failed and no cache entry available: {}", e))
                }
            }
        }
    }

    /// Try to load a DID document from local storage if it's a self-referential DID
    /// Returns Some(document) if successfully loaded from local storage, None otherwise
    async fn try_load_local_did(
        &self,
        did: &str,
    ) -> Option<affinidi_did_common::Document> {
        if let Some(document) = self
            .load_gateway_own_did_if_matches(did)
            .await
        {
            info!("✓ [DID Cache] Loaded gateway's own DID from vc_keys (bypassed HTTP): {}", did);
            return Some(document);
        }

        // Check if we have local domain configured
        let local_domain = self
            .config
            .local_domain
            .as_ref()?;

        // DID path segments percent-encode colons (':' → '%3A'), so we need to
        // compare using the encoded form of local_domain.
        let local_domain_encoded = local_domain.replace(':', "%3A");

        let path_parts = extract_did_path_parts(did, local_domain_encoded)?;

        if path_parts.is_empty()
            && let Some(document) = self
                .load_gateway_own_did_document(did)
                .await
        {
            info!("✓ [DID Cache] Loaded gateway's own DID from vc_keys (bypassed HTTP): {}", did);
            return Some(document);
        }

        // Check if this is a connection point DID
        if let Some(cp_storage_path) = self
            .config
            .connection_points_storage_path
            .as_ref()
            && path_parts.len() >= 2
            && path_parts[0] == "connection-points"
        {
            let cp_id = path_parts[1];
            let did_doc_path = format!("{}/{}/did.json", cp_storage_path, cp_id);

            // Try to read the DID document from local storage
            match tokio::fs::read_to_string(&did_doc_path).await {
                Ok(content) => match serde_json::from_str::<affinidi_did_common::Document>(&content) {
                    Ok(document) => {
                        info!("✓ [DID Cache] Loaded connection point DID from local storage: {}", did);
                        return Some(document);
                    }
                    Err(e) => {
                        warn!("Failed to parse local DID document for {}: {}", did, e);
                    }
                },
                Err(e) => {
                    debug!("Could not load local DID document for {}: {}", did, e);
                }
            }
        }

        None
    }

    async fn load_gateway_own_did_document(
        &self,
        did: &str,
    ) -> Option<affinidi_did_common::Document> {
        let vc_keys_path = self
            .config
            .vc_keys_path
            .as_ref()?;
        let did_doc_path = format!("{}/did.json", vc_keys_path);
        let content = match tokio::fs::read_to_string(&did_doc_path).await {
            Ok(content) => content,
            Err(e) => {
                debug!("Could not load gateway DID document from vc_keys for {}: {}", did, e);
                return None;
            }
        };

        match serde_json::from_str::<affinidi_did_common::Document>(&content) {
            Ok(document) => Some(document),
            Err(e) => {
                warn!("Failed to parse gateway DID document from vc_keys for {}: {}", did, e);
                None
            }
        }
    }

    async fn load_gateway_own_did_if_matches(
        &self,
        did: &str,
    ) -> Option<affinidi_did_common::Document> {
        let document = self
            .load_gateway_own_did_document(did)
            .await?;
        let value = match serde_json::to_value(&document) {
            Ok(value) => value,
            Err(e) => {
                warn!("Failed to inspect gateway DID document from vc_keys for {}: {}", did, e);
                return None;
            }
        };

        let id_matches = value
            .get("id")
            .and_then(|id| id.as_str())
            == Some(did);
        let alias_matches = value
            .get("alsoKnownAs")
            .and_then(|aliases| aliases.as_array())
            .is_some_and(|aliases| {
                aliases
                    .iter()
                    .any(|alias| alias.as_str() == Some(did))
            });
        if !id_matches && !alias_matches {
            return None;
        }

        Some(document)
    }

    /// Resolve a DID from the network only (no cache)
    async fn resolve_from_network(
        &self,
        did: &str,
    ) -> Result<affinidi_did_common::Document> {
        let start_time = std::time::Instant::now();
        info!("🔍 [DID Cache] Starting network resolution for: {}", did);

        // First, check if this is a self-referential DID that we can load locally
        if let Some(document) = self
            .try_load_local_did(did)
            .await
        {
            return Ok(document);
        }

        // Use the persistent resolver client (reused across calls for connection pooling)
        info!(
            "🔍 [DID Cache] Using persistent resolver for: {} (elapsed: {}ms)",
            did,
            start_time
                .elapsed()
                .as_millis()
        );

        // Resolve with a 3-second timeout to prevent hanging
        let resolve_start = std::time::Instant::now();
        let resolution_result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.resolver_client
                .resolve(did),
        )
        .await
        .map_err(|_| {
            error!(
                "⏱️ [DID Cache] Resolution timed out for: {} (total: {}ms)",
                did,
                start_time
                    .elapsed()
                    .as_millis()
            );
            anyhow::anyhow!("DID resolution timed out after 3 seconds for: {}", did)
        })?
        .map_err(|e| {
            error!(
                "❌ [DID Cache] Resolution failed for {}: {} (time: {}ms)",
                did,
                e,
                start_time
                    .elapsed()
                    .as_millis()
            );
            anyhow::anyhow!("Failed to resolve DID {}: {}", did, e)
        })?;

        info!(
            "✓ [DID Cache] DID {} resolved from network (resolution: {}ms, total: {}ms)",
            did,
            resolve_start
                .elapsed()
                .as_millis(),
            start_time
                .elapsed()
                .as_millis()
        );
        Ok(resolution_result.doc)
    }

    /// Populate an ATM's DID resolver cache with a DID document
    /// This pre-populates the cache so pack_encrypted doesn't need to fetch it
    pub async fn populate_atm_cache(
        &self,
        did: &str,
        document: &affinidi_did_common::Document,
        tdk_state: &affinidi_tdk_common::TDKSharedState,
    ) {
        use highway::HighwayHash;

        let cache = tdk_state
            .did_resolver()
            .get_cache();
        let did_hash = highway::HighwayHasher::default().hash128(did.as_bytes());

        cache
            .insert(did_hash, document.clone())
            .await;
        debug!("✓ Populated ATM DID resolver cache for {}", did);
    }

    /// Resolve a DID and populate both our cache and the ATM's cache
    /// Returns the document and whether it came from cache
    pub async fn resolve_and_cache_for_atm(
        &self,
        did: &str,
        tdk_state: &affinidi_tdk_common::TDKSharedState,
    ) -> Result<(affinidi_did_common::Document, bool)> {
        let (document, was_cached) = self
            .resolve_with_fallback(did)
            .await?;

        // Populate the ATM's cache regardless of whether we got it from our cache or network
        self.populate_atm_cache(did, &document, tdk_state)
            .await;

        Ok((document, was_cached))
    }

    /// Pre-warm the cache by resolving and caching DIDs for all active gateways and connection points
    /// This reduces latency and CPU usage during message processing by avoiding on-demand resolutions
    pub async fn prewarm_cache<GS, CS>(
        &self,
        gateway_store: &Option<Arc<GS>>,
        connection_point_store: &Option<Arc<CS>>,
    ) -> Result<usize>
    where
        GS: crate::gateways::filesystem::GatewayStore + Send + Sync,
        CS: crate::gateways::connection_points::filesystem::ConnectionPointStore + Send + Sync,
    {
        info!("🔥 Pre-warming DID cache for active gateways and connection points...");
        let mut prewarmed = 0;

        // Collect all gateway DIDs if gateway store is available
        if let Some(gw_store) = gateway_store {
            match gw_store.list_all().await {
                Ok(gateways) => {
                    for gateway in gateways {
                        if let Err(e) = self
                            .resolve_with_fallback(&gateway.did)
                            .await
                        {
                            warn!("Failed to pre-warm cache for gateway DID {}: {}", gateway.did, e);
                        } else {
                            prewarmed += 1;
                            debug!("✓ Pre-warmed cache for gateway: {}", gateway.did);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to list gateways for cache pre-warming: {}", e);
                }
            }
        }

        // Collect all connection point DIDs if connection point store is available
        if let Some(cp_store) = connection_point_store {
            match cp_store.list_all().await {
                Ok(connection_points) => {
                    for cp in connection_points {
                        // Pre-warm the connection point's own DID
                        if let Err(e) = self
                            .resolve_with_fallback(&cp.connection_point_did)
                            .await
                        {
                            warn!(
                                "Failed to pre-warm cache for connection point DID {}: {}",
                                cp.connection_point_did, e
                            );
                        } else {
                            prewarmed += 1;
                            debug!("✓ Pre-warmed cache for connection point: {}", cp.connection_point_did);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to list connection points for cache pre-warming: {}", e);
                }
            }
        }

        info!("✓ Pre-warmed DID cache with {} entries", prewarmed);
        Ok(prewarmed)
    }
}

fn extract_did_path_parts(
    did: &str,
    local_domain_encoded: String,
) -> Option<Vec<&str>> {
    if let Some(without_prefix) = did.strip_prefix("did:web:") {
        let parts: Vec<&str> = without_prefix
            .split(':')
            .collect();
        if parts.first().copied() != Some(local_domain_encoded.as_str()) {
            return None;
        }
        return Some(parts[1..].to_vec());
    }

    if let Some(without_prefix) = did.strip_prefix("did:webvh:") {
        let parts: Vec<&str> = without_prefix
            .split(':')
            .collect();
        if parts.is_empty() {
            return None;
        }

        let has_scid = parts.len() >= 2 && !parts[0].contains('.') && !parts[0].contains('%');
        let domain_idx = if has_scid { 1 } else { 0 };
        if parts.get(domain_idx).copied() != Some(local_domain_encoded.as_str()) {
            return None;
        }
        return Some(parts[domain_idx + 1..].to_vec());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{DIDCache, DIDCacheConfig, HostPolicy, headless_tdk_config_for, host_policy_for};
    use chrono::Utc;

    #[test]
    fn host_policy_follows_allow_private_hosts() {
        assert_eq!(host_policy_for(false), HostPolicy::PublicOnly);
        assert_eq!(host_policy_for(true), HostPolicy::AllowPrivate);
    }

    async fn resolve_error(
        host_policy: HostPolicy,
        did: &str,
    ) -> String {
        let tdk = affinidi_tdk_common::TDKSharedState::new(headless_tdk_config_for(host_policy).unwrap())
            .await
            .unwrap();
        match tdk
            .did_resolver()
            .resolve(did)
            .await
        {
            Ok(_) => panic!("resolving an unreachable DID must fail"),
            Err(error) => error.to_string(),
        }
    }

    #[tokio::test]
    async fn public_only_tdk_resolver_refuses_localhost_did_web() {
        let error = resolve_error(HostPolicy::PublicOnly, "did:web:localhost%3A1").await;
        assert!(error.contains("SSRF-prone host"), "expected a blocked-host refusal, got: {error}");
    }

    #[tokio::test]
    async fn allow_private_tdk_resolver_contacts_localhost_did_web() {
        let error = resolve_error(HostPolicy::AllowPrivate, "did:web:localhost%3A1").await;
        assert!(!error.contains("SSRF-prone host"), "AllowPrivate must not refuse localhost, got: {error}");
    }

    fn minimal_document(did_str: &str) -> affinidi_did_common::Document {
        affinidi_did_common::Document::new(did_str).unwrap()
    }

    async fn make_cache(tmp: &std::path::Path) -> DIDCache {
        // Ensure the shared DID resolver is initialised (no-op if already done).
        super::init_shared_resolver()
            .await
            .expect("failed to init shared resolver");

        let config = DIDCacheConfig {
            ttl_seconds: 3600,
            max_entries: 100,
            stale_threshold_percent: 80,
            storage_path: tmp
                .to_string_lossy()
                .to_string(),
            local_domain: None,
            vc_keys_path: None,
            connection_points_storage_path: None,
        };
        DIDCache::new(config)
            .await
            .unwrap()
    }

    // === DID Cache Tests ===
    /// A just-stored entry must be returned by get() within the TTL.
    #[tokio::test]
    async fn cache_hit_within_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path()).await;

        let did = "did:web:example.com";
        cache
            .store(did.to_string(), minimal_document(did), true)
            .await
            .unwrap();

        let result = cache.get(did).await;
        assert!(result.is_some(), "Cache must return a hit for a freshly stored entry");
        let (_, is_stale) = result.unwrap();
        assert!(!is_stale, "A freshly stored entry must not be stale");
    }

    /// An expired entry must be accessible via get_expired() as a last-resort fallback.
    #[tokio::test]
    async fn stale_entry_returned_on_network_failure() {
        let tmp = tempfile::tempdir().unwrap();
        super::init_shared_resolver()
            .await
            .expect("failed to init shared resolver");
        // Use a 1-second TTL so we can easily make entries expire
        let config = DIDCacheConfig {
            ttl_seconds: 1,
            max_entries: 100,
            stale_threshold_percent: 80,
            storage_path: tmp
                .path()
                .to_string_lossy()
                .to_string(),
            local_domain: None,
            vc_keys_path: None,
            connection_points_storage_path: None,
        };
        let cache = DIDCache::new(config)
            .await
            .unwrap();

        let did = "did:web:stale-fallback.example.com";
        cache
            .store(did.to_string(), minimal_document(did), true)
            .await
            .unwrap();

        // Fast-forward: wait for the entry to expire
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        // Normal get() must no longer find it
        assert!(cache.get(did).await.is_none(), "Expired entry must not be returned by get()");

        // get_expired() — the network-failure fallback — must still find it
        let fallback = cache.get_expired(did).await;
        assert!(fallback.is_some(), "Expired entry must be returned by get_expired() as a fallback");
    }

    /// A stored entry must be persisted as a JSON file on disk.
    #[tokio::test]
    async fn cache_persists_entries_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path()).await;

        let did = "did:web:persist.example.com";
        cache
            .store(did.to_string(), minimal_document(did), true)
            .await
            .unwrap();

        // DIDCache saves to <storage_path>/<did with : and / replaced by _>.json
        let filename = did.replace([':', '/'], "_") + ".json";
        let expected_path = tmp.path().join(filename);

        assert!(expected_path.exists(), "Cache entry must be persisted to disk at {:?}", expected_path);

        let content = std::fs::read_to_string(&expected_path).unwrap();
        let _: serde_json::Value = serde_json::from_str(&content).expect("Persisted cache entry must be valid JSON");
    }

    /// Writing a serialised cache entry to disk must be loaded back by load_from_disk().
    #[tokio::test]
    async fn cache_loads_entries_from_disk() {
        let tmp = tempfile::tempdir().unwrap();

        // Write a fixture file in the serialisable format that DIDCache expects
        let did = "did:web:load-from-disk.example.com";
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let fixture = serde_json::json!({
            "did": did,
            "document": { "id": did },
            "cached_at": Utc::now().to_rfc3339(),
            "expires_at": expires_at.to_rfc3339(),
            "is_fresh": true
        });

        let filename = did.replace([':', '/'], "_") + ".json";
        let path = tmp.path().join(filename);
        std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();

        let cache = make_cache(tmp.path()).await;
        let loaded = cache
            .load_from_disk()
            .await
            .unwrap();

        assert!(loaded >= 1, "at least one entry must be loaded from disk");
        assert!(cache.get(did).await.is_some(), "Entry loaded from disk must be retrievable via get()");
    }

    /// When the cache is full, the oldest entry must be evicted to make room.
    #[tokio::test]
    async fn cache_evicts_oldest_entry_when_full() {
        let tmp = tempfile::tempdir().unwrap();
        super::init_shared_resolver()
            .await
            .expect("failed to init shared resolver");
        let config = DIDCacheConfig {
            ttl_seconds: 3600,
            max_entries: 1,
            stale_threshold_percent: 80,
            storage_path: tmp
                .path()
                .to_string_lossy()
                .to_string(),
            local_domain: None,
            vc_keys_path: None,
            connection_points_storage_path: None,
        };
        let cache = DIDCache::new(config)
            .await
            .unwrap();

        let did_a = "did:web:oldest.example.com";
        let did_b = "did:web:newest.example.com";

        // Store A first — it will be the oldest entry
        cache
            .store(did_a.to_string(), minimal_document(did_a), true)
            .await
            .unwrap();
        // Ensure distinct cached_at timestamps
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        // Store B — cache is full (max=1), so A must be evicted
        cache
            .store(did_b.to_string(), minimal_document(did_b), true)
            .await
            .unwrap();

        assert!(
            cache
                .get(did_a)
                .await
                .is_none(),
            "Oldest entry (A) must have been evicted"
        );
        assert!(
            cache
                .get(did_b)
                .await
                .is_some(),
            "Newest entry (B) must still be in the cache"
        );
    }

    #[tokio::test]
    async fn local_gateway_didwebvh_loads_from_vc_keys() {
        let tmp = tempfile::tempdir().unwrap();
        super::init_shared_resolver()
            .await
            .expect("failed to init shared resolver");
        let vc_keys = tmp.path().join("vc_keys");
        std::fs::create_dir_all(&vc_keys).unwrap();

        let did = "did:web:local.example.com";
        let doc = serde_json::json!({ "id": did, "verificationMethod": [] });
        std::fs::write(vc_keys.join("did.json"), serde_json::to_string(&doc).unwrap()).unwrap();

        let config = DIDCacheConfig {
            ttl_seconds: 3600,
            max_entries: 100,
            stale_threshold_percent: 80,
            storage_path: tmp
                .path()
                .join("cache")
                .to_string_lossy()
                .to_string(),
            local_domain: Some("local.example.com".to_string()),
            vc_keys_path: Some(
                vc_keys
                    .to_string_lossy()
                    .to_string(),
            ),
            connection_points_storage_path: None,
        };
        let cache = DIDCache::new(config)
            .await
            .unwrap();

        let resolved = cache
            .try_load_local_did("did:webvh:z6MkScid123:local.example.com")
            .await;
        assert!(resolved.is_some(), "did:webvh gateway DID must load from local vc_keys did.json");
        assert_eq!(resolved.unwrap().id.as_str(), did);
    }

    #[tokio::test]
    async fn local_gateway_didwebvh_with_encoded_port_loads_from_vc_keys_alias() {
        let tmp = tempfile::tempdir().unwrap();
        super::init_shared_resolver()
            .await
            .expect("failed to init shared resolver");
        let vc_keys = tmp.path().join("vc_keys");
        std::fs::create_dir_all(&vc_keys).unwrap();

        let web_did = "did:web:localhost%3A22285";
        let webvh_did = "did:webvh:z6MkScid123:localhost%3A22285";
        let doc = serde_json::json!({
            "id": web_did,
            "alsoKnownAs": [webvh_did],
            "verificationMethod": []
        });
        std::fs::write(vc_keys.join("did.json"), serde_json::to_string(&doc).unwrap()).unwrap();

        let config = DIDCacheConfig {
            ttl_seconds: 3600,
            max_entries: 100,
            stale_threshold_percent: 80,
            storage_path: tmp
                .path()
                .join("cache")
                .to_string_lossy()
                .to_string(),
            local_domain: Some("localhost".to_string()),
            vc_keys_path: Some(
                vc_keys
                    .to_string_lossy()
                    .to_string(),
            ),
            connection_points_storage_path: None,
        };
        let cache = DIDCache::new(config)
            .await
            .unwrap();

        let resolved = cache
            .try_load_local_did(webvh_did)
            .await;
        assert!(resolved.is_some(), "local did:webvh alias with encoded port must load from vc_keys");
        assert_eq!(resolved.unwrap().id.as_str(), web_did);
    }

    #[tokio::test]
    async fn local_connection_point_didwebvh_loads_from_storage() {
        let tmp = tempfile::tempdir().unwrap();
        super::init_shared_resolver()
            .await
            .expect("failed to init shared resolver");
        let cp_storage = tmp
            .path()
            .join("connection_points");
        let cp_id = "1234";
        std::fs::create_dir_all(cp_storage.join(cp_id)).unwrap();

        let doc = serde_json::json!({
            "id": "did:web:local.example.com:connection-points:1234",
            "verificationMethod": []
        });
        std::fs::write(
            cp_storage
                .join(cp_id)
                .join("did.json"),
            serde_json::to_string(&doc).unwrap(),
        )
        .unwrap();

        let config = DIDCacheConfig {
            ttl_seconds: 3600,
            max_entries: 100,
            stale_threshold_percent: 80,
            storage_path: tmp
                .path()
                .join("cache")
                .to_string_lossy()
                .to_string(),
            local_domain: Some("local.example.com".to_string()),
            vc_keys_path: None,
            connection_points_storage_path: Some(
                cp_storage
                    .to_string_lossy()
                    .to_string(),
            ),
        };
        let cache = DIDCache::new(config)
            .await
            .unwrap();

        let resolved = cache
            .try_load_local_did("did:webvh:z6MkScid123:local.example.com:connection-points:1234")
            .await;
        assert!(resolved.is_some(), "did:webvh connection point DID must load local did.json");
        assert_eq!(resolved.unwrap().id.as_str(), "did:web:local.example.com:connection-points:1234");
    }
}
