//! Storage for agent identity mappings
//!
//! This module provides a trait for storing agent identity to DID mappings,
//! along with a filesystem-based implementation.

use std::path::PathBuf;
use std::sync::Arc;

pub use super::IdentityStore;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use tracing::info;

/// Per-channel usage statistics for an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelUsage {
    /// The channel config ID
    pub channel_config_id: String,

    /// Number of times this identity was used on this channel
    pub usage_count: u64,

    /// Timestamp when this identity was last used on this channel
    pub last_used_at: chrono::DateTime<chrono::Utc>,
}

fn normalize_did_port(did: &str) -> String {
    let normalize_host = |host: &str| {
        host.replace("%3A", ":")
            .replace("%3a", ":")
    };

    if let Some(without_prefix) = did.strip_prefix("did:web:") {
        let parts: Vec<&str> = without_prefix
            .splitn(2, ':')
            .collect();
        if parts.is_empty() {
            return did.to_string();
        }

        let host_part = normalize_host(parts[0]);
        if parts.len() == 1 {
            return format!("did:web:{}", host_part);
        }

        return format!("did:web:{}:{}", host_part, parts[1]);
    }

    if let Some(without_prefix) = did.strip_prefix("did:webvh:") {
        let parsed =
            match crate::identity::didwebvh::identifier::parse_did_webvh(&format!("did:webvh:{}", without_prefix)) {
                Ok(parsed) => parsed,
                Err(_) => return did.to_string(),
            };

        if parsed.domain.is_empty() {
            return did.to_string();
        }

        let host_part = normalize_host(&parsed.domain);
        if parsed.path.is_empty() {
            return format!("did:web:{}", host_part);
        }

        return format!("did:web:{}:{}", host_part, parsed.path.join(":"));
    }

    did.to_string()
}

/// How an identity record entered the store: issued by this gateway for a managed surface,
/// or recorded for an external caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityOrigin {
    Managed,
    ExternalCaller,
}

/// The surface slot whose identity setting created a managed identity: the protected slot
/// (or the legacy surface `managed_identity`), or a Transit Point's own `managed_identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManagedSlot {
    Protected,
    TransitPoint { alias: String },
}

/// Rotations kept per record; older ones are dropped, since every identity row and
/// WebSocket update carries the list.
pub const MAX_ROTATIONS: usize = 20;

/// A change of the stored credential behind a credential-derived identity that kept its DID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialRotation {
    /// The credential's `updated_at` after the change; `None` when the change happened before
    /// the gateway recorded rotations.
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,

    /// The identity fields the change replaced, with their earlier values. Empty for a
    /// credential whose identity fields don't describe its value, such as an API key.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub previous: std::collections::HashMap<String, serde_json::Value>,
}

/// Where a managed identity comes from, as seen when it is issued or reused.
#[derive(Debug, Clone, PartialEq)]
pub struct ManagedIdentitySource {
    pub slot: ManagedSlot,
    /// `updated_at` of the stored certificate or secret the identity is derived from.
    pub credential_updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ManagedIdentitySource {
    pub fn protected() -> Self {
        Self {
            slot: ManagedSlot::Protected,
            credential_updated_at: None,
        }
    }

    pub fn transit_point(alias: impl Into<String>) -> Self {
        Self {
            slot: ManagedSlot::TransitPoint { alias: alias.into() },
            credential_updated_at: None,
        }
    }

    pub fn with_credential_updated_at(
        mut self,
        updated_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        self.credential_updated_at = updated_at;
        self
    }
}

/// Represents a stored agent identity record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentityRecord {
    /// The DID assigned to this agent
    pub did: String,

    /// SHA256 hash of the normalized agent identity payload
    pub identity_hash: String,

    /// Timestamp when this record was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// The extracted identity fields (only x-identity marked fields)
    /// This is a map of field path to value for fields marked with x-identity: true
    pub identity_fields: std::collections::HashMap<String, serde_json::Value>,

    /// Global usage count (total across all channels)
    #[serde(default)]
    pub usage_count: u64,

    /// Global timestamp when this identity was last used (across all channels)
    #[serde(default)]
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Per-channel usage statistics
    #[serde(default)]
    pub channel_usage: Vec<ChannelUsage>,

    /// The agent's private key (JWK format) for signing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<JsonValue>,

    /// The channel config ID where this identity was last used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_config_id: Option<String>,

    /// Whether this is a locally created identity or received from another gateway
    #[serde(default = "default_is_local")]
    pub is_local: bool,

    /// Whether this identity was cryptographically verified (for external identities)
    /// True if VP/VC signature verification succeeded
    #[serde(default)]
    pub verified: bool,

    /// Origin of this identity; `None` for records written before origin tracking
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<IdentityOrigin>,

    /// Slot that created this managed identity; `None` for other identities and for managed
    /// records not used since slot tracking began
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<ManagedSlot>,

    /// `updated_at` of the credential this identity was last seen derived from
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_updated_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Rotations of that credential, oldest first; at most [`MAX_ROTATIONS`]. When older
    /// ones are dropped, the oldest kept rotation's `previous` takes their earliest values
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotations: Vec<CredentialRotation>,

    /// Whether older rotations were dropped to keep [`MAX_ROTATIONS`]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rotations_dropped: bool,
}

fn default_is_local() -> bool {
    true // Default to local for backward compatibility
}

impl AgentIdentityRecord {
    /// Stored origin, or `ExternalCaller` for legacy remote records; legacy local records stay unknown.
    pub fn effective_origin(&self) -> Option<IdentityOrigin> {
        match self.origin {
            Some(origin) => Some(origin),
            None if !self.is_local => Some(IdentityOrigin::ExternalCaller),
            None => None,
        }
    }

    /// Records `source` on this managed identity, now derived with `identity_fields`, and
    /// returns whether anything changed.
    ///
    /// The slot is kept once known. A credential's first `updated_at` is stored as the
    /// baseline. After that, an mTLS certificate rotates when its identity fields change, and
    /// any other credential, whose fields don't describe its value, whenever its `updated_at`
    /// changes. A field change seen when the baseline is stored is a rotation of unknown time.
    /// Only the latest [`MAX_ROTATIONS`] rotations are kept; the oldest kept one takes the
    /// earliest values of the dropped ones, so the fields before it stay the creation fields.
    pub fn apply_managed_source(
        &mut self,
        source: &ManagedIdentitySource,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> bool {
        let mut changed = false;
        if self.slot.is_none() {
            self.slot = Some(source.slot.clone());
            changed = true;
        }
        let Some(updated_at) = source.credential_updated_at else {
            return changed;
        };
        if self.credential_updated_at == Some(updated_at) {
            return changed;
        }
        let fields_changed = self.identity_fields != *identity_fields;
        let rotated = match self.credential_updated_at {
            None => fields_changed,
            Some(_) => fields_changed || identity_fields.get("credential_type") != Some(&serde_json::json!("mtls")),
        };
        if rotated {
            let previous = self
                .identity_fields
                .iter()
                .filter(|(key, value)| identity_fields.get(*key) != Some(*value))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            self.rotations
                .push(CredentialRotation {
                    rotated_at: self
                        .credential_updated_at
                        .map(|_| updated_at),
                    previous,
                });
            let excess = self
                .rotations
                .len()
                .saturating_sub(MAX_ROTATIONS);
            if excess > 0 {
                let mut earliest = std::collections::HashMap::new();
                for dropped in self.rotations.drain(..excess) {
                    for (key, value) in dropped.previous {
                        earliest
                            .entry(key)
                            .or_insert(value);
                    }
                }
                let oldest_kept = &mut self.rotations[0].previous;
                for (key, value) in oldest_kept.drain() {
                    earliest
                        .entry(key)
                        .or_insert(value);
                }
                *oldest_kept = earliest;
                self.rotations_dropped = true;
            }
        }
        self.identity_fields = identity_fields.clone();
        self.credential_updated_at = Some(updated_at);
        true
    }
}

/// Implement StorableEntity for AgentIdentityRecord to use generic filesystem storage
impl StorableEntity for AgentIdentityRecord {
    fn id(&self) -> &str {
        &self.identity_hash
    }
}

/// Filesystem-based implementation of IdentityStore
pub struct FilesystemIdentityStore {
    storage: Box<dyn StorageBackend<AgentIdentityRecord>>,
    storage_path: PathBuf,
    ws_state: Option<Arc<crate::server::WsState>>,
    /// Serialises read-modify-save of one record, so concurrent requests don't overwrite
    /// each other's usage, origin or rotation updates.
    record_locks: [tokio::sync::Mutex<()>; RECORD_LOCK_STRIPES],
}

const RECORD_LOCK_STRIPES: usize = 64;

impl FilesystemIdentityStore {
    /// Create a new filesystem-based identity store
    #[allow(dead_code)]
    pub async fn new(storage_path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::new_with_ws(storage_path, None).await
    }

    /// Create a new filesystem-based identity store with WebSocket support
    pub async fn new_with_ws(
        storage_path: impl AsRef<std::path::Path>,
        ws_state: Option<Arc<crate::server::WsState>>,
    ) -> Result<Self> {
        let storage_path = storage_path
            .as_ref()
            .to_path_buf();
        let storage = cached_storage(storage_path.clone(), "identity").await?;

        Ok(Self {
            storage,
            storage_path,
            ws_state,
            record_locks: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        })
    }

    /// The lock serialising read-modify-write cycles on the record keyed by
    /// `identity_hash`. Hold one record lock at a time.
    fn record_lock(
        &self,
        identity_hash: &str,
    ) -> &tokio::sync::Mutex<()> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        identity_hash.hash(&mut hasher);
        &self.record_locks[(hasher.finish() % RECORD_LOCK_STRIPES as u64) as usize]
    }

    async fn save_record(
        &self,
        record: AgentIdentityRecord,
        is_new: bool,
    ) -> Result<()> {
        self.storage
            .save(&record)
            .await?;

        if is_new
            && let Some(ws) = &self.ws_state
            && let Ok(identity_json) = serde_json::to_value(&record)
        {
            info!(
                did = %record.did,
                identity_hash = %record.identity_hash,
                "📡 Broadcasting identity create via WebSocket"
            );
            ws.broadcast(crate::server::WsUpdate::IdentityCreated { identity: identity_json });
        }

        Ok(())
    }

    /// Find by DID
    async fn find_by_did_impl(
        &self,
        did: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        let records = self
            .storage
            .list_all()
            .await?;

        if let Some(record) = records
            .iter()
            .find(|r| r.did == did)
        {
            return Ok(Some(record.clone()));
        }

        let normalized_search = normalize_did_port(did);
        for record in records {
            let normalized_record = normalize_did_port(&record.did);
            if normalized_record == normalized_search {
                return Ok(Some(record.clone()));
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl IdentityStore for FilesystemIdentityStore {
    async fn find_by_hash(
        &self,
        identity_hash: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        self.storage
            .get(identity_hash)
            .await
    }

    async fn create(
        &self,
        record: AgentIdentityRecord,
    ) -> Result<()> {
        // Treat this as a creation event when the storage doesn't already
        // know about this identity_hash. Update paths reuse `create` to
        // persist edits (e.g. `store_external_did`), so we must distinguish
        // brand-new records from re-saves to avoid duplicate UI events.
        let is_new = self
            .storage
            .get(&record.identity_hash)
            .await
            .ok()
            .flatten()
            .is_none();
        self.save_record(record, is_new)
            .await
    }

    async fn create_if_absent(
        &self,
        record: AgentIdentityRecord,
    ) -> Result<Option<AgentIdentityRecord>> {
        let _guard = self
            .record_lock(&record.identity_hash)
            .lock()
            .await;
        if let Some(existing) = self
            .storage
            .get(&record.identity_hash)
            .await?
        {
            return Ok(Some(existing));
        }
        self.save_record(record, true)
            .await?;
        Ok(None)
    }

    async fn list_all(&self) -> Result<Vec<AgentIdentityRecord>> {
        self.storage.list_all().await
    }

    async fn update_usage(
        &self,
        identity_hash: &str,
        channel_config_id: Option<String>,
    ) -> Result<()> {
        let _guard = self
            .record_lock(identity_hash)
            .lock()
            .await;
        if let Some(mut record) = self
            .storage
            .get(identity_hash)
            .await?
        {
            let now = chrono::Utc::now();

            info!(
                identity_hash = %identity_hash,
                channel_config_id = ?channel_config_id,
                did = %record.did,
                "🔄 Updating identity usage tracking"
            );

            // Update global usage stats
            record.usage_count += 1;
            record.last_used_at = Some(now);

            // Update channel_config_id to track the last-used channel
            if let Some(ref channel_id) = channel_config_id {
                record.channel_config_id = Some(channel_id.clone());

                // Update per-channel usage stats
                if let Some(channel_usage) = record
                    .channel_usage
                    .iter_mut()
                    .find(|cu| &cu.channel_config_id == channel_id)
                {
                    // Update existing channel usage
                    channel_usage.usage_count += 1;
                    channel_usage.last_used_at = now;
                } else {
                    // Add new channel usage entry
                    record
                        .channel_usage
                        .push(ChannelUsage {
                            channel_config_id: channel_id.clone(),
                            usage_count: 1,
                            last_used_at: now,
                        });
                }
            }

            // Clone record for broadcast before saving
            let record_for_broadcast = record.clone();

            // Save to storage
            self.storage
                .save(&record)
                .await?;

            // Broadcast identity update via WebSocket
            if let Some(ws) = &self.ws_state {
                if let Ok(identity_json) = serde_json::to_value(&record_for_broadcast) {
                    info!(
                        did = %record_for_broadcast.did,
                        usage_count = record_for_broadcast.usage_count,
                        last_used_at = ?record_for_broadcast.last_used_at,
                        "📡 Broadcasting identity update via WebSocket"
                    );
                    ws.broadcast(crate::server::WsUpdate::IdentityUpdated { identity: identity_json });
                } else {
                    tracing::warn!("Failed to serialize identity record for WebSocket broadcast");
                }
            } else {
                tracing::debug!("No WebSocket state available - identity update not broadcasted");
            }
        }

        Ok(())
    }

    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        self.find_by_did_impl(did)
            .await
    }

    async fn store_external_did(
        &self,
        did: &str,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        channel_config_id: Option<String>,
        verified: bool,
    ) -> Result<()> {
        let identity_hash = match self.find_by_did(did).await? {
            Some(found) => found.identity_hash,
            None => format!("external:{}", did),
        };
        // Re-read under the lock, so a concurrent request's usage or rotation update isn't lost
        let _guard = self
            .record_lock(&identity_hash)
            .lock()
            .await;
        if let Some(mut existing) = self
            .storage
            .get(&identity_hash)
            .await?
        {
            let now = chrono::Utc::now();

            // Update global usage stats
            existing.last_used_at = Some(now);
            existing.usage_count += 1;

            // Update channel_config_id to track the last-used channel
            if let Some(ref channel_id) = channel_config_id {
                existing.channel_config_id = Some(channel_id.clone());

                // Update per-channel usage stats
                if let Some(channel_usage) = existing
                    .channel_usage
                    .iter_mut()
                    .find(|cu| &cu.channel_config_id == channel_id)
                {
                    // Update existing channel usage
                    channel_usage.usage_count += 1;
                    channel_usage.last_used_at = now;
                } else {
                    // Add new channel usage entry
                    existing
                        .channel_usage
                        .push(ChannelUsage {
                            channel_config_id: channel_id.clone(),
                            usage_count: 1,
                            last_used_at: now,
                        });
                }
            }

            // Update verified status if it changed from false to true
            if verified && !existing.verified {
                existing.verified = true;
                info!("Updated external DID {} to verified=true", did);
            }

            if existing.origin.is_none() && !existing.is_local {
                existing.origin = Some(IdentityOrigin::ExternalCaller);
            }

            // Update identity fields if they're not empty and existing ones are empty
            if !identity_fields.is_empty()
                && existing
                    .identity_fields
                    .is_empty()
            {
                existing.identity_fields = identity_fields;
                info!("Updated identity fields for external DID {}", did);
            }

            return self
                .save_record(existing, false)
                .await;
        }

        // Create a record for external DID with identity fields
        let now = chrono::Utc::now();
        let channel_usage = if let Some(ref channel_id) = channel_config_id {
            vec![ChannelUsage {
                channel_config_id: channel_id.clone(),
                usage_count: 1,
                last_used_at: now,
            }]
        } else {
            vec![]
        };

        let record = AgentIdentityRecord {
            identity_hash: format!("external:{}", did), // Mark as external
            did: did.to_string(),
            created_at: now,
            last_used_at: Some(now),
            usage_count: 1,
            identity_fields, // Store the identity fields from the VC
            channel_usage,
            channel_config_id,
            private_key: None, // No private key for external DIDs
            is_local: false,   // External DID is remote
            verified,          // Track whether VP/VC signature was verified
            origin: Some(IdentityOrigin::ExternalCaller),
            slot: None,
            credential_updated_at: None,
            rotations: Vec::new(),
            rotations_dropped: false,
        };

        self.save_record(record, true)
            .await
    }

    async fn set_origin(
        &self,
        identity_hash: &str,
        origin: IdentityOrigin,
    ) -> Result<Option<IdentityOrigin>> {
        let _guard = self
            .record_lock(identity_hash)
            .lock()
            .await;
        let Some(mut record) = self
            .storage
            .get(identity_hash)
            .await?
        else {
            anyhow::bail!("identity record not found: {}", identity_hash);
        };
        if let Some(existing) = record.origin {
            return Ok(Some(existing));
        }
        record.origin = Some(origin);
        self.storage
            .save(&record)
            .await?;
        Ok(Some(origin))
    }

    async fn apply_managed_source(
        &self,
        identity_hash: &str,
        source: &ManagedIdentitySource,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        let _guard = self
            .record_lock(identity_hash)
            .lock()
            .await;
        let Some(mut record) = self
            .storage
            .get(identity_hash)
            .await?
        else {
            anyhow::bail!("identity record not found: {}", identity_hash);
        };
        if !record.apply_managed_source(source, identity_fields) {
            return Ok(());
        }
        self.storage
            .save(&record)
            .await?;
        if let Some(ws) = &self.ws_state
            && let Ok(identity_json) = serde_json::to_value(&record)
        {
            ws.broadcast(crate::server::WsUpdate::IdentityUpdated { identity: identity_json });
        }
        Ok(())
    }

    fn base_path(&self) -> Option<std::path::PathBuf> {
        Some(self.storage_path.clone())
    }
}

/// Calculate SHA256 hash of a normalized JSON payload
pub fn calculate_identity_hash(identity: &serde_json::Value) -> String {
    // Serialize to canonical JSON to ensure consistent hashing
    let canonical = serde_json::to_string(identity).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin_record(
        origin: Option<IdentityOrigin>,
        is_local: bool,
    ) -> AgentIdentityRecord {
        AgentIdentityRecord {
            did: "did:web:origin".to_string(),
            identity_hash: "hash".to_string(),
            created_at: chrono::Utc::now(),
            identity_fields: std::collections::HashMap::new(),
            usage_count: 0,
            last_used_at: None,
            channel_usage: vec![],
            private_key: None,
            channel_config_id: None,
            is_local,
            verified: false,
            origin,
            slot: None,
            credential_updated_at: None,
            rotations: Vec::new(),
            rotations_dropped: false,
        }
    }

    #[test]
    fn effective_origin_prefers_stored_origin() {
        assert_eq!(
            origin_record(Some(IdentityOrigin::Managed), false).effective_origin(),
            Some(IdentityOrigin::Managed)
        );
        assert_eq!(
            origin_record(Some(IdentityOrigin::ExternalCaller), true).effective_origin(),
            Some(IdentityOrigin::ExternalCaller)
        );
    }

    #[test]
    fn effective_origin_infers_legacy_remote_as_caller_and_leaves_legacy_local_unknown() {
        assert_eq!(origin_record(None, false).effective_origin(), Some(IdentityOrigin::ExternalCaller));
        assert_eq!(origin_record(None, true).effective_origin(), None);
    }

    #[tokio::test]
    async fn test_find_by_did_matches_webvh_record_from_legacy_web_form() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let record = AgentIdentityRecord {
            did: "did:webvh:zQmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:localhost%3A8081:channel:abc".to_string(),
            identity_hash: "hash-1".to_string(),
            created_at: chrono::Utc::now(),
            identity_fields: std::collections::HashMap::new(),
            usage_count: 0,
            last_used_at: None,
            channel_usage: vec![],
            private_key: None,
            channel_config_id: None,
            is_local: true,
            verified: true,
            origin: None,
            slot: None,
            credential_updated_at: None,
            rotations: Vec::new(),
            rotations_dropped: false,
        };

        store
            .create(record.clone())
            .await
            .unwrap();

        let found = store
            .find_by_did("did:web:localhost%3A8081:channel:abc")
            .await
            .unwrap();

        assert!(found.is_some(), "legacy did:web lookup must match stored did:webvh record");
        assert_eq!(found.unwrap().did, record.did);
    }

    #[test]
    fn test_normalize_did_port_with_encoded_port() {
        let encoded = "did:web:localhost%3A8081:agent:1";
        let decoded = "did:web:localhost:8081:agent:1";

        assert_eq!(normalize_did_port(encoded), "did:web:localhost:8081:agent:1");
        assert_eq!(normalize_did_port(decoded), "did:web:localhost:8081:agent:1");
        assert_eq!(normalize_did_port(encoded), normalize_did_port(decoded));
    }

    #[test]
    fn test_normalize_did_port_lowercase_encoding() {
        let encoded = "did:web:localhost%3a8081:agent:1";
        assert_eq!(normalize_did_port(encoded), "did:web:localhost:8081:agent:1");
    }

    #[test]
    fn test_normalize_did_port_no_port() {
        let did = "did:web:example.com:agent:1";
        assert_eq!(normalize_did_port(did), "did:web:example.com:agent:1");
    }

    #[test]
    fn test_normalize_did_port_non_web_did() {
        let did = "did:key:z6ExampleKeyId000001";
        assert_eq!(normalize_did_port(did), did);
    }

    #[test]
    fn test_normalize_did_port_host_only() {
        let did = "did:web:localhost%3A8081";
        assert_eq!(normalize_did_port(did), "did:web:localhost:8081");
    }

    #[test]
    fn test_normalize_did_port_webvh_with_scid_and_encoded_port() {
        let did = "did:webvh:zQmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:localhost%3A8081:channel:abc";
        assert_eq!(normalize_did_port(did), "did:web:localhost:8081:channel:abc");
    }

    #[test]
    fn test_normalize_did_port_webvh_with_raw_scid_and_encoded_port() {
        let did = "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:localhost%3A8081:channel:abc";
        assert_eq!(normalize_did_port(did), "did:web:localhost:8081:channel:abc");
    }

    #[test]
    fn test_normalize_did_port_webvh_without_scid() {
        let did = "did:webvh:localhost%3A8081:channel:abc";
        assert_eq!(normalize_did_port(did), "did:web:localhost:8081:channel:abc");
    }

    fn local_record(identity_hash: &str) -> AgentIdentityRecord {
        AgentIdentityRecord {
            did: format!("did:web:example.com:{identity_hash}"),
            identity_hash: identity_hash.to_string(),
            created_at: chrono::Utc::now(),
            identity_fields: std::collections::HashMap::new(),
            usage_count: 0,
            last_used_at: None,
            channel_usage: vec![],
            private_key: None,
            channel_config_id: None,
            is_local: true,
            verified: true,
            origin: None,
            slot: None,
            credential_updated_at: None,
            rotations: Vec::new(),
            rotations_dropped: false,
        }
    }

    #[test]
    fn test_legacy_record_without_origin_round_trips_without_key() {
        let legacy = serde_json::json!({
            "did": "did:web:example.com:legacy",
            "identity_hash": "legacy",
            "created_at": "2026-01-01T00:00:00Z",
            "identity_fields": {}
        });

        let record: AgentIdentityRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(record.origin, None);

        let reserialized = serde_json::to_value(&record).unwrap();
        assert!(
            reserialized
                .get("origin")
                .is_none()
        );
    }

    #[test]
    fn test_origin_serializes_snake_case() {
        let mut record = local_record("h");
        record.origin = Some(IdentityOrigin::ExternalCaller);
        assert_eq!(serde_json::to_value(&record).unwrap()["origin"], "external_caller");
        record.origin = Some(IdentityOrigin::Managed);
        assert_eq!(serde_json::to_value(&record).unwrap()["origin"], "managed");
    }

    #[tokio::test]
    async fn test_store_external_did_stamps_external_caller() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        store
            .store_external_did("did:web:caller.example", std::collections::HashMap::new(), Some("s1".into()), true)
            .await
            .unwrap();

        let record = store
            .find_by_did("did:web:caller.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.origin, Some(IdentityOrigin::ExternalCaller));
        assert!(!record.is_local);
    }

    #[tokio::test]
    async fn test_store_external_did_backfills_origin_on_legacy_external_record() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let mut legacy = local_record("external:did:web:caller.example");
        legacy.did = "did:web:caller.example".to_string();
        legacy.is_local = false;
        store
            .create(legacy)
            .await
            .unwrap();

        store
            .store_external_did("did:web:caller.example", std::collections::HashMap::new(), None, false)
            .await
            .unwrap();

        let record = store
            .find_by_hash("external:did:web:caller.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.origin, Some(IdentityOrigin::ExternalCaller));
        assert_eq!(record.usage_count, 1);
    }

    #[tokio::test]
    async fn test_store_external_did_keeps_managed_origin() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let mut managed = local_record("m");
        managed.origin = Some(IdentityOrigin::Managed);
        let did = managed.did.clone();
        store
            .create(managed)
            .await
            .unwrap();

        store
            .store_external_did(&did, std::collections::HashMap::new(), None, true)
            .await
            .unwrap();

        let record = store
            .find_by_hash("m")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.origin, Some(IdentityOrigin::Managed));
    }

    #[tokio::test]
    async fn test_set_origin_persists_across_store_instances() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        store
            .create(local_record("h1"))
            .await
            .unwrap();

        store
            .set_origin("h1", IdentityOrigin::Managed)
            .await
            .unwrap();

        let reopened = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let record = reopened
            .find_by_hash("h1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.origin, Some(IdentityOrigin::Managed));
    }

    #[tokio::test]
    async fn test_set_origin_keeps_the_first_origin() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        store
            .create(local_record("h1"))
            .await
            .unwrap();

        let first = store
            .set_origin("h1", IdentityOrigin::Managed)
            .await
            .unwrap();
        let second = store
            .set_origin("h1", IdentityOrigin::ExternalCaller)
            .await
            .unwrap();

        assert_eq!(first, Some(IdentityOrigin::Managed));
        assert_eq!(second, Some(IdentityOrigin::Managed));
        let record = store
            .find_by_hash("h1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.origin, Some(IdentityOrigin::Managed));
    }

    #[tokio::test]
    async fn test_create_if_absent_keeps_the_first_record() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let mut first = local_record("h1");
        first.origin = Some(IdentityOrigin::Managed);
        let mut second = local_record("h1");
        second.did = "did:web:example.com:other".to_string();
        second.origin = Some(IdentityOrigin::ExternalCaller);

        assert!(
            store
                .create_if_absent(first.clone())
                .await
                .unwrap()
                .is_none()
        );
        let kept = store
            .create_if_absent(second)
            .await
            .unwrap()
            .expect("the first record is returned");

        assert_eq!(kept.did, first.did);
        let stored = store
            .find_by_hash("h1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.did, first.did);
        assert_eq!(stored.origin, Some(IdentityOrigin::Managed));
    }

    /// Races `write` against `set_origin(Managed)` on fresh origin-less local
    /// records and returns the records whose origin did not survive.
    async fn origins_lost_to_concurrent<F, Fut>(write: F) -> Vec<String>
    where
        F: Fn(Arc<FilesystemIdentityStore>, AgentIdentityRecord) -> Fut,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemIdentityStore::new(temp_dir.path())
                .await
                .unwrap(),
        );
        let mut lost = Vec::new();
        for round in 0..200 {
            let record = local_record(&format!("race-{round}"));
            let hash = record.identity_hash.clone();
            store
                .create(record.clone())
                .await
                .unwrap();
            let write = tokio::spawn(write(store.clone(), record));
            let origin = tokio::spawn({
                let store = store.clone();
                let hash = hash.clone();
                async move {
                    store
                        .set_origin(&hash, IdentityOrigin::Managed)
                        .await
                }
            });
            write.await.unwrap().unwrap();
            origin.await.unwrap().unwrap();
            let stored = store
                .find_by_hash(&hash)
                .await
                .unwrap()
                .unwrap();
            if stored.origin != Some(IdentityOrigin::Managed) {
                lost.push(hash);
            }
        }
        lost
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_update_usage_never_drops_a_concurrent_origin() {
        let lost = origins_lost_to_concurrent(|store, record| async move {
            store
                .update_usage(&record.identity_hash, Some("surface-a".into()))
                .await
        })
        .await;
        assert!(lost.is_empty(), "origin overwritten by a usage update: {lost:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_store_external_did_never_drops_a_concurrent_origin() {
        let lost = origins_lost_to_concurrent(|store, record| async move {
            store
                .store_external_did(&record.did, std::collections::HashMap::new(), Some("surface-a".into()), true)
                .await
        })
        .await;
        assert!(lost.is_empty(), "origin overwritten by an external DID update: {lost:?}");
    }

    #[tokio::test]
    async fn test_set_origin_unknown_hash_errors() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let result = store
            .set_origin("missing", IdentityOrigin::Managed)
            .await;

        assert!(result.is_err());
        assert!(
            store
                .find_by_hash("missing")
                .await
                .unwrap()
                .is_none()
        );
    }

    fn at(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_767_225_600 + seconds, 0).unwrap()
    }

    fn mtls_fields(fingerprint: &str) -> std::collections::HashMap<String, JsonValue> {
        std::collections::HashMap::from([
            ("credential_type".to_string(), serde_json::json!("mtls")),
            ("certificate_id".to_string(), serde_json::json!("cert-1")),
            ("fingerprint_sha256".to_string(), serde_json::json!(fingerprint)),
            ("subject_dn".to_string(), serde_json::json!("CN=agent")),
        ])
    }

    fn api_key_fields() -> std::collections::HashMap<String, JsonValue> {
        std::collections::HashMap::from([
            ("credential_type".to_string(), serde_json::json!("api_key")),
            ("api_key_id".to_string(), serde_json::json!("key-1")),
        ])
    }

    fn credential_record(
        fields: std::collections::HashMap<String, JsonValue>,
        updated_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AgentIdentityRecord {
        let mut record = local_record("h");
        record.identity_fields = fields;
        record.credential_updated_at = updated_at;
        record
    }

    fn observed(updated_at: i64) -> ManagedIdentitySource {
        ManagedIdentitySource::protected().with_credential_updated_at(Some(at(updated_at)))
    }

    #[test]
    fn apply_managed_source_sets_the_slot_once() {
        let mut record = local_record("h");

        assert!(
            record.apply_managed_source(&ManagedIdentitySource::transit_point("tp-1"), &record.identity_fields.clone())
        );
        assert!(!record.apply_managed_source(&ManagedIdentitySource::protected(), &record.identity_fields.clone()));

        assert_eq!(record.slot, Some(ManagedSlot::TransitPoint { alias: "tp-1".into() }));
        assert_eq!(record.credential_updated_at, None);
        assert!(record.rotations.is_empty());
    }

    #[test]
    fn apply_managed_source_stores_the_first_updated_at_as_a_baseline() {
        let mut record = credential_record(mtls_fields("aa"), None);

        assert!(record.apply_managed_source(&observed(0), &mtls_fields("aa")));

        assert_eq!(record.credential_updated_at, Some(at(0)));
        assert!(record.rotations.is_empty());
    }

    #[test]
    fn apply_managed_source_records_a_changed_certificate_with_its_previous_fields() {
        let mut record = credential_record(mtls_fields("aa"), Some(at(0)));

        assert!(record.apply_managed_source(&observed(60), &mtls_fields("bb")));

        assert_eq!(
            record.rotations,
            vec![CredentialRotation {
                rotated_at: Some(at(60)),
                previous: std::collections::HashMap::from([(
                    "fingerprint_sha256".to_string(),
                    serde_json::json!("aa")
                )]),
            }]
        );
        assert_eq!(record.identity_fields, mtls_fields("bb"));
        assert_eq!(record.credential_updated_at, Some(at(60)));
    }

    #[test]
    fn apply_managed_source_ignores_a_certificate_edit_that_keeps_the_certificate() {
        let mut record = credential_record(mtls_fields("aa"), Some(at(0)));

        assert!(record.apply_managed_source(&observed(60), &mtls_fields("aa")));

        assert!(record.rotations.is_empty());
        assert_eq!(record.credential_updated_at, Some(at(60)));
    }

    #[test]
    fn apply_managed_source_records_every_api_key_update_without_fields() {
        let mut record = credential_record(api_key_fields(), Some(at(0)));

        assert!(record.apply_managed_source(&observed(60), &api_key_fields()));

        assert_eq!(
            record.rotations,
            vec![CredentialRotation {
                rotated_at: Some(at(60)),
                previous: std::collections::HashMap::new(),
            }]
        );
    }

    #[test]
    fn apply_managed_source_records_a_change_before_the_baseline_without_a_time() {
        let mut record = credential_record(mtls_fields("aa"), None);

        assert!(record.apply_managed_source(&observed(60), &mtls_fields("bb")));

        assert_eq!(record.rotations.len(), 1);
        assert_eq!(record.rotations[0].rotated_at, None);
        assert_eq!(record.credential_updated_at, Some(at(60)));
    }

    #[test]
    fn apply_managed_source_changes_nothing_for_the_same_credential() {
        let mut record = credential_record(api_key_fields(), Some(at(0)));
        record.slot = Some(ManagedSlot::Protected);

        assert!(!record.apply_managed_source(&observed(0), &api_key_fields()));

        assert!(record.rotations.is_empty());
    }

    #[test]
    fn apply_managed_source_keeps_only_the_latest_rotations() {
        let mut record = credential_record(api_key_fields(), Some(at(0)));
        let updates = i64::try_from(MAX_ROTATIONS).unwrap() + 5;

        for updated_at in 1..=updates {
            record.apply_managed_source(&observed(updated_at), &api_key_fields());
        }

        assert_eq!(record.rotations.len(), MAX_ROTATIONS);
        assert_eq!(record.rotations[0].rotated_at, Some(at(6)));
        assert_eq!(record.rotations[MAX_ROTATIONS - 1].rotated_at, Some(at(updates)));
        assert!(record.rotations_dropped);
    }

    #[test]
    fn apply_managed_source_keeps_the_creation_fields_when_rotations_are_dropped() {
        let mut record = credential_record(mtls_fields("f0"), Some(at(0)));
        let updates = i64::try_from(MAX_ROTATIONS).unwrap() + 3;

        for updated_at in 1..=updates {
            record.apply_managed_source(&observed(updated_at), &mtls_fields(&format!("f{updated_at}")));
        }

        assert!(record.rotations_dropped);
        assert_eq!(record.rotations.len(), MAX_ROTATIONS);
        assert_eq!(
            record.rotations[0]
                .previous
                .get("fingerprint_sha256"),
            Some(&serde_json::json!("f0")),
            "the oldest kept rotation replaced the creation fingerprint"
        );
        assert_eq!(
            record.rotations[1]
                .previous
                .get("fingerprint_sha256"),
            Some(&serde_json::json!(format!("f{}", updates - i64::try_from(MAX_ROTATIONS).unwrap() + 1)))
        );
    }

    #[test]
    fn apply_managed_source_does_not_flag_dropped_rotations_within_the_limit() {
        let mut record = credential_record(api_key_fields(), Some(at(0)));

        for updated_at in 1..=i64::try_from(MAX_ROTATIONS).unwrap() {
            record.apply_managed_source(&observed(updated_at), &api_key_fields());
        }

        assert_eq!(record.rotations.len(), MAX_ROTATIONS);
        assert!(!record.rotations_dropped);
    }

    #[test]
    fn rotations_and_slot_serialize_only_when_present() {
        let mut record = local_record("h");
        let empty = serde_json::to_value(&record).unwrap();
        for absent in ["slot", "credential_updated_at", "rotations"] {
            assert!(empty.get(absent).is_none(), "{absent} should be omitted");
        }

        record.slot = Some(ManagedSlot::TransitPoint { alias: "tp-1".into() });
        record
            .rotations
            .push(CredentialRotation {
                rotated_at: None,
                previous: std::collections::HashMap::new(),
            });
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["slot"], serde_json::json!({ "kind": "transit_point", "alias": "tp-1" }));
        assert_eq!(value["rotations"], serde_json::json!([{ "rotated_at": null }]));
    }

    #[tokio::test]
    async fn test_apply_managed_source_persists_a_rotation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        store
            .create(credential_record(mtls_fields("aa"), Some(at(0))))
            .await
            .unwrap();

        store
            .apply_managed_source("h", &observed(60), &mtls_fields("bb"))
            .await
            .unwrap();

        let reopened = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let record = reopened
            .find_by_hash("h")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.slot, Some(ManagedSlot::Protected));
        assert_eq!(record.rotations.len(), 1);
        assert_eq!(record.identity_fields, mtls_fields("bb"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_usage_and_rotation_updates_are_not_lost() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemIdentityStore::new(temp_dir.path())
                .await
                .unwrap(),
        );
        store
            .create(credential_record(api_key_fields(), Some(at(0))))
            .await
            .unwrap();

        let requests = 16;
        let tasks: Vec<_> = (0..requests)
            .map(|_| {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    store
                        .update_usage("h", Some("surface-1".to_string()))
                        .await
                        .unwrap();
                    store
                        .apply_managed_source("h", &observed(60), &api_key_fields())
                        .await
                        .unwrap();
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }

        let record = store
            .find_by_hash("h")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.usage_count, requests);
        assert_eq!(record.rotations.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_external_did_and_usage_updates_are_not_lost() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemIdentityStore::new(temp_dir.path())
                .await
                .unwrap(),
        );
        let managed = local_record("h");
        let managed_did = managed.did.clone();
        store
            .create(managed)
            .await
            .unwrap();
        let external_did = "did:web:caller.example";

        let requests = 16;
        let tasks: Vec<_> = (0..requests)
            .map(|_| {
                let store = Arc::clone(&store);
                let managed_did = managed_did.clone();
                tokio::spawn(async move {
                    store
                        .store_external_did(
                            external_did,
                            std::collections::HashMap::new(),
                            Some("surface-1".to_string()),
                            true,
                        )
                        .await
                        .unwrap();
                    store
                        .store_external_did(
                            &managed_did,
                            std::collections::HashMap::new(),
                            Some("surface-1".to_string()),
                            true,
                        )
                        .await
                        .unwrap();
                    store
                        .update_usage("h", Some("surface-1".to_string()))
                        .await
                        .unwrap();
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }

        let external = store
            .find_by_hash(&format!("external:{external_did}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(external.usage_count, requests);
        assert_eq!(external.channel_usage[0].usage_count, requests);
        let managed = store
            .find_by_hash("h")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(managed.usage_count, 2 * requests);
        assert_eq!(managed.channel_usage[0].usage_count, 2 * requests);
    }

    #[tokio::test]
    async fn test_apply_managed_source_unknown_hash_errors() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FilesystemIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let result = store
            .apply_managed_source("missing", &observed(0), &api_key_fields())
            .await;

        assert!(result.is_err());
    }
}
