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
}

fn default_is_local() -> bool {
    true // Default to local for backward compatibility
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
}

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
        })
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

        let record_for_broadcast = record.clone();
        self.storage
            .save(&record)
            .await?;

        if is_new
            && let Some(ws) = &self.ws_state
            && let Ok(identity_json) = serde_json::to_value(&record_for_broadcast)
        {
            info!(
                did = %record_for_broadcast.did,
                identity_hash = %record_for_broadcast.identity_hash,
                "📡 Broadcasting identity create via WebSocket"
            );
            ws.broadcast(crate::server::WsUpdate::IdentityCreated { identity: identity_json });
        }

        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<AgentIdentityRecord>> {
        self.storage.list_all().await
    }

    async fn update_usage(
        &self,
        identity_hash: &str,
        channel_config_id: Option<String>,
    ) -> Result<()> {
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
        // Check if we already have this DID
        if let Some(mut existing) = self.find_by_did(did).await? {
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

            // Update identity fields if they're not empty and existing ones are empty
            if !identity_fields.is_empty()
                && existing
                    .identity_fields
                    .is_empty()
            {
                existing.identity_fields = identity_fields;
                info!("Updated identity fields for external DID {}", did);
            }

            return self.create(existing).await;
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
        };

        self.create(record).await
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
}
