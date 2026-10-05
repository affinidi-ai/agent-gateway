//! DID:webvh Identity Manager
//!
//! Manages UUID-based identity records for DID:webvh identities, providing
//! storage and retrieval operations for identities with their associated metadata.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::types::{DidDocument, KeyPair};

/// Metadata for a DID:webvh identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentity {
    /// Internal UUID identifier
    pub id: Uuid,

    /// The DID:webvh string (e.g., did:webvh:example.com:alice)
    pub did: String,

    /// Signing key pair for this identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pair: Option<KeyPair>,

    /// Current version number
    pub version: u64,

    /// Timestamp when created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Optional metadata about the agent
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,

    /// Whether this identity is active
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

fn extract_path_from_did(did: &str) -> Option<String> {
    let parsed = super::identifier::parse_did_webvh(did).ok()?;
    if parsed.path.is_empty() {
        return None;
    }

    Some(parsed.path.join("/"))
}

/// Create request for a new DID:webvh identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidRequest {
    /// Optional custom DID path (if not provided, UUID will be used)
    #[serde(alias = "path")]
    pub did_path: Option<String>,

    /// Agent metadata (code, model, deployment info, etc.)
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,

    /// Optional existing key pair (if not provided, new keys will be generated)
    pub key_pair: Option<KeyPair>,
}

/// Response from creating a DID:webvh identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidResponse {
    /// Internal UUID identifier
    pub id: Uuid,

    /// The created DID:webvh string
    pub did: String,

    /// The initial DID document
    pub did_document: DidDocument,

    /// Timestamp when created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// List item for DID:webvh identities (without sensitive key material)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentityListItem {
    /// Internal UUID identifier
    pub id: Uuid,

    /// The DID:webvh string
    pub did: String,

    /// Current version
    pub version: u64,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Whether active
    pub active: bool,

    /// Metadata summary (without sensitive data)
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl From<DidWebVhIdentity> for DidWebVhIdentityListItem {
    fn from(identity: DidWebVhIdentity) -> Self {
        Self {
            id: identity.id,
            did: identity.did,
            version: identity.version,
            created_at: identity.created_at,
            updated_at: identity.updated_at,
            active: identity.active,
            metadata: identity.metadata,
        }
    }
}

/// API view of a single DID:webvh identity: carries the public key only,
/// never the private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentityResponse {
    /// Internal UUID identifier
    pub id: Uuid,

    /// The DID:webvh string
    pub did: String,

    /// Public key in JWK format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<serde_json::Value>,

    /// Key type (e.g., "Ed25519")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,

    /// Current version
    pub version: u64,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Whether active
    pub active: bool,

    /// Metadata (without sensitive data)
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl From<DidWebVhIdentity> for DidWebVhIdentityResponse {
    fn from(identity: DidWebVhIdentity) -> Self {
        let (public_key, key_type) = match identity.key_pair {
            Some(key_pair) => {
                (Some(super::create::strip_jwk_private_key(&key_pair.public_key)), Some(key_pair.key_type))
            }
            None => (None, None),
        };
        Self {
            id: identity.id,
            did: identity.did,
            public_key,
            key_type,
            version: identity.version,
            created_at: identity.created_at,
            updated_at: identity.updated_at,
            active: identity.active,
            metadata: identity.metadata,
        }
    }
}

/// Trait for DID:webvh identity storage operations
#[async_trait]
pub trait DidWebVhIdentityStore: Send + Sync {
    /// Create a new DID:webvh identity
    async fn create(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()>;

    /// Get an identity by UUID
    async fn get(
        &self,
        id: &Uuid,
    ) -> Result<Option<DidWebVhIdentity>>;

    /// Get an identity by DID string
    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<DidWebVhIdentity>>;

    /// Get an identity by path (e.g., "agents/123" or "alice")
    async fn get_by_path(
        &self,
        path: &str,
    ) -> Result<Option<DidWebVhIdentity>>;

    /// List all identities
    async fn list(&self) -> Result<Vec<DidWebVhIdentityListItem>>;

    /// Update an existing identity
    async fn update(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()>;

    /// Delete an identity
    async fn delete(
        &self,
        id: &Uuid,
    ) -> Result<()>;
}

/// Filesystem-based implementation of DidWebVhIdentityStore
pub struct FileSystemDidWebVhIdentityStore {
    storage_path: PathBuf,
    cache: Arc<RwLock<HashMap<Uuid, DidWebVhIdentity>>>,
    did_index: Arc<RwLock<HashMap<String, Uuid>>>,  // DID -> UUID mapping
    path_index: Arc<RwLock<HashMap<String, Uuid>>>, // Path -> UUID mapping (e.g., "agents/123" -> UUID)
}

impl FileSystemDidWebVhIdentityStore {
    /// Create a new filesystem-based identity store
    pub async fn new(storage_path: impl AsRef<std::path::Path>) -> Result<Self> {
        let storage_path = storage_path
            .as_ref()
            .to_path_buf();

        // Create directory if it doesn't exist
        tokio::fs::create_dir_all(&storage_path)
            .await
            .context("Failed to create identity storage directory")?;

        let store = Self {
            storage_path,
            cache: Arc::new(RwLock::new(HashMap::new())),
            did_index: Arc::new(RwLock::new(HashMap::new())),
            path_index: Arc::new(RwLock::new(HashMap::new())),
        };

        // Load existing identities into cache
        store.load_all().await?;

        Ok(store)
    }

    /// Get the file path for an identity
    fn identity_path(
        &self,
        id: &Uuid,
    ) -> PathBuf {
        self.storage_path
            .join(format!("{}.json", id))
    }

    /// Load all identities from disk into cache
    async fn load_all(&self) -> Result<()> {
        let mut entries = tokio::fs::read_dir(&self.storage_path).await?;
        let mut count = 0;
        let mut seen = std::collections::HashSet::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Resolve both plaintext `{id}.json` and whole-file-encrypted
            // `{id}.json.enc` records to the logical plaintext path;
            // `read_secret_file` transparently reads whichever form exists.
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let logical = if let Some(stem) = file_name.strip_suffix(".json.enc") {
                self.storage_path
                    .join(format!("{stem}.json"))
            } else if file_name.ends_with(".json") {
                path.clone()
            } else {
                continue;
            };

            if !seen.insert(logical.clone()) {
                continue;
            }

            {
                match self
                    .load_identity_from_file(&logical)
                    .await
                {
                    Ok(identity) => {
                        let id = identity.id;
                        let did = identity.did.clone();
                        let path = extract_path_from_did(&did);

                        self.cache
                            .write()
                            .await
                            .insert(id, identity);
                        self.did_index
                            .write()
                            .await
                            .insert(did, id);
                        if let Some(path) = path {
                            self.path_index
                                .write()
                                .await
                                .insert(path, id);
                        }
                        count += 1;
                    }
                    Err(e) => {
                        warn!("Failed to load identity from {:?}: {}", path, e);
                    }
                }
            }
        }

        info!("Loaded {} DID:webvh identities from {}", count, self.storage_path.display());
        Ok(())
    }

    /// Load a single identity from file
    async fn load_identity_from_file(
        &self,
        path: &Path,
    ) -> Result<DidWebVhIdentity> {
        let content = crate::encryption::secret_file::read_secret_file(path)
            .await
            .context("Failed to read identity file")?
            .ok_or_else(|| anyhow::anyhow!("Identity file not found: {}", path.display()))?;

        let identity: DidWebVhIdentity = serde_json::from_str(&content).context("Failed to parse identity JSON")?;

        Ok(identity)
    }

    /// Save an identity to disk
    async fn save_identity(
        &self,
        identity: &DidWebVhIdentity,
    ) -> Result<()> {
        let path = self.identity_path(&identity.id);
        let content = serde_json::to_string_pretty(identity).context("Failed to serialize identity")?;

        crate::encryption::secret_file::write_secret_file(&path, &content)
            .await
            .context("Failed to write identity file")?;

        debug!("Saved DID:webvh identity {} to {:?}", identity.did, path);
        Ok(())
    }
}

#[async_trait]
impl DidWebVhIdentityStore for FileSystemDidWebVhIdentityStore {
    async fn create(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()> {
        let id = identity.id;
        let did = identity.did.clone();

        // Check if ID already exists
        if self
            .cache
            .read()
            .await
            .contains_key(&id)
        {
            anyhow::bail!("Identity with ID {} already exists", id);
        }

        // Check if DID already exists
        if self
            .did_index
            .read()
            .await
            .contains_key(&did)
        {
            anyhow::bail!("Identity with DID {} already exists", did);
        }

        // Save to disk
        self.save_identity(&identity)
            .await?;

        // Extract path from DID for path index
        let path = extract_path_from_did(&did);

        // Update cache
        self.cache
            .write()
            .await
            .insert(id, identity);
        self.did_index
            .write()
            .await
            .insert(did.clone(), id);
        if let Some(path) = path {
            self.path_index
                .write()
                .await
                .insert(path, id);
        }

        info!("Created DID:webvh identity {}", id);
        Ok(())
    }

    async fn get(
        &self,
        id: &Uuid,
    ) -> Result<Option<DidWebVhIdentity>> {
        Ok(self
            .cache
            .read()
            .await
            .get(id)
            .cloned())
    }

    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<DidWebVhIdentity>> {
        let id = self
            .did_index
            .read()
            .await
            .get(did)
            .cloned();

        match id {
            Some(id) => self.get(&id).await,
            None => Ok(None),
        }
    }

    async fn get_by_path(
        &self,
        path: &str,
    ) -> Result<Option<DidWebVhIdentity>> {
        let id = self
            .path_index
            .read()
            .await
            .get(path)
            .cloned();

        match id {
            Some(id) => self.get(&id).await,
            None => Ok(None),
        }
    }

    async fn list(&self) -> Result<Vec<DidWebVhIdentityListItem>> {
        let cache = self.cache.read().await;
        let mut items: Vec<DidWebVhIdentityListItem> = cache
            .values()
            .map(|identity| identity.clone().into())
            .collect();

        // Sort by creation time (newest first)
        items.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(items)
    }

    async fn update(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()> {
        let id = identity.id;
        let did = identity.did.clone();

        // Check if identity exists
        if !self
            .cache
            .read()
            .await
            .contains_key(&id)
        {
            anyhow::bail!("Identity with ID {} not found", id);
        }

        // Save to disk
        self.save_identity(&identity)
            .await?;

        // Update cache
        let old_did = self
            .cache
            .write()
            .await
            .insert(id, identity.clone());

        // Update DID and path indexes if DID changed
        if let Some(old_identity) = old_did
            && old_identity.did != did
        {
            // Remove old DID from index
            self.did_index
                .write()
                .await
                .remove(&old_identity.did);

            // Remove old path from index
            if let Some(old_path) = extract_path_from_did(&old_identity.did) {
                self.path_index
                    .write()
                    .await
                    .remove(&old_path);
            }

            // Add new DID to index
            self.did_index
                .write()
                .await
                .insert(did.clone(), id);

            // Add new path to index
            if let Some(new_path) = extract_path_from_did(&did) {
                self.path_index
                    .write()
                    .await
                    .insert(new_path, id);
            }
        }

        debug!("Updated DID:webvh identity {}", id);
        Ok(())
    }

    async fn delete(
        &self,
        id: &Uuid,
    ) -> Result<()> {
        // Get identity to find DID
        let identity = self
            .cache
            .read()
            .await
            .get(id)
            .cloned();

        if let Some(identity) = identity {
            // Remove from disk (both plaintext and whole-file-encrypted forms)
            let path = self.identity_path(id);
            if path.exists() {
                tokio::fs::remove_file(&path)
                    .await
                    .context("Failed to delete identity file")?;
            }
            let enc_path = crate::encryption::secret_file::secret_enc_path(&path);
            if enc_path.exists() {
                tokio::fs::remove_file(&enc_path)
                    .await
                    .context("Failed to delete encrypted identity file")?;
            }

            // Remove from cache and indexes
            self.cache
                .write()
                .await
                .remove(id);
            self.did_index
                .write()
                .await
                .remove(&identity.did);

            // Remove path from index
            if let Some(path) = extract_path_from_did(&identity.did) {
                self.path_index
                    .write()
                    .await
                    .remove(&path);
            }

            info!("Deleted DID:webvh identity {}", id);
            Ok(())
        } else {
            anyhow::bail!("Identity with ID {} not found", id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_didwebvh_fix_create_request_accepts_legacy_path_alias() {
        let request: CreateDidRequest = serde_json::from_value(serde_json::json!({
            "path": "agents/test"
        }))
        .expect("legacy path alias should deserialize");

        assert_eq!(request.did_path.as_deref(), Some("agents/test"));
    }

    #[tokio::test]
    async fn test_create_and_get_identity() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:alice".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        let retrieved = store.get(&id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().did, identity.did);
    }

    #[tokio::test]
    async fn identity_records_are_encrypted_at_rest() {
        crate::encryption::global::set_test_encryption(
            crate::config::EncryptionConfig {
                enabled: true,
                ..Default::default()
            },
            crate::encryption::EncryptionService::new(crate::encryption::KeySource::Raw { key: [5u8; 32] }).unwrap(),
        );

        let temp_dir = TempDir::new().unwrap();
        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:secret".to_string(),
            key_pair: Some(super::super::types::KeyPair {
                public_key: serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": "pub" }),
                private_key: serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "d": "super-secret-material" }),
                key_type: "Ed25519".to_string(),
            }),
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };

        {
            let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
                .await
                .unwrap();
            store
                .create(identity.clone())
                .await
                .unwrap();
        }

        // The identity record embeds private key material — it must be an
        // encrypted envelope on disk, never plaintext JSON.
        let plaintext = temp_dir
            .path()
            .join(format!("{}.json", id));
        let encrypted = temp_dir
            .path()
            .join(format!("{}.json.enc", id));
        assert!(!plaintext.exists(), "plaintext identity record must not remain when encryption is active");
        assert!(encrypted.exists(), "encrypted identity record must be written");
        let on_disk = std::fs::read_to_string(&encrypted).unwrap();
        assert!(on_disk.starts_with("ENC["), "identity record must be an ENC[...] envelope");
        assert!(
            !on_disk.contains("super-secret-material"),
            "private key material must not appear in plaintext on disk"
        );

        // A fresh store must scan the `.enc` file, decrypt it, and round-trip.
        let reloaded_store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let reloaded = reloaded_store
            .get(&id)
            .await
            .unwrap()
            .expect("identity must be recovered from the encrypted record");
        assert_eq!(reloaded.did, identity.did);
        assert_eq!(
            reloaded
                .key_pair
                .unwrap()
                .private_key,
            serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "d": "super-secret-material" }),
            "private key material must round-trip through the encrypted store"
        );
    }

    #[tokio::test]
    async fn test_get_by_did() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let identity = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:bob".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        let retrieved = store
            .get_by_did(&identity.did)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, identity.id);
    }

    #[tokio::test]
    async fn test_get_by_path() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let identity = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:agents:123".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        // Test path lookup - "agents:123" -> "agents/123"
        let retrieved = store
            .get_by_path("agents/123")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, identity.id);

        // Test simple path
        let identity2 = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:alice".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };

        store
            .create(identity2.clone())
            .await
            .unwrap();

        let retrieved2 = store
            .get_by_path("alice")
            .await
            .unwrap();
        assert!(retrieved2.is_some());
        assert_eq!(retrieved2.unwrap().id, identity2.id);

        // Test SCID-based format: did:webvh:<scid>:<domain>:<path>
        // The SCID (valid multihash) should be skipped so path = "agents/456"
        let identity3 = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:localhost%3A8080:agents:456".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };
        store
            .create(identity3.clone())
            .await
            .unwrap();
        let retrieved3 = store
            .get_by_path("agents/456")
            .await
            .unwrap();
        assert!(retrieved3.is_some(), "SCID-based DID must be findable by its path component");
        assert_eq!(retrieved3.unwrap().id, identity3.id);
    }

    #[tokio::test]
    async fn test_list_identities() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        for i in 0..3 {
            let identity = DidWebVhIdentity {
                id: Uuid::new_v4(),
                did: format!("did:webvh:example.com:user{}", i),
                key_pair: None,
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                metadata: HashMap::new(),
                active: true,
            };
            store
                .create(identity)
                .await
                .unwrap();
        }

        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_update_identity() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let id = Uuid::new_v4();
        let mut identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:charlie".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        identity.version = 2;
        identity.updated_at = chrono::Utc::now();
        store
            .update(identity.clone())
            .await
            .unwrap();

        let retrieved = store
            .get(&id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.version, 2);
    }

    #[tokio::test]
    async fn test_delete_identity() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:dave".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
        };

        store
            .create(identity)
            .await
            .unwrap();
        store
            .delete(&id)
            .await
            .unwrap();

        let retrieved = store.get(&id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let id = Uuid::new_v4();

        {
            let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
                .await
                .unwrap();
            let identity = DidWebVhIdentity {
                id,
                did: "did:webvh:example.com:eve".to_string(),
                key_pair: None,
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                metadata: HashMap::new(),
                active: true,
            };
            store
                .create(identity)
                .await
                .unwrap();
        }

        // Create new store instance to test loading from disk
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let retrieved = store.get(&id).await.unwrap();
        assert!(retrieved.is_some());
    }
}
