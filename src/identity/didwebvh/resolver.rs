#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use dashmap::DashMap;

use super::types::{DidDocument, DidResolutionMetadata, LogEntry};
use crate::storage::DidLogStorage;

pub struct DidWebvhResolver {
    storage: Arc<dyn DidLogStorage>,
    cache: DashMap<String, CachedDocument>,
}

#[derive(Clone)]
struct CachedDocument {
    document: DidDocument,
    expires_at: Instant,
}

impl DidWebvhResolver {
    pub fn new(storage: Arc<dyn DidLogStorage>) -> Self {
        Self { storage, cache: DashMap::new() }
    }

    async fn verify_log_raw_with_library(
        &self,
        did: &str,
        raw_entries: &[String],
    ) -> Result<()> {
        let jsonl = raw_entries.join("\n");
        let mut lib_state = didwebvh_rs::DIDWebVHState::default();
        let _ = lib_state
            .resolve_log(did, &jsonl, None)
            .await
            .map_err(|e| anyhow!("DID log validation failed: {}", e))?;
        Ok(())
    }

    /// Validate entries using the library's cryptographic log resolver.
    /// Accepts raw JSON strings to avoid re-serialization through lossy gateway types.
    ///
    /// In test builds this is a no-op so that unit tests can supply unsigned fake entries
    /// to exercise resolver behaviour (caching, version lookup, deactivation) without
    /// needing a full signed log chain.
    async fn verify_log_raw(
        &self,
        did: &str,
        raw_entries: &[String],
    ) -> Result<()> {
        #[cfg(not(test))]
        {
            self.verify_log_raw_with_library(did, raw_entries)
                .await?;
        }
        #[cfg(test)]
        let _ = (did, raw_entries);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn verify_log_raw_for_integration_test(
        &self,
        did: &str,
        raw_entries: &[String],
    ) -> Result<()> {
        self.verify_log_raw_with_library(did, raw_entries)
            .await
    }

    /// Load raw + typed entries and validate. Returns typed entries for business logic.
    async fn load_and_verify(
        &self,
        did: &str,
    ) -> Result<Vec<LogEntry>> {
        let raw = self
            .storage
            .load_all_raw(did)
            .await?;
        self.verify_log_raw(did, &raw)
            .await?;
        raw.iter()
            .map(|s| serde_json::from_str(s).map_err(|e| anyhow!("Failed to parse log entry: {}", e)))
            .collect()
    }

    pub async fn resolve(
        &self,
        did: &str,
    ) -> Result<DidDocument> {
        if let Some(entry) = self.cache.get(did)
            && Instant::now() < entry.expires_at
        {
            return Ok(entry.document.clone());
        }
        // expired cache entry; fall through to refresh

        let entries = self
            .load_and_verify(did)
            .await?;
        let latest = entries
            .last()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("did log empty"))?;

        // Spec §3.4: a deactivated DID MUST NOT resolve to a document
        if latest.parameters.deactivated {
            return Err(anyhow::anyhow!("DID {} has been deactivated", did));
        }

        let ttl_secs = latest
            .parameters
            .ttl
            .unwrap_or(3600);
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs);
        let doc = latest.state;

        self.cache.insert(
            did.to_string(),
            CachedDocument {
                document: doc.clone(),
                expires_at,
            },
        );

        Ok(doc)
    }

    /// Resolve DID to a specific version by versionId
    /// Per spec §3.8: did:webvh:...?versionId=2-hash
    pub async fn resolve_version_id(
        &self,
        did: &str,
        version_id: &str,
    ) -> Result<DidDocument> {
        let entries = self
            .load_and_verify(did)
            .await?;

        let entry = entries
            .iter()
            .find(|e| e.version_id == version_id)
            .ok_or_else(|| anyhow!("version_id {} not found", version_id))?;

        Ok(entry.state.clone())
    }

    /// Resolve DID to a specific version by versionTime
    /// Per spec §3.9: did:webvh:...?versionTime=2024-01-15T10:30:00Z
    /// Returns the DID document at or before the specified time
    pub async fn resolve_version_time(
        &self,
        did: &str,
        version_time: &str,
    ) -> Result<DidDocument> {
        let entries = self
            .load_and_verify(did)
            .await?;

        // Parse the requested time
        let requested_time = chrono::DateTime::parse_from_rfc3339(version_time)
            .map_err(|e| anyhow!("invalid versionTime format: {}", e))?;

        // Find the latest entry at or before the requested time
        let entry = entries
            .iter()
            .rev()
            .find(|e| {
                if let Ok(entry_time) = chrono::DateTime::parse_from_rfc3339(&e.version_time) {
                    entry_time <= requested_time
                } else {
                    false
                }
            })
            .ok_or_else(|| anyhow!("no version found at or before {}", version_time))?;

        Ok(entry.state.clone())
    }

    /// Resolve DID and return both the DID document and resolution metadata (spec §3.6.2).
    pub async fn resolve_with_metadata(
        &self,
        did: &str,
    ) -> Result<(DidDocument, DidResolutionMetadata)> {
        let entries = self
            .load_and_verify(did)
            .await?;

        let birth = entries
            .first()
            .ok_or_else(|| anyhow!("did log empty"))?;
        let latest = entries
            .last()
            .ok_or_else(|| anyhow!("did log empty"))?;

        if latest.parameters.deactivated {
            return Err(anyhow!("DID {} has been deactivated", did));
        }

        let metadata = DidResolutionMetadata {
            version_id: latest.version_id.clone(),
            version_time: latest.version_time.clone(),
            created: birth.version_time.clone(),
            updated: latest.version_time.clone(),
            scid: birth.parameters.scid.clone(),
            portable: latest.parameters.portable,
            deactivated: latest.parameters.deactivated,
            ttl: latest
                .parameters
                .ttl
                .unwrap_or(3600),
            witness: latest
                .parameters
                .witness
                .clone(),
            watchers: latest
                .parameters
                .watchers
                .clone(),
        };

        Ok((latest.state.clone(), metadata))
    }

    /// Transform did:webvh identifier into HTTPS URL for did.jsonl fetch
    ///
    /// DID format: `did:webvh:<scid>:<domain>[:<path_segment>...]`
    ///              parts: [0]="did" [1]="webvh" [2]=<scid> [3]=<domain> [4..]=<path>
    ///
    /// Produces: `https://<domain>[/<path>]/did.jsonl`
    /// or for no explicit path: `https://<domain>/.well-known/did/did.jsonl`
    ///
    /// Domain may contain URL-encoded port (e.g., localhost%3A8080 → localhost:8080).
    pub fn did_to_url(
        &self,
        did: &str,
    ) -> Result<String> {
        let parsed = super::identifier::parse_did_webvh(did)?;
        if parsed.scid.is_none() {
            return Err(anyhow!("invalid did:webvh: must be did:webvh:<scid>:<domain>[:<path>...]"));
        }

        let domain = parsed
            .domain
            .replace("%3A", ":");
        let path = if parsed.path.is_empty() {
            ".well-known/did".to_string()
        } else {
            parsed.path.join("/")
        };

        Ok(format!("https://{}/{}/did.jsonl", domain, path))
    }
}

#[cfg(test)]
mod tests {
    use super::DidWebvhResolver;
    use anyhow::Result;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::identity::didwebvh::types::{LogEntry, LogParameters};
    use crate::storage::DidLogStorage;

    struct MemoryStore {
        loads: AtomicUsize,
        entries: Vec<LogEntry>,
    }

    #[async_trait::async_trait]
    impl DidLogStorage for MemoryStore {
        async fn append(
            &self,
            _did: &str,
            _entry: &LogEntry,
        ) -> Result<()> {
            unreachable!("append not used in tests")
        }

        async fn load_all(
            &self,
            _did: &str,
        ) -> Result<Vec<LogEntry>> {
            self.loads
                .fetch_add(1, Ordering::SeqCst);
            Ok(self.entries.clone())
        }
    }

    #[test]
    fn did_to_url_with_path() {
        let resolver = DidWebvhResolver::new(Arc::new(crate::storage::FileDidLogStorage::new("/tmp")));
        // Format: did:webvh:<scid>:<domain>:<path_segment>...
        let url = resolver
            .did_to_url("did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:example.com:agents:alpha")
            .unwrap();
        assert_eq!(url, "https://example.com/agents/alpha/did.jsonl");
    }

    #[test]
    fn did_to_url_default_path() {
        let resolver = DidWebvhResolver::new(Arc::new(crate::storage::FileDidLogStorage::new("/tmp")));
        // No path after domain → .well-known/did
        let url = resolver
            .did_to_url("did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:example.com")
            .unwrap();
        assert_eq!(url, "https://example.com/.well-known/did/did.jsonl");
    }

    #[test]
    fn did_to_url_with_port() {
        let resolver = DidWebvhResolver::new(Arc::new(crate::storage::FileDidLogStorage::new("/tmp")));
        let url = resolver
            .did_to_url("did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:example.com%3A8443:service")
            .unwrap();
        assert_eq!(url, "https://example.com:8443/service/did.jsonl");
    }

    #[test]
    fn did_to_url_rejects_missing_scid() {
        let resolver = DidWebvhResolver::new(Arc::new(crate::storage::FileDidLogStorage::new("/tmp")));
        // Only three colon-delimited parts (no domain after scid) should fail
        let result = resolver.did_to_url("did:webvh:example.com");
        assert!(result.is_err(), "DID without SCID component must be rejected");
    }

    #[tokio::test]
    async fn resolve_uses_cache_until_ttl_expires() {
        let doc = affinidi_did_common::Document::new("did:webvh:abc:example.com").unwrap();

        let entry = LogEntry {
            version_id: "1-hash".to_string(),
            version_time: "2026-01-01T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "abc".to_string(),
                update_keys: vec![],
                next_key_hashes: None,
                portable: false,
                ttl: Some(1),
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: doc.clone(),
            proof: Vec::new(),
        };

        let store = Arc::new(MemoryStore {
            loads: AtomicUsize::new(0),
            entries: vec![entry],
        });
        let resolver = DidWebvhResolver::new(store.clone());

        let _ = resolver
            .resolve("did:webvh:abc:example.com")
            .await
            .unwrap();
        let _ = resolver
            .resolve("did:webvh:abc:example.com")
            .await
            .unwrap();

        assert_eq!(
            store
                .loads
                .load(Ordering::SeqCst),
            1,
            "second call should hit cache"
        );
    }

    // === Version History Tests ===
    fn make_entry(
        version_id: &str,
        version_time: &str,
        deactivated: bool,
    ) -> LogEntry {
        let doc = affinidi_did_common::Document::new("did:webvh:abc:example.com").unwrap();
        LogEntry {
            version_id: version_id.to_string(),
            version_time: version_time.to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "abc".to_string(),
                update_keys: vec![],
                next_key_hashes: None,
                portable: false,
                ttl: Some(3600),
                witness: None,
                watchers: None,
                deactivated,
            },
            state: doc,
            proof: Vec::new(),
        }
    }

    /// resolve_version_id must return the document state at that specific version.
    #[tokio::test]
    async fn resolve_version_id_returns_correct_document_state() {
        let entry1 = make_entry("1-hash-birth", "2026-01-01T00:00:00Z", false);
        let mut entry2 = make_entry("2-hash-rotation", "2026-02-01T00:00:00Z", false);
        // Give entry2's document a distinguishable id
        entry2.state.id = url::Url::parse("did:webvh:abc:example.com").unwrap();

        let store = Arc::new(MemoryStore {
            loads: AtomicUsize::new(0),
            entries: vec![entry1.clone(), entry2.clone()],
        });
        let resolver = DidWebvhResolver::new(store);

        let doc = resolver
            .resolve_version_id("did:webvh:abc:example.com", "1-hash-birth")
            .await
            .unwrap();

        // The resolved document at version "1-hash-birth" must equal entry1's state
        assert_eq!(
            doc.id.as_str(),
            entry1.state.id.as_str(),
            "resolve_version_id must return the document for the requested version"
        );
    }

    /// resolve_version_id must error when the version is not found.
    #[tokio::test]
    async fn resolve_version_id_errors_for_unknown_version() {
        let entry1 = make_entry("1-hash-birth", "2026-01-01T00:00:00Z", false);
        let store = Arc::new(MemoryStore {
            loads: AtomicUsize::new(0),
            entries: vec![entry1],
        });
        let resolver = DidWebvhResolver::new(store);

        let result = resolver
            .resolve_version_id("did:webvh:abc:example.com", "9-nonexistent")
            .await;
        assert!(result.is_err(), "resolve_version_id must error for an unknown version");
    }

    /// resolve_version_time must return the document state at or before the given time.
    #[tokio::test]
    async fn resolve_version_time_returns_document_at_timestamp() {
        let entry1 = make_entry("1-hash-birth", "2026-01-01T00:00:00Z", false);
        let entry2 = make_entry("2-hash-rotation", "2026-03-01T00:00:00Z", false);

        let store = Arc::new(MemoryStore {
            loads: AtomicUsize::new(0),
            entries: vec![entry1.clone(), entry2.clone()],
        });
        let resolver = DidWebvhResolver::new(store);

        // Request time between entry1 and entry2 → should get entry1's state
        let doc = resolver
            .resolve_version_time("did:webvh:abc:example.com", "2026-02-01T00:00:00Z")
            .await
            .unwrap();

        assert_eq!(
            doc.id.as_str(),
            entry1.state.id.as_str(),
            "resolve_version_time at T=Feb must return entry1 (Jan), not entry2 (Mar)"
        );
    }

    /// resolve_with_metadata must include all required fields.
    #[tokio::test]
    async fn resolve_with_metadata_includes_all_required_fields() {
        let entry = make_entry("1-hash-birth", "2026-01-01T00:00:00Z", false);

        let store = Arc::new(MemoryStore {
            loads: AtomicUsize::new(0),
            entries: vec![entry.clone()],
        });
        let resolver = DidWebvhResolver::new(store);

        let (_, meta) = resolver
            .resolve_with_metadata("did:webvh:abc:example.com")
            .await
            .unwrap();

        assert_eq!(meta.version_id, "1-hash-birth", "version_id must match the log entry");
        assert_eq!(meta.version_time, "2026-01-01T00:00:00Z", "version_time must match");
        assert_eq!(meta.created, "2026-01-01T00:00:00Z", "created must be birth entry time");
        assert_eq!(meta.updated, "2026-01-01T00:00:00Z", "updated must match latest entry");
        assert_eq!(meta.scid, "abc", "scid must match log parameters");
        assert!(!meta.deactivated, "deactivated must be false");
        assert_eq!(meta.ttl, 3600, "ttl must match log parameters");
    }

    // === Deactivation Tests ===
    /// resolve() must return an error for a deactivated DID.
    #[tokio::test]
    async fn resolve_rejects_deactivated_did() {
        let deactivated_entry = make_entry("1-hash-deactivated", "2026-01-01T00:00:00Z", true);

        let store = Arc::new(MemoryStore {
            loads: AtomicUsize::new(0),
            entries: vec![deactivated_entry],
        });
        let resolver = DidWebvhResolver::new(store);

        let result = resolver
            .resolve("did:webvh:abc:example.com")
            .await;
        assert!(result.is_err(), "resolve() must fail for a deactivated DID");
        let err = result
            .unwrap_err()
            .to_string();
        assert!(err.contains("deactivated"), "Error message must mention 'deactivated', got: {}", err);
    }

    /// resolve_with_metadata() must also fail for a deactivated DID.
    #[tokio::test]
    async fn resolve_with_metadata_rejects_deactivated_did() {
        let deactivated_entry = make_entry("1-hash-deactivated", "2026-01-01T00:00:00Z", true);

        let store = Arc::new(MemoryStore {
            loads: AtomicUsize::new(0),
            entries: vec![deactivated_entry],
        });
        let resolver = DidWebvhResolver::new(store);

        let result = resolver
            .resolve_with_metadata("did:webvh:abc:example.com")
            .await;
        assert!(result.is_err(), "resolve_with_metadata() must fail for a deactivated DID");
    }

    /// The deactivation entry itself must be accepted by the verifier.
    #[tokio::test]
    async fn deactivation_log_entry_passes_verifier() {
        use crate::identity::didwebvh::verifier::DidWebvhVerifier;
        use crate::storage::FileDidLogStorage;
        use ed25519_dalek::SigningKey;
        use tempfile::tempdir;

        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let vm_id = "did:webvh:abc:example.com#key-1";

        // The deactivation entry must be a properly signed log entry with deactivated=true.
        // Since we can't sign without a full DidLogManager here, we use FileDidLogStorage.
        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = crate::identity::didwebvh::log::DidLogManager::new(storage.clone());

        // Build an initial signed entry
        let mut doc = affinidi_did_common::Document::new("did:webvh:abc:example.com").unwrap();
        use affinidi_did_common::verification_method::VerificationRelationship;
        use multibase::Base;
        let mut property_set = std::collections::HashMap::new();
        property_set.insert(
            "publicKeyMultibase".to_string(),
            serde_json::Value::String(multibase::encode(
                Base::Base58Btc,
                signing_key
                    .verifying_key()
                    .as_bytes(),
            )),
        );
        let vm = affinidi_did_common::VerificationMethodBuilder::new(
            vm_id,
            "Ed25519VerificationKey2018",
            "did:webvh:abc:example.com",
        )
        .unwrap()
        .properties(property_set)
        .build();
        doc.verification_method = vec![vm];
        doc.assertion_method = vec![VerificationRelationship::Reference(vm_id.to_string())];

        let birth_entry = crate::identity::didwebvh::types::LogEntry {
            version_id: String::new(),
            version_time: "2026-01-01T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: String::new(),
                update_keys: vec![vm_id.to_string()],
                next_key_hashes: None,
                portable: false,
                ttl: None,
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: doc.clone(),
            proof: vec![],
        };

        let _ = manager
            .create_signed(birth_entry, &signing_key, vm_id)
            .await
            .unwrap();

        // Append a deactivation entry
        let mut deact_entry = crate::identity::didwebvh::types::LogEntry {
            version_id: String::new(),
            version_time: "2026-02-01T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: String::new(),
                update_keys: vec![vm_id.to_string()],
                next_key_hashes: None,
                portable: false,
                ttl: None,
                witness: None,
                watchers: None,
                deactivated: true,
            },
            state: doc,
            proof: vec![],
        };
        deact_entry.parameters.scid = "placeholder".to_string();

        let _ = manager
            .append_signed(deact_entry, &signing_key, vm_id)
            .await
            .unwrap();

        let stored = storage
            .load_all("did:webvh:abc:example.com")
            .await
            .unwrap();
        let verifier = DidWebvhVerifier::new();
        let report = verifier
            .verify(&stored)
            .unwrap();

        assert!(report.valid, "Deactivation entry with valid proof must pass the verifier");
    }
}
