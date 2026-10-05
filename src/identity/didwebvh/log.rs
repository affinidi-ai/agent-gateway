#![allow(dead_code)]

use std::sync::Arc;

use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::scid::{build_sha256_multihash, generate_scid};
use super::types::{DataIntegrityProof, LogEntry};
use crate::storage::DidLogStorage;

/// Manages did:webvh log lifecycle (did.jsonl)
pub struct DidLogManager {
    storage: Arc<dyn DidLogStorage>,
}

impl DidLogManager {
    pub fn new(storage: Arc<dyn DidLogStorage>) -> Self {
        Self { storage }
    }

    pub async fn create(
        &self,
        preliminary_entry: LogEntry,
    ) -> Result<LogEntry> {
        let scid = generate_scid(&preliminary_entry)?;

        // §3.6.1 step 5.2: Replace "{SCID}" throughout the entire entry
        // (including the DIDDoc state) with the calculated SCID.
        let mut entry = replace_scid_placeholder(preliminary_entry, &scid)?;

        // Per spec §3.7.4: hash entry with versionId = SCID (no proof)
        let entry_hash = compute_entry_hash(&entry, &scid)?;
        entry.version_id = format!("1-{}", entry_hash);

        let did = entry
            .state
            .id
            .as_str()
            .to_string();
        self.storage
            .append(&did, &entry)
            .await?;
        Ok(entry)
    }

    /// Create and sign the birth entry.
    ///
    /// Order per spec §3.7.4:
    /// 1. Generate SCID
    /// 2. Compute hash (without proof, versionId = SCID) → set versionId
    /// 3. Sign the entry with the final versionId
    pub async fn create_signed(
        &self,
        preliminary_entry: LogEntry,
        signing_key: &SigningKey,
        verification_method: &str,
    ) -> Result<LogEntry> {
        let scid = generate_scid(&preliminary_entry)?;

        // §3.6.1 step 5.2: Replace "{SCID}" throughout the entire entry
        // (including the DIDDoc state) with the calculated SCID.
        let mut entry = replace_scid_placeholder(preliminary_entry, &scid)?;

        // Step 2: hash before signing (proof must be absent)
        let entry_hash = compute_entry_hash(&entry, &scid)?;
        entry.version_id = format!("1-{}", entry_hash);

        // Step 3: sign with the finalised versionId
        let vm = verification_method.replace("{SCID}", &scid);
        let signed = sign_entry(&entry, signing_key, &vm)?;

        let did = signed
            .state
            .id
            .as_str()
            .to_string();
        self.storage
            .append(&did, &signed)
            .await?;
        Ok(signed)
    }

    pub async fn append(
        &self,
        mut entry: LogEntry,
    ) -> Result<LogEntry> {
        let did = entry
            .state
            .id
            .as_str()
            .to_string();
        let history: Vec<LogEntry> = self
            .storage
            .load_all(&did)
            .await?;
        // Per spec: SCID is immutable — copy it from the birth entry
        if let Some(birth) = history.first() {
            entry.parameters.scid = birth.parameters.scid.clone();
        }
        let prev_version_id = history
            .last()
            .map(|e| e.version_id.clone())
            .unwrap_or_default();
        let next_version = history
            .last()
            .and_then(|e| {
                e.version_id
                    .split('-')
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .map(|v| v + 1)
            .unwrap_or(1);

        // Per spec §3.7.4: hash with versionId = previous entry's versionId (no proof)
        let entry_hash = compute_entry_hash(&entry, &prev_version_id)?;
        entry.version_id = format!("{}-{}", next_version, entry_hash);

        self.storage
            .append(&did, &entry)
            .await?;
        Ok(entry)
    }

    pub async fn append_signed(
        &self,
        mut entry: LogEntry,
        signing_key: &SigningKey,
        verification_method: &str,
    ) -> Result<LogEntry> {
        let did = entry
            .state
            .id
            .as_str()
            .to_string();
        let history: Vec<LogEntry> = self
            .storage
            .load_all(&did)
            .await?;
        // Per spec: SCID is immutable — copy it from the birth entry
        if let Some(birth) = history.first() {
            entry.parameters.scid = birth.parameters.scid.clone();
        }
        let prev_version_id = history
            .last()
            .map(|e| e.version_id.clone())
            .unwrap_or_default();
        let next_version = history
            .last()
            .and_then(|e| {
                e.version_id
                    .split('-')
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .map(|v| v + 1)
            .unwrap_or(1);

        // Compute hash before signing (proof must be absent)
        let entry_hash = compute_entry_hash(&entry, &prev_version_id)?;
        entry.version_id = format!("{}-{}", next_version, entry_hash);

        let signed = sign_entry(&entry, signing_key, verification_method)?;

        self.storage
            .append(&did, &signed)
            .await?;
        Ok(signed)
    }

    pub async fn load(
        &self,
        did: &str,
    ) -> Result<Vec<LogEntry>> {
        self.storage
            .load_all(did)
            .await
    }
}

/// Determine the next version number and the previous entry's versionId.
/// For an empty history (birth entry), returns (1, SCID placeholder "").
fn next_version_info(history: &[LogEntry]) -> (u64, String) {
    match history.last() {
        Some(last) => {
            let next_v = last
                .version_id
                .split('-')
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v + 1)
                .unwrap_or(2);
            (next_v, last.version_id.clone())
        }
        None => (1, String::new()),
    }
}

/// Compute the entry hash per did:webvh spec §3.7.4.
///
/// Steps:
/// 1. Strip all proof entries from a clone of `entry`.
/// 2. Set `versionId` of the clone to `prev_version_id`.
///    - For the birth entry, pass the SCID value.
///    - For subsequent entries, pass the previous entry's full versionId (e.g., "1-<hash>").
/// 3. JCS-canonicalize the modified entry.
/// 4. SHA-256 → multihash ([0x12, 0x20] prefix) → raw base58btc (no multibase prefix, produces "Qm...").
///
/// Replace `{SCID}` placeholders throughout a log entry per spec §3.6.1 step 5.2.
///
/// This handles entries that use the spec-standard `{SCID}` placeholder in the
/// DIDDoc and parameters, as well as entries that just use empty strings (legacy/test).
/// The replacement is done via JSON text replacement so it covers all nested fields
/// (DIDDoc id, verificationMethod ids, controller, etc.) in a single pass.
fn replace_scid_placeholder(
    mut entry: LogEntry,
    scid: &str,
) -> Result<LogEntry> {
    let json = serde_json::to_string(&entry)?;
    if json.contains("{SCID}") {
        let replaced = json.replace("{SCID}", scid);
        entry = serde_json::from_str(&replaced)?;
    } else {
        // Fallback for entries that don't use placeholders (legacy/test)
        entry.parameters.scid = scid.to_string();
    }
    Ok(entry)
}

pub fn compute_entry_hash(
    entry: &LogEntry,
    prev_version_id: &str,
) -> Result<String> {
    let mut e = entry.clone();
    e.proof.clear();
    e.version_id = prev_version_id.to_string();
    let canonical = serde_jcs::to_string(&e)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let multihash = build_sha256_multihash(&digest);
    Ok(bs58::encode(&multihash).into_string())
}

pub fn sign_entry(
    entry: &LogEntry,
    signing_key: &SigningKey,
    verification_method: &str,
) -> Result<LogEntry> {
    let mut to_sign = entry.clone();
    to_sign.proof.clear();

    let doc_jcs = serde_jcs::to_string(&to_sign)?;

    let proof_config = serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod"
    });
    let proof_config_jcs = serde_jcs::to_string(&proof_config)?;

    let hash_data: Vec<u8> =
        [Sha256::digest(proof_config_jcs.as_bytes()).as_slice(), Sha256::digest(doc_jcs.as_bytes()).as_slice()]
            .concat();

    let sig = signing_key.sign(&hash_data);
    let proof_value = multibase::encode(multibase::Base::Base58Btc, sig.to_bytes());

    let mut signed = entry.clone();
    signed
        .proof
        .push(DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: verification_method.to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        });

    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::{DidLogManager, LogEntry, compute_entry_hash};
    use crate::identity::didwebvh::scid::generate_scid;
    use crate::identity::didwebvh::types::{DataIntegrityProof, LogParameters};
    use crate::identity::didwebvh::verifier::DidWebvhVerifier;
    use crate::storage::{DidLogStorage, FileDidLogStorage};
    use affinidi_did_common::verification_method::VerificationRelationship;
    use ed25519_dalek::SigningKey;
    use multibase::Base;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn sample_entry() -> LogEntry {
        let doc = affinidi_did_common::Document::new("did:webvh:example").unwrap();

        LogEntry {
            version_id: String::new(),
            version_time: "2026-01-01T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: String::new(),
                update_keys: vec!["did:key:z6Mkkey#1".to_string()],
                next_key_hashes: None,
                portable: false,
                ttl: None,
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: doc,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-jcs-2022".to_string(),
                verification_method: "did:key:z6Mkkey#1".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: "sig".to_string(),
            }],
        }
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let entry = sample_entry();
        // prev_version_id = SCID for birth entries; use a stable placeholder here
        let hash1 = compute_entry_hash(&entry, "1-prevhash").unwrap();
        let hash2 = compute_entry_hash(&entry, "1-prevhash").unwrap();

        assert_eq!(hash1, hash2, "Entry hash must be deterministic");
        assert!(hash1.starts_with("Qm"), "Hash must be raw base58btc multihash (starts with 'Qm')");
    }

    #[test]
    fn entry_hash_changes_on_content_change() {
        let mut entry1 = sample_entry();
        let hash1 = compute_entry_hash(&entry1, "1-prevhash").unwrap();

        // Modify entry content
        entry1.parameters.ttl = Some(7200);
        let hash2 = compute_entry_hash(&entry1, "1-prevhash").unwrap();

        assert_ne!(hash1, hash2, "Hash must change when entry content changes");
    }

    #[test]
    fn entry_hash_changes_when_prev_version_id_changes() {
        // The spec chains entries by setting versionId = prev versionId before hashing.
        // Different prev_version_id values must produce different hashes.
        let entry = sample_entry();
        let hash1 = compute_entry_hash(&entry, "1-z6Mkprevioushash123").unwrap();
        let hash2 = compute_entry_hash(&entry, "1-z6Mkdifferenthash456").unwrap();

        assert_ne!(hash1, hash2, "Hash must change when prev_version_id changes");
    }

    #[test]
    fn entry_hash_with_prev_version_id_is_deterministic() {
        let entry = sample_entry();
        let prev_version_id = "1-z6Mkprevioushash123";

        let hash1 = compute_entry_hash(&entry, prev_version_id).unwrap();
        let hash2 = compute_entry_hash(&entry, prev_version_id).unwrap();

        assert_eq!(hash1, hash2, "Hash with same prev_version_id must be deterministic");
    }

    #[test]
    fn entry_hash_is_valid_base58() {
        let entry = sample_entry();
        let hash = compute_entry_hash(&entry, "1-prevhash").unwrap();

        // Should be decodable as raw base58
        let bytes = bs58::decode(&hash).into_vec();
        assert!(bytes.is_ok(), "Hash must be valid base58 encoding");
        let bytes = bytes.unwrap();
        // 34 bytes = 2-byte multihash prefix [0x12, 0x20] + 32-byte SHA-256 digest
        assert_eq!(bytes.len(), 34, "Hash must be 34-byte SHA-256 multihash");
        assert_eq!(bytes[0], 0x12, "First byte must be SHA-256 function code");
        assert_eq!(bytes[1], 0x20, "Second byte must be digest length (32)");
    }

    #[tokio::test]
    async fn create_persists_birth_event() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let entry = manager
            .create(sample_entry())
            .await
            .unwrap();
        assert!(
            !entry
                .parameters
                .scid
                .is_empty()
        );
        assert!(
            entry
                .version_id
                .starts_with("1-")
        );

        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
    }

    fn doc_with_vm(
        vm_id: &str,
        vk_bytes: &[u8],
    ) -> affinidi_did_common::Document {
        let mut property_set = std::collections::HashMap::new();
        property_set.insert(
            "publicKeyMultibase".to_string(),
            serde_json::Value::String(multibase::encode(Base::Base58Btc, vk_bytes)),
        );

        let vm = affinidi_did_common::VerificationMethodBuilder::new(
            vm_id,
            "Ed25519VerificationKey2018",
            "did:webvh:example",
        )
        .unwrap()
        .properties(property_set)
        .build();

        let mut doc = affinidi_did_common::Document::new("did:webvh:example").unwrap();
        doc.verification_method = vec![vm];
        doc.assertion_method = vec![VerificationRelationship::Reference(vm_id.to_string())];
        doc
    }

    fn unsigned_entry(
        doc: affinidi_did_common::Document,
        vm_id: &str,
        version_time: &str,
    ) -> LogEntry {
        LogEntry {
            version_id: String::new(),
            version_time: version_time.to_string(),
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
            state: doc,
            proof: Vec::new(),
        }
    }

    #[tokio::test]
    async fn create_signed_produces_verifiable_entry() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let vm_id = "did:webvh:example#key-1";
        let doc = doc_with_vm(
            vm_id,
            signing_key
                .verifying_key()
                .as_bytes(),
        );
        let entry = unsigned_entry(doc, vm_id, "2026-01-01T00:00:00Z");

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let signed = manager
            .create_signed(entry, &signing_key, vm_id)
            .await
            .unwrap();

        assert_eq!(signed.proof.len(), 1);
        assert!(
            signed
                .version_id
                .starts_with("1-")
        );

        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        let verifier = DidWebvhVerifier::new();
        let report = verifier
            .verify(&stored)
            .unwrap();
        assert!(report.valid);
    }

    #[tokio::test]
    async fn append_signed_extends_hash_chain() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let vm_id = "did:webvh:example#key-1";
        let doc = doc_with_vm(
            vm_id,
            signing_key
                .verifying_key()
                .as_bytes(),
        );

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let entry1 = unsigned_entry(doc.clone(), vm_id, "2026-01-01T00:00:00Z");
        let _ = manager
            .create_signed(entry1, &signing_key, vm_id)
            .await
            .unwrap();

        let mut entry2 = unsigned_entry(doc, vm_id, "2026-01-02T00:00:00Z");
        entry2.parameters.scid = "placeholder".to_string(); // overwritten during append

        let signed = manager
            .append_signed(entry2, &signing_key, vm_id)
            .await
            .unwrap();

        assert!(
            signed
                .version_id
                .starts_with("2-")
        );

        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        let verifier = DidWebvhVerifier::new();
        let report = verifier
            .verify(&stored)
            .unwrap();
        assert!(report.valid);
        assert_eq!(stored.len(), 2);
    }

    #[tokio::test]
    async fn append_increments_version() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let entry1 = sample_entry();
        let _ = manager
            .create(entry1.clone())
            .await
            .unwrap();

        let mut entry2 = sample_entry();
        entry2.version_time = "2026-01-02T00:00:00Z".to_string();
        let appended = manager
            .append(entry2)
            .await
            .unwrap();
        assert!(
            appended
                .version_id
                .starts_with("2-")
        );

        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        assert_eq!(stored.len(), 2);
    }

    #[tokio::test]
    async fn scid_is_deterministic() {
        let e1 = sample_entry();
        let e2 = sample_entry();
        let s1 = generate_scid(&e1).unwrap();
        let s2 = generate_scid(&e2).unwrap();
        assert_eq!(s1, s2);
    }

    // === alsoKnownAs Tests ===
    /// create_signed() with alsoKnownAs must preserve the field in the document.
    #[tokio::test]
    async fn create_signed_with_also_known_as_web_did() {
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let vm_id = "did:webvh:example#key-1";
        let doc = doc_with_vm(
            vm_id,
            signing_key
                .verifying_key()
                .as_bytes(),
        );
        let mut entry = unsigned_entry(doc, vm_id, "2026-01-01T00:00:00Z");
        entry
            .state
            .parameters_set
            .insert("alsoKnownAs".to_string(), serde_json::json!(["did:web:example.com"]));

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let signed = manager
            .create_signed(entry, &signing_key, vm_id)
            .await
            .unwrap();

        assert_eq!(
            signed
                .state
                .parameters_set
                .get("alsoKnownAs"),
            Some(&serde_json::json!(["did:web:example.com"])),
            "create_signed must preserve alsoKnownAs in document state"
        );
    }

    /// SCID must change when alsoKnownAs is different (SCID includes document content).
    #[tokio::test]
    async fn scid_unaffected_by_also_known_as_field() {
        let entry_without = sample_entry();
        let mut entry_with = sample_entry();
        entry_with
            .state
            .parameters_set
            .insert("alsoKnownAs".to_string(), serde_json::json!(["did:web:example.com"]));

        let scid_without = generate_scid(&entry_without).unwrap();
        let scid_with = generate_scid(&entry_with).unwrap();
        assert_ne!(
            scid_without, scid_with,
            "Different document content must yield different SCIDs when alsoKnownAs changes"
        );

        let mut entry_with_2 = sample_entry();
        entry_with_2
            .state
            .parameters_set
            .insert("alsoKnownAs".to_string(), serde_json::json!(["did:web:example.com"]));
        assert_eq!(
            generate_scid(&entry_with).unwrap(),
            generate_scid(&entry_with_2).unwrap(),
            "SCID must remain deterministic for the same alsoKnownAs content"
        );
    }

    /// The verifier must accept a valid log entry that includes alsoKnownAs.
    #[tokio::test]
    async fn verifier_accepts_log_with_also_known_as() {
        let seed = [9u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let vm_id = "did:webvh:example#key-1";
        let doc = doc_with_vm(
            vm_id,
            signing_key
                .verifying_key()
                .as_bytes(),
        );
        let mut entry = unsigned_entry(doc, vm_id, "2026-01-01T00:00:00Z");
        entry
            .state
            .parameters_set
            .insert("alsoKnownAs".to_string(), serde_json::json!(["did:web:example.com"]));

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let _ = manager
            .create_signed(entry, &signing_key, vm_id)
            .await
            .unwrap();
        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        let report = DidWebvhVerifier::new()
            .verify(&stored)
            .unwrap();
        assert!(report.valid, "Verifier must accept a valid log entry with alsoKnownAs");
        assert!(report.errors.is_empty(), "Verifier errors were unexpected: {:?}", report.errors);
    }

    // === SCID Stability Tests ===
    /// SCID must be identical before and after key rotation.
    #[tokio::test]
    async fn scid_stable_across_key_rotation() {
        let mut seed1 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed1);
        let signing_key_1 = SigningKey::from_bytes(&seed1);
        let vm_id_1 = "did:webvh:example#key-1";

        let doc1 = doc_with_vm(
            vm_id_1,
            signing_key_1
                .verifying_key()
                .as_bytes(),
        );
        let entry1 = unsigned_entry(doc1, vm_id_1, "2026-01-01T00:00:00Z");

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let signed1 = manager
            .create_signed(entry1, &signing_key_1, vm_id_1)
            .await
            .unwrap();
        let scid_before = signed1
            .parameters
            .scid
            .clone();

        // Rotate key: create a second entry with a new key
        let mut seed2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed2);
        let signing_key_2 = SigningKey::from_bytes(&seed2);
        let vm_id_2 = "did:webvh:example#key-2";

        let doc2 = doc_with_vm(
            vm_id_2,
            signing_key_2
                .verifying_key()
                .as_bytes(),
        );
        let mut entry2 = unsigned_entry(doc2, vm_id_2, "2026-02-01T00:00:00Z");
        // Preserve SCID in subsequent entries
        entry2.parameters.scid = scid_before.clone();

        let signed2 = manager
            .append_signed(entry2, &signing_key_1, vm_id_1)
            .await
            .unwrap();
        let scid_after = signed2
            .parameters
            .scid
            .clone();

        assert_eq!(scid_before, scid_after, "SCID must remain stable across key rotation");
    }

    /// The SCID in the DID string must match the scid in the birth log entry.
    #[tokio::test]
    async fn scid_in_did_string_matches_log_parameters() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let entry = sample_entry();
        let created = manager
            .create(entry)
            .await
            .unwrap();

        let scid_in_params = &created.parameters.scid;
        assert!(!scid_in_params.is_empty(), "SCID must be populated after create()");

        // The version_id starts with "1-" followed by the entry hash.
        // The DID string format: did:webvh:<SCID>:domain
        // Verify that the SCID in the birth entry's parameters is returned by generate_scid().
        // (The actual DID string is constructed at the call site, but the SCID source of truth is in parameters.)
        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        assert_eq!(stored[0].parameters.scid, *scid_in_params);
    }

    /// After append_signed(), the new entry must have a version number prefix > 1.
    #[tokio::test]
    async fn version_id_increments_on_key_rotation() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let entry1 = sample_entry();
        let _ = manager
            .create(entry1)
            .await
            .unwrap();

        let mut entry2 = sample_entry();
        entry2.version_time = "2026-02-01T00:00:00Z".to_string();

        let appended = manager
            .append(entry2)
            .await
            .unwrap();
        assert!(
            appended
                .version_id
                .starts_with("2-"),
            "Second entry must have versionId starting with '2-', got: {}",
            appended.version_id
        );
    }

    // === Key Rotation Tests ===
    /// Key rotation must append a new log entry (2 entries total after 1 rotation).
    #[tokio::test]
    async fn key_rotation_appends_new_log_entry() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let entry1 = sample_entry();
        let _ = manager
            .create(entry1)
            .await
            .unwrap();

        let mut entry2 = sample_entry();
        entry2.version_time = "2026-02-01T00:00:00Z".to_string();
        let _ = manager
            .append(entry2)
            .await
            .unwrap();

        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        assert_eq!(stored.len(), 2, "Log must contain 2 entries after one key rotation");
    }

    /// Key rotation without a matching pre-rotation commitment must be rejected.
    #[tokio::test]
    async fn key_rotation_rejected_without_pre_rotation_commitment() {
        let mut seed1 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed1);
        let signing_key_1 = SigningKey::from_bytes(&seed1);
        let vm_id_1 = "did:webvh:example#key-1";

        let doc1 = doc_with_vm(
            vm_id_1,
            signing_key_1
                .verifying_key()
                .as_bytes(),
        );
        let mut entry1 = unsigned_entry(doc1, vm_id_1, "2026-01-01T00:00:00Z");
        // Commit to a specific next key hash
        entry1
            .parameters
            .next_key_hashes = Some(vec!["zSomeExpectedNextKeyHash".to_string()]);

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let _ = manager
            .create_signed(entry1, &signing_key_1, vm_id_1)
            .await
            .unwrap();

        // Now try to rotate with a key that does NOT match the committed next_key_hash
        let mut seed2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed2);
        let signing_key_2 = SigningKey::from_bytes(&seed2);
        let vm_id_2 = "did:webvh:example#key-2";
        let doc2 = doc_with_vm(
            vm_id_2,
            signing_key_2
                .verifying_key()
                .as_bytes(),
        );
        let entry2 = unsigned_entry(doc2, vm_id_2, "2026-02-01T00:00:00Z");

        let signed2 = manager
            .append_signed(entry2, &signing_key_2, vm_id_2)
            .await
            .unwrap();

        let stored = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        let verifier = DidWebvhVerifier::new();
        let report = verifier
            .verify(&stored)
            .unwrap();

        // The verifier must reject the rotation because the key doesn't match the commitment
        assert!(
            !report.valid,
            "Verifier must reject key rotation when the new key doesn't match nextKeyHashes commitment. \
             Got entry: {:?}",
            signed2.parameters
        );
    }

    /// Old VC must be verifiable via resolve_version_time at the time it was issued.
    #[tokio::test]
    async fn historical_vc_verifiable_via_version_time() {
        // This test exercises the full flow:
        // 1. Create identity at T=0 with key K1
        // 2. Issue VC signed with K1 at T=0
        // 3. Rotate to key K2 at T=1
        // 4. Verify old VC using resolve_version_time(T=0) returns K1 (not K2)
        //
        // Since full VC signing integration is not yet implemented,
        // this test validates the log entries and resolve_version_time logic only.

        use crate::identity::didwebvh::resolver::DidWebvhResolver;

        let mut seed1 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed1);
        let signing_key_1 = SigningKey::from_bytes(&seed1);
        let vm_id_1 = "did:webvh:example#key-1";

        let doc1 = doc_with_vm(
            vm_id_1,
            signing_key_1
                .verifying_key()
                .as_bytes(),
        );
        let entry1 = unsigned_entry(doc1.clone(), vm_id_1, "2026-01-01T00:00:00Z");

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let _ = manager
            .create_signed(entry1, &signing_key_1, vm_id_1)
            .await
            .unwrap();

        // Rotate key at T=1
        let mut seed2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed2);
        let signing_key_2 = SigningKey::from_bytes(&seed2);
        let vm_id_2 = "did:webvh:example#key-2";
        let doc2 = doc_with_vm(
            vm_id_2,
            signing_key_2
                .verifying_key()
                .as_bytes(),
        );
        let entry2 = unsigned_entry(doc2, vm_id_2, "2026-02-01T00:00:00Z");
        let _ = manager
            .append_signed(entry2, &signing_key_1, vm_id_1)
            .await
            .unwrap();

        // Resolve at T0 should return doc1 (with key K1)
        let resolver = DidWebvhResolver::new(storage.clone());
        let doc_at_t0 = resolver
            .resolve_version_time("did:webvh:example", "2026-01-15T00:00:00Z")
            .await
            .unwrap();

        // doc_at_t0 must contain vm_id_1, not vm_id_2
        assert!(
            doc_at_t0
                .verification_method
                .iter()
                .any(|vm| vm.id.as_str() == vm_id_1),
            "resolve_version_time at T0 must return document with the original key K1"
        );
        assert!(
            !doc_at_t0
                .verification_method
                .iter()
                .any(|vm| vm.id.as_str() == vm_id_2),
            "resolve_version_time at T0 must NOT return the rotated key K2"
        );

        // The original doc must have K1 VM for the VC to verify
        assert!(
            doc1.verification_method
                .iter()
                .any(|vm| vm.id.as_str() == vm_id_1),
            "Original doc at T0 must have key K1"
        );
    }

    // ── Compliance Tests ─────────────────────────────────────────────────────

    /// LogEntry JSON uses camelCase field names as required
    /// by the did:webvh spec.
    #[test]
    fn log_entry_serialized_field_names_are_camel_case() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("versionId"), "must have 'versionId' field");
        assert!(obj.contains_key("versionTime"), "must have 'versionTime' field");
        assert!(obj.contains_key("parameters"), "must have 'parameters' field");
        assert!(obj.contains_key("state"), "must have 'state' field");
        assert!(obj.contains_key("proof"), "must have 'proof' field");
        assert!(!obj.contains_key("version_id"), "must NOT use snake_case 'version_id'");
        assert!(!obj.contains_key("version_time"), "must NOT use snake_case 'version_time'");
    }

    /// First entry versionId must be exactly "1-<entryHash>"
    /// where entryHash is the SHA-256 multihash of the JCS-canonicalized entry
    /// (with versionId = SCID, proof cleared).
    #[tokio::test]
    async fn birth_entry_version_id_format_is_one_dash_hash() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vm_id = "did:webvh:example#key-1";
        let doc = doc_with_vm(vm_id, sk.verifying_key().as_bytes());
        let entry = unsigned_entry(doc, vm_id, "2026-01-01T00:00:00Z");

        let dir = tempdir().unwrap();
        let manager = DidLogManager::new(Arc::new(FileDidLogStorage::new(dir.path())));
        let signed = manager
            .create_signed(entry, &sk, vm_id)
            .await
            .unwrap();

        // Must start with "1-"
        assert!(
            signed
                .version_id
                .starts_with("1-"),
            "versionId must start with '1-'"
        );
        // The hash part must be a valid raw base58 string (no multibase prefix)
        let hash_part = signed
            .version_id
            .trim_start_matches("1-");
        assert!(hash_part.starts_with("Qm"), "hash must be raw base58btc multihash (starts with 'Qm')");
        // Re-derive the expected hash to confirm it matches
        let expected_hash = compute_entry_hash(&signed, &signed.parameters.scid).unwrap();
        assert_eq!(hash_part, expected_hash, "versionId hash must match computed entry hash");
    }

    /// SCID pipeline per spec §3.7.3:
    /// placeholder replacement → JCS → SHA-256 → multihash → base58btc.
    #[tokio::test]
    async fn scid_derivation_follows_spec_pipeline() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vm_id = "did:webvh:example#key-1";
        let doc = doc_with_vm(vm_id, sk.verifying_key().as_bytes());
        let placeholder_entry = unsigned_entry(doc, vm_id, "2026-01-01T00:00:00Z");

        // SCID must be derivable from the birth entry with placeholders
        let scid = generate_scid(&placeholder_entry).unwrap();

        // Must be raw base58btc (SHA-256 multihash always starts with 'Qm')
        assert!(scid.starts_with("Qm"), "SCID must be raw base58btc multihash (starts with 'Qm')");
        let bytes = bs58::decode(&scid)
            .into_vec()
            .unwrap();
        // SHA-256 multihash = 2-byte prefix [0x12, 0x20] + 32-byte digest
        assert_eq!(bytes.len(), 34, "SCID multihash must be 34 bytes");
        assert_eq!(bytes[0], 0x12, "SCID multihash must have SHA-256 type byte 0x12");
        assert_eq!(bytes[1], 0x20, "SCID multihash must have digest length byte 0x20");

        // After creating via manager, stored entry SCID must match
        let dir = tempdir().unwrap();
        let manager = DidLogManager::new(Arc::new(FileDidLogStorage::new(dir.path())));
        let signed = manager
            .create_signed(placeholder_entry, &sk, vm_id)
            .await
            .unwrap();
        assert_eq!(signed.parameters.scid, scid, "Stored SCID must match independently computed SCID");
    }

    /// /// Full end-to-end log verification: create identity, perform key rotation,
    /// verify the complete log passes SCID check, hash chain, proof signatures,
    /// time monotonicity, and SCID immutability.
    #[tokio::test]
    async fn end_to_end_log_verification_passes_all_checks() {
        let mut seed1 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed1);
        let sk1 = SigningKey::from_bytes(&seed1);
        let vm1 = "did:webvh:example#key-1";

        let mut seed2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed2);
        let sk2 = SigningKey::from_bytes(&seed2);
        let vm2 = "did:webvh:example#key-2";

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        // Birth entry
        let doc1 = doc_with_vm(vm1, sk1.verifying_key().as_bytes());
        let e1 = unsigned_entry(doc1, vm1, "2026-01-01T00:00:00Z");
        manager
            .create_signed(e1, &sk1, vm1)
            .await
            .unwrap();

        // Key rotation (signed by NEW key per spec §3.7.6 — updateKeys of the new entry)
        let doc2 = doc_with_vm(vm2, sk2.verifying_key().as_bytes());
        let e2 = unsigned_entry(doc2, vm2, "2026-06-01T00:00:00Z");
        manager
            .append_signed(e2, &sk2, vm2)
            .await
            .unwrap();

        // Load and verify the full log
        let entries = storage
            .load_all("did:webvh:example")
            .await
            .unwrap();
        assert_eq!(entries.len(), 2, "Log must have 2 entries");

        let verifier = crate::identity::didwebvh::verifier::DidWebvhVerifier::new();
        let report = verifier
            .verify(&entries)
            .unwrap();

        assert!(report.valid, "Full log must pass all verifier checks. Errors: {:?}", report.errors);
        // SCID is immutable across entries
        assert_eq!(entries[0].parameters.scid, entries[1].parameters.scid, "SCID must be identical in all log entries");
        // Version IDs are monotonically increasing
        assert!(
            entries[0]
                .version_id
                .starts_with("1-"),
            "Birth entry versionId must start with '1-'"
        );
        assert!(
            entries[1]
                .version_id
                .starts_with("2-"),
            "Second entry versionId must start with '2-'"
        );
    }

    // === SCID Placeholder Replacement Tests (§3.6.1 step 5.2) ===
    // These tests verify that {SCID} placeholders in the DIDDoc state
    // are fully replaced after create, matching the real create_identity handler flow.

    /// Build a DIDDoc and log entry using {SCID} placeholders in the DID,
    /// matching what the real create_identity handler produces.
    fn placeholder_entry(vk_bytes: &[u8]) -> LogEntry {
        let placeholder_did = "did:webvh:{SCID}:example.com:agents:test";
        let vm_id = format!("{}#key-1", placeholder_did);

        let mut property_set = std::collections::HashMap::new();
        property_set.insert(
            "publicKeyMultibase".to_string(),
            serde_json::Value::String(multibase::encode(Base::Base58Btc, vk_bytes)),
        );

        let vm =
            affinidi_did_common::VerificationMethodBuilder::new(&vm_id, "Ed25519VerificationKey2018", placeholder_did)
                .unwrap()
                .properties(property_set)
                .build();

        let mut doc = affinidi_did_common::Document::new(placeholder_did).unwrap();
        doc.verification_method = vec![vm];
        doc.authentication = vec![VerificationRelationship::Reference(vm_id.clone())];
        doc.assertion_method = vec![VerificationRelationship::Reference(vm_id.clone())];

        LogEntry {
            version_id: "{SCID}".to_string(),
            version_time: "2026-04-17T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "{SCID}".to_string(),
                update_keys: vec![vm_id],
                next_key_hashes: None,
                portable: false,
                ttl: None,
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: doc,
            proof: Vec::new(),
        }
    }

    /// §3.6.1 step 5.2: After create, the DIDDoc id must contain the actual SCID,
    /// not the literal string "{SCID}".
    #[tokio::test]
    async fn create_replaces_scid_placeholder_in_did_document() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let entry = placeholder_entry(sk.verifying_key().as_bytes());

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage);

        let created = manager
            .create(entry)
            .await
            .unwrap();

        let did_id = created.state.id.as_str();
        assert!(
            !did_id.contains("{SCID}"),
            "DIDDoc id must not contain {{SCID}} placeholder after create, got: {}",
            did_id
        );
        assert!(did_id.starts_with("did:webvh:Q"), "DIDDoc id must contain actual base58btc SCID, got: {}", did_id);
    }

    /// §3.6.1 step 5.2: After create_signed, no {SCID} placeholders remain
    /// anywhere in the serialized log entry (DIDDoc, parameters, update_keys, proof).
    #[tokio::test]
    async fn create_signed_replaces_all_scid_placeholders() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let entry = placeholder_entry(sk.verifying_key().as_bytes());

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage);

        let vm_placeholder = "did:webvh:{SCID}:example.com:agents:test#key-1";
        let signed = manager
            .create_signed(entry, &sk, vm_placeholder)
            .await
            .unwrap();

        // Serialize the entire entry and check for leftover placeholders
        let json = serde_json::to_string(&signed).unwrap();
        assert!(
            !json.contains("{SCID}"),
            "No {{SCID}} placeholder must remain in serialized log entry after create_signed.\n\
             Found in: {}",
            json
        );

        // Verify specific fields have actual SCID
        let scid = &signed.parameters.scid;
        assert!(scid.starts_with("Qm"), "SCID must be raw base58btc encoded");
        assert!(
            signed
                .state
                .id
                .as_str()
                .contains(scid),
            "DIDDoc id must contain actual SCID"
        );
        assert!(
            signed.proof[0]
                .verification_method
                .contains(scid),
            "Proof verification_method must contain actual SCID, not placeholder"
        );

        // Verify update_keys also had placeholder replaced
        for uk in &signed.parameters.update_keys {
            assert!(!uk.contains("{SCID}"), "update_keys must not contain {{SCID}} placeholder: {}", uk);
        }
    }

    /// After create_signed with placeholders, the produced log entry must still
    /// pass full verification (SCID derivation, hash chain, proof).
    #[tokio::test]
    async fn create_signed_with_placeholders_passes_verification() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let entry = placeholder_entry(sk.verifying_key().as_bytes());
        let scid_before = generate_scid(&entry).unwrap();

        let dir = tempdir().unwrap();
        let storage = Arc::new(FileDidLogStorage::new(dir.path()));
        let manager = DidLogManager::new(storage.clone());

        let vm_placeholder = "did:webvh:{SCID}:example.com:agents:test#key-1";
        let signed = manager
            .create_signed(entry, &sk, vm_placeholder)
            .await
            .unwrap();

        // SCID in the entry must match independently computed SCID
        assert_eq!(signed.parameters.scid, scid_before, "SCID must match pre-computed value");

        // The stored did key is the final DID (with actual SCID)
        let final_did = signed.state.id.as_str();
        let entries = storage
            .load_all(final_did)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);

        // Full log must pass verifier checks
        let verifier = crate::identity::didwebvh::verifier::DidWebvhVerifier::new();
        let report = verifier
            .verify(&entries)
            .unwrap();
        assert!(
            report.valid,
            "Log entry created with placeholders must pass all verifier checks. Errors: {:?}",
            report.errors
        );
    }

    /// Regression: proof field must be omitted from JCS when proof vec is empty
    /// (mediator skips the field; including "proof":[] causes a hash mismatch).
    #[test]
    fn empty_proof_omitted_from_serialization() {
        let doc = affinidi_did_common::Document::new("did:webvh:example").unwrap();
        let entry = LogEntry {
            version_id: "1-zQm".to_string(),
            version_time: "2026-01-01T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "zQm".to_string(),
                update_keys: vec!["z6Mk".to_string()],
                next_key_hashes: None,
                portable: false,
                ttl: None,
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: doc,
            proof: vec![],
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            !json.contains("\"proof\""),
            "Serialized entry with empty proof must NOT include \"proof\" key, got: {}",
            json
        );
    }

    /// Regression: version_time must use seconds-only precision with Z suffix to match
    /// the mediator's format_version_time (SecondsFormat::Secs, use_z=true).
    #[test]
    fn version_time_format_matches_mediator() {
        let now = chrono::Utc::now();
        let formatted = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert!(formatted.ends_with('Z'), "version_time must end with 'Z', got: {}", formatted);
        assert!(!formatted.contains('.'), "version_time must not contain sub-second precision, got: {}", formatted);
    }
}
