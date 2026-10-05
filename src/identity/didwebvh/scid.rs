#![allow(dead_code)]

use anyhow::Result;
use sha2::{Digest, Sha256};

use super::types::LogEntry;

/// Generate SCID from a preliminary log entry (did:webvh spec §3.7.3)
///
/// Algorithm:
/// 1. Replace `parameters.scid` with the literal "{SCID}" placeholder
/// 2. Replace `versionId` with the literal "{SCID}" placeholder
/// 3. Remove any existing `proof` entries
/// 4. Canonicalize the entry using JCS (RFC 8785)
/// 5. Compute SHA-256 digest
/// 6. Prepend multihash prefix [0x12, 0x20] (SHA-256 function code + digest length)
/// 7. Base58btc-encode the 34-byte multihash (raw, no multibase prefix — produces "Qm...")
pub fn generate_scid(preliminary_entry: &LogEntry) -> Result<String> {
    let mut entry = preliminary_entry.clone();
    // Steps 1-3: normalise placeholders and remove proof
    entry.parameters.scid = "{SCID}".to_string();
    entry.version_id = "{SCID}".to_string();
    entry.proof.clear();

    // Step 4: Canonicalize via JSON Canonicalization Scheme (RFC 8785)
    let canonical = serde_jcs::to_string(&entry)?;

    // Steps 5-7: SHA-256 multihash, then raw base58btc (no multibase prefix)
    let digest = Sha256::digest(canonical.as_bytes());
    let multihash = build_sha256_multihash(&digest);
    Ok(bs58::encode(&multihash).into_string())
}

/// Build a SHA-256 multihash: [0x12, 0x20] ++ digest (34 bytes total)
/// 0x12 = SHA-256 function code, 0x20 = 32-byte digest length
pub(crate) fn build_sha256_multihash(digest: &[u8]) -> Vec<u8> {
    let mut multihash = Vec::with_capacity(2 + digest.len());
    multihash.push(0x12); // SHA-256 function code
    multihash.push(0x20); // digest size = 32
    multihash.extend_from_slice(digest);
    multihash
}

#[cfg(test)]
mod tests {
    use super::{LogEntry, generate_scid};
    use crate::identity::didwebvh::types::LogParameters;
    use affinidi_did_common::verification_method::VerificationRelationship;
    use chrono::Utc;
    use std::collections::HashMap;

    fn create_test_entry() -> LogEntry {
        let mut props = HashMap::new();
        props.insert(
            "publicKeyMultibase".to_string(),
            serde_json::json!("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );

        let vm = affinidi_did_common::VerificationMethodBuilder::new(
            "did:webvh:{SCID}:example.com#key-1",
            "JsonWebKey2020",
            "did:webvh:{SCID}:example.com",
        )
        .unwrap()
        .properties(props)
        .build();

        let mut doc = affinidi_did_common::Document::new("did:webvh:{SCID}:example.com").unwrap();
        doc.verification_method = vec![vm];
        doc.authentication =
            vec![VerificationRelationship::Reference("did:webvh:{SCID}:example.com#key-1".to_string())];

        LogEntry {
            version_id: "1-abc123".to_string(),
            version_time: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "{SCID}".to_string(),
                update_keys: vec!["did:webvh:{SCID}:example.com#key-1".to_string()],
                next_key_hashes: None,
                portable: true,
                ttl: Some(3600),
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: doc,
            proof: vec![],
        }
    }

    #[test]
    fn generates_deterministic_scid() {
        let entry = create_test_entry();
        let scid1 = generate_scid(&entry).expect("Failed to generate SCID");
        let scid2 = generate_scid(&entry).expect("Failed to generate SCID");

        assert_eq!(scid1, scid2, "SCID generation must be deterministic");
        assert!(scid1.starts_with("Qm"), "SCID must be raw base58btc multihash (starts with 'Qm')");
        // Raw base58btc encoded 34-byte SHA-256 multihash: ~46 base58 chars
        assert!(scid1.len() >= 45 && scid1.len() <= 48, "SCID length unexpected: {}", scid1.len());
    }

    #[test]
    fn scid_changes_on_document_change() {
        let mut entry1 = create_test_entry();
        let scid1 = generate_scid(&entry1).expect("Failed to generate SCID");

        // Change document state via parameters_set
        entry1
            .state
            .parameters_set
            .insert("alsoKnownAs".to_string(), serde_json::json!(["https://alias.example"]));
        let scid2 = generate_scid(&entry1).expect("Failed to generate SCID");

        assert_ne!(scid1, scid2, "SCID must change when document changes");
    }

    #[test]
    fn scid_changes_on_parameters_change() {
        let mut entry1 = create_test_entry();
        let scid1 = generate_scid(&entry1).expect("Failed to generate SCID");

        entry1.parameters.ttl = Some(7200);
        let scid2 = generate_scid(&entry1).expect("Failed to generate SCID");

        assert_ne!(scid1, scid2, "SCID must change when parameters change");
    }

    #[test]
    fn scid_ignores_version_id_but_not_document_content() {
        let mut entry1 = create_test_entry();
        let scid1 = generate_scid(&entry1).expect("Failed to generate SCID");

        entry1.version_id = "99-different".to_string();
        let scid2 = generate_scid(&entry1).expect("Failed to generate SCID");

        assert_eq!(scid1, scid2, "SCID must not change when version_id changes because version_id is normalized");

        entry1.version_time = "2099-01-01T00:00:00Z".to_string();
        let scid3 = generate_scid(&entry1).expect("Failed to generate SCID");

        assert_ne!(
            scid1, scid3,
            "SCID must change when version_time changes because it is part of the canonicalized entry"
        );
    }

    #[test]
    fn scid_placeholder_is_normalized() {
        let entry = create_test_entry();
        let scid = generate_scid(&entry).expect("Failed to generate SCID");

        assert!(!scid.contains("{SCID}"), "Generated SCID must not contain placeholder");
        assert!(!scid.contains("SCID"), "Generated SCID must not contain 'SCID' text");
    }

    #[test]
    fn scid_is_valid_base58_multihash() {
        let entry = create_test_entry();
        let scid = generate_scid(&entry).expect("Failed to generate SCID");

        let bytes = bs58::decode(&scid).into_vec();
        assert!(bytes.is_ok(), "SCID must be valid base58 encoding");
        let bytes = bytes.unwrap();
        // 34 bytes = 2-byte multihash prefix [0x12, 0x20] + 32-byte SHA-256 digest
        assert_eq!(bytes.len(), 34, "SCID must encode 34-byte SHA-256 multihash");
        assert_eq!(bytes[0], 0x12, "First byte must be SHA-256 function code");
        assert_eq!(bytes[1], 0x20, "Second byte must be digest length (32)");
    }
}
