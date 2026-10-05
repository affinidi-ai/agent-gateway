#![allow(dead_code)]

use serde::{Deserialize, Serialize};

pub use affinidi_did_common::Document as DidDocument;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub version_id: String,
    pub version_time: String,
    pub parameters: LogParameters,
    pub state: DidDocument,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof: Vec<DataIntegrityProof>,
}

/// Parameters of one log entry. After the first entry only *changed*
/// parameters are present (did:webvh §3.7), so the required-in-birth fields
/// default on read and are not written back when empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogParameters {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scid: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub update_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_hashes: Option<Vec<String>>,
    #[serde(default)]
    pub portable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub deactivated: bool,
}

fn is_false(v: &bool) -> bool {
    !v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessConfig {
    #[serde(default)]
    pub threshold: Option<u8>,
    #[serde(default)]
    pub witnesses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String,
}

/// Cryptographic key pair for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Public key in JWK format
    pub public_key: serde_json::Value,

    /// Private key in JWK format (should be stored securely)
    pub private_key: serde_json::Value,

    /// Key type (e.g., "Ed25519", "secp256k1")
    #[serde(default = "default_key_type")]
    pub key_type: String,
}

fn default_key_type() -> String {
    "Ed25519".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    #[serde(default)]
    pub valid: bool,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// DID Resolution Metadata per did:webvh spec §3.6.2
///
/// Returned alongside the DID document to convey log-level metadata
/// that is not part of the document itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidResolutionMetadata {
    /// The versionId of the resolved entry ("N-<hash>")
    pub version_id: String,

    /// The versionTime of the resolved entry (RFC 3339)
    pub version_time: String,

    /// The timestamp of the birth (genesis) log entry
    pub created: String,

    /// The timestamp of the last log entry
    pub updated: String,

    /// The Self-Certifying Identifier
    pub scid: String,

    /// Whether the DID is portable
    pub portable: bool,

    /// Whether the DID has been deactivated
    pub deactivated: bool,

    /// Cache TTL in seconds (0 means no caching)
    pub ttl: u64,

    /// Witness configuration, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessConfig>,

    /// Watcher URLs, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchers: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::{DataIntegrityProof, LogEntry, LogParameters, VerificationReport, WitnessConfig};

    #[test]
    fn data_integrity_proof_serialization_roundtrip() {
        let proof = DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: "did:example:123#key-1".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "proofvalue123".to_string(),
        };

        let json = serde_json::to_string(&proof).expect("Failed to serialize");
        let deserialized: DataIntegrityProof = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.proof_type, proof.proof_type);
        assert_eq!(deserialized.cryptosuite, proof.cryptosuite);
        assert_eq!(deserialized.verification_method, proof.verification_method);
        assert_eq!(deserialized.proof_purpose, proof.proof_purpose);
        assert_eq!(deserialized.proof_value, proof.proof_value);
    }

    #[test]
    fn data_integrity_proof_type_field_renamed() {
        let proof = DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: "did:example:123#key-1".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "proofvalue123".to_string(),
        };

        let json = serde_json::to_string(&proof).expect("Failed to serialize");
        assert!(json.contains("\"type\":"), "proof_type should serialize as 'type'");
        assert!(!json.contains("\"proofType\":"), "Should not use proofType field");
    }

    #[test]
    fn log_parameters_serialization_roundtrip() {
        let params = LogParameters {
            method: "did:webvh:1.0".to_string(),
            scid: "z6Mkscid123".to_string(),
            update_keys: vec!["did:key:z6Mk#1".to_string()],
            next_key_hashes: Some(vec!["hash1".to_string(), "hash2".to_string()]),
            portable: true,
            ttl: Some(3600),
            witness: Some(WitnessConfig {
                threshold: Some(2),
                witnesses: vec!["witness1".to_string(), "witness2".to_string()],
            }),
            watchers: None,
            deactivated: false,
        };

        let json = serde_json::to_string(&params).expect("Failed to serialize");
        let deserialized: LogParameters = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.method, params.method);
        assert_eq!(deserialized.scid, params.scid);
        assert_eq!(deserialized.update_keys, params.update_keys);
        assert_eq!(deserialized.next_key_hashes, params.next_key_hashes);
        assert_eq!(deserialized.portable, params.portable);
        assert_eq!(deserialized.ttl, params.ttl);
        assert!(deserialized.witness.is_some());
    }

    #[test]
    fn log_parameters_optional_fields_omitted_when_none() {
        let params = LogParameters {
            method: "did:webvh:1.0".to_string(),
            scid: "z6Mkscid123".to_string(),
            update_keys: vec!["did:key:z6Mk#1".to_string()],
            next_key_hashes: None,
            portable: false,
            ttl: None,
            witness: None,
            watchers: None,
            deactivated: false,
        };

        let json = serde_json::to_string(&params).expect("Failed to serialize");
        assert!(!json.contains("\"nextKeyHashes\""), "None fields should be omitted");
        assert!(!json.contains("\"ttl\""), "None ttl should be omitted");
        assert!(!json.contains("\"witness\""), "None witness should be omitted");
    }

    #[test]
    fn verification_report_serialization_roundtrip() {
        let report = VerificationReport {
            valid: true,
            errors: vec!["error1".to_string(), "error2".to_string()],
        };

        let json = serde_json::to_string(&report).expect("Failed to serialize");
        let deserialized: VerificationReport = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.valid, report.valid);
        assert_eq!(deserialized.errors, report.errors);
    }

    #[test]
    fn verification_report_default_values() {
        let report = VerificationReport::default();
        assert!(!report.valid, "Default valid should be false");
        assert!(report.errors.is_empty(), "Default errors should be empty");
    }

    /// An update entry carries only the parameters that changed, so
    /// `"parameters": {}` must parse and must not gain invented values on write.
    #[test]
    fn delta_log_entry_parses_and_round_trips_without_inventing_parameters() {
        let state = serde_json::to_string(&affinidi_did_common::Document::new("did:webvh:example").unwrap()).unwrap();
        let raw = format!(
            r#"{{"versionId":"2-zHash","versionTime":"2026-01-02T00:00:00Z","parameters":{{}},"state":{state}}}"#
        );

        let entry: LogEntry = serde_json::from_str(&raw).expect("delta entry must parse");
        assert!(
            entry
                .parameters
                .method
                .is_empty()
        );
        assert!(
            entry
                .parameters
                .scid
                .is_empty()
        );
        assert!(
            entry
                .parameters
                .update_keys
                .is_empty()
        );

        let json = serde_json::to_value(&entry).unwrap();
        let params = json["parameters"]
            .as_object()
            .unwrap();
        assert!(!params.contains_key("method"), "empty method must not be written: {params:?}");
        assert!(!params.contains_key("scid"), "empty scid must not be written: {params:?}");
        assert!(!params.contains_key("updateKeys"), "empty updateKeys must not be written: {params:?}");
    }

    #[test]
    fn log_entry_serialization_roundtrip() {
        let doc = affinidi_did_common::Document::new("did:webvh:example").unwrap();

        let entry = LogEntry {
            version_id: "1-hash123".to_string(),
            version_time: "2026-01-01T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "z6Mkscid".to_string(),
                update_keys: vec!["did:key:z6Mk#1".to_string()],
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
                verification_method: "did:key:z6Mk#1".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: "proofvalue".to_string(),
            }],
        };

        let json = serde_json::to_string(&entry).expect("Failed to serialize");
        let deserialized: LogEntry = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.version_id, entry.version_id);
        assert_eq!(deserialized.version_time, entry.version_time);
        assert_eq!(deserialized.parameters.scid, entry.parameters.scid);
        assert_eq!(deserialized.proof.len(), 1);
    }

    #[test]
    fn witness_config_serialization_roundtrip() {
        let config = WitnessConfig {
            threshold: Some(3),
            witnesses: vec!["w1".to_string(), "w2".to_string(), "w3".to_string()],
        };

        let json = serde_json::to_string(&config).expect("Failed to serialize");
        let deserialized: WitnessConfig = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.threshold, config.threshold);
        assert_eq!(deserialized.witnesses, config.witnesses);
    }

    /// DidResolutionMetadata must serialize all required fields
    /// with camelCase names per the did:webvh spec §3.6.2.
    #[test]
    fn did_resolution_metadata_contains_all_required_fields() {
        use super::DidResolutionMetadata;

        let meta = DidResolutionMetadata {
            version_id: "2-zSomeHash".to_string(),
            version_time: "2026-06-01T00:00:00Z".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            updated: "2026-06-01T00:00:00Z".to_string(),
            scid: "zSomeSCID".to_string(),
            portable: false,
            deactivated: false,
            ttl: 3600,
            witness: None,
            watchers: None,
        };

        let json = serde_json::to_string(&meta).expect("Failed to serialize");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        // All required fields must be present with camelCase names
        assert!(obj.contains_key("versionId"), "must have 'versionId'");
        assert!(obj.contains_key("versionTime"), "must have 'versionTime'");
        assert!(obj.contains_key("created"), "must have 'created'");
        assert!(obj.contains_key("updated"), "must have 'updated'");
        assert!(obj.contains_key("scid"), "must have 'scid'");
        assert!(obj.contains_key("portable"), "must have 'portable'");
        assert!(obj.contains_key("deactivated"), "must have 'deactivated'");
        assert!(obj.contains_key("ttl"), "must have 'ttl'");
        // None fields omitted
        assert!(!obj.contains_key("witness"), "None witness should be omitted");
        assert!(!obj.contains_key("watchers"), "None watchers should be omitted");

        // Round-trip deserialization must preserve values
        let deserialized: DidResolutionMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version_id, meta.version_id);
        assert_eq!(deserialized.scid, meta.scid);
        assert_eq!(deserialized.ttl, meta.ttl);
        assert_eq!(deserialized.created, meta.created);
    }
}
