#![allow(dead_code)]

use anyhow::{Result, bail};
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::types::{BehavioralFingerprint, GenesisFingerprint, ModelSpec, OperationalFingerprint};

/// Compute Genesis fingerprint from agent code, model spec, and configuration
pub fn compute_genesis(
    code_source: &[u8],
    model_spec: &ModelSpec,
    config: &[u8],
    ownership_proof: Option<&str>,
) -> Result<GenesisFingerprint> {
    // Code hash
    let code_hash = hex::encode(Sha256::digest(code_source));

    // Model spec canonicalization
    let model_str = format!(
        "{}:{}:{}",
        model_spec.provider,
        model_spec.model,
        model_spec
            .version
            .as_deref()
            .unwrap_or("latest")
    );

    // Config hash
    let config_hash = hex::encode(Sha256::digest(config));

    // Combined genesis hash
    let combined = format!("genesis:{}:{}:{}:{}", code_hash, model_str, config_hash, ownership_proof.unwrap_or("none"));
    let genesis_hash = hex::encode(Sha256::digest(combined.as_bytes()));

    Ok(GenesisFingerprint {
        code_hash,
        model_spec: model_spec.clone(),
        config_hash,
        ownership_proof: ownership_proof.map(String::from),
        genesis_hash,
        computed_at: Utc::now().to_rfc3339(),
    })
}

pub fn compute_behavioral() -> Result<BehavioralFingerprint> {
    bail!("compute_behavioral() not yet implemented")
}

pub fn compute_operational() -> Result<OperationalFingerprint> {
    bail!("compute_operational() not yet implemented")
}

/// Compute Merkle root from attestation hashes
pub fn compute_attestation_root(attestation_hashes: &[String]) -> String {
    if attestation_hashes.is_empty() {
        return hex::encode(Sha256::digest(b"empty"));
    }

    let mut layer: Vec<Vec<u8>> = attestation_hashes
        .iter()
        .map(|h| Sha256::digest(h.as_bytes()).to_vec())
        .collect();

    while layer.len() > 1 {
        let mut next_layer = Vec::new();
        for chunk in layer.chunks(2) {
            let combined = if chunk.len() == 2 {
                let mut concat = chunk[0].clone();
                concat.extend_from_slice(&chunk[1]);
                concat
            } else {
                chunk[0].clone()
            };
            next_layer.push(Sha256::digest(&combined).to_vec());
        }
        layer = next_layer;
    }

    hex::encode(&layer[0])
}

#[cfg(test)]
mod tests {
    use super::{ModelSpec, compute_attestation_root, compute_genesis};

    #[test]
    fn genesis_fingerprint_deterministic() {
        let code = b"agent-code-v1.0";
        let model = ModelSpec {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            version: Some("turbo".to_string()),
        };
        let config = b"config: { temperature: 0.7 }";

        let fp1 = compute_genesis(code, &model, config, None).unwrap();
        let fp2 = compute_genesis(code, &model, config, None).unwrap();

        assert_eq!(fp1.genesis_hash, fp2.genesis_hash);
        assert!(!fp1.code_hash.is_empty());
        assert!(!fp1.config_hash.is_empty());
        assert_eq!(fp1.model_spec.provider, "openai");
    }

    #[test]
    fn genesis_with_ownership_proof() {
        let code = b"agent-code-v1.0";
        let model = ModelSpec {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            version: None,
        };
        let config = b"config: {}";

        let fp_with = compute_genesis(code, &model, config, Some("proof-sig")).unwrap();
        let fp_without = compute_genesis(code, &model, config, None).unwrap();

        assert_ne!(fp_with.genesis_hash, fp_without.genesis_hash);
        assert_eq!(fp_with.ownership_proof, Some("proof-sig".to_string()));
        assert_eq!(fp_without.ownership_proof, None);
    }

    #[test]
    fn attestation_merkle_single() {
        let attestations = vec!["attestation1".to_string()];
        let root = compute_attestation_root(&attestations);
        assert!(!root.is_empty());
        assert_eq!(root.len(), 64); // sha256 hex
    }

    #[test]
    fn attestation_merkle_multiple() {
        let attestations = vec!["attestation1".to_string(), "attestation2".to_string(), "attestation3".to_string()];
        let root = compute_attestation_root(&attestations);
        assert!(!root.is_empty());
    }

    #[test]
    fn attestation_merkle_empty() {
        let attestations = vec![];
        let root = compute_attestation_root(&attestations);
        assert!(!root.is_empty());
    }
}
