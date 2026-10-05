//! Trust Score Computation Engine
//!
//! Computes trust scores for DID:webvh identities based on multiple components:
//! - Genesis Stability: How stable the agent's genesis fingerprint has been over time
//! - Behavioral Consistency: How consistent the agent's behavioral patterns are
//! - Operational Security: Security features like TEE attestations
//! - Attestation Quality: Quality and reputation of third-party attestations
//! - History Length: How long the identity has existed and how many updates

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::log::DidLogManager;
use super::types::LogEntry;
use crate::identity::uai::types::{AgentDna, BehavioralFingerprint, GenesisFingerprint, TrustComponents, TrustScore};

/// Configurable weights for trust score computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustWeights {
    /// Weight for genesis stability (0.0-1.0)
    pub genesis_stability: f64,

    /// Weight for behavioral consistency (0.0-1.0)
    pub behavioral_consistency: f64,

    /// Weight for operational security (0.0-1.0)
    pub operational_security: f64,

    /// Weight for attestation quality (0.0-1.0)
    pub attestation_quality: f64,

    /// Weight for history length (0.0-1.0)
    pub history_length: f64,
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            genesis_stability: 0.25,
            behavioral_consistency: 0.25,
            operational_security: 0.20,
            attestation_quality: 0.20,
            history_length: 0.10,
        }
    }
}

/// Trust score computation engine
pub struct TrustComputer {
    weights: TrustWeights,
}

impl TrustComputer {
    /// Create a new TrustComputer with default weights
    pub fn new() -> Self {
        Self {
            weights: TrustWeights::default(),
        }
    }

    /// Create a new TrustComputer with custom weights
    pub fn with_weights(weights: TrustWeights) -> Self {
        Self { weights }
    }

    /// Compute overall trust score for an identity
    ///
    /// Returns a TrustScore with weighted components and overall score (0.0-1.0)
    pub async fn compute(
        &self,
        did: &str,
        log_manager: &DidLogManager,
        dna: Option<&AgentDna>,
    ) -> Result<TrustScore> {
        // Load the complete DID log
        let log_entries = log_manager
            .load(did)
            .await
            .context("Failed to load DID log")?;

        if log_entries.is_empty() {
            anyhow::bail!("No log entries found for DID: {}", did);
        }

        // Compute individual components
        let genesis_stability = self
            .compute_genesis_stability(&log_entries, dna)
            .await
            .context("Failed to compute genesis stability")?;

        let behavioral_consistency = self
            .compute_behavioral_consistency(&log_entries, dna)
            .await
            .context("Failed to compute behavioral consistency")?;

        let operational_security = self
            .compute_operational_security(&log_entries, dna)
            .await
            .context("Failed to compute operational security")?;

        let attestation_quality = self
            .compute_attestation_quality(&log_entries, dna)
            .await
            .context("Failed to compute attestation quality")?;

        let history_length = self
            .compute_history_score(&log_entries)
            .await
            .context("Failed to compute history score")?;

        // Build components
        let components = TrustComponents {
            genesis_stability,
            behavioral_consistency,
            operational_security,
            attestation_quality,
            history_length,
        };

        // Compute weighted overall score
        let score = (genesis_stability * self.weights.genesis_stability)
            + (behavioral_consistency
                * self
                    .weights
                    .behavioral_consistency)
            + (operational_security
                * self
                    .weights
                    .operational_security)
            + (attestation_quality
                * self
                    .weights
                    .attestation_quality)
            + (history_length * self.weights.history_length);

        // Get latest version info
        let latest_entry = log_entries.last().unwrap();
        let version_id = latest_entry
            .version_id
            .clone();

        debug!(
            did = did,
            score = score,
            genesis = genesis_stability,
            behavioral = behavioral_consistency,
            operational = operational_security,
            attestation = attestation_quality,
            history = history_length,
            "Computed trust score"
        );

        Ok(TrustScore {
            score,
            components,
            computed_at: Utc::now().to_rfc3339(),
            version_id,
        })
    }

    /// Compute genesis stability score (0.0-1.0)
    ///
    /// Higher score = genesis has remained stable over time
    /// Lower score = genesis has changed frequently
    pub async fn compute_genesis_stability(
        &self,
        log_entries: &[LogEntry],
        dna: Option<&AgentDna>,
    ) -> Result<f64> {
        if log_entries.is_empty() {
            return Ok(0.0);
        }

        // If no DNA provided, assume stable genesis
        let Some(_current_dna) = dna else {
            return Ok(0.5); // Neutral score when no DNA available
        };

        // Count how many times the genesis fingerprint has changed
        let mut genesis_changes = 0;
        let mut last_genesis: Option<GenesisFingerprint> = None;

        // Check genesis from DNA/metadata in log entries
        for entry in log_entries {
            // Try to extract genesis from entry metadata
            if let Some(dna_in_entry) = extract_dna_from_entry(entry) {
                if let Some(ref last) = last_genesis {
                    // Compare genesis hashes
                    if last.genesis_hash
                        != dna_in_entry
                            .genesis
                            .genesis_hash
                    {
                        genesis_changes += 1;
                    }
                }
                last_genesis = Some(dna_in_entry.genesis.clone());
            }
        }

        // Calculate stability score
        // 0 changes = 1.0, 1 change = 0.8, 2 changes = 0.6, etc.
        let total_versions = log_entries.len() as f64;
        let change_rate = genesis_changes as f64 / total_versions.max(1.0);

        // Invert: fewer changes = higher stability
        let stability = (1.0 - change_rate).clamp(0.0, 1.0);

        Ok(stability)
    }

    /// Compute behavioral consistency score (0.0-1.0)
    ///
    /// Higher score = behavioral patterns are consistent over time
    /// Lower score = behavioral patterns vary significantly
    pub async fn compute_behavioral_consistency(
        &self,
        log_entries: &[LogEntry],
        dna: Option<&AgentDna>,
    ) -> Result<f64> {
        if log_entries.is_empty() {
            return Ok(0.0);
        }

        // If no DNA provided, assume moderate consistency
        let Some(_current_dna) = dna else {
            return Ok(0.5); // Neutral score when no behavioral data
        };

        // Count behavioral fingerprint changes
        let mut behavioral_changes = 0;
        let mut last_behavioral: Option<BehavioralFingerprint> = None;

        for entry in log_entries {
            if let Some(dna_in_entry) = extract_dna_from_entry(entry) {
                if let Some(ref last) = last_behavioral
                    && last.behavioral_hash
                        != dna_in_entry
                            .behavioral
                            .behavioral_hash
                {
                    behavioral_changes += 1;
                }
                last_behavioral = Some(
                    dna_in_entry
                        .behavioral
                        .clone(),
                );
            }
        }

        // Calculate consistency score
        let total_versions = log_entries.len() as f64;

        // Some behavioral changes are expected, so we're more lenient
        // 0 changes = 1.0, few changes = still high, many changes = lower
        let change_rate = behavioral_changes as f64 / total_versions.max(1.0);
        let consistency = if behavioral_changes == 0 {
            1.0
        } else if change_rate < 0.2 {
            0.9 // Minimal changes - still very consistent
        } else if change_rate < 0.5 {
            0.7 // Moderate changes - reasonably consistent
        } else {
            0.4 // Frequent changes - less consistent
        };

        Ok(consistency)
    }

    /// Compute operational security score (0.0-1.0)
    ///
    /// Higher score = strong security features (TEE, cloud attestations)
    /// Lower score = basic security, no additional attestations
    pub async fn compute_operational_security(
        &self,
        log_entries: &[LogEntry],
        dna: Option<&AgentDna>,
    ) -> Result<f64> {
        if log_entries.is_empty() {
            return Ok(0.0);
        }

        // If no DNA provided, assume basic security
        let Some(current_dna) = dna else {
            return Ok(0.3); // Basic security score when no operational data
        };

        let mut security_score: f64 = 0.5; // Base score for having operational fingerprint

        // Check for TEE attestation (adds significant trust)
        if let Some(ref tee) = current_dna
            .operational
            .tee_attestation
            && tee.r#type.is_some()
            && tee.quote.is_some()
        {
            security_score += 0.3; // TEE adds 30%
        }

        // Check for cloud attestation (adds moderate trust)
        if let Some(ref cloud) = current_dna
            .operational
            .cloud_attestation
            && cloud.provider.is_some()
            && cloud.instance_id.is_some()
        {
            security_score += 0.2; // Cloud attestation adds 20%
        }

        Ok(security_score.min(1.0))
    }

    /// Compute attestation quality score (0.0-1.0)
    ///
    /// Higher score = many attestations from reputable sources
    /// Lower score = few or no attestations
    pub async fn compute_attestation_quality(
        &self,
        log_entries: &[LogEntry],
        dna: Option<&AgentDna>,
    ) -> Result<f64> {
        if log_entries.is_empty() {
            return Ok(0.0);
        }

        // If no DNA provided, assume no attestations
        let Some(current_dna) = dna else {
            return Ok(0.0);
        };

        let attestation_count = current_dna.attestations.count;

        // Score based on number of attestations
        // 0 = 0.0, 1 = 0.3, 3 = 0.5, 5 = 0.7, 10+ = 0.9
        let quality = match attestation_count {
            0 => 0.0,
            1 => 0.3,
            2 => 0.4,
            3..=4 => 0.5,
            5..=7 => 0.7,
            8..=10 => 0.8,
            _ => 0.9,
        };

        // TODO: Factor in issuer reputation when available
        // TODO: Check attestation recency

        Ok(quality)
    }

    /// Compute history length score based on version count and age (0.0-1.0)
    ///
    /// Higher score = longer history with more versions
    /// Lower score = newly created identity
    pub async fn compute_history_score(
        &self,
        log_entries: &[LogEntry],
    ) -> Result<f64> {
        if log_entries.is_empty() {
            return Ok(0.0);
        }

        let _version_count = log_entries.len() as f64;

        // Score based on number of versions
        // 1 = 0.2, 3 = 0.4, 5 = 0.6, 10+ = 0.9
        let version_score = match log_entries.len() {
            1 => 0.2,
            2 => 0.3,
            3..=4 => 0.4,
            5..=7 => 0.6,
            8..=10 => 0.8,
            _ => 0.9,
        };

        // Calculate age bonus
        let first_entry = &log_entries[0];
        let age_bonus = if let Ok(created_time) = DateTime::parse_from_rfc3339(&first_entry.version_time) {
            let age = Utc::now().signed_duration_since(created_time.with_timezone(&Utc));
            let days_old = age.num_days() as f64;

            // Age bonus (max 0.1): 0 days = 0.0, 7 days = 0.03, 30 days = 0.07, 90+ days = 0.1
            (days_old / 900.0).min(0.1)
        } else {
            0.0
        };

        Ok((version_score + age_bonus).min(1.0))
    }
}

impl Default for TrustComputer {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract AgentDna from a log entry's DID document metadata
///
/// This looks for DNA stored in the DID document's metadata fields
fn extract_dna_from_entry(_entry: &LogEntry) -> Option<AgentDna> {
    // Try to extract from DID document metadata
    // For now, return None as DNA extraction logic depends on where DNA is stored
    // TODO: Implement DNA extraction when storage location is defined
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::uai::types::{
        AgentDna, AttestationData, BehavioralFingerprint, CloudAttestation, GenesisFingerprint, ModelSpec,
        OperationalFingerprint, TeeAttestation,
    };

    #[test]
    fn test_trust_weights_default() {
        let weights = TrustWeights::default();
        assert_eq!(weights.genesis_stability, 0.25);
        assert_eq!(weights.behavioral_consistency, 0.25);
        assert_eq!(weights.operational_security, 0.20);
        assert_eq!(weights.attestation_quality, 0.20);
        assert_eq!(weights.history_length, 0.10);

        // Weights should sum to 1.0
        let sum = weights.genesis_stability
            + weights.behavioral_consistency
            + weights.operational_security
            + weights.attestation_quality
            + weights.history_length;
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_trust_computer_creation() {
        let computer = TrustComputer::new();
        assert_eq!(
            computer
                .weights
                .genesis_stability,
            0.25
        );

        let custom_weights = TrustWeights {
            genesis_stability: 0.3,
            behavioral_consistency: 0.3,
            operational_security: 0.2,
            attestation_quality: 0.1,
            history_length: 0.1,
        };
        let custom_computer = TrustComputer::with_weights(custom_weights);
        assert_eq!(
            custom_computer
                .weights
                .genesis_stability,
            0.3
        );
    }

    #[tokio::test]
    async fn test_history_score_single_version() {
        let computer = TrustComputer::new();
        let now = Utc::now().to_rfc3339();
        let entries = vec![create_mock_entry("1-hash", &now)];

        let score = computer
            .compute_history_score(&entries)
            .await
            .expect("Failed to compute history score");

        assert_eq!(score, 0.2, "Single fresh version should receive the base history score without age bonus");
    }

    #[tokio::test]
    async fn test_history_score_multiple_versions() {
        let computer = TrustComputer::new();
        let entries = vec![
            create_mock_entry("1-hash", "2026-01-01T00:00:00Z"),
            create_mock_entry("2-hash", "2026-01-15T00:00:00Z"),
            create_mock_entry("3-hash", "2026-02-01T00:00:00Z"),
            create_mock_entry("4-hash", "2026-02-10T00:00:00Z"),
            create_mock_entry("5-hash", "2026-02-13T00:00:00Z"),
        ];

        let score = computer
            .compute_history_score(&entries)
            .await
            .expect("Failed to compute history score");

        // 5 versions should give 0.6 base + age bonus
        assert!(score >= 0.6);
        assert!(score <= 1.0);
    }

    #[tokio::test]
    async fn test_operational_security_no_dna() {
        let computer = TrustComputer::new();
        let entries = vec![create_mock_entry("1-hash", "2026-02-13T00:00:00Z")];

        let score = computer
            .compute_operational_security(&entries, None)
            .await
            .expect("Failed to compute operational security");

        assert_eq!(score, 0.3); // Base score when no DNA
    }

    #[tokio::test]
    async fn test_operational_security_with_tee() {
        let computer = TrustComputer::new();
        let entries = vec![create_mock_entry("1-hash", "2026-02-13T00:00:00Z")];

        let mut dna = create_mock_dna();
        dna.operational
            .tee_attestation = Some(TeeAttestation {
            r#type: Some("SGX".to_string()),
            quote: Some("quote123".to_string()),
            measurement_hash: Some("hash".to_string()),
            verified_by: Some("Intel".to_string()),
            verified_at: Some("2026-02-13T00:00:00Z".to_string()),
        });

        let score = computer
            .compute_operational_security(&entries, Some(&dna))
            .await
            .expect("Failed to compute operational security");

        assert_eq!(score, 0.8); // Base 0.5 + TEE 0.3 = 0.8
    }

    #[tokio::test]
    async fn test_operational_security_with_cloud() {
        let computer = TrustComputer::new();
        let entries = vec![create_mock_entry("1-hash", "2026-02-13T00:00:00Z")];

        let mut dna = create_mock_dna();
        dna.operational
            .cloud_attestation = Some(CloudAttestation {
            provider: Some("AWS".to_string()),
            project_id: None,
            zone: None,
            instance_id: Some("i-123456".to_string()),
            identity_token: Some("token".to_string()),
        });

        let score = computer
            .compute_operational_security(&entries, Some(&dna))
            .await
            .expect("Failed to compute operational security");

        assert_eq!(score, 0.7); // Base 0.5 + Cloud 0.2 = 0.7
    }

    #[tokio::test]
    async fn test_attestation_quality_varying_counts() {
        let computer = TrustComputer::new();
        let entries = vec![create_mock_entry("1-hash", "2026-02-13T00:00:00Z")];

        // 0 attestations
        let mut dna = create_mock_dna();
        dna.attestations.count = 0;
        let score = computer
            .compute_attestation_quality(&entries, Some(&dna))
            .await
            .unwrap();
        assert_eq!(score, 0.0);

        // 1 attestation
        dna.attestations.count = 1;
        let score = computer
            .compute_attestation_quality(&entries, Some(&dna))
            .await
            .unwrap();
        assert_eq!(score, 0.3);

        // 5 attestations
        dna.attestations.count = 5;
        let score = computer
            .compute_attestation_quality(&entries, Some(&dna))
            .await
            .unwrap();
        assert_eq!(score, 0.7);

        // 15 attestations
        dna.attestations.count = 15;
        let score = computer
            .compute_attestation_quality(&entries, Some(&dna))
            .await
            .unwrap();
        assert_eq!(score, 0.9);
    }

    // Helper functions for tests

    fn create_mock_entry(
        version_id: &str,
        version_time: &str,
    ) -> LogEntry {
        use crate::identity::didwebvh::types::{DataIntegrityProof, LogParameters};

        let doc = affinidi_did_common::Document::new("did:webvh:example.com:alice").unwrap();

        LogEntry {
            version_id: version_id.to_string(),
            version_time: version_time.to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "z6Mktest".to_string(),
                update_keys: vec![],
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
                verification_method: "did:webvh:example.com:alice#key-1".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: "proof123".to_string(),
            }],
        }
    }

    fn create_mock_dna() -> AgentDna {
        use crate::identity::uai::types::BirthEvent;

        AgentDna {
            uai: "uai:1:z6Mktest:gen.beh.op.att".to_string(),
            birth_event: BirthEvent {
                scid: "z6Mktest".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                initial_genesis: GenesisFingerprint::default(),
                birth_entry_hash: "hash".to_string(),
            },
            genesis: GenesisFingerprint {
                code_hash: "code123".to_string(),
                model_spec: ModelSpec {
                    provider: "OpenAI".to_string(),
                    model: "gpt-4".to_string(),
                    version: Some("2024-01-01".to_string()),
                },
                config_hash: "config123".to_string(),
                ownership_proof: None,
                genesis_hash: "genesis123".to_string(),
                computed_at: "2026-01-01T00:00:00Z".to_string(),
            },
            behavioral: BehavioralFingerprint {
                latency_profile_hash: Some("latency123".to_string()),
                challenge_response_hash: None,
                token_pattern_hash: None,
                behavioral_hash: "behavioral123".to_string(),
                measured_at: "2026-01-01T00:00:00Z".to_string(),
            },
            operational: OperationalFingerprint {
                tee_attestation: None,
                cloud_attestation: None,
                capabilities_hash: "capabilities123".to_string(),
                operational_hash: "operational123".to_string(),
                attested_at: "2026-01-01T00:00:00Z".to_string(),
            },
            attestations: AttestationData {
                merkle_root: "root123".to_string(),
                count: 0,
                last_updated: Some("2026-01-01T00:00:00Z".to_string()),
            },
        }
    }
}
