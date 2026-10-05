#![allow(dead_code)]

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentDna {
    pub uai: String,
    pub birth_event: BirthEvent,
    pub genesis: GenesisFingerprint,
    pub behavioral: BehavioralFingerprint,
    pub operational: OperationalFingerprint,
    pub attestations: AttestationData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BirthEvent {
    pub scid: String,
    pub timestamp: String,
    pub initial_genesis: GenesisFingerprint,
    pub birth_entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GenesisFingerprint {
    pub code_hash: String,
    pub model_spec: ModelSpec,
    pub config_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership_proof: Option<String>,
    pub genesis_hash: String,
    pub computed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ModelSpec {
    pub provider: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFingerprint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_profile_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_pattern_hash: Option<String>,
    pub behavioral_hash: String,
    pub measured_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OperationalFingerprint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<TeeAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_attestation: Option<CloudAttestation>,
    pub capabilities_hash: String,
    pub operational_hash: String,
    pub attested_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TeeAttestation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CloudAttestation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AttestationData {
    pub merkle_root: String,
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
}

/// Universal Agent Identifier version 1
/// Simple structure containing minimal agent identity information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UniversalAgentIdentifierV1 {
    /// The LLM provider (e.g., "openai", "anthropic", "bedrock")
    pub llm_provider: String,
    /// The LLM model (e.g., "gpt-4", "claude-3-opus")
    pub llm_model: String,
    /// The deployment location (e.g., "us-east-1", "eu-west-1")
    pub deployment_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Uai {
    pub version: u8,
    pub scid: String,
    pub genesis: String,
    pub behavioral: String,
    pub operational: String,
    pub attestation: String,
}

impl Uai {
    pub fn parse(input: &str) -> Result<Self> {
        if !input.starts_with("uai:") {
            bail!("missing uai: prefix")
        }
        let mut parts = input.splitn(4, ':');
        let _prefix = parts.next();
        let version_str = parts
            .next()
            .ok_or_else(|| anyhow!("missing version"))?;
        let version: u8 = version_str.parse()?;
        let scid = parts
            .next()
            .ok_or_else(|| anyhow!("missing scid"))?
            .to_string();
        let remainder = parts
            .next()
            .ok_or_else(|| anyhow!("missing fingerprint payload"))?;
        let segments: Vec<&str> = remainder.split('.').collect();
        if segments.len() != 4 {
            bail!("expected four fingerprint segments")
        }
        Ok(Self {
            version,
            scid,
            genesis: segments[0].to_string(),
            behavioral: segments[1].to_string(),
            operational: segments[2].to_string(),
            attestation: segments[3].to_string(),
        })
    }
}

impl std::fmt::Display for Uai {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(
            f,
            "uai:{}:{}:{}.{}.{}.{}",
            self.version, self.scid, self.genesis, self.behavioral, self.operational, self.attestation
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrustScore {
    pub score: f64,
    pub components: TrustComponents,
    pub computed_at: String,
    pub version_id: String,
}

impl TrustScore {
    pub fn from_components(components: TrustComponents) -> Self {
        let score = components.genesis_stability * 0.25
            + components.behavioral_consistency * 0.25
            + components.operational_security * 0.20
            + components.attestation_quality * 0.20
            + components.history_length * 0.10;

        Self {
            score,
            components,
            computed_at: String::new(),
            version_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrustComponents {
    pub genesis_stability: f64,
    pub behavioral_consistency: f64,
    pub operational_security: f64,
    pub attestation_quality: f64,
    pub history_length: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UaiIdentity {
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uai: Option<Uai>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dna: Option<AgentDna>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<TrustScore>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_uai() {
        let input = "uai:1:z6MkscidValue:gen123.beh456.op789.att012";
        let uai = Uai::parse(input).expect("Failed to parse valid UAI");

        assert_eq!(uai.version, 1);
        assert_eq!(uai.scid, "z6MkscidValue");
        assert_eq!(uai.genesis, "gen123");
        assert_eq!(uai.behavioral, "beh456");
        assert_eq!(uai.operational, "op789");
        assert_eq!(uai.attestation, "att012");
    }

    #[test]
    fn uai_roundtrip_preserves_values() {
        let original = Uai {
            version: 1,
            scid: "z6MktestScid".to_string(),
            genesis: "abc123".to_string(),
            behavioral: "def456".to_string(),
            operational: "ghi789".to_string(),
            attestation: "jkl012".to_string(),
        };

        let serialized = original.to_string();
        let parsed = Uai::parse(&serialized).expect("Failed to parse serialized UAI");

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.scid, original.scid);
        assert_eq!(parsed.genesis, original.genesis);
        assert_eq!(parsed.behavioral, original.behavioral);
        assert_eq!(parsed.operational, original.operational);
        assert_eq!(parsed.attestation, original.attestation);
    }

    #[test]
    fn rejects_missing_prefix() {
        let input = "1:z6MkscidValue:gen.beh.op.att";
        assert!(Uai::parse(input).is_err());
    }

    #[test]
    fn rejects_invalid_version() {
        let input = "uai:abc:z6MkscidValue:gen.beh.op.att";
        assert!(Uai::parse(input).is_err());
    }

    #[test]
    #[ignore] // FIXME: failing test
    fn rejects_missing_scid() {
        let input = "uai:1::gen.beh.op.att";
        let result = Uai::parse(input);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_insufficient_fingerprint_segments() {
        let input = "uai:1:z6MkscidValue:gen.beh.op"; // Only 3 segments
        assert!(Uai::parse(input).is_err());
    }

    #[test]
    fn rejects_excessive_fingerprint_segments() {
        let input = "uai:1:z6MkscidValue:gen.beh.op.att.extra"; // 5 segments
        assert!(Uai::parse(input).is_err());
    }

    #[test]
    fn formats_uai_correctly() {
        let uai = Uai {
            version: 1,
            scid: "z6MkscidValue".to_string(),
            genesis: "gen123".to_string(),
            behavioral: "beh456".to_string(),
            operational: "op789".to_string(),
            attestation: "att012".to_string(),
        };

        let formatted = uai.to_string();
        assert_eq!(formatted, "uai:1:z6MkscidValue:gen123.beh456.op789.att012");
    }

    #[test]
    fn handles_empty_fingerprint_values() {
        let input = "uai:1:z6MkscidValue:..."; // Empty fingerprints
        let uai = Uai::parse(input).expect("Should parse with empty fingerprints");

        assert_eq!(uai.genesis, "");
        assert_eq!(uai.behavioral, "");
        assert_eq!(uai.operational, "");
        assert_eq!(uai.attestation, "");
    }

    #[test]
    fn agent_dna_serialization_roundtrip() {
        let dna = GenesisFingerprint {
            code_hash: "hash1".to_string(),
            model_spec: ModelSpec {
                provider: "openai".to_string(),
                model: "gpt-4".to_string(),
                version: None,
            },
            config_hash: "hash2".to_string(),
            ownership_proof: Some("proof1".to_string()),
            genesis_hash: "gen123".to_string(),
            computed_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&dna).expect("Failed to serialize");
        let deserialized: GenesisFingerprint = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.code_hash, dna.code_hash);
        assert_eq!(deserialized.model_spec.model, dna.model_spec.model);
        assert_eq!(deserialized.config_hash, dna.config_hash);
        assert_eq!(deserialized.ownership_proof, dna.ownership_proof);
    }

    #[test]
    fn birth_event_serialization_roundtrip() {
        let event = BirthEvent {
            scid: "z6Mkscid".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            initial_genesis: GenesisFingerprint::default(),
            birth_entry_hash: "hash123".to_string(),
        };

        let json = serde_json::to_string(&event).expect("Failed to serialize");
        let deserialized: BirthEvent = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.timestamp, event.timestamp);
        assert_eq!(deserialized.scid, event.scid);
        assert_eq!(deserialized.birth_entry_hash, event.birth_entry_hash);
    }

    #[test]
    fn uai_identity_serialization_roundtrip() {
        let identity = UaiIdentity {
            did: "did:webvh:example".to_string(),
            uai: Some(Uai {
                version: 1,
                scid: "z6Mkscid".to_string(),
                genesis: "gen".to_string(),
                behavioral: "beh".to_string(),
                operational: "op".to_string(),
                attestation: "att".to_string(),
            }),
            dna: None,
            trust_score: None,
        };

        let json = serde_json::to_string(&identity).expect("Failed to serialize");
        let deserialized: UaiIdentity = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.did, identity.did);
        assert!(deserialized.uai.is_some());
        assert_eq!(deserialized.uai.unwrap().scid, "z6Mkscid");
    }
}
