//! Unified caller-identity abstraction for the Agent Gateway proxy.
//!
//! Both the classical **HTTP path** (identity extracted via `x-identity` field markers)
//! and the **DID-aware path** (agent presents a `did:webvh` DID through message metadata
//! or the `X-DID-Identity` header) converge onto a single [`CallerIdentity`] value before
//! policy evaluation, audit logging, and upstream header injection.
//!
//! # Why a common abstraction?
//!
//! HTTP agents and DID-aware agents currently take divergent code paths that duplicate
//! logic for policy input building and upstream forwarding.  The [`CallerIdentity`] type
//! is the AG-internal representation of *who is calling*.  Once both paths produce one,
//! all downstream code works uniformly.
//!
//! # February demo scope
//!
//! For the demo, Agent DNA is randomly generated at identity-creation time (no real
//! measurement infrastructure).  The `identity_source` field signals to the managed agent
//! how much trust the gateway itself places in the presented identity.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How the caller's identity was established by the Agent Gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdentitySource {
    /// The gateway computed the caller's DID from request fields extracted via
    /// `x-identity: true` markers (classical HTTP-client path).
    GatewayComputed,
    /// The caller self-asserted a DID (e.g. via `X-DID-Identity` header or A2A
    /// agent-identity extension) — the gateway has not independently verified it.
    SelfPresented,
    /// The gateway resolved the caller's `did.jsonl` and verified the Data
    /// Integrity proof chain before accepting the identity.
    VerifiedPresentation,
}

impl std::fmt::Display for IdentitySource {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::GatewayComputed => write!(f, "gateway-computed"),
            Self::SelfPresented => write!(f, "self-presented"),
            Self::VerifiedPresentation => write!(f, "verified-presentation"),
        }
    }
}

/// Unified caller identity — produced by both HTTP and DID-aware proxy paths.
///
/// ## HTTP path (classical `x-identity` extraction)
/// 1. Identity fields extracted from the inbound request body/headers.
/// 2. Canonical SHA-256 hash computed from those fields.
/// 3. DID looked up / created via `VCIssuer` (gateway-managed keys).
/// 4. [`CallerIdentity::from_gateway_computed`] called.
///
/// ## DID-aware path (A2A with agent-identity extension, or `X-DID-Identity` header)
/// 1. DID extracted from message metadata or explicit header.
/// 2. `did.jsonl` optionally fetched and verified (proof chain check).
/// 3. Agent DNA extracted from DID document or accompanying agent card.
/// 4. [`CallerIdentity::from_self_presented`] or [`CallerIdentity::from_verified_presentation`] called.
///
/// After construction, shared pipeline code (policy evaluation, audit logging,
/// [`CallerHeaders::build`] for upstream injection) operates exclusively on this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerIdentity {
    /// The caller's DID (gateway-computed or self-presented).
    pub did: String,

    /// The caller's resolved DID document in JSON form, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,

    /// Agent DNA extracted from the caller's agent card or DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_dna: Option<crate::identity::uai::types::AgentDna>,

    /// How the gateway established this identity.
    pub identity_source: IdentitySource,

    /// Raw identity key–value fields: `x-identity`-extracted values (HTTP path) or
    /// DID-document service-endpoint metadata (DID-aware path).
    #[serde(default)]
    pub identity_fields: HashMap<String, serde_json::Value>,
}

impl CallerIdentity {
    /// Construct from a gateway-computed identity (classical HTTP-client path).
    pub fn from_gateway_computed(
        did: String,
        identity_fields: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            did,
            did_document: None,
            agent_dna: None,
            identity_source: IdentitySource::GatewayComputed,
            identity_fields,
        }
    }

    /// Construct from a self-presented DID (DID-aware client — unverified by the gateway).
    pub fn from_self_presented(
        did: String,
        did_document: Option<serde_json::Value>,
        agent_dna: Option<crate::identity::uai::types::AgentDna>,
    ) -> Self {
        Self {
            did,
            did_document,
            agent_dna,
            identity_source: IdentitySource::SelfPresented,
            identity_fields: HashMap::new(),
        }
    }

    /// Construct from a verified presentation (DID-aware client, `did.jsonl` proof chain
    /// verified by the gateway).
    #[allow(dead_code)]
    pub fn from_verified_presentation(
        did: String,
        did_document: Option<serde_json::Value>,
        agent_dna: Option<crate::identity::uai::types::AgentDna>,
    ) -> Self {
        Self {
            did,
            did_document,
            agent_dna,
            identity_source: IdentitySource::VerifiedPresentation,
            identity_fields: HashMap::new(),
        }
    }
}

/// Standard HTTP header names injected by the Agent Gateway on every upstream request.
///
/// These headers are set regardless of whether the caller used the HTTP path or the
/// DID-aware path and let managed agents know *who* is calling and *how* the gateway
/// verified that claim.
///
/// ## Header summary
///
/// | Header | Value | Always present |
/// |---|---|---|
/// | `x-caller-did` | The caller's DID | Yes |
/// | `x-caller-identity-source` | `gateway-computed` / `self-presented` / `verified-presentation` | Yes |
/// | `x-caller-dna-uai` | UAI string from caller's Agent DNA | When DNA is available |
/// | `x-gateway-did` | The AG's own DID | When configured |
pub struct CallerHeaders;

impl CallerHeaders {
    /// The caller's DID.
    pub const CALLER_DID: &'static str = "x-caller-did";

    /// How the gateway established the caller's identity.
    pub const CALLER_IDENTITY_SOURCE: &'static str = "x-caller-identity-source";

    /// UAI string from the caller's Agent DNA (omitted when DNA is unavailable).
    pub const CALLER_DNA_UAI: &'static str = "x-caller-dna-uai";

    /// The Agent Gateway's own DID (omitted when not configured).
    pub const GATEWAY_DID: &'static str = "x-gateway-did";

    /// Build the caller-info header set from a [`CallerIdentity`].
    ///
    /// Returns a `Vec<(name, value)>` suitable for appending to an outgoing
    /// `reqwest::RequestBuilder` via `.header(name, value)`.
    ///
    /// `gateway_did` is the AGW's own DID; pass `None` when it is not configured.
    pub fn build(
        identity: &CallerIdentity,
        gateway_did: Option<&str>,
    ) -> Vec<(String, String)> {
        let mut headers = Vec::with_capacity(4);

        headers.push((Self::CALLER_DID.to_string(), identity.did.clone()));
        headers.push((
            Self::CALLER_IDENTITY_SOURCE.to_string(),
            identity
                .identity_source
                .to_string(),
        ));

        if let Some(dna) = &identity.agent_dna
            && !dna.uai.is_empty()
        {
            headers.push((Self::CALLER_DNA_UAI.to_string(), dna.uai.clone()));
        }

        if let Some(did) = gateway_did
            && !did.is_empty()
        {
            headers.push((Self::GATEWAY_DID.to_string(), did.to_string()));
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── IdentitySource ───────────────────────────────────────────────────────

    #[test]
    fn test_identity_source_display_gateway_computed() {
        assert_eq!(IdentitySource::GatewayComputed.to_string(), "gateway-computed");
    }

    #[test]
    fn test_identity_source_display_self_presented() {
        assert_eq!(IdentitySource::SelfPresented.to_string(), "self-presented");
    }

    #[test]
    fn test_identity_source_display_verified_presentation() {
        assert_eq!(IdentitySource::VerifiedPresentation.to_string(), "verified-presentation");
    }

    /// IdentitySource round-trips through serde with kebab-case JSON strings.
    #[test]
    fn test_identity_source_serde_round_trip() {
        let variants = [
            (IdentitySource::GatewayComputed, "\"gateway-computed\""),
            (IdentitySource::SelfPresented, "\"self-presented\""),
            (IdentitySource::VerifiedPresentation, "\"verified-presentation\""),
        ];
        for (variant, expected_json) in &variants {
            let serialized = serde_json::to_string(variant).unwrap();
            assert_eq!(&serialized, expected_json, "Unexpected serialized form for {:?}", variant);

            let deserialized: IdentitySource = serde_json::from_str(expected_json).unwrap();
            assert_eq!(&deserialized, variant, "Deserialized value must match original");
        }
    }

    // ─── CallerIdentity constructors ──────────────────────────────────────────

    #[test]
    fn test_from_gateway_computed_sets_source_and_fields() {
        let mut fields = HashMap::new();
        fields.insert("email".to_string(), serde_json::json!("alice@example.com"));

        let identity = CallerIdentity::from_gateway_computed("did:example:alice".to_string(), fields.clone());

        assert_eq!(identity.did, "did:example:alice");
        assert_eq!(identity.identity_source, IdentitySource::GatewayComputed);
        assert!(
            identity
                .did_document
                .is_none(),
            "did_document must be None for gateway-computed path"
        );
        assert!(identity.agent_dna.is_none(), "agent_dna must be None for gateway-computed path");
        assert_eq!(
            identity
                .identity_fields
                .get("email"),
            fields.get("email")
        );
    }

    #[test]
    fn test_from_self_presented_sets_source_and_document() {
        let doc = serde_json::json!({"id": "did:webvh:example.com:bob"});
        let identity =
            CallerIdentity::from_self_presented("did:webvh:example.com:bob".to_string(), Some(doc.clone()), None);

        assert_eq!(identity.did, "did:webvh:example.com:bob");
        assert_eq!(identity.identity_source, IdentitySource::SelfPresented);
        assert_eq!(
            identity
                .did_document
                .as_ref()
                .unwrap(),
            &doc
        );
        assert!(identity.agent_dna.is_none());
        assert!(
            identity
                .identity_fields
                .is_empty(),
            "identity_fields must be empty for DID-aware path"
        );
    }

    #[test]
    fn test_from_verified_presentation_sets_source() {
        let identity =
            CallerIdentity::from_verified_presentation("did:webvh:example.com:carol".to_string(), None, None);

        assert_eq!(identity.identity_source, IdentitySource::VerifiedPresentation);
        assert_eq!(identity.did, "did:webvh:example.com:carol");
    }

    #[test]
    fn test_caller_identity_serde_round_trip() {
        let identity = CallerIdentity::from_gateway_computed("did:example:dave".to_string(), HashMap::new());

        let json = serde_json::to_string(&identity).unwrap();
        let restored: CallerIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.did, identity.did);
        assert_eq!(restored.identity_source, identity.identity_source);
    }

    // ─── CallerHeaders::build ─────────────────────────────────────────────────

    fn make_identity(source: IdentitySource) -> CallerIdentity {
        CallerIdentity {
            did: "did:example:test".to_string(),
            did_document: None,
            agent_dna: None,
            identity_source: source,
            identity_fields: HashMap::new(),
        }
    }

    fn header_value<'a>(
        headers: &'a [(String, String)],
        name: &str,
    ) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Minimal build: no DNA, no gateway DID → exactly 2 headers.
    #[test]
    fn test_caller_headers_minimal() {
        let identity = make_identity(IdentitySource::GatewayComputed);
        let headers = CallerHeaders::build(&identity, None);

        assert_eq!(headers.len(), 2, "Expected exactly 2 headers, got {}", headers.len());
        assert_eq!(header_value(&headers, CallerHeaders::CALLER_DID), Some("did:example:test"));
        assert_eq!(header_value(&headers, CallerHeaders::CALLER_IDENTITY_SOURCE), Some("gateway-computed"));
    }

    /// Identity source is reflected correctly for each variant.
    #[test]
    fn test_caller_headers_identity_source_variants() {
        let cases = [
            (IdentitySource::GatewayComputed, "gateway-computed"),
            (IdentitySource::SelfPresented, "self-presented"),
            (IdentitySource::VerifiedPresentation, "verified-presentation"),
        ];
        for (source, expected) in &cases {
            let identity = make_identity(source.clone());
            let headers = CallerHeaders::build(&identity, None);
            assert_eq!(
                header_value(&headers, CallerHeaders::CALLER_IDENTITY_SOURCE),
                Some(*expected),
                "Unexpected identity source header for {:?}",
                source
            );
        }
    }

    /// When DNA has a non-empty UAI, x-caller-dna-uai is present.
    #[test]
    fn test_caller_headers_with_dna_uai() {
        let mut identity = make_identity(IdentitySource::SelfPresented);
        identity.agent_dna = Some(crate::identity::uai::types::AgentDna {
            uai: "uai:1:scid:abc12345.def12345.ghi12345.jkl12345".to_string(),
            birth_event: crate::identity::uai::types::BirthEvent {
                scid: "scid".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                initial_genesis: crate::identity::uai::types::GenesisFingerprint {
                    code_hash: "a".repeat(64),
                    model_spec: crate::identity::uai::types::ModelSpec {
                        provider: "test".to_string(),
                        model: "test".to_string(),
                        version: None,
                    },
                    config_hash: "b".repeat(64),
                    ownership_proof: None,
                    genesis_hash: "c".repeat(64),
                    computed_at: "2024-01-01T00:00:00Z".to_string(),
                },
                birth_entry_hash: "d".repeat(64),
            },
            genesis: crate::identity::uai::types::GenesisFingerprint {
                code_hash: "a".repeat(64),
                model_spec: crate::identity::uai::types::ModelSpec {
                    provider: "test".to_string(),
                    model: "test".to_string(),
                    version: None,
                },
                config_hash: "b".repeat(64),
                ownership_proof: None,
                genesis_hash: "c".repeat(64),
                computed_at: "2024-01-01T00:00:00Z".to_string(),
            },
            behavioral: crate::identity::uai::types::BehavioralFingerprint {
                latency_profile_hash: None,
                challenge_response_hash: None,
                token_pattern_hash: None,
                behavioral_hash: "e".repeat(64),
                measured_at: "2024-01-01T00:00:00Z".to_string(),
            },
            operational: crate::identity::uai::types::OperationalFingerprint {
                tee_attestation: None,
                cloud_attestation: None,
                capabilities_hash: "f".repeat(64),
                operational_hash: "g".repeat(64),
                attested_at: "2024-01-01T00:00:00Z".to_string(),
            },
            attestations: crate::identity::uai::types::AttestationData {
                merkle_root: "h".repeat(64),
                count: 1,
                last_updated: None,
            },
        });

        let headers = CallerHeaders::build(&identity, None);

        assert_eq!(headers.len(), 3, "Expected 3 headers with DNA, got {}", headers.len());
        assert_eq!(
            header_value(&headers, CallerHeaders::CALLER_DNA_UAI),
            Some("uai:1:scid:abc12345.def12345.ghi12345.jkl12345")
        );
    }

    /// When DNA is present but UAI is empty, x-caller-dna-uai is omitted.
    #[test]
    fn test_caller_headers_empty_uai_omitted() {
        let mut identity = make_identity(IdentitySource::GatewayComputed);
        identity.agent_dna = Some(crate::identity::uai::types::AgentDna {
            uai: String::new(), // empty — must not be emitted
            birth_event: crate::identity::uai::types::BirthEvent {
                scid: "s".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                initial_genesis: crate::identity::uai::types::GenesisFingerprint {
                    code_hash: "a".repeat(64),
                    model_spec: crate::identity::uai::types::ModelSpec {
                        provider: "t".to_string(),
                        model: "t".to_string(),
                        version: None,
                    },
                    config_hash: "b".repeat(64),
                    ownership_proof: None,
                    genesis_hash: "c".repeat(64),
                    computed_at: "2024-01-01T00:00:00Z".to_string(),
                },
                birth_entry_hash: "d".repeat(64),
            },
            genesis: crate::identity::uai::types::GenesisFingerprint {
                code_hash: "a".repeat(64),
                model_spec: crate::identity::uai::types::ModelSpec {
                    provider: "t".to_string(),
                    model: "t".to_string(),
                    version: None,
                },
                config_hash: "b".repeat(64),
                ownership_proof: None,
                genesis_hash: "c".repeat(64),
                computed_at: "2024-01-01T00:00:00Z".to_string(),
            },
            behavioral: crate::identity::uai::types::BehavioralFingerprint {
                latency_profile_hash: None,
                challenge_response_hash: None,
                token_pattern_hash: None,
                behavioral_hash: "e".repeat(64),
                measured_at: "2024-01-01T00:00:00Z".to_string(),
            },
            operational: crate::identity::uai::types::OperationalFingerprint {
                tee_attestation: None,
                cloud_attestation: None,
                capabilities_hash: "f".repeat(64),
                operational_hash: "g".repeat(64),
                attested_at: "2024-01-01T00:00:00Z".to_string(),
            },
            attestations: crate::identity::uai::types::AttestationData {
                merkle_root: "h".repeat(64),
                count: 0,
                last_updated: None,
            },
        });

        let headers = CallerHeaders::build(&identity, None);

        assert_eq!(headers.len(), 2, "x-caller-dna-uai must be omitted when UAI is empty");
        assert!(
            header_value(&headers, CallerHeaders::CALLER_DNA_UAI).is_none(),
            "x-caller-dna-uai header must not be present when UAI is empty"
        );
    }

    /// gateway_did = Some(non-empty) → x-gateway-did is appended.
    #[test]
    fn test_caller_headers_with_gateway_did() {
        let identity = make_identity(IdentitySource::GatewayComputed);
        let headers = CallerHeaders::build(&identity, Some("did:webvh:example.com:gw"));

        assert_eq!(headers.len(), 3, "Expected 3 headers with gateway DID, got {}", headers.len());
        assert_eq!(header_value(&headers, CallerHeaders::GATEWAY_DID), Some("did:webvh:example.com:gw"));
    }

    /// gateway_did = Some("") → x-gateway-did is omitted.
    #[test]
    fn test_caller_headers_empty_gateway_did_omitted() {
        let identity = make_identity(IdentitySource::GatewayComputed);
        let headers = CallerHeaders::build(&identity, Some(""));

        assert_eq!(headers.len(), 2, "x-gateway-did must be omitted when gateway_did is empty string");
        assert!(header_value(&headers, CallerHeaders::GATEWAY_DID).is_none(), "x-gateway-did must not be present");
    }

    /// gateway_did = None → x-gateway-did is omitted.
    #[test]
    fn test_caller_headers_none_gateway_did_omitted() {
        let identity = make_identity(IdentitySource::GatewayComputed);
        let headers = CallerHeaders::build(&identity, None);

        assert!(
            header_value(&headers, CallerHeaders::GATEWAY_DID).is_none(),
            "x-gateway-did must not be present when gateway_did is None"
        );
    }

    /// Constants match expected wire-format header names.
    #[test]
    fn test_caller_headers_constant_values() {
        assert_eq!(CallerHeaders::CALLER_DID, "x-caller-did");
        assert_eq!(CallerHeaders::CALLER_IDENTITY_SOURCE, "x-caller-identity-source");
        assert_eq!(CallerHeaders::CALLER_DNA_UAI, "x-caller-dna-uai");
        assert_eq!(CallerHeaders::GATEWAY_DID, "x-gateway-did");
    }
}
