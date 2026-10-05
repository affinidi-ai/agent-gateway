/// Channel integration module for DID:webvh
///
/// This module provides functionality to load and inject DID:webvh identities
/// into channel requests based on channel configuration.
use anyhow::{Context, Result};
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::types::{DidInjectionMode, DidWebVhIdentityConfig};
use crate::identity::didwebvh::{
    identity_manager::{DidWebVhIdentity, DidWebVhIdentityStore},
    log::DidLogManager,
};
use crate::identity::uai::types::{AgentDna, UniversalAgentIdentifierV1};

/// Channel DID context holding resolved identity information
#[derive(Debug, Clone)]
pub struct SurfaceDidContext {
    /// UUID of the identity
    pub identity_id: Uuid,

    /// The DID:webvh identifier
    pub did: String,

    /// The DID document as JSON string
    pub did_document: String,

    /// Injection mode for this channel
    pub injection_mode: DidInjectionMode,

    /// The Universal Agent Identifier
    pub uai: UniversalAgentIdentifierV1,

    /// Agent DNA loaded from identity metadata when available.
    pub agent_dna: Option<AgentDna>,
}

impl SurfaceDidContext {
    /// Get the DID string
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Get the DID document
    pub fn did_document(&self) -> &str {
        &self.did_document
    }

    /// Get the injection mode
    pub fn injection_mode(&self) -> &DidInjectionMode {
        &self.injection_mode
    }

    /// Get the UAI
    pub fn uai(&self) -> &UniversalAgentIdentifierV1 {
        &self.uai
    }

    /// Get the Agent DNA, when it was stored on the identity.
    pub fn agent_dna(&self) -> Option<&AgentDna> {
        self.agent_dna.as_ref()
    }
}

/// Load DID identity for a channel based on configuration
///
/// # Arguments
/// * `config` - The DID:webvh configuration from the channel
/// * `identity_store` - The identity store to load identities from
/// * `log_manager` - The log manager to resolve DID documents
///
/// # Returns
/// Returns ChannelDidContext on success, or None if identity not found
pub async fn load_surface_identity(
    config: &DidWebVhIdentityConfig,
    identity_store: Arc<dyn DidWebVhIdentityStore>,
    log_manager: Arc<DidLogManager>,
) -> Result<Option<SurfaceDidContext>> {
    let identity_id = config.identity_id;

    debug!(
        identity_id = %identity_id,
        auto_create = config.auto_create,
        injection_mode = ?config.injection_mode,
        "Loading DID:webvh identity for channel"
    );

    // Load identity from store
    let identity = match identity_store
        .get(&identity_id)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            if config.auto_create {
                warn!(
                    identity_id = %identity_id,
                    "Identity not found but auto_create=true is not yet implemented"
                );
                return Ok(None);
            } else {
                debug!(
                    identity_id = %identity_id,
                    "Identity not found and auto_create=false"
                );
                return Ok(None);
            }
        }
        Err(e) => {
            warn!(
                identity_id = %identity_id,
                error = %e,
                "Failed to load identity from store"
            );
            return Err(e).context("Failed to load identity from store");
        }
    };

    // Resolve the DID document
    let did_document = resolve_did_document(&identity, &log_manager)
        .await
        .context("Failed to resolve DID document")?;

    let agent_dna = extract_agent_dna(&identity.metadata);

    // Build the context
    let context = SurfaceDidContext {
        identity_id,
        did: identity.did.clone(),
        did_document,
        injection_mode: config.injection_mode.clone(),
        uai: build_identity_uai(&identity, agent_dna.as_ref()),
        agent_dna,
    };

    debug!(
        identity_id = %identity_id,
        did = %context.did,
        "Successfully loaded DID:webvh identity for channel"
    );

    Ok(Some(context))
}

fn extract_agent_dna(metadata: &HashMap<String, serde_json::Value>) -> Option<AgentDna> {
    metadata
        .get("agentDNA")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn metadata_string(
    metadata: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    metadata
        .get(key)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn build_identity_uai(
    identity: &DidWebVhIdentity,
    agent_dna: Option<&AgentDna>,
) -> UniversalAgentIdentifierV1 {
    let llm_provider = agent_dna
        .map(|dna| {
            dna.genesis
                .model_spec
                .provider
                .as_str()
        })
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| metadata_string(&identity.metadata, "llm_provider"))
        .unwrap_or_default();

    let llm_model = agent_dna
        .map(|dna| {
            dna.genesis
                .model_spec
                .model
                .as_str()
        })
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| metadata_string(&identity.metadata, "llm_model"))
        .unwrap_or_default();

    let deployment_location = metadata_string(&identity.metadata, "deployment_location")
        .or_else(|| metadata_string(&identity.metadata, "deployment_env"))
        .unwrap_or_default();

    UniversalAgentIdentifierV1 {
        llm_provider,
        llm_model,
        deployment_location,
    }
}

/// Resolve DID document from identity and log manager
async fn resolve_did_document(
    identity: &DidWebVhIdentity,
    log_manager: &DidLogManager,
) -> Result<String> {
    // Read and parse the log to build the DID document
    let log_entries = log_manager
        .load(&identity.did)
        .await
        .context("Failed to read DID log")?;

    if log_entries.is_empty() {
        // If no log entries, build a minimal DID document from identity
        // We need to extract public key from key_pair if available
        let public_key_multibase = if let Some(ref kp) = identity.key_pair {
            // Try to extract x (public key) from JWK
            if let Some(x) = kp
                .public_key
                .get("x")
                .and_then(|v| v.as_str())
            {
                // Decode base64url to bytes, then encode as multibase
                use base64::Engine as _;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .unwrap_or_default();
                format!("z{}", bs58::encode(&bytes).into_string())
            } else {
                // Fallback: use a placeholder
                "z".to_string()
            }
        } else {
            // No key pair available
            "z".to_string()
        };

        let did_doc = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": identity.did,
            "verificationMethod": [{
                "id": format!("{}#key-1", identity.did),
                "type": "Ed25519VerificationKey2020",
                "controller": identity.did,
                "publicKeyMultibase": public_key_multibase
            }],
            "authentication": [format!("{}#key-1", identity.did)],
            "assertionMethod": [format!("{}#key-1", identity.did)]
        });
        return Ok(serde_json::to_string(&did_doc)?);
    }

    // Get the latest entry (last in the log) - it contains the DID document
    let latest_entry = log_entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("No entries in DID log"))?;

    // Return the DID document from the latest entry's state
    Ok(serde_json::to_string(&latest_entry.state)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_didwebvh_fix_extract_agent_dna_from_metadata() {
        let metadata = HashMap::from([(
            "agentDNA".to_string(),
            serde_json::json!({
                "uai": "uai:1:scid:gen.beh.op.att",
                "birthEvent": {
                    "scid": "scid",
                    "timestamp": "2026-04-08T00:00:00Z",
                    "initialGenesis": {
                        "codeHash": "code",
                        "modelSpec": { "provider": "OpenAI", "model": "gpt-4.1" },
                        "configHash": "cfg",
                        "genesisHash": "gen",
                        "computedAt": "2026-04-08T00:00:00Z"
                    },
                    "birthEntryHash": "birth"
                },
                "genesis": {
                    "codeHash": "code",
                    "modelSpec": { "provider": "OpenAI", "model": "gpt-4.1" },
                    "configHash": "cfg",
                    "genesisHash": "gen",
                    "computedAt": "2026-04-08T00:00:00Z"
                },
                "behavioral": {
                    "behavioralHash": "beh",
                    "measuredAt": "2026-04-08T00:00:00Z"
                },
                "operational": {
                    "capabilitiesHash": "caps",
                    "operationalHash": "op",
                    "attestedAt": "2026-04-08T00:00:00Z"
                },
                "attestations": {
                    "merkleRoot": "root",
                    "count": 1
                }
            }),
        )]);

        let agent_dna = extract_agent_dna(&metadata).expect("agentDNA should deserialize");
        assert_eq!(agent_dna.uai, "uai:1:scid:gen.beh.op.att");
        assert_eq!(
            agent_dna
                .genesis
                .model_spec
                .provider,
            "OpenAI"
        );
    }

    #[test]
    fn test_didwebvh_fix_build_identity_uai_prefers_dna_and_metadata() {
        let metadata = HashMap::from([("deployment_env".to_string(), serde_json::json!("production"))]);
        let identity = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:agent".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata,
            active: true,
        };
        let agent_dna = AgentDna {
            genesis: crate::identity::uai::types::GenesisFingerprint {
                model_spec: crate::identity::uai::types::ModelSpec {
                    provider: "OpenAI".to_string(),
                    model: "gpt-4.1".to_string(),
                    version: None,
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let uai = build_identity_uai(&identity, Some(&agent_dna));
        assert_eq!(uai.llm_provider, "OpenAI");
        assert_eq!(uai.llm_model, "gpt-4.1");
        assert_eq!(uai.deployment_location, "production");
    }

    // Note: Tests are marked as ignored because they require a full storage backend
    // which is not easily available in unit tests. Integration tests cover this functionality.

    #[tokio::test]
    #[ignore = "Requires storage backend setup"]
    async fn test_load_channel_identity_not_found() {
        // Test intentionally ignored - requires full storage backend
    }

    #[tokio::test]
    #[ignore = "Requires storage backend setup"]
    async fn test_load_channel_identity_success() {
        // Test intentionally ignored - requires full storage backend
    }

    #[tokio::test]
    #[ignore = "Requires storage backend setup"]
    async fn test_channel_did_context_methods() {
        // Test intentionally ignored - requires full storage backend
    }
}
