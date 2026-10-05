use std::collections::HashMap;

use anyhow::Result;
use ssi_claims_core::SignatureEnvironment;
use ssi_json_ld::ContextLoader;

pub const CTX_AGENT_IDENTITY_V1: &str = include_str!("./contexts/agent-identity-v1.json");
pub const CTX_AGENT_IDENTITY_V1_URL: &str = "https://d2oeuqaac90cm.cloudfront.net/TAgentIdentityCredentialV1R0.jsonld";

pub const CTX_DELEGATION_V1: &str = include_str!("./contexts/delegation-v1.json");
pub const CTX_DELEGATION_V1_URL: &str = "https://fabric.affinidi.io/credentials/delegation/v1";

/// Contexts are embedded at compile time. Could be fetched via HTTP for flexibility.
/// @required_contexts - optional list of contexts to be preloaded, now not used, then can be used to fetch with HTTP
pub async fn create_signature_environment(
    _required_contexts: Option<Vec<String>>
) -> Result<SignatureEnvironment<ContextLoader>> {
    let mut ctx_map = HashMap::new();
    ctx_map.insert(CTX_AGENT_IDENTITY_V1_URL.to_string(), CTX_AGENT_IDENTITY_V1.to_string());
    ctx_map.insert(CTX_DELEGATION_V1_URL.to_string(), CTX_DELEGATION_V1.to_string());

    let loader = ContextLoader::default()
        .with_context_map_from(ctx_map)
        .map_err(|e| anyhow::anyhow!("Failed to create context loader: {}", e))?;

    Ok(SignatureEnvironment {
        json_ld_loader: loader,
        ..Default::default()
    })
}
