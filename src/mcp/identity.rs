//! MCP-specific identity injection functions
//!
//! This module contains functions for injecting identity credentials into MCP
//! protocol messages using the _meta field.

use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::info;

/// Inject identity credential into MCP request (_meta field)
/// For MCP protocol, we:
/// 1. Remove _meta[meta_field_name] (raw identity data)
/// 2. Add _meta[EXTENSION_URI] with the VP containing the DID
#[allow(dead_code)]
pub async fn inject_identity_credential_mcp(
    body_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
    meta_field_name: &str,
    context: super::meta::McpMetadataContext,
) -> anyhow::Result<bytes::Bytes> {
    let mut body_json: JsonValue = serde_json::from_slice(body_bytes)?;
    super::meta::normalize_metadata(&mut body_json, context)?;
    super::meta::validate_raw_identity_key(meta_field_name, context)?;
    super::meta::remove_metadata_key(&mut body_json, meta_field_name);
    // Create VP containing VC signed by agent DID
    let vp_jwt = vc_issuer
        .create_agent_identity_presentation(agent_did, identity_fields, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create identity presentation: {}", e))?;

    info!(channel = channel_name, did = agent_did, "Created identity credential VP for MCP forwarding");

    let extension_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    super::meta::insert_gateway_metadata(
        &mut body_json,
        context,
        super::meta::McpMetaTarget::TopLevel,
        extension_uri,
        serde_json::json!({
            "verifiablePresentation": vp_jwt,
            "did": agent_did,
        }),
    )?;

    info!(channel = channel_name, "Injected identity credential VP into MCP _meta field, removed raw identity");

    // Serialize back to bytes
    let modified_json =
        serde_json::to_vec(&body_json).map_err(|e| anyhow::anyhow!("Failed to serialize modified JSON: {}", e))?;

    Ok(bytes::Bytes::from(modified_json))
}

/// Inject DID:webvh identity into MCP _meta field (protocol-native mode)
#[cfg(feature = "didwebvh")]
pub async fn inject_didwebvh_identity_mcp(
    body_bytes: &bytes::Bytes,
    did_context: &crate::identity::didwebvh::SurfaceDidContext,
    channel_name: &str,
    context: super::meta::McpMetadataContext,
) -> anyhow::Result<bytes::Bytes> {
    use tracing::debug;

    // Parse the body as JSON
    let mut body_json: JsonValue =
        serde_json::from_slice(body_bytes).map_err(|e| anyhow::anyhow!("Failed to parse body as JSON: {}", e))?;

    // Use a dedicated field for DID:webvh identity in MCP
    let identity_field = "didwebvhIdentity";

    // Add DID identity to _meta
    let identity_data = serde_json::json!({
        "did": did_context.did(),
        "uai": {
            "llm_provider": did_context.uai().llm_provider,
            "llm_model": did_context.uai().llm_model,
            "deployment_location": did_context.uai().deployment_location,
        }
    });

    super::meta::insert_gateway_metadata(
        &mut body_json,
        context,
        super::meta::McpMetaTarget::TopLevel,
        identity_field,
        identity_data,
    )?;
    debug!(
        channel = channel_name,
        field = identity_field,
        did = %did_context.did(),
        "Added DID:webvh identity to MCP _meta field"
    );

    // Serialize back to bytes
    let modified_json =
        serde_json::to_vec(&body_json).map_err(|e| anyhow::anyhow!("Failed to serialize modified JSON: {}", e))?;

    Ok(bytes::Bytes::from(modified_json))
}
