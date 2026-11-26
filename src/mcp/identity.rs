//! MCP-specific identity injection functions
//!
//! This module contains functions for injecting identity into MCP protocol
//! messages using the _meta field.

#[cfg(feature = "didwebvh")]
use serde_json::Value as JsonValue;

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
