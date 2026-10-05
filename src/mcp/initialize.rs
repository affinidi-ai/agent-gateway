//! MCP initialization handshake handling

use axum::response::Response;
use serde_json::{Value as JsonValue, json};
use tracing::{debug, info};

use super::MCP_PROTOCOL_VERSION;
use super::errors::{create_mcp_error_response, error_codes};

/// Handle MCP initialize request
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_initialize(
    body: &JsonValue,
    channel_name: &str,
) -> Result<JsonValue, Response> {
    let params = body
        .get("params")
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'params' in initialize request",
                None,
            )
        })?;

    let client_info = params.get("clientInfo");
    let _client_capabilities = params.get("capabilities");
    let protocol_version = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or(MCP_PROTOCOL_VERSION);

    info!(
        channel = channel_name,
        protocol_version = protocol_version,
        client = ?client_info,
        "MCP initialize request received"
    );

    // Build server capabilities based on what we support
    let server_capabilities = json!({
        "logging": {},
        "prompts": {
            "listChanged": true
        },
        "resources": {
            "subscribe": true,
            "listChanged": true
        },
        "tools": {
            "listChanged": true
        }
    });

    // Create initialize response
    let response = json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": server_capabilities,
        "serverInfo": {
            "name": format!("Affinidi Trust Fabric Gateway - {}", channel_name),
            "version": env!("CARGO_PKG_VERSION"),
        }
    });

    debug!(channel = channel_name, "MCP initialize response: {}", serde_json::to_string(&response).unwrap_or_default());

    Ok(response)
}

/// Inject custom server metadata into initialize response
/// Similar to A2A custom metadata injection
pub fn inject_server_metadata(
    response: &mut JsonValue,
    custom_metadata: &Option<serde_json::Value>,
) {
    if let Some(metadata) = custom_metadata
        && let Some(server_info) = response.get_mut("serverInfo")
        && let Some(obj) = server_info.as_object_mut()
    {
        // Merge custom metadata into serverInfo
        if let Some(metadata_obj) = metadata.as_object() {
            for (key, value) in metadata_obj {
                obj.insert(key.clone(), value.clone());
            }
        }
    }
}
