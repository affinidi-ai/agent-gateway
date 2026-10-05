//! MCP sampling (LLM requests) handling
//!
//! Deprecated: MCP `2026-07-28` deprecates sampling in favour of direct LLM
//! provider integration. Kept for legacy (`2024-11-05`) peers only; do not
//! extend it or wire it into modern handling.

use axum::response::Response;
use serde_json::Value as JsonValue;
use tracing::info;

use super::errors::{create_mcp_error_response, error_codes};

/// Handle sampling/createMessage request - forward to upstream and capture
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_sampling_create_message(
    body: &JsonValue,
    _channel_name: &str,
) -> Result<JsonValue, Response> {
    let params = body
        .get("params")
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'params' in sampling/createMessage request",
                None,
            )
        })?;

    let messages = params
        .get("messages")
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'messages' in sampling/createMessage params",
                None,
            )
        })?;

    info!(
        "Forwarding sampling/createMessage with {} messages",
        messages
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0)
    );

    // This will be forwarded to upstream MCP server
    // Return placeholder - actual forwarding happens in handler
    Ok(serde_json::json!({
        "role": "assistant",
        "content": {
            "type": "text",
            "text": ""
        }
    }))
}
