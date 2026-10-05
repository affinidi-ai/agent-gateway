//! MCP prompts handling

use axum::response::Response;
use serde_json::Value as JsonValue;
use tracing::info;

use super::errors::{create_mcp_error_response, error_codes};

/// Handle prompts/list request - forward to upstream and capture
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_prompts_list(
    _body: &JsonValue,
    _channel_name: &str,
) -> Result<JsonValue, Response> {
    info!("Forwarding prompts/list to upstream");

    // Return empty list as placeholder - actual forwarding happens in handler
    Ok(serde_json::json!({
        "prompts": []
    }))
}

/// Handle prompts/get request - forward to upstream and capture
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_prompts_get(
    body: &JsonValue,
    _channel_name: &str,
) -> Result<JsonValue, Response> {
    let params = body
        .get("params")
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'params' in prompts/get request",
                None,
            )
        })?;

    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'name' in prompts/get params",
                None,
            )
        })?;

    info!("Forwarding prompts/get for prompt: {}", name);

    // This will be forwarded to upstream MCP server
    // Return placeholder - actual forwarding happens in handler
    Ok(serde_json::json!({
        "messages": []
    }))
}
