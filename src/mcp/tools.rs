//! MCP tools handling

use axum::response::Response;
use serde_json::Value as JsonValue;
use tracing::info;

use super::errors::{create_mcp_error_response, error_codes};

/// Handle tools/list request - forward to upstream and capture
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_tools_list(
    _body: &JsonValue,
    _channel_name: &str,
) -> Result<JsonValue, Response> {
    // This will be forwarded to upstream MCP server
    // The proxy will capture and potentially cache the tool list
    info!("Forwarding tools/list to upstream");

    // Return empty list as placeholder - actual forwarding happens in handler
    Ok(serde_json::json!({
        "tools": []
    }))
}

/// Handle tools/call request - forward to upstream and capture
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_tools_call(
    body: &JsonValue,
    _channel_name: &str,
) -> Result<JsonValue, Response> {
    let params = body
        .get("params")
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'params' in tools/call request",
                None,
            )
        })?;

    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'name' in tools/call params",
                None,
            )
        })?;

    info!("Forwarding tools/call for tool: {}", tool_name);

    // This will be forwarded to upstream MCP server
    // Return placeholder - actual forwarding happens in handler
    Ok(serde_json::json!({
        "content": []
    }))
}
