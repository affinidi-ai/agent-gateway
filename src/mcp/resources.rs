//! MCP resources handling

use axum::response::Response;
use serde_json::Value as JsonValue;
use tracing::info;

use super::errors::{create_mcp_error_response, error_codes};

/// Handle resources/list request - forward to upstream and capture
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_resources_list(
    _body: &JsonValue,
    _channel_name: &str,
) -> Result<JsonValue, Response> {
    info!("Forwarding resources/list to upstream");

    // Return empty list as placeholder - actual forwarding happens in handler
    Ok(serde_json::json!({
        "resources": []
    }))
}

/// Handle resources/read request - forward to upstream and capture
#[allow(dead_code)]
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_resources_read(
    body: &JsonValue,
    _channel_name: &str,
) -> Result<JsonValue, Response> {
    let params = body
        .get("params")
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'params' in resources/read request",
                None,
            )
        })?;

    let uri = params
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_PARAMS,
                "Missing 'uri' in resources/read params",
                None,
            )
        })?;

    info!("Forwarding resources/read for URI: {}", uri);

    // This will be forwarded to upstream MCP server
    // Return placeholder - actual forwarding happens in handler
    Ok(serde_json::json!({
        "contents": []
    }))
}
