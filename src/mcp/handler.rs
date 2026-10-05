//! MCP request routing and handling
//!
//! This module handles routing of MCP JSON-RPC requests to appropriate handlers

use crate::channel_info;
use axum::{
    body::Body,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value as JsonValue;
use tracing::{debug, info, warn};

use crate::mcp::*;
use crate::state::ProxyState;

/// Handle MCP request and route to appropriate handler based on method.
///
/// Channel OPA policy enforcement runs in the proxy pipeline's
/// general channel OPA gate (`proxy_handler_with_mcp_runtime`), which fires
/// AFTER extension inspection so the full `PolicyInput` (including
/// `extension_identity`, `identity_binding`, `agent`, `payment`) is available.
/// For MCP `tools/call`, that gate's denial response is reshaped into a
/// JSON-RPC `-32001` error via [`build_tools_call_policy_denied_response`].
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn handle_mcp_request(
    state: &ProxyState,
    body_bytes: &[u8],
    channel_name: &str,
) -> Result<JsonValue, Response> {
    // Parse JSON-RPC request
    let body: JsonValue = serde_json::from_slice(body_bytes).map_err(|e| {
        warn!(channel = channel_name, error = %e, "Failed to parse MCP request as JSON");
        create_mcp_error_response(
            None,
            error_codes::PARSE_ERROR,
            "Invalid JSON",
            Some(serde_json::json!({"details": e.to_string()})),
        )
    })?;

    // Validate JSON-RPC message
    if let Err(e) = validate_mcp_message(&body) {
        warn!(channel = channel_name, error = %e, "Invalid MCP message");
        return Err(create_mcp_error_response(body.get("id").cloned(), error_codes::INVALID_REQUEST, &e, None));
    }

    // Check if this is a notification (no response needed)
    if is_notification(&body) {
        // Handle notifications
        if let Some(method) = body
            .get("method")
            .and_then(|m| m.as_str())
        {
            match method {
                "notifications/message" => {
                    handle_logging_message(&body, channel_name).await;
                    // Notifications don't return responses
                    return Err(Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .unwrap());
                }
                _ => {
                    debug!(channel = channel_name, method = method, "Received unhandled MCP notification");
                }
            }
        }
        return Err(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap());
    }

    // Get method and ID for request routing
    let method = body
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or_else(|| {
            create_mcp_error_response(
                body.get("id").cloned(),
                error_codes::INVALID_REQUEST,
                "Missing 'method' field",
                None,
            )
        })?;

    let config_id = state
        .surface
        .surface_id
        .as_str();
    channel_info!(config_id, "Handling MCP request method={}", method);

    // Note: Rate limiting is checked in `proxy_handler_with_mcp_runtime` before this function is called.
    // Channel OPA `tools/call` enforcement is performed via `evaluate_tools_call_policy`
    // from the proxy pipeline after extension inspection (see this function's docs).

    // Route to appropriate handler based on method
    // All methods are forwarded to upstream
    match method {
        "initialize" => {
            // Initialize is special - we may want to modify it or handle it locally
            // For now, forward to upstream but signal that we want to inject metadata in response
            info!(
                channel = channel_name,
                method = method,
                "Initialize request - will forward to upstream and inject metadata"
            );
            Err(create_forward_signal())
        }
        // All other methods should be forwarded to upstream
        "tools/list"
        | "tools/call"
        | "resources/list"
        | "resources/read"
        | "prompts/list"
        | "prompts/get"
        | "sampling/createMessage" => {
            info!(channel = channel_name, method = method, "Standard MCP method - will forward to upstream");
            Err(create_forward_signal())
        }
        _ => {
            // For unknown methods, we'll also forward to upstream
            info!(channel = channel_name, method = method, "Unknown MCP method - will forward to upstream");
            Err(create_forward_signal())
        }
    }
}

/// Check if the request is an MCP protocol request
pub fn is_mcp_request(
    headers: &HeaderMap,
    body_bytes: &[u8],
) -> bool {
    // Check Content-Type header
    if let Some(content_type) = headers.get("content-type")
        && let Ok(ct_str) = content_type.to_str()
        && ct_str.contains("application/json")
    {
        // Try to parse as JSON and check for jsonrpc field
        if let Ok(body) = serde_json::from_slice::<JsonValue>(body_bytes)
            && body
                .get("jsonrpc")
                .and_then(|v| v.as_str())
                == Some("2.0")
        {
            return true;
        }
    }

    false
}

/// Create a response that signals the proxy should forward to upstream
/// This is a special marker response that the proxy handler will recognize
fn create_forward_signal() -> Response {
    // Use a special status code to signal forwarding
    Response::builder()
        .status(StatusCode::OK)
        .header("X-MCP-Forward", "true")
        .body(Body::empty())
        .unwrap()
}

/// Inject custom metadata into MCP initialize response
pub fn inject_mcp_metadata(
    response: &mut JsonValue,
    custom_metadata: &Option<serde_json::Value>,
) {
    inject_server_metadata(response, custom_metadata);
}

/// Build the JSON-RPC `-32001` policy-denial **envelope body** for an MCP
/// `tools/call` request. The returned value is the plain JSON-RPC payload
/// (`{"jsonrpc":"2.0","id":…,"error":{…}}`) without an HTTP wrapper, so it can
/// be embedded in any transport — the direct path wraps it in an axum
/// `Response`, the G2G connection-point path embeds it inside a
/// `ForwardResponse` `body` string.
///
/// `body_bytes` is the original request body — the JSON-RPC `id` and tool name
/// are extracted from it (missing/invalid → `null` id, generic message).
pub fn build_tools_call_policy_denied_envelope(
    body_bytes: &[u8],
    deny_reason: Option<&str>,
) -> JsonValue {
    let body: Option<JsonValue> = serde_json::from_slice(body_bytes).ok();
    let id = body
        .as_ref()
        .and_then(|b| b.get("id"))
        .cloned();
    let tool_name = body
        .as_ref()
        .and_then(|b| b.get("params"))
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("<unknown>")
        .to_string();
    let message = match deny_reason {
        Some(reason) if !reason.is_empty() => {
            format!("Tool '{}' is not allowed by policy: {}", tool_name, reason)
        }
        _ => format!("Tool '{}' is not allowed by policy", tool_name),
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32001,
            "message": message,
        },
    })
}

/// Build a JSON-RPC `-32001` policy-denial axum response for an MCP
/// `tools/call` request. Used by the direct path so a denied MCP call lands on
/// the client as a protocol-shaped error instead of HTTP 403. The body is
/// produced by [`build_tools_call_policy_denied_envelope`].
pub fn build_tools_call_policy_denied_response(
    body_bytes: &[u8],
    deny_reason: Option<&str>,
) -> Response {
    let envelope = build_tools_call_policy_denied_envelope(body_bytes, deny_reason);
    let id = envelope.get("id").cloned();
    let error = &envelope["error"];
    let message = error["message"]
        .as_str()
        .unwrap_or("Tool is not allowed by policy");
    create_mcp_error_response(id, -32001, message, None)
}

/// Best-effort check: returns `true` when the request body parses as a
/// JSON-RPC `tools/call`. Used by the channel OPA gate to decide whether to
/// emit an MCP-shaped denial response.
pub fn is_tools_call_request(body_bytes: &[u8]) -> bool {
    serde_json::from_slice::<JsonValue>(body_bytes)
        .ok()
        .and_then(|b| {
            b.get("method")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
        })
        .is_some_and(|m| m == "tools/call")
}

/// Best-effort check: returns `true` when the request body parses as a
/// JSON-RPC `tools/list`. Used to decide whether an SSE response must be
/// buffered so the MCP tool-list filter / gating can run on it.
pub fn is_tools_list_request(body_bytes: &[u8]) -> bool {
    serde_json::from_slice::<JsonValue>(body_bytes)
        .ok()
        .and_then(|b| {
            b.get("method")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
        })
        .is_some_and(|m| m == "tools/list")
}

/// Build the empty `tools/list` result used when a gated response cannot be
/// inspected. The id is echoed from the request, and a modern result carries
/// the `resultType` and cache hints its schema requires.
pub fn fail_closed_tools_list(
    request_body: &[u8],
    context: crate::mcp::meta::McpMetadataContext,
) -> String {
    let id = serde_json::from_slice::<JsonValue>(request_body)
        .ok()
        .and_then(|body| body.get("id").cloned())
        .unwrap_or(JsonValue::Null);
    let mut result = serde_json::json!({ "tools": [] });
    if context.is_modern() {
        result["resultType"] = serde_json::json!("complete");
        result["ttlMs"] = serde_json::json!(0);
        result["cacheScope"] = serde_json::json!("private");
    }
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use serde_json::json;

    fn body(json_value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json_value).unwrap()
    }

    #[test]
    fn is_tools_call_request_true_for_tools_call() {
        let b = body(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}}));
        assert!(is_tools_call_request(&b));
    }

    #[test]
    fn is_tools_call_request_false_for_other_methods() {
        let b = body(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
        assert!(!is_tools_call_request(&b));
    }

    #[test]
    fn is_tools_call_request_false_for_invalid_json() {
        assert!(!is_tools_call_request(b"not json"));
        assert!(!is_tools_call_request(b""));
    }

    #[test]
    fn is_tools_list_request_true_only_for_tools_list() {
        let list = body(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
        assert!(is_tools_list_request(&list));
        let call = body(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}}));
        assert!(!is_tools_list_request(&call));
        assert!(!is_tools_list_request(b"not json"));
    }

    #[test]
    fn fail_closed_tools_list_echoes_the_request_id_and_keeps_modern_results_valid() {
        use crate::mcp::meta::McpMetadataContext;
        use crate::mcp::request_validation::{McpRequestClassification, McpVersionPolicy, validate_mcp_post};

        let request = body(json!({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list"}));
        let legacy: serde_json::Value =
            serde_json::from_str(&fail_closed_tools_list(&request, McpMetadataContext::legacy(None))).unwrap();
        assert_eq!(legacy, json!({"jsonrpc": "2.0", "id": "list-1", "result": {"tools": []}}));

        let unparsable =
            serde_json::from_str::<serde_json::Value>(&fail_closed_tools_list(b"", McpMetadataContext::legacy(None)))
                .unwrap();
        assert_eq!(unparsable["id"], serde_json::Value::Null);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-method", "tools/list".parse().unwrap());
        let modern_request = body(json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}}));
        let classification = validate_mcp_post(
            &headers,
            &modern_request,
            crate::mcp::request_validation::LegacySessionEvidence::Absent,
            McpVersionPolicy::new(&[crate::mcp::MCP_MODERN_VERSION], &[crate::mcp::MCP_MODERN_VERSION]),
        )
        .unwrap();
        let McpRequestClassification::Modern(admitted) = &classification else {
            panic!("expected an admitted modern request");
        };
        let context = McpMetadataContext::from_classification(&classification, None);
        let modern: serde_json::Value =
            serde_json::from_str(&fail_closed_tools_list(&modern_request, context)).unwrap();
        assert_eq!(modern["id"], 7);
        assert_eq!(modern["result"]["tools"], json!([]));
        assert_eq!(
            crate::mcp::modern::validate_response(admitted, &modern, crate::mcp::modern::ResultSource::ModernServer),
            Ok(Some("complete"))
        );
        assert_eq!(modern["result"]["cacheScope"], "private");
        assert_eq!(modern["result"]["ttlMs"], 0);
    }

    async fn response_to_json(resp: Response) -> serde_json::Value {
        let (_parts, body) = resp.into_parts();
        let bytes = to_bytes(body, usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn build_tools_call_policy_denied_response_preserves_id_and_tool_name() {
        let req = body(json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}}
        }));
        let resp = build_tools_call_policy_denied_response(&req, None);
        assert_eq!(resp.status(), StatusCode::OK);
        let j = response_to_json(resp).await;
        assert_eq!(j["jsonrpc"], "2.0");
        assert_eq!(j["id"], 42);
        assert_eq!(j["error"]["code"], -32001);
        assert_eq!(j["error"]["message"], "Tool 'search' is not allowed by policy");
    }

    #[tokio::test]
    async fn build_tools_call_policy_denied_response_appends_deny_reason() {
        let req = body(json!({
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "tools/call",
            "params": {"name": "delete_all"}
        }));
        let resp = build_tools_call_policy_denied_response(&req, Some("requires admin role"));
        let j = response_to_json(resp).await;
        assert_eq!(j["id"], "abc");
        assert_eq!(j["error"]["code"], -32001);
        assert_eq!(j["error"]["message"], "Tool 'delete_all' is not allowed by policy: requires admin role");
    }

    #[tokio::test]
    async fn build_tools_call_policy_denied_response_falls_back_when_fields_missing() {
        let resp = build_tools_call_policy_denied_response(b"not json", None);
        let j = response_to_json(resp).await;
        assert!(j["id"].is_null());
        assert_eq!(j["error"]["code"], -32001);
        assert_eq!(j["error"]["message"], "Tool '<unknown>' is not allowed by policy");
    }

    #[tokio::test]
    async fn build_tools_call_policy_denied_response_ignores_empty_deny_reason() {
        let req = body(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "echo"}
        }));
        let resp = build_tools_call_policy_denied_response(&req, Some(""));
        let j = response_to_json(resp).await;
        assert_eq!(j["error"]["message"], "Tool 'echo' is not allowed by policy");
    }

    #[test]
    fn build_tools_call_policy_denied_envelope_returns_jsonrpc_payload() {
        let req = body(json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "delete_all"}
        }));
        let env = build_tools_call_policy_denied_envelope(&req, Some("requires admin role"));
        assert_eq!(env["jsonrpc"], "2.0");
        assert_eq!(env["id"], 11);
        assert_eq!(env["error"]["code"], -32001);
        assert_eq!(env["error"]["message"], "Tool 'delete_all' is not allowed by policy: requires admin role");
    }

    #[test]
    fn build_tools_call_policy_denied_envelope_falls_back_when_fields_missing() {
        let env = build_tools_call_policy_denied_envelope(b"not json", None);
        assert!(env["id"].is_null());
        assert_eq!(env["error"]["code"], -32001);
        assert_eq!(env["error"]["message"], "Tool '<unknown>' is not allowed by policy");
    }
}
