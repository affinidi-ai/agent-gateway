//! MCP JSON-RPC request analyzer
//!
//! Extracts tool/method information from MCP requests for policy evaluation

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Parsed MCP tool request information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolRequest {
    /// The JSON-RPC method/tool name (e.g., "echo", "get_resource", "call_function")
    pub method: String,

    /// Tool parameters (optional)
    pub params: Option<Value>,

    /// JSON-RPC request ID
    pub id: Value,

    /// JSON-RPC protocol version
    #[serde(default = "default_jsonrpc_version")]
    pub jsonrpc: String,
}

fn default_jsonrpc_version() -> String {
    "2.0".to_string()
}

impl McpToolRequest {
    /// Parse an MCP JSON-RPC request from bytes
    ///
    /// # Example
    /// ```
    /// let body = r#"{"jsonrpc":"2.0","method":"echo","params":{"message":"hello"},"id":1}"#;
    /// let request = McpToolRequest::from_json_rpc(body.as_bytes()).unwrap();
    /// assert_eq!(request.method, "echo");
    /// ```
    pub fn from_json_rpc(body: &[u8]) -> Result<Self> {
        // Parse as JSON
        let json: Value = serde_json::from_slice(body).context("Failed to parse MCP request as JSON")?;

        // Extract method
        let method = json
            .get("method")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'method' field in JSON-RPC request"))?
            .to_string();

        // Extract params (optional)
        let params = json.get("params").cloned();

        // Extract id
        let id = json
            .get("id")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Missing 'id' field in JSON-RPC request"))?;

        // Extract jsonrpc version (default to "2.0" if missing)
        let jsonrpc = json
            .get("jsonrpc")
            .and_then(|v| v.as_str())
            .unwrap_or("2.0")
            .to_string();

        Ok(Self { method, params, id, jsonrpc })
    }

    /// Check if this is a specific method
    #[allow(dead_code)]
    pub fn is_method(
        &self,
        method_name: &str,
    ) -> bool {
        self.method == method_name
    }

    /// Get a parameter value by key
    #[allow(dead_code)]
    pub fn get_param(
        &self,
        key: &str,
    ) -> Option<&Value> {
        self.params.as_ref()?.get(key)
    }

    pub fn tool_name(&self) -> Option<&str> {
        if self.method != "tools/call" {
            return None;
        }

        self.params
            .as_ref()?
            .get("name")?
            .as_str()
    }
}

/// Why an MCP POST body is refused at admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyRefusal {
    /// A JSON-RPC batch (a top-level array): 422.
    Batch,
    /// Not JSON serde can parse, such as a batch behind a UTF-8 BOM:
    /// JSON-RPC `-32700`.
    NotJson(String),
    /// JSON that is not an object: JSON-RPC `-32600`.
    NotObject,
}

impl BodyRefusal {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Batch => "JSON-RPC batch",
            Self::NotJson(_) => "invalid JSON",
            Self::NotObject => "not a JSON-RPC object",
        }
    }

    /// The caller's response. Unparseable and non-object bodies get the same
    /// JSON-RPC errors as the Access Point's malformed-body guard.
    pub fn into_response(self) -> axum::response::Response {
        match self {
            Self::Batch => crate::a2a::create_error_response(
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "JSON-RPC batches are not supported",
            ),
            Self::NotJson(details) => super::create_mcp_error_response(
                None,
                super::error_codes::PARSE_ERROR,
                "Invalid JSON",
                Some(serde_json::json!({ "details": details })),
            ),
            Self::NotObject => super::create_mcp_error_response(
                None,
                super::error_codes::INVALID_REQUEST,
                "Invalid JSON-RPC request",
                None,
            ),
        }
    }
}

/// Why an MCP POST body is refused at admission, or `None` when it is one
/// JSON-RPC object.
///
/// Access Points, Transit Points and Fabric receive refuse anything else:
/// tool gating, tool-scoped credentials and MCP identity verification each
/// read one JSON-RPC object, and [`called_tool_name`] reports no tool for a
/// batch or a body serde can't parse. An upstream may still accept such a
/// body (a lenient parser strips a UTF-8 BOM, for example) and run every
/// call in it unchecked.
pub fn single_object_refusal(body: &[u8]) -> Option<BodyRefusal> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(_)) => None,
        Ok(Value::Array(_)) => Some(BodyRefusal::Batch),
        Ok(_) => Some(BodyRefusal::NotObject),
        Err(error) => Some(BodyRefusal::NotJson(error.to_string())),
    }
}

/// The tool a request calls: `params.name` of a single JSON-RPC `tools/call`,
/// with or without an `id`. Batches, other methods, and unparseable bodies
/// call no tool, so callers must refuse them first (see
/// [`single_object_refusal`]).
pub fn called_tool_name(body: &[u8]) -> Option<String> {
    let request: Value = serde_json::from_slice(body).ok()?;
    if request
        .get("method")?
        .as_str()?
        != "tools/call"
    {
        return None;
    }
    request
        .get("params")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_echo_request() {
        let body = r#"{"jsonrpc":"2.0","method":"echo","params":{"message":"hello"},"id":1}"#;
        let request = McpToolRequest::from_json_rpc(body.as_bytes()).unwrap();

        assert_eq!(request.method, "echo");
        assert_eq!(request.jsonrpc, "2.0");
        assert!(request.params.is_some());
        assert_eq!(request.id, serde_json::json!(1));
    }

    #[test]
    fn test_parse_request_without_params() {
        let body = r#"{"jsonrpc":"2.0","method":"list_resources","id":"abc-123"}"#;
        let request = McpToolRequest::from_json_rpc(body.as_bytes()).unwrap();

        assert_eq!(request.method, "list_resources");
        assert!(request.params.is_none());
        assert_eq!(request.id, serde_json::json!("abc-123"));
    }

    #[test]
    fn test_is_method() {
        let body = r#"{"jsonrpc":"2.0","method":"get_resource","id":1}"#;
        let request = McpToolRequest::from_json_rpc(body.as_bytes()).unwrap();

        assert!(request.is_method("get_resource"));
        assert!(!request.is_method("echo"));
    }

    #[test]
    fn test_get_param() {
        let body = r#"{"jsonrpc":"2.0","method":"echo","params":{"message":"hello","count":5},"id":1}"#;
        let request = McpToolRequest::from_json_rpc(body.as_bytes()).unwrap();

        assert_eq!(
            request
                .get_param("message")
                .unwrap(),
            &serde_json::json!("hello")
        );
        assert_eq!(
            request
                .get_param("count")
                .unwrap(),
            &serde_json::json!(5)
        );
        assert!(
            request
                .get_param("nonexistent")
                .is_none()
        );
    }

    #[test]
    fn test_tool_name_returns_tools_call_name() {
        let body = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{}},"id":1}"#;
        let request = McpToolRequest::from_json_rpc(body.as_bytes()).unwrap();

        assert_eq!(request.tool_name(), Some("echo"));
    }

    #[test]
    fn test_tool_name_ignores_non_tool_methods() {
        let body = r#"{"jsonrpc":"2.0","method":"tools/list","params":{"name":"echo"},"id":1}"#;
        let request = McpToolRequest::from_json_rpc(body.as_bytes()).unwrap();

        assert_eq!(request.tool_name(), None);
    }

    #[test]
    fn called_tool_name_reads_only_single_tools_call() {
        assert_eq!(
            called_tool_name(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#),
            Some("echo".to_string())
        );
        assert_eq!(
            called_tool_name(br#"{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"echo"}}"#),
            None
        );
        assert_eq!(
            called_tool_name(br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}]"#),
            None
        );
        assert_eq!(
            called_tool_name(br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}"#),
            Some("echo".to_string())
        );
        assert_eq!(called_tool_name(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#), None);
        assert_eq!(called_tool_name(b"not json"), None);
    }

    #[test]
    fn single_object_refusal_admits_only_one_json_object() {
        for (body, expected) in [
            (&br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"[x]"}}"#[..], None),
            (b" \r\n\t{}", None),
            (br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#, Some("JSON-RPC batch")),
            (b" \r\n\t[]", Some("JSON-RPC batch")),
            (b"\xEF\xBB\xBF[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}]", Some("invalid JSON")),
            (b"\xEF\xBB\xBF{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", Some("invalid JSON")),
            (b"", Some("invalid JSON")),
            (b"{\"jsonrpc\":", Some("invalid JSON")),
            (b"{} {}", Some("invalid JSON")),
            (b"\"tools/call\"", Some("not a JSON-RPC object")),
            (b"42", Some("not a JSON-RPC object")),
        ] {
            assert_eq!(
                single_object_refusal(body)
                    .as_ref()
                    .map(BodyRefusal::reason),
                expected,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[tokio::test]
    async fn body_refusals_match_the_malformed_body_guard() {
        for (body, status, expected) in [
            (
                &b"[]"[..],
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({"type": "https://a2a-protocol.org/errors/proxy-error", "title": "Unprocessable Entity",
                    "status": 422, "detail": "JSON-RPC batches are not supported"}),
            ),
            (
                b"42",
                axum::http::StatusCode::OK,
                serde_json::json!({"jsonrpc": "2.0", "id": null,
                    "error": {"code": -32600, "message": "Invalid JSON-RPC request"}}),
            ),
        ] {
            let response = single_object_refusal(body)
                .unwrap()
                .into_response();
            assert_eq!(response.status(), status);
            let json: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(json, expected);
        }

        let response = single_object_refusal(b"{\"jsonrpc\":")
            .unwrap()
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let json: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(json["error"]["code"], -32700);
        assert_eq!(json["error"]["message"], "Invalid JSON");
    }

    #[test]
    fn test_parse_invalid_json() {
        let body = b"not json";
        let result = McpToolRequest::from_json_rpc(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_method() {
        let body = r#"{"jsonrpc":"2.0","id":1}"#;
        let result = McpToolRequest::from_json_rpc(body.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_id() {
        let body = r#"{"jsonrpc":"2.0","method":"echo"}"#;
        let result = McpToolRequest::from_json_rpc(body.as_bytes());
        assert!(result.is_err());
    }
}
