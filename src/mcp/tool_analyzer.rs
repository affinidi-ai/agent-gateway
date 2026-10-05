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
