//! MCP policy evaluation context and utilities

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// MCP method information for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMethodInfo {
    /// The method/tool name (e.g., "echo", "get_resource")
    pub method: String,

    /// Method parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,

    /// Protocol version
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_capabilities: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_info: Option<Value>,
}

fn default_protocol() -> String {
    "json-rpc-2.0".to_string()
}

/// Complete policy evaluation context for MCP requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicyContext {
    /// MCP method information
    pub mcp: McpMethodInfo,

    /// JWT claims (if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<HashMap<String, Value>>,

    /// Channel information
    pub channel: SurfacePolicyContext,

    /// Request information
    pub request: RequestPolicyContext,
}

/// Channel context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfacePolicyContext {
    /// Channel name
    pub name: String,

    /// Channel ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Channel protocol
    pub protocol: String,
}

/// Request context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPolicyContext {
    /// Source IP address
    pub source_ip: String,

    /// Request method (HTTP)
    pub method: String,

    /// Request path
    pub path: String,
}

impl McpPolicyContext {
    /// Create a new MCP policy context
    pub fn new(
        method: String,
        params: Option<Value>,
        jwt_claims: Option<HashMap<String, Value>>,
        channel_name: String,
        channel_id: Option<String>,
        channel_protocol: String,
        source_ip: String,
        request_method: String,
        request_path: String,
    ) -> Self {
        Self {
            mcp: McpMethodInfo {
                method,
                params,
                protocol: "json-rpc-2.0".to_string(),
                protocol_version: None,
                client_capabilities: None,
                client_info: None,
            },
            jwt: jwt_claims,
            channel: SurfacePolicyContext {
                name: channel_name,
                id: channel_id,
                protocol: channel_protocol,
            },
            request: RequestPolicyContext {
                source_ip,
                method: request_method,
                path: request_path,
            },
        }
    }

    pub fn with_modern_request(
        mut self,
        context: Option<&crate::surface_context::McpContext>,
    ) -> Self {
        if let Some(context) = context.filter(|context| {
            context
                .protocol_version
                .is_some()
        }) {
            self.mcp.method = context.method.clone();
            self.mcp.params = context.params.clone();
            self.mcp.protocol_version = context
                .protocol_version
                .clone();
            self.mcp.client_capabilities = context
                .client_capabilities
                .clone();
            self.mcp.client_info = context.client_info.clone();
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_policy_context_serialization() {
        let mut jwt_claims = HashMap::new();
        jwt_claims.insert("sub".to_string(), serde_json::json!("user@example.com"));
        jwt_claims.insert("role".to_string(), serde_json::json!("admin"));

        let context = McpPolicyContext::new(
            "echo".to_string(),
            Some(serde_json::json!({"message": "hello"})),
            Some(jwt_claims),
            "test-channel".to_string(),
            Some("ch-123".to_string()),
            "mcp".to_string(),
            "192.168.1.1".to_string(),
            "POST".to_string(),
            "/mcp".to_string(),
        );

        let serialized = serde_json::to_value(&context).unwrap();
        assert_eq!(
            serialized["mcp"],
            serde_json::json!({
                "method": "echo", "params": {"message": "hello"}, "protocol": "json-rpc-2.0"
            })
        );

        // Verify structure
        assert_eq!(context.mcp.method, "echo");
        assert_eq!(context.channel.name, "test-channel");
        assert_eq!(context.request.source_ip, "192.168.1.1");
    }

    #[test]
    fn tool_policy_uses_modern_snapshot_without_modifying_legacy_contract() {
        let legacy = McpPolicyContext::new(
            "tools/list".to_string(),
            None,
            None,
            "surface".to_string(),
            None,
            "mcp".to_string(),
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/mcp".to_string(),
        );
        let original = serde_json::to_value(&legacy).unwrap();
        assert_eq!(
            serde_json::to_value(
                legacy
                    .clone()
                    .with_modern_request(Some(&Default::default()))
            )
            .unwrap(),
            original
        );
        let modern = crate::surface_context::McpContext {
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({"name": "echo", "arguments": {"value": [1, true]}})),
            protocol_version: Some(crate::mcp::MCP_MODERN_VERSION.to_string()),
            client_capabilities: Some(serde_json::json!({"extensions": {"com.example/tools": {}}})),
            ..Default::default()
        };
        let enriched = serde_json::to_value(legacy.with_modern_request(Some(&modern))).unwrap();
        assert_eq!(
            enriched["mcp"],
            serde_json::json!({
                "method": modern.method, "params": modern.params, "protocol": "json-rpc-2.0",
                "protocol_version": crate::mcp::MCP_MODERN_VERSION, "client_capabilities": modern.client_capabilities,
            })
        );
        assert!(enriched.get("jwt").is_none());
        assert_eq!(enriched["request"], original["request"]);
    }
}
