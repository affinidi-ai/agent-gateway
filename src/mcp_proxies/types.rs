use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// Represents the status of an MCP Proxy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum McpProxyStatus {
    #[default]
    Active,
    Disabled,
}

/// Represents an MCP Proxy record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpProxy {
    /// Unique identifier for this MCP Proxy
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// MCP Proxy name
    pub name: String,

    /// MCP Proxy description
    pub description: String,

    /// Base URL for the REST API
    pub base_url: String,

    /// OpenAPI specification (YAML format)
    pub openapi_spec: String,

    /// Status of the MCP Proxy
    pub status: McpProxyStatus,

    /// Channel prefix selected from network.json (e.g., "/mcp")
    pub channel_prefix: String,

    /// Endpoint path where this MCP proxy is hosted (e.g., "/my-api")
    pub endpoint_path: String,

    /// When true, POST request body parameters are flattened into the tool's
    /// inputSchema so MCP clients can send flat arguments instead of wrapping
    /// them in a `request_body` object.
    #[serde(default)]
    pub flatten_post_params: bool,

    /// When false, the proxy is served only through a surface that targets it
    /// (`proxy://<id>`), never on the unauthenticated direct MCP proxy route.
    #[serde(default = "default_direct_access")]
    pub direct_access: bool,

    /// The product that created and maintains this proxy through the API
    /// (e.g. "Boris"), shown in the dashboard so an operator knows their edits
    /// may be overwritten. A label only: it grants and restricts nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_protocol_mode: Option<crate::config::McpProtocolMode>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_http: Option<crate::config::McpHttpConfig>,

    /// Timestamp when this record was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this record was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl McpProxy {
    pub fn new(
        name: String,
        description: String,
        base_url: String,
        openapi_spec: String,
        channel_prefix: String,
        endpoint_path: String,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: None,
            name,
            description,
            base_url,
            openapi_spec,
            status: McpProxyStatus::Active,
            channel_prefix,
            endpoint_path,
            flatten_post_params: false,
            direct_access: true,
            managed_by: None,
            mcp_protocol_mode: None,
            mcp_http: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Get the full MCP endpoint path (channel_prefix + endpoint_path)
    pub fn full_path(&self) -> String {
        format!("{}{}", self.channel_prefix, self.endpoint_path)
    }
}

fn default_direct_access() -> bool {
    true
}

impl StorableEntity for McpProxy {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Request to create a new MCP Proxy
#[derive(Debug, Deserialize)]
pub struct CreateMcpProxyRequest {
    /// Caller-chosen id. Server-generated (a UUID) when absent.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub base_url: String,
    pub openapi_spec: String,
    pub channel_prefix: String,
    pub endpoint_path: String,
    #[serde(default)]
    pub flatten_post_params: bool,
    #[serde(default)]
    pub direct_access: Option<bool>,
    #[serde(default)]
    pub managed_by: Option<String>,
    pub mcp_protocol_mode: Option<crate::config::McpProtocolMode>,
    pub mcp_http: Option<crate::config::McpHttpConfig>,
}

/// Request to update an MCP Proxy
#[derive(Debug, Deserialize)]
pub struct UpdateMcpProxyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub base_url: Option<String>,
    pub openapi_spec: Option<String>,
    pub status: Option<McpProxyStatus>,
    pub channel_prefix: Option<String>,
    pub endpoint_path: Option<String>,
    pub flatten_post_params: Option<bool>,
    pub direct_access: Option<bool>,
    /// Absent keeps the stored label; an empty string clears it.
    pub managed_by: Option<String>,
    pub mcp_protocol_mode: Option<crate::config::McpProtocolMode>,
    pub mcp_http: Option<crate::config::McpHttpConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_protocol_mode_is_omitted_by_default_and_round_trips() {
        let mut proxy = McpProxy::new(
            "example".into(),
            String::new(),
            "https://example.org".into(),
            String::new(),
            "/mcp".into(),
            "/example".into(),
        );
        assert!(
            serde_json::to_value(&proxy)
                .unwrap()
                .get("mcp_protocol_mode")
                .is_none()
        );
        proxy.mcp_protocol_mode = Some(crate::config::McpProtocolMode::Dual);
        let restored: McpProxy = serde_json::from_value(serde_json::to_value(&proxy).unwrap()).unwrap();
        assert_eq!(restored.mcp_protocol_mode, proxy.mcp_protocol_mode);
    }
}
