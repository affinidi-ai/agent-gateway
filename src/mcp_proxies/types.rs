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
            mcp_http: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Get the full MCP endpoint path (channel_prefix + endpoint_path)
    pub fn full_path(&self) -> String {
        format!("{}{}", self.channel_prefix, self.endpoint_path)
    }

    /// The digest of what a tool call through this proxy does and of what it
    /// shows the agent: its `base_url`, its OpenAPI spec, as stored, and
    /// `flatten_post_params`, which together decide the request each tool
    /// sends and the tools `tools/list` describes, and its `name`, which
    /// `initialize` answers with. `sha256:` and 64 lowercase hex digits. Every
    /// MCP Proxy answer carries it as `grant_pin`. A `proxy://` Transit Point's
    /// `consent_mode: external` binding is pinned to it
    /// ([`crate::config::agent_surface::TransitCredentials::mcp_proxy_pin`]),
    /// and the Transit Point answers and sends the grant through the proxy
    /// only while the proxy still has it, so an edit to the proxy cannot change
    /// what a grant is used for, or what the agent is told, until a surface
    /// save sends the proxy's new pin. Its other fields (`description`,
    /// `status`, the timestamps, `managed_by`, `channel_prefix`,
    /// `endpoint_path`, `mcp_http`, `tenant_id`, `direct_access`) are not part
    /// of it: none is shown to the agent or decides a request sent through a
    /// Transit Point (`status` only refuses, and `tenant_id` and
    /// `direct_access` are checked on their own), so an update that changes
    /// none of the four keeps it.
    pub fn grant_pin(&self) -> String {
        use sha2::Digest;
        let mut digest = sha2::Sha256::new();
        digest.update(b"agent-gateway mcp-proxy grant pin v2\n");
        for field in [
            self.base_url.as_bytes(),
            self.openapi_spec.as_bytes(),
            if self.flatten_post_params {
                b"flatten"
            } else {
                b"keep"
            },
            self.name.as_bytes(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        format!("sha256:{}", hex::encode(digest.finalize()))
    }
}

/// The id of the MCP Proxy a `proxy://<id>` endpoint names: all of the
/// endpoint after the scheme, as a surface's Target and a Transit Point are
/// dispatched. `None` for an endpoint of another scheme.
pub fn endpoint_proxy_id(endpoint: &str) -> Option<&str> {
    endpoint.strip_prefix("proxy://")
}

/// The id of the MCP Proxy a Transit Point's `proxy://<id>` endpoint names,
/// when it is one an MCP Proxy can have
/// ([`crate::mcp_proxies::handlers::is_valid_mcp_proxy_id`]). A surface save
/// refuses any other, and a call never looks it up.
pub fn transit_proxy_id(endpoint: &str) -> Option<&str> {
    endpoint_proxy_id(endpoint).filter(|id| super::handlers::is_valid_mcp_proxy_id(id))
}

fn default_direct_access() -> bool {
    true
}

impl StorableEntity for McpProxy {
    fn id(&self) -> &str {
        &self.id
    }
}

/// An MCP Proxy as the API answers with it: the record and its
/// [`McpProxy::grant_pin`], which a surface save sends as a `proxy://` Transit
/// Point binding's `mcp_proxy_pin` to pin the binding to the proxy as it is.
#[derive(Debug, Serialize)]
pub struct McpProxyAnswer {
    #[serde(flatten)]
    pub proxy: McpProxy,
    pub grant_pin: String,
}

impl From<McpProxy> for McpProxyAnswer {
    fn from(proxy: McpProxy) -> Self {
        let grant_pin = proxy.grant_pin();
        Self { proxy, grant_pin }
    }
}

/// A created or updated MCP Proxy, with its [`McpProxy::grant_pin`] and any
/// problem that left part of it unusable without failing the write.
#[derive(Debug, Serialize)]
pub struct McpProxyWriteResponse {
    #[serde(flatten)]
    pub proxy: McpProxy,
    pub grant_pin: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl McpProxyWriteResponse {
    pub fn new(
        proxy: McpProxy,
        warnings: Vec<String>,
    ) -> Self {
        let grant_pin = proxy.grant_pin();
        Self { proxy, grant_pin, warnings }
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
    pub mcp_http: Option<crate::config::McpHttpConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_carrying_the_retired_protocol_mode_loads_and_saves_without_it() {
        let proxy = McpProxy::new(
            "example".into(),
            String::new(),
            "https://example.org".into(),
            String::new(),
            "/mcp".into(),
            "/example".into(),
        );
        for mode in ["legacy", "dual"] {
            let mut stored = serde_json::to_value(&proxy).unwrap();
            stored["mcp_protocol_mode"] = serde_json::json!(mode);
            let restored: McpProxy = serde_json::from_value(stored).unwrap();
            assert_eq!(restored.id, proxy.id);
            assert!(
                serde_json::to_value(&restored)
                    .unwrap()
                    .get("mcp_protocol_mode")
                    .is_none()
            );
        }
        let request: UpdateMcpProxyRequest =
            serde_json::from_value(serde_json::json!({"name": "renamed", "mcp_protocol_mode": "legacy"})).unwrap();
        assert_eq!(request.name.as_deref(), Some("renamed"));
    }
}
