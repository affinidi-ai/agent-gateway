use crate::bdd_support::config::mcp_proxy::McpProxyFixture;
use crate::bdd_support::config::single_surface_fixture::{McpToolPolicyFixture, SurfaceTargetAuthConfig};

#[derive(Debug, Clone)]
pub enum SourceAuthSpec {
    ApiKey { header_name: String, secret_id: String, valid_key: String },
}

pub type TargetAuthSpec = SurfaceTargetAuthConfig;

pub type McpToolPolicySpec = McpToolPolicyFixture;

pub type McpProxySpec = McpProxyFixture;

#[derive(Debug, Clone)]
pub struct SurfaceSpec {
    pub surface_id: String,
    pub route: String,
    pub protocol: String,
    /// Target endpoint: a mock URL, `fabric://{gw}/{surface}`, or
    /// `proxy://{id}`. May be rewritten post-federation.
    pub target_endpoint: String,
    pub target_auth: Option<TargetAuthSpec>,
    pub source_auth: Option<SourceAuthSpec>,
    pub inbound_policy_rego: Option<String>,
    pub transit_policy_rego: Option<String>,
    /// Surface-level managed identity derived from the managed agent's
    /// `agent-identity/v1` payload; Transit Points inherit it and mint a VP.
    pub managed_identity: bool,
    pub mcp_tool_policy: Option<McpToolPolicySpec>,
    pub mcp_proxy: Option<McpProxySpec>,
    /// `mcp_protocol_mode` of the surface; `None` leaves it unset (legacy).
    pub mcp_protocol_mode: Option<String>,
    /// The target is a real upstream serving one path, not a harness mock.
    pub external_target: bool,
    pub transit_points: Vec<TransitPointSpec>,
}

#[derive(Debug, Clone)]
pub struct TransitPointSpec {
    pub alias: String,
    pub protocol: String,
    pub target_endpoint: String,
    pub header_metadata_mapping: TransitPointHeaderMetadataMappingSpec,
    pub managed_identity_fields: Option<Vec<String>>,
}

impl TransitPointSpec {
    pub fn new(
        alias: impl Into<String>,
        protocol: impl Into<String>,
        target_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            alias: alias.into(),
            protocol: protocol.into(),
            target_endpoint: target_endpoint.into(),
            header_metadata_mapping: Default::default(),
            managed_identity_fields: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransitPointHeaderMetadataMappingSpec {
    pub headers: Vec<TransitPointHeaderMetadataMappingRowSpec>,
    pub strip_mapped_headers: bool,
}

impl Default for TransitPointHeaderMetadataMappingSpec {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            strip_mapped_headers: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransitPointHeaderMetadataMappingRowSpec {
    pub header: String,
    pub field: String,
}

impl SurfaceSpec {
    pub fn new(
        surface_id: &str,
        route: &str,
        protocol: &str,
        target_endpoint: &str,
    ) -> Self {
        Self {
            surface_id: surface_id.to_string(),
            route: route.to_string(),
            protocol: protocol.to_string(),
            target_endpoint: target_endpoint.to_string(),
            target_auth: None,
            source_auth: None,
            inbound_policy_rego: None,
            transit_policy_rego: None,
            managed_identity: false,
            mcp_tool_policy: None,
            mcp_proxy: None,
            mcp_protocol_mode: None,
            external_target: false,
            transit_points: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn surface_spec_captures_route_protocol_and_target() {
        let spec = super::SurfaceSpec::new("orders", "/orders", "mcp", "fabric://gw/orders");

        assert_eq!(spec.surface_id, "orders");
        assert_eq!(spec.route, "/orders");
        assert_eq!(spec.protocol, "mcp");
        assert_eq!(spec.target_endpoint, "fabric://gw/orders");
    }
}
