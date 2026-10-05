use std::collections::HashMap;

use crate::bdd_support::config::config_tree::PolicyDefinitionFixture;

#[derive(Debug, Clone)]
pub struct SurfaceConfigBuilder {
    pub protocol: String,
    pub route: String,
    pub surface_name: Option<String>,
    pub registered_routes: Vec<String>,
    pub seed_surface: bool,
    pub source_auth: Option<SurfaceSourceAuthConfig>,
    pub alternate_variant_source_auth: Option<SurfaceSourceAuthConfig>,
    pub alternate_variant_target_timeout_secs: Option<u64>,
    pub alternate_variant_complete_mode: bool,
    pub managed_identity: bool,
    pub managed_identity_strip_raw: bool,
    pub mcp_inbound_identity: bool,
    pub mcp_inbound_identity_strip_raw: bool,
    pub target_auth: Option<SurfaceTargetAuthConfig>,
    pub mcp_tool_policy: Option<McpToolPolicyFixture>,
    pub mcp_tool_gating: Option<serde_json::Value>,
    pub mcp_tool_gating_condition_policy: Option<RequestPolicyFixture>,
    pub mcp_wildcard_tool_policy: Option<McpWildcardToolPolicyFixture>,
    pub request_policy: Option<RequestPolicyFixture>,
    pub alternate_variant_inbound_policy: Option<VariantInboundPolicyFixture>,
    pub alternate_variant_target_policy: Option<VariantTargetPolicyFixture>,
    pub custom_response_headers: HashMap<String, String>,
    pub override_target_url: Option<String>,
    pub mcp_proxy_target: Option<McpProxyTargetFixture>,
    pub a2a_proxy_target: Option<A2aProxyTargetFixture>,
    pub custom_metadata: Option<SurfaceCustomMetadataConfig>,
    pub credential_delegation: Option<SurfaceCredentialDelegationConfig>,
    pub oauth_provider_base_url: Option<String>,
    pub oauth_callback_base_url: Option<String>,
    pub mcp_identity_payload_schema: Option<serde_json::Value>,
    pub required_mcp_identity_field: Option<String>,
    pub constrained_mcp_identity_field: Option<String>,
    pub agent_card_path: Option<String>,
    pub transit_point: Option<SurfaceTransitPointConfig>,
    pub didwebvh_identity: Option<DidWebVhIdentityFixture>,
    pub caller_trust_check_list: Vec<serde_json::Value>,
    pub target_trust_check_list: Vec<serde_json::Value>,
    pub transit_shared_policy: Option<RequestPolicyFixture>,
    pub mcp_protocol_mode: Option<String>,
    pub mcp_http: Option<serde_json::Value>,
}

impl Default for SurfaceConfigBuilder {
    fn default() -> Self {
        Self {
            protocol: "a2a".to_string(),
            route: "/smoke".to_string(),
            surface_name: None,
            registered_routes: vec!["/smoke".to_string()],
            seed_surface: true,
            source_auth: None,
            alternate_variant_source_auth: None,
            alternate_variant_target_timeout_secs: None,
            alternate_variant_complete_mode: false,
            managed_identity: false,
            managed_identity_strip_raw: false,
            mcp_inbound_identity: false,
            mcp_inbound_identity_strip_raw: false,
            target_auth: None,
            mcp_tool_policy: None,
            mcp_tool_gating: None,
            mcp_tool_gating_condition_policy: None,
            mcp_wildcard_tool_policy: None,
            request_policy: None,
            alternate_variant_inbound_policy: None,
            alternate_variant_target_policy: None,
            custom_response_headers: HashMap::new(),
            override_target_url: None,
            mcp_proxy_target: None,
            a2a_proxy_target: None,
            custom_metadata: None,
            credential_delegation: None,
            oauth_provider_base_url: None,
            oauth_callback_base_url: None,
            mcp_identity_payload_schema: None,
            required_mcp_identity_field: None,
            constrained_mcp_identity_field: None,
            agent_card_path: None,
            transit_point: None,
            didwebvh_identity: None,
            caller_trust_check_list: Vec::new(),
            target_trust_check_list: Vec::new(),
            transit_shared_policy: None,
            mcp_protocol_mode: None,
            mcp_http: None,
        }
    }
}

/// Seed for a did:webvh managed identity that the BDD harness writes to
/// `{base_dir}/identities/didwebvh/{identity_id}.json` before the gateway
/// boots. The runtime reads this file via `FileSystemDidWebVhIdentityStore`
/// and surfaces `agent_dna` (when set) as the `agentDNA` field on the
/// agent card.
#[derive(Debug, Clone)]
pub struct DidWebVhIdentityFixture {
    pub identity_id: uuid::Uuid,
    pub did: String,
    pub agent_dna: Option<String>,
}

impl DidWebVhIdentityFixture {
    pub fn new(did: impl Into<String>) -> Self {
        Self {
            identity_id: uuid::Uuid::new_v4(),
            did: did.into(),
            agent_dna: None,
        }
    }

    pub fn with_agent_dna(
        mut self,
        agent_dna: impl Into<String>,
    ) -> Self {
        self.agent_dna = Some(agent_dna.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct A2aProxyTargetFixture {
    pub proxy_id: String,
    pub secret_id: String,
    pub secret_value: String,
    pub disabled: bool,
    pub no_answer: bool,
}

impl A2aProxyTargetFixture {
    pub fn new(
        proxy_id: impl Into<String>,
        secret_id: impl Into<String>,
        secret_value: impl Into<String>,
    ) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            secret_id: secret_id.into(),
            secret_value: secret_value.into(),
            disabled: false,
            no_answer: false,
        }
    }

    pub fn with_disabled(mut self) -> Self {
        self.disabled = true;
        self
    }

    pub fn without_reply(mut self) -> Self {
        self.no_answer = true;
        self
    }
}

#[derive(Debug, Clone)]
pub struct McpProxyTargetFixture {
    pub proxy_id: String,
    pub openapi_spec: Option<String>,
    pub disabled: bool,
}

impl McpProxyTargetFixture {
    pub fn new(proxy_id: impl Into<String>) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            openapi_spec: None,
            disabled: false,
        }
    }

    pub fn with_openapi_spec(
        mut self,
        spec: impl Into<String>,
    ) -> Self {
        self.openapi_spec = Some(spec.into());
        self
    }

    pub fn with_disabled(mut self) -> Self {
        self.disabled = true;
        self
    }
}

#[derive(Debug, Clone)]
pub struct SurfaceTransitPointConfig {
    pub alias: String,
    pub protocol: String,
    pub header_metadata_mapping: TransitPointHeaderMetadataMappingConfig,
    pub managed_identity: Option<TransitPointManagedIdentityConfig>,
}

#[derive(Debug, Clone)]
pub struct TransitPointHeaderMetadataMappingConfig {
    pub headers: Vec<TransitPointHeaderMetadataMappingRow>,
    pub strip_mapped_headers: bool,
}

impl Default for TransitPointHeaderMetadataMappingConfig {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            strip_mapped_headers: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransitPointHeaderMetadataMappingRow {
    pub header: String,
    pub field: String,
}

#[derive(Debug, Clone)]
pub struct TransitPointManagedIdentityConfig {
    pub fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum SurfaceSourceAuthConfig {
    JwtBearer(JwtSourceAuthConfig),
    ApiKey(ApiKeySourceAuthConfig),
    ApiKeyProvider(ApiKeyProviderSourceAuthConfig),
}

#[derive(Debug, Clone)]
pub struct JwtSourceAuthConfig {
    pub jwks_url: String,
    pub issuer: String,
    pub audiences: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ApiKeySourceAuthConfig {
    pub header_name: String,
    pub secret_id: String,
    pub valid_key: String,
}

#[derive(Debug, Clone)]
pub struct ApiKeyProviderSourceAuthConfig {
    pub header_name: String,
    pub agent_id: String,
    pub key_id: String,
    pub client_id: String,
    pub valid_key: String,
}

#[derive(Debug, Clone)]
pub struct SurfaceTargetAuthConfig {
    pub secret_id: String,
    pub header_name: String,
    pub header_format: String,
    pub fallback: String,
    pub secret_value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct McpToolPolicyFixture {
    pub allowed_tool: String,
    pub policy_definition_id: String,
    pub rego: String,
}

/// A wildcard `*` tool policy entry. When present, the gateway falls back to
/// this policy for any tool call that has no explicit per-tool entry.
#[derive(Debug, Clone)]
pub struct McpWildcardToolPolicyFixture {
    pub policy_definition_id: String,
    pub rego: String,
}

pub type RequestPolicyFixture = PolicyDefinitionFixture;

/// Access-point (inbound) OPA policy applied to a variant override. The
/// harness seeds the policy definition to disk and the variant builder
/// writes `access_point.inbound_policy.policy_definition_id` into the
/// variant override JSON. The runtime evaluates this gate BEFORE the
/// target-side surface policy, so a deny here returns 403 to the caller
/// without ever forwarding upstream.
#[derive(Debug, Clone)]
pub struct VariantInboundPolicyFixture {
    pub policy_definition_id: String,
    pub rego: String,
}

impl VariantInboundPolicyFixture {
    /// A canonical deny-all inbound policy. The access-point inbound OPA
    /// query is `data.surface.policy.allow`, so a `default allow := false`
    /// package blocks every request that hits the variant.
    pub fn deny_all() -> Self {
        Self {
            policy_definition_id: "alternate-variant-inbound-policy".to_string(),
            rego: "package surface.policy\n\ndefault allow := false\n".to_string(),
        }
    }

    /// Denies only callers whose source authentication failed
    /// (`input.source_auth.method == "failed"`), allowing everything else. A
    /// caller-attributable source-auth failure is non-blocking and surfaces to
    /// policy this way; a caller with no source auth configured (method absent)
    /// is still allowed, so this fixture proves the variant *applied* source
    /// auth and the credential was rejected.
    pub fn deny_unverified_source_auth() -> Self {
        Self {
            policy_definition_id: "alternate-variant-inbound-policy".to_string(),
            rego: "package surface.policy\n\ndefault allow := true\n\nallow := false if {\n    input.source_auth.method == \"failed\"\n}\n".to_string(),
        }
    }
}

/// Target OPA policy applied to a variant override. The harness seeds the
/// policy definition to disk and the variant builder writes
/// `target.policy.policy_definition_id` into the variant override JSON.
#[derive(Debug, Clone)]
pub struct VariantTargetPolicyFixture {
    pub policy_definition_id: String,
    pub rego: String,
}

impl VariantTargetPolicyFixture {
    /// A canonical deny-all target policy. The surface OPA query is
    /// `data.surface.policy.allow`, so a `default allow := false` package
    /// blocks every request that hits the variant.
    pub fn deny_all() -> Self {
        Self {
            policy_definition_id: "alternate-variant-target-policy".to_string(),
            rego: "package surface.policy\n\ndefault allow := false\n".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SurfaceCustomMetadataConfig {
    pub key: String,
    pub value: String,
    pub injection_target: String,
}

#[derive(Debug, Clone)]
pub struct SurfaceCredentialDelegationConfig {
    pub provider_id: String,
    pub provider_kind: CredentialProviderKind,
    pub required_tool: Option<String>,
    pub inject_as: DelegatedCredentialInjection,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialProviderKind {
    OAuth2AuthorizationCode,
    ApiKey { secret_id: String, secret_value: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedCredentialInjection {
    BearerHeader,
    CustomHeader { name: String, format: String },
    Meta { field: String },
}

#[cfg(test)]
mod tests {
    #[test]
    fn surface_config_builder_defaults_to_seeded_a2a_smoke_surface() {
        let config = super::SurfaceConfigBuilder::default();

        assert_eq!(config.protocol, "a2a");
        assert_eq!(config.route, "/smoke");
        assert_eq!(config.registered_routes, vec!["/smoke"]);
        assert!(config.seed_surface);
        assert!(
            config
                .alternate_variant_source_auth
                .is_none(),
            "alternate_variant_source_auth defaults to None"
        );
        assert!(
            config
                .agent_card_path
                .is_none(),
            "agent_card_path defaults to None (default well-known path)"
        );
        assert!(
            config
                .alternate_variant_target_timeout_secs
                .is_none()
        );
        assert!(!config.alternate_variant_complete_mode);
        assert!(
            config
                .alternate_variant_inbound_policy
                .is_none()
        );
        assert!(
            config
                .alternate_variant_target_policy
                .is_none()
        );
    }

    #[test]
    fn variant_inbound_policy_fixture_deny_all_blocks_everything() {
        let f = super::VariantInboundPolicyFixture::deny_all();
        assert_eq!(f.policy_definition_id, "alternate-variant-inbound-policy");
        assert!(
            f.rego
                .contains("package surface.policy")
        );
        assert!(
            f.rego
                .contains("default allow := false")
        );
    }

    #[test]
    fn variant_target_policy_fixture_deny_all_blocks_everything() {
        let f = super::VariantTargetPolicyFixture::deny_all();
        assert_eq!(f.policy_definition_id, "alternate-variant-target-policy");
        assert!(
            f.rego
                .contains("package surface.policy")
        );
        assert!(
            f.rego
                .contains("default allow := false")
        );
    }

    #[test]
    fn surface_config_source_auth_fixtures_keep_values() {
        let jwt = super::SurfaceSourceAuthConfig::JwtBearer(super::JwtSourceAuthConfig {
            jwks_url: "https://issuer.example/.well-known/jwks.json".to_string(),
            issuer: "https://issuer.example".to_string(),
            audiences: Vec::new(),
        });
        let api_key = super::SurfaceSourceAuthConfig::ApiKey(super::ApiKeySourceAuthConfig {
            header_name: "x-api-key".to_string(),
            secret_id: "secret".to_string(),
            valid_key: "valid".to_string(),
        });
        let api_key_provider = super::SurfaceSourceAuthConfig::ApiKeyProvider(super::ApiKeyProviderSourceAuthConfig {
            header_name: "x-api-key".to_string(),
            agent_id: "agent".to_string(),
            key_id: "key".to_string(),
            client_id: "client".to_string(),
            valid_key: "valid".to_string(),
        });

        match jwt {
            super::SurfaceSourceAuthConfig::JwtBearer(config) => {
                assert_eq!(config.jwks_url, "https://issuer.example/.well-known/jwks.json");
                assert_eq!(config.issuer, "https://issuer.example");
            }
            super::SurfaceSourceAuthConfig::ApiKey(_) | super::SurfaceSourceAuthConfig::ApiKeyProvider(_) => {
                panic!("expected JWT Bearer config");
            }
        }
        match api_key {
            super::SurfaceSourceAuthConfig::ApiKey(config) => {
                assert_eq!(config.header_name, "x-api-key");
                assert_eq!(config.secret_id, "secret");
                assert_eq!(config.valid_key, "valid");
            }
            super::SurfaceSourceAuthConfig::JwtBearer(_) | super::SurfaceSourceAuthConfig::ApiKeyProvider(_) => {
                panic!("expected API Key config");
            }
        }
        match api_key_provider {
            super::SurfaceSourceAuthConfig::ApiKeyProvider(config) => {
                assert_eq!(config.header_name, "x-api-key");
                assert_eq!(config.agent_id, "agent");
                assert_eq!(config.key_id, "key");
                assert_eq!(config.client_id, "client");
                assert_eq!(config.valid_key, "valid");
            }
            super::SurfaceSourceAuthConfig::JwtBearer(_) | super::SurfaceSourceAuthConfig::ApiKey(_) => {
                panic!("expected API Key Provider config")
            }
        }
    }
}
