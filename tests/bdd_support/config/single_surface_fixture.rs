use std::collections::HashMap;

use crate::bdd_support::config::config_tree::PolicyDefinitionFixture;

/// The public https origin a surface's protected resource is published under.
pub const PROTECTED_RESOURCE_PUBLIC_ORIGIN: &str = "https://gateway.bdd.example";

/// RFC 9728 discovery settings of the surface's caller authentication.
#[derive(Debug, Clone)]
pub struct ProtectedResourceFixture {
    pub authorization_server: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SurfaceConfigBuilder {
    pub protocol: String,
    pub route: String,
    pub surface_name: Option<String>,
    pub registered_routes: Vec<String>,
    pub seed_surface: bool,
    pub source_auth: Option<SurfaceSourceAuthConfig>,
    /// Source authentication methods after `source_auth`, in order.
    pub additional_source_auth: Vec<SurfaceSourceAuthConfig>,
    pub alternate_variant_source_auth: Option<SurfaceSourceAuthConfig>,
    pub alternate_variant_target_timeout_secs: Option<u64>,
    pub alternate_variant_complete_mode: bool,
    pub managed_identity: bool,
    pub managed_identity_strip_raw: bool,
    pub mcp_inbound_identity: bool,
    pub mcp_inbound_identity_strip_raw: bool,
    /// The inbound identity is the `sub` claim of the caller's JWT (`from_jwt_claim`).
    pub jwt_claim_inbound_identity: bool,
    pub target_auth: Option<SurfaceTargetAuthConfig>,
    pub target_auth_provider: Option<SurfaceTargetAuthProviderConfig>,
    pub mcp_tool_policy: Option<McpToolPolicyFixture>,
    pub mcp_tool_gating: Option<serde_json::Value>,
    pub mcp_tool_gating_condition_policy: Option<RequestPolicyFixture>,
    pub mcp_wildcard_tool_policy: Option<McpWildcardToolPolicyFixture>,
    pub request_policy: Option<RequestPolicyFixture>,
    pub alternate_variant_inbound_policy: Option<VariantInboundPolicyFixture>,
    pub alternate_variant_target_policy: Option<VariantTargetPolicyFixture>,
    pub custom_response_headers: HashMap<String, String>,
    pub override_target_url: Option<String>,
    /// The path the Target endpoint, or the MCP proxy base URL, adds to the target's address.
    pub target_base_path: Option<String>,
    pub mcp_proxy_target: Option<McpProxyTargetFixture>,
    pub a2a_proxy_target: Option<A2aProxyTargetFixture>,
    pub custom_metadata: Option<SurfaceCustomMetadataConfig>,
    pub credential_delegation: Option<SurfaceCredentialDelegationConfig>,
    pub oauth_provider_base_url: Option<String>,
    pub oauth_callback_base_url: Option<String>,
    /// The RFC 9207 `iss` the surface's OAuth provider records as its authorization server's.
    pub oauth_authorization_response_issuer: Option<String>,
    /// OAuth providers the gateway has besides the surface's own, by provider id.
    pub additional_oauth_providers: Vec<String>,
    /// The surface's OAuth provider is stored as the admin API now creates one: with a
    /// record id of its own, which its callback path ends in, instead of its provider id.
    pub oauth_callback_path_ends_in_record_id: bool,
    pub mcp_identity_payload_schema: Option<serde_json::Value>,
    pub required_mcp_identity_field: Option<String>,
    pub constrained_mcp_identity_field: Option<String>,
    pub agent_card_path: Option<String>,
    pub transit_points: Vec<SurfaceTransitPointConfig>,
    /// The surface sets `transit.source_auth`, as one stored before the admin
    /// API refused it does.
    pub transit_source_auth: bool,
    /// How long the surface's transit tokens live, in seconds.
    pub transit_token_lifetime_secs: Option<u64>,
    /// The appliance's `transit_token_max_lifetime_secs` in `gateway.json`.
    pub transit_token_max_lifetime_secs: Option<u64>,
    pub didwebvh_identity: Option<DidWebVhIdentityFixture>,
    pub caller_trust_check_list: Vec<serde_json::Value>,
    pub trust_recorder_entries: Vec<serde_json::Value>,
    pub transit_shared_policy: Option<RequestPolicyFixture>,
    pub mcp_http: Option<serde_json::Value>,
    pub protected_resource: Option<ProtectedResourceFixture>,
    /// The outbound listener is also published at [`PROTECTED_RESOURCE_PUBLIC_ORIGIN`], the
    /// https origin a Transit Point's `mcp_http.authorization` resource must use.
    pub outbound_public_origin: bool,
    pub a2a_settings: Option<serde_json::Value>,
    /// Requests the Access Point admits per minute.
    pub rate_limit_per_minute: Option<u32>,
    /// The gateway starts with the VP Audit Log keeping every audit event.
    pub audit_log_keeps_every_event: bool,
    /// The gateway logs its `audit` target events at info level and keeps its log for the
    /// scenario to read.
    pub logs_audit_events: bool,
    /// The tenant that owns the surface; appliance-wide when absent.
    pub tenant_id: Option<String>,
    /// The `[credential_policy]` rules the gateway starts with set to `enforce`.
    pub enforced_credential_rules: Vec<String>,
    pub token_request_timeout_secs: Option<u64>,
    /// The gateway logs warnings and keeps its log for the scenario to read.
    pub keeps_gateway_log: bool,
    /// The gateway writes its log files to `_storage/logs`, the directory the log routes act on.
    pub writes_log_directory: bool,
    /// The gateway serves a dashboard build from `www/` at `/`, falling back to its
    /// `index.html` for every path no other route takes, as a deployed dashboard does.
    pub serves_dashboard: bool,
    /// Channel, MCP proxy and redirect prefixes `gateway.json` adds to the surface's.
    pub gateway_prefixes: Vec<GatewayPrefixFixture>,
    /// API key records stored before the gateway starts.
    pub stored_api_keys: Vec<StoredApiKeyFixture>,
    /// Further stored surfaces, disabled, by id.
    pub other_stored_surfaces: Vec<String>,
    /// Further stored surfaces, each on its own route and with its own status.
    pub stored_surfaces_on_routes: Vec<StoredSurfaceFixture>,
    /// The key id the seeded surface's protected Identity takes its DID from.
    pub protected_identity_api_key_id: Option<String>,
    /// When the API Key Provider's key was created; when the gateway starts if absent.
    pub api_key_provider_key_created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The gateway starts in Standby mode.
    pub starts_standby: bool,
    /// The Redis URL an integration stored before the gateway starts streams sign-in events to.
    pub sign_in_event_stream: Option<String>,
    /// A second integration streams sign-in events with Agent Watch's record template.
    pub streams_sign_in_records: bool,
    /// Console users sign in with SAML rather than passkeys.
    pub signs_in_with_saml: bool,
}

/// A prefix the operator adds to `gateway.json`.
#[derive(Debug, Clone)]
pub enum GatewayPrefixFixture {
    Channel(String),
    McpProxy(String),
    Redirect { prefix: String, target: String },
}

/// A surface stored before the gateway starts, on a route of its own that
/// `gateway.json` does not add as a prefix.
#[derive(Debug, Clone)]
pub struct StoredSurfaceFixture {
    pub id: String,
    pub route: String,
    /// `active` or `disabled`.
    pub status: String,
}

/// An API key record stored before the gateway starts.
#[derive(Debug, Clone)]
pub struct StoredApiKeyFixture {
    pub owner: String,
    pub key_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether the gateway can load the owner's key folder.
    pub loads: bool,
}

impl SurfaceConfigBuilder {
    /// The stored id of the credential provider `provider_id`, which is also the last
    /// segment of its callback path.
    pub fn provider_record_id(
        &self,
        provider_id: &str,
    ) -> String {
        let own = self
            .credential_delegation
            .as_ref()
            .is_some_and(|delegation| delegation.provider_id == provider_id);
        if own && self.oauth_callback_path_ends_in_record_id {
            format!("0b6e4c2a-{provider_id}-record")
        } else {
            provider_id.to_string()
        }
    }
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
            additional_source_auth: Vec::new(),
            alternate_variant_source_auth: None,
            alternate_variant_target_timeout_secs: None,
            alternate_variant_complete_mode: false,
            managed_identity: false,
            managed_identity_strip_raw: false,
            mcp_inbound_identity: false,
            mcp_inbound_identity_strip_raw: false,
            jwt_claim_inbound_identity: false,
            target_auth: None,
            target_auth_provider: None,
            mcp_tool_policy: None,
            mcp_tool_gating: None,
            mcp_tool_gating_condition_policy: None,
            mcp_wildcard_tool_policy: None,
            request_policy: None,
            alternate_variant_inbound_policy: None,
            alternate_variant_target_policy: None,
            custom_response_headers: HashMap::new(),
            override_target_url: None,
            target_base_path: None,
            mcp_proxy_target: None,
            a2a_proxy_target: None,
            protected_resource: None,
            outbound_public_origin: false,
            custom_metadata: None,
            credential_delegation: None,
            oauth_provider_base_url: None,
            oauth_callback_base_url: None,
            oauth_authorization_response_issuer: None,
            additional_oauth_providers: Vec::new(),
            oauth_callback_path_ends_in_record_id: false,
            mcp_identity_payload_schema: None,
            required_mcp_identity_field: None,
            constrained_mcp_identity_field: None,
            agent_card_path: None,
            transit_points: Vec::new(),
            transit_source_auth: false,
            transit_token_lifetime_secs: None,
            transit_token_max_lifetime_secs: None,
            didwebvh_identity: None,
            caller_trust_check_list: Vec::new(),
            trust_recorder_entries: Vec::new(),
            transit_shared_policy: None,
            mcp_http: None,
            a2a_settings: None,
            rate_limit_per_minute: None,
            audit_log_keeps_every_event: false,
            logs_audit_events: false,
            tenant_id: None,
            enforced_credential_rules: Vec::new(),
            token_request_timeout_secs: None,
            keeps_gateway_log: false,
            writes_log_directory: false,
            serves_dashboard: false,
            gateway_prefixes: Vec::new(),
            stored_api_keys: Vec::new(),
            other_stored_surfaces: Vec::new(),
            stored_surfaces_on_routes: Vec::new(),
            protected_identity_api_key_id: None,
            api_key_provider_key_created_at: None,
            starts_standby: false,
            sign_in_event_stream: None,
            streams_sign_in_records: false,
            signs_in_with_saml: false,
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
    /// The proxy's `base_url` names the REST API with `https://` instead of `http://`.
    pub https_base_url: bool,
}

impl McpProxyTargetFixture {
    pub fn new(proxy_id: impl Into<String>) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            openapi_spec: None,
            disabled: false,
            https_base_url: false,
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
    pub trust_check_list: Vec<serde_json::Value>,
    pub policy: Option<RequestPolicyFixture>,
    pub require_transit_token: bool,
    /// The Transit Point's own `source_auth`.
    pub source_auth: Option<serde_json::Value>,
    /// Serves callers it does not authenticate when it requires no transit
    /// token and has no `source_auth`.
    pub allow_unauthenticated_callers: bool,
    /// The surface's delegated credential is this Transit Point's own
    /// `transit_credentials` rather than the surface's `outbound_credentials`.
    pub delegated_credentials: bool,
    /// The Transit Point authenticates its target with the surface's
    /// `target_auth_provider`.
    pub target_auth_provider: bool,
    /// The `fallback` of the Transit Point's `target_auth`.
    pub target_auth_fallback: String,
    /// The Transit Point authenticates its target with a static secret that the gateway does
    /// not hold instead.
    pub target_auth_secret: Option<SurfaceTargetAuthConfig>,
    /// The path the Transit Point's target endpoint adds to its destination's address.
    pub target_base_path: Option<String>,
    /// Requests per minute the Transit Point admits from each caller
    /// (`per_caller_rate_limit`).
    pub per_caller_rate_limit_per_minute: Option<u32>,
}

impl SurfaceTransitPointConfig {
    pub fn new(
        alias: impl Into<String>,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            alias: alias.into(),
            protocol: protocol.into(),
            header_metadata_mapping: Default::default(),
            managed_identity: None,
            trust_check_list: Vec::new(),
            policy: None,
            require_transit_token: false,
            source_auth: None,
            allow_unauthenticated_callers: true,
            delegated_credentials: false,
            target_auth_provider: false,
            target_auth_fallback: "reject".to_string(),
            target_auth_secret: None,
            target_base_path: None,
            per_caller_rate_limit_per_minute: None,
        }
    }
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
    /// The claim `audiences` is matched against; `None` stores no
    /// `audience_claim`, which the gateway reads as `aud`.
    pub audience_claim: Option<String>,
    pub forward_header: bool,
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

/// A Target authenticated with a credential provider's token. The harness serves the
/// provider's token endpoint and sets `token_endpoint` before the gateway starts.
#[derive(Debug, Clone)]
pub struct SurfaceTargetAuthProviderConfig {
    pub grant: TargetAuthProviderGrant,
    pub fallback: String,
    pub token_status: u16,
    pub expires_in: u64,
    pub token_endpoint: Option<String>,
    /// The test allowlist admits the http token endpoint's origin for egress only, so the
    /// gateway holds it to the https rule as it would any http token endpoint.
    pub insecure_token_endpoint: bool,
    /// The surface's own Target authenticates with this provider; `false` when only a
    /// Transit Point or a delegated credential binding uses it.
    pub authenticates_surface_target: bool,
    /// A JWT Bearer provider's signing-key secret holds a whole service account JSON key
    /// file whose `private_key_id` names the key, and the provider sets no key id itself.
    pub signing_key_is_service_account_file: bool,
    /// The `jwt_subject` a JWT Bearer provider stores; the grant's `sub` claim.
    pub jwt_subject: Option<String>,
    pub client_authentication: Option<TargetAuthClientAuthentication>,
    /// A JWT Bearer provider stores a client ID and a client secret although it sets no
    /// client authentication.
    pub stores_unused_client_references: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAuthProviderGrant {
    ClientCredentials,
    JwtBearer,
}

/// How a JWT Bearer provider's client identifies itself with its grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAuthClientAuthentication {
    ClientIdOnly,
    HttpBasic,
    FormBody,
}

impl TargetAuthClientAuthentication {
    /// The choice a scenario names: "the client ID only", "HTTP Basic" or "the form body".
    pub fn from_wording(wording: &str) -> Self {
        match wording {
            "the client ID only" => Self::ClientIdOnly,
            "HTTP Basic" => Self::HttpBasic,
            "the form body" => Self::FormBody,
            other => panic!(
                "unknown client authentication {other:?}: use \"the client ID only\", \"HTTP Basic\" or \"the form body\""
            ),
        }
    }

    /// The value the admin API takes for `client_authentication`.
    pub fn api_value(self) -> &'static str {
        match self {
            Self::ClientIdOnly => "none",
            Self::HttpBasic => "client_secret_basic",
            Self::FormBody => "client_secret_post",
        }
    }

    fn sends_secret(self) -> bool {
        self != Self::ClientIdOnly
    }
}

impl SurfaceTargetAuthProviderConfig {
    pub fn new(grant: TargetAuthProviderGrant) -> Self {
        Self {
            grant,
            fallback: "reject".to_string(),
            token_status: 200,
            expires_in: 3600,
            token_endpoint: None,
            insecure_token_endpoint: false,
            authenticates_surface_target: true,
            signing_key_is_service_account_file: false,
            jwt_subject: Some("bdd-subject@example.com".to_string()),
            client_authentication: None,
            stores_unused_client_references: false,
        }
    }

    pub fn stores_client_id(&self) -> bool {
        self.grant == TargetAuthProviderGrant::ClientCredentials
            || self.stores_unused_client_references
            || self
                .client_authentication
                .is_some()
    }

    pub fn stores_client_secret(&self) -> bool {
        self.grant == TargetAuthProviderGrant::ClientCredentials
            || self.stores_unused_client_references
            || self
                .client_authentication
                .is_some_and(TargetAuthClientAuthentication::sends_secret)
    }
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
    ApiKey {
        secret_id: String,
        secret_value: String,
    },
    /// A provider the gateway has no record of, as after it was deleted.
    Unknown,
    /// The client credentials provider the harness serves as the surface's
    /// `target_auth_provider`, whose fixture and secrets that config writes.
    ClientCredentials,
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
            audience_claim: None,
            forward_header: false,
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
