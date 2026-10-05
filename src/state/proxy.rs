//! State structures for single-channel proxy handlers

use crate::config::GatewayConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Compiled engines for a specific virtual channel variant
#[derive(Clone)]
pub struct VariantEngines {
    /// Rules engine scoped to identity management (compiled from managed_identity.extension_rules)
    pub identity_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    pub identity_selector: Option<Arc<crate::identity::IdentitySelector>>,
    /// Optional per-slot engines for the protected identity slot
    /// (`identity_slots.protected`). When set, prefer over the channel-wide
    /// engines so the slot enforces its own JSON schema/rules independently.
    pub protected_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    pub protected_selector: Option<Arc<crate::identity::IdentitySelector>>,
    /// Optional per-slot engines for the external identity slot
    /// (`identity_slots.external`). Drives `resolve_external_agent_identity`.
    pub external_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    pub external_selector: Option<Arc<crate::identity::IdentitySelector>>,
}

/// State for single-channel proxy handler
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<GatewayConfig>,
    pub network_config: Arc<crate::config::NetworkConfig>,
    pub client: reqwest::Client,
    pub metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    /// Rules engine scoped to identity management (compiled from managed_identity.extension_rules)
    pub identity_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    pub identity_selector: Option<Arc<crate::identity::IdentitySelector>>,
    /// Per-slot engines for the protected identity slot
    /// (`identity_slots.protected`). Used by `resolve_protected_agent_identity`
    /// when present, otherwise the channel-wide `identity_selector` is used.
    pub protected_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    pub protected_selector: Option<Arc<crate::identity::IdentitySelector>>,
    /// Per-slot engines for the external identity slot
    /// (`identity_slots.external`). Drives `resolve_external_agent_identity`
    /// on response-side processing. `None` when the slot is not configured.
    pub external_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    pub external_selector: Option<Arc<crate::identity::IdentitySelector>>,
    pub task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    pub task_id: Option<String>,
    pub ws_state: Option<Arc<crate::server::WsState>>,
    pub listener_manager: Arc<RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    pub secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    /// Certificate store — used to resolve `ManagedIdentityConfig::FromMtls`
    /// to a stable did:webvh per stored certificate.
    pub certificates_store: Option<Arc<dyn crate::certificates::CertificateStore>>,
    /// VCIssuer — used to issue / retrieve DIDs for credential-based managed
    /// identity mode (`FromApiKey`) on the inbound path.
    pub vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    pub policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    pub gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    pub didauth_session_store: Arc<crate::didauth::DidAuthSessionStore>,
    pub transaction_store: Option<Arc<crate::x402::TransactionStore>>,
    pub mpp_transaction_store: Option<Arc<crate::mpp::MppTransactionStore>>,

    /// Optional trust registry listener manager for agent trust OPA context building
    pub trust_registry_listener_manager: Option<Arc<crate::trust_registries::TrustRegistryListenerManager>>,

    /// Unified source authentication middleware (replaces jwt_bearer_middleware + identity_config auth).
    pub source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,

    #[cfg(feature = "didwebvh")]
    pub didwebvh_identity_store: Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,

    #[cfg(feature = "didwebvh")]
    pub didwebvh_log_manager: Option<Arc<crate::identity::didwebvh::log::DidLogManager>>,

    /// Credential provider store for delegation credential lookups
    pub credential_provider_store: Option<Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>>,

    /// Delegation vault store for cached OAuth tokens
    pub delegation_vault_store: Option<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>>,

    /// Gateway base URL for building OAuth callback URLs
    pub gateway_base_url: Option<String>,

    /// Transit token issuer for generating transit tokens on forwarded requests.
    pub transit_token_issuer: Option<Arc<crate::proxy::transit_token::TransitTokenIssuer>>,

    /// MCP-proxy store used by `proxy://`-target surfaces to load the
    /// MCP-proxy record at request time. Forwarded from the boot-built
    /// store on `MultiSurfaceProxyState`. `None` only on misconfiguration
    /// (the orchestrator always wires it when MCP-proxy storage is
    /// available); handlers must surface a 500 rather than panic.
    pub mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,

    /// A2A-proxy store used by `a2a-proxy://`-target surfaces to load
    /// A2A-proxy records at request time.
    pub a2a_proxy_store: Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,

    /// Surface variant alias selected by the request URL (`/route$alias/...`).
    /// `None` when the request targets the default variant.
    pub active_variant_alias: Option<String>,
    pub active_variant_id: Option<String>,

    /// Set when the requested alias could not select a variant and the
    /// request fell back to the base surface. Legacy requests keep that
    /// fallback; admitted modern requests are rejected instead.
    pub variant_resolution_error: Option<crate::config::agent_surface_variants::VariantResolveError>,

    /// Resolved [`AgentSurface`] for this request — the source of
    /// truth for the hot path. Looked up from
    /// [`crate::surfaces::ResolvedSurfaceCache`] by `(surface_id,
    /// active_variant_alias)` so every variant override is already
    /// applied.
    pub surface: Arc<crate::config::agent_surface::AgentSurface>,
}

/// Surface info with routing support (includes rules engines and identity selector)
#[derive(Clone)]
pub struct SurfaceInfo {
    /// Authoritative runtime carrier. All hot-path reads come off the
    /// surface.
    pub surface: Arc<crate::config::agent_surface::AgentSurface>,
    /// Rules engine scoped to identity management (compiled from managed_identity.extension_rules)
    #[allow(dead_code)]
    pub identity_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    #[allow(dead_code)]
    pub identity_selector: Option<Arc<crate::identity::IdentitySelector>>,
    #[allow(dead_code)]
    pub protected_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    #[allow(dead_code)]
    pub protected_selector: Option<Arc<crate::identity::IdentitySelector>>,
    #[allow(dead_code)]
    pub external_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    #[allow(dead_code)]
    pub external_selector: Option<Arc<crate::identity::IdentitySelector>>,
    pub task_id: String,
    /// Pre-compiled engines for each virtual channel variant (keyed by variant_id)
    pub variant_engines: HashMap<String, VariantEngines>,
}
