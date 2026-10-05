//! State structures for multi-channel proxy handlers

use super::proxy::SurfaceInfo;
use crate::config::GatewayConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Multi-channel proxy state for handling multiple routes on the same port
#[derive(Clone)]
pub struct MultiSurfaceProxyState {
    pub config: Arc<GatewayConfig>,
    pub network_config: Arc<crate::config::NetworkConfig>,
    pub client: reqwest::Client,
    pub channels: Arc<RwLock<Vec<SurfaceInfo>>>, // All channels sharing this port (mutable for dynamic updates)
    pub metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    pub task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
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

    /// MCP-proxy store used by `proxy://`-target surfaces. Forwarded into
    /// per-request `ProxyState` so `handle_mcp_proxy_request` can load
    /// MCP-proxy records from the boot-resolved storage path rather than
    /// the process's CWD. `None` only on misconfiguration; the orchestrator
    /// always wires it.
    pub mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,

    /// A2A-proxy store used by `a2a-proxy://`-target surfaces.
    pub a2a_proxy_store: Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,

    /// Pre-resolved per-variant `AgentSurface` snapshots. The inbound
    /// handler reads this to obtain the active surface for the request.
    /// Always non-null; may be empty during early startup before
    /// `apply_surface_change` has populated it.
    pub resolved_surface_cache: Arc<crate::surfaces::ResolvedSurfaceCache>,
}
