//! State for the outbound proxy handler.

use crate::config::NetworkConfig;
use std::sync::Arc;

/// Live-updatable, surface-specific state for outbound requests.
///
/// Grouped behind a `std::sync::RwLock` so that config updates (from the
/// identity API or config reload) are visible to the very next request without
/// restarting the outbound listener.
#[derive(Clone)]
pub struct OutboundSurfaceState {
    /// Authoritative runtime carrier for the outbound pipeline.
    pub surface: Arc<crate::config::agent_surface::AgentSurface>,
    /// Rules engine scoped to identity management (compiled from managed_identity.extension_rules).
    pub identity_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    /// Identity selector with compiled JSON schema (for schema validation and x-identity field extraction).
    pub identity_selector: Option<Arc<crate::identity::IdentitySelector>>,
}

/// Application state passed to every outbound request handler.
///
/// Mirrors [`crate::state::ProxyState`] but is scoped to the outbound pipeline:
/// it carries the outbound-specific surface policy manager, the VCIssuer for
/// identity signing, and omits fields that are inbound-only (e.g. didauth
/// session store, transaction store, mirroring).
#[derive(Clone)]
pub struct OutboundProxyState {
    /// Network configuration (listener metadata, DID domain, etc.).
    pub network_config: Arc<NetworkConfig>,
    /// Live channel state (channel config + compiled rules engines).
    /// Uses `std::sync::RwLock` because reads are sub-microsecond (clone Arcs)
    /// and writes only happen during channel config updates.
    pub channel_state: Arc<std::sync::RwLock<OutboundSurfaceState>>,
    /// Metrics store for recording latency and status.
    pub metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    /// Secrets store (used by target auth injection).
    pub secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    /// Certificate store — used to resolve `ManagedIdentityConfig::FromMtls`
    /// to a stable did:webvh per stored certificate.
    pub certificates_store: Option<Arc<dyn crate::certificates::CertificateStore>>,
    /// Surface-level policy manager (rate limiting + surface-level OPA).
    pub policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    /// Gateway-level OPA policy manager.
    pub gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    /// Trust registry listener manager (for Step 7 — trust context collection).
    pub trust_registry_listener_manager: Option<Arc<crate::trust_registries::TrustRegistryListenerManager>>,
    /// Connection-point listener manager — shared slot populated once the
    /// gateway's fabric listeners are up. Required to forward transit points
    /// whose `target_endpoint` is a `fabric://{gateway_id}/{channel_id}` URL.
    pub listener_manager: Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    /// VCIssuer — provides identity store access and VP creation for Step 10 (signing).
    pub vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    /// Transit token issuer/validator — validates tokens echoed back by the managed agent.
    pub transit_token_issuer: Option<Arc<crate::proxy::transit_token::TransitTokenIssuer>>,
    /// Delegation vault store — for credential injection (Step 11.5).
    pub delegation_vault_store: Option<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>>,
    /// Credential provider store — resolves provider metadata for OAuth flows.
    pub credential_provider_store: Option<Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>>,
    pub consent_identity_strategies: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    pub mcp_continuations: Option<Arc<crate::mcp::continuations::config::ContinuationRuntime>>,
    /// Gateway base URL — for building OAuth authorization URLs.
    pub gateway_base_url: Option<String>,
    /// Task monitor — used to record per-transit-point throughput, total
    /// connections, and errors so the dashboard can render TP rows under
    /// their parent surface group.
    pub task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    /// Byte cap for a buffered MCP upstream response (`a2a.max_body_size`).
    pub max_response_bytes: usize,

    /// When set, skip path-based virtual-channel resolution and use this
    /// alias directly. Populated at route-registration time when the VC
    /// is mounted at a custom `listen_path` (and therefore the request
    /// path no longer follows the `/outgoing/<route>/<alias>` convention
    /// that [`crate::proxy::outbound_handler::resolve_virtual_channel`]
    /// relies on).
    pub vc_alias_override: Option<String>,
}
