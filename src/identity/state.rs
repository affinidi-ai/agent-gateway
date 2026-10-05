//! Identity API state and shared structures

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::GatewayConfig;
use crate::identity::VCIssuer;

/// Shared state for the identity API
#[derive(Clone)]
pub struct IdentityApiState {
    pub vc_issuer: Arc<VCIssuer>,
    pub config: Arc<GatewayConfig>,
    pub network_config: Arc<crate::config::NetworkConfig>,
    pub ws_state: Arc<crate::server::WsState>,
    pub settings_store: Arc<crate::storage::SettingsStore>,
    pub user_settings_store: Arc<crate::storage::UserSettingsStore>,
    pub metrics_store: Arc<crate::metrics::MetricsStore>,
    pub channel_manager: Arc<crate::server::SurfaceTaskManager>,
    pub tls_acceptor: tokio_rustls::TlsAcceptor,
    pub client: reqwest::Client,
    pub bootstrap_config: Arc<crate::config::BootstrapConfig>,
    pub rbac_config: Arc<crate::rbac::RbacConfig>,
    pub task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    pub onboarding_sessions: Arc<crate::identity::handlers::OnboardingSessionManager>,
    pub policy_manager: Arc<crate::policies::SurfacePolicyManager>,
    pub gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    pub notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    pub policy_definition_store: Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>,
    pub global_policy_store: Option<Arc<crate::policies::FileSystemGlobalPolicyStore>>,
    pub global_policy_manager: Option<Arc<crate::policies::GlobalPolicyManager>>,
    pub agent_surface_store: Option<Arc<crate::surfaces::FileSystemAgentSurfaceStore>>,
    pub gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    pub connection_point_store: Option<Arc<crate::gateways::FileSystemConnectionPointStore>>,
    pub mediator_store: Option<Arc<crate::mediators::FileSystemMediatorStore>>,
    pub issuer_store: Option<Arc<crate::issuers::FileSystemIssuerStore>>,
    pub trust_registry_store: Option<Arc<crate::trust_registries::FileSystemTrustRegistryStore>>,
    pub authority_store: Option<Arc<crate::authorities::FileSystemAuthorityStore>>,
    pub integration_store: Option<Arc<crate::storage::IntegrationStorage>>,
    pub mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
    pub a2a_proxy_store: Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,
    pub secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    pub certificate_store: Option<Arc<dyn crate::certificates::CertificateStore>>,
    pub jwt_verification_strategy_store: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    pub credential_provider_store: Option<Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>>,
    pub sts_client_store: Option<Arc<dyn crate::sts::store::StsClientStorage>>,
    /// Pre-resolved per-variant surface snapshots. Phase C scaffolding —
    /// kept in lockstep with `agent_surface_store` writes by
    /// `crate::identity::handlers::surfaces::apply_surface_change`. Phase
    /// D will switch the inbound request pipeline to read snapshots from
    /// here instead of re-deriving them from `ChannelMapping`.
    pub resolved_surface_cache: Arc<crate::surfaces::ResolvedSurfaceCache>,
    pub surface_template_store: Option<Arc<crate::surface_templates::FileSystemSurfaceTemplateStore>>,

    // DID:webvh support (optional, behind feature gate)
    #[cfg(feature = "didwebvh")]
    pub didwebvh_identity_store: Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
    #[cfg(feature = "didwebvh")]
    pub didwebvh_log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
    #[cfg(feature = "didwebvh")]
    pub didwebvh_base_url: Option<String>,
}

/// Request body for issuing a credential
#[derive(Debug, Deserialize)]
pub struct IssueCredentialRequest {
    /// The agent identity payload
    pub agent_identity: serde_json::Value,
}

/// Error response
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}
