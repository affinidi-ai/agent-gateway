//! State structures for multi-channel proxy handlers

use super::proxy::{ProxyState, SurfaceInfo, VariantEngines};
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

impl MultiSurfaceProxyState {
    /// The surface a request on `channel` serves for the URL's `alias` and the
    /// `selected` variant, with the variant it records. Prefers the pre-resolved
    /// snapshot in `resolved_surface_cache`, which `apply_surface_change` fills
    /// whenever a surface is saved and which keeps its last good entry when that
    /// fails; otherwise the selected variant is applied to the channel's surface.
    pub fn served_surface(
        &self,
        channel: &SurfaceInfo,
        alias: Option<&str>,
        selected: Option<&crate::config::agent_surface_variants::SurfaceVariant>,
    ) -> (Arc<crate::config::agent_surface::AgentSurface>, String) {
        match channel
            .surface
            .config_id()
            .and_then(|surface_id| {
                self.resolved_surface_cache
                    .resolve(surface_id, alias)
                    .ok()
            }) {
            Some(cached) => (cached.surface, cached.surface_variant),
            None => {
                let served = channel
                    .surface
                    .serve_selected(selected);
                (Arc::new(served.surface), served.recorded)
            }
        }
    }

    /// The single-surface state a request on `channel` runs with.
    pub fn proxy_state_for(
        &self,
        channel: &SurfaceInfo,
        engines: VariantEngines,
        active_variant_alias: Option<String>,
        active_variant_id: Option<String>,
        surface: Arc<crate::config::agent_surface::AgentSurface>,
    ) -> ProxyState {
        ProxyState {
            config: self.config.clone(),
            network_config: self.network_config.clone(),
            client: self.client.clone(),
            metrics_store: self.metrics_store.clone(),
            identity_rules_engine: engines.identity_rules_engine,
            identity_selector: engines.identity_selector,
            protected_rules_engine: engines.protected_rules_engine,
            protected_selector: engines.protected_selector,
            external_rules_engine: engines.external_rules_engine,
            external_selector: engines.external_selector,
            task_monitor: self.task_monitor.clone(),
            task_id: Some(channel.task_id.clone()),
            ws_state: self.ws_state.clone(),
            listener_manager: self.listener_manager.clone(),
            secrets_store: self.secrets_store.clone(),
            certificates_store: self
                .certificates_store
                .clone(),
            policy_manager: self.policy_manager.clone(),
            gateway_policy_manager: self
                .gateway_policy_manager
                .clone(),
            didauth_session_store: self
                .didauth_session_store
                .clone(),
            transaction_store: self.transaction_store.clone(),
            mpp_transaction_store: self
                .mpp_transaction_store
                .clone(),
            trust_registry_listener_manager: self
                .trust_registry_listener_manager
                .clone(),
            source_auth_middleware: self
                .source_auth_middleware
                .clone(),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: self
                .didwebvh_identity_store
                .clone(),
            #[cfg(feature = "didwebvh")]
            didwebvh_log_manager: self
                .didwebvh_log_manager
                .clone(),
            credential_provider_store: self
                .credential_provider_store
                .clone(),
            delegation_vault_store: self
                .delegation_vault_store
                .clone(),
            gateway_base_url: self.gateway_base_url.clone(),
            transit_token_issuer: self
                .transit_token_issuer
                .clone(),
            mcp_proxy_store: self.mcp_proxy_store.clone(),
            a2a_proxy_store: self.a2a_proxy_store.clone(),
            vc_issuer: self.vc_issuer.clone(),
            active_variant_alias,
            active_variant_id,
            surface,
        }
    }

    /// The state a request on the base route (the Access Point URL without a
    /// `$alias`) of the surface `surface_id` gets on this listener. `None` when no
    /// channel here runs the surface, or when the request path refuses the base
    /// route because its default Surface Variant is missing, disabled or not
    /// compiled.
    pub async fn base_proxy_state(
        &self,
        surface_id: &str,
    ) -> Option<ProxyState> {
        let channels = self.channels.read().await;
        let channel = channels
            .iter()
            .find(|channel| channel.surface.config_id() == Some(surface_id))?;
        let selected = channel
            .surface
            .select_variant(None)
            .ok()?;
        let variant_id = selected.map(|variant| variant.id.clone());
        let engines = channel.engines_for(variant_id.as_deref())?;
        let (surface, _) = self.served_surface(channel, None, selected);
        Some(self.proxy_state_for(channel, engines, None, variant_id, surface))
    }
}
