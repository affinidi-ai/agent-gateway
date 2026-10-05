//! Channel task manager for managing proxy channels lifecycle

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::AbortHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::GatewayConfig;

/// Extract port number from an address string
#[allow(dead_code)]
fn extract_port_from_address(addr: &str) -> Option<u16> {
    let addr_without_protocol = addr
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let default_port = if addr.starts_with("https://") {
        443
    } else if addr.starts_with("http://") {
        80
    } else {
        0
    };

    if let Some(colon_pos) = addr_without_protocol.rfind(':') {
        let port_str = &addr_without_protocol[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return Some(port);
        }
    }

    if default_port > 0 {
        Some(default_port)
    } else {
        None
    }
}

/// Shared state for managing channel tasks and configuration reloading
#[derive(Clone)]
pub struct SurfaceTaskManager {
    /// Handles to running port listener tasks (mapped by port - should NOT be restarted)
    pub(crate) port_listener_handles: Arc<RwLock<HashMap<u16, AbortHandle>>>,
    /// MultiSurfaceProxyState for each port listener (for dynamic channel updates)
    pub(crate) port_listener_states: Arc<RwLock<HashMap<u16, Arc<crate::state::MultiSurfaceProxyState>>>>,
    /// Live-updatable outbound channel states keyed by config_id
    pub(crate) outbound_channel_states:
        Arc<std::sync::RwLock<HashMap<String, Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>>>>>,
    /// Handles to running channel tasks mapped by channel name (DEPRECATED - channels don't have separate tasks anymore)
    pub(crate) channel_handles: Arc<RwLock<HashMap<String, AbortHandle>>>,
    /// Task IDs mapped by channel name (for unregistering from TaskMonitor)
    pub(crate) task_ids: Arc<RwLock<HashMap<String, String>>>,
    /// Configuration for channels
    config: Arc<RwLock<Arc<GatewayConfig>>>,
    /// Bootstrap configuration
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    /// Configuration cache for fallback
    config_cache: Arc<crate::storage::ConfigCache>,
    /// WebSocket state for real-time updates (shared across all channels)
    ws_state: Option<Arc<crate::server::WsState>>,
    /// VC issuer for generating agent DIDs
    vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    /// Connection point listener manager for fabric:// protocol forwarding
    listener_manager: Arc<RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    /// Identity API routers for HTTP and HTTPS (to be merged into port listeners during reload)
    identity_http_router: Arc<RwLock<Option<axum::Router>>>,
    identity_https_router: Arc<RwLock<Option<axum::Router>>>,
    /// Onboarding routers for HTTP and HTTPS
    onboarding_http_router: Arc<RwLock<Option<axum::Router>>>,
    onboarding_https_router: Arc<RwLock<Option<axum::Router>>>,
    /// DID routers for HTTP and HTTPS
    did_http_router: Arc<RwLock<Option<axum::Router>>>,
    did_https_router: Arc<RwLock<Option<axum::Router>>>,
    /// Secrets/Vault routers for HTTP and HTTPS
    vault_http_router: Arc<RwLock<Option<axum::Router>>>,
    vault_https_router: Arc<RwLock<Option<axum::Router>>>,
    /// MCP proxy store for MCP channel support
    mcp_proxy_store: Arc<RwLock<Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>>>,
    /// A2A proxy store for A2A target adapter support
    a2a_proxy_store: Arc<RwLock<Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>>>,
    /// MCP server manager for MCP channel support
    mcp_server_manager: Arc<RwLock<Option<Arc<crate::mcp_proxies::handlers::McpServerManager>>>>,
    /// Secrets store for secrets API
    secrets_store: Arc<RwLock<Option<Arc<dyn crate::secrets::SecretsStore>>>>,
    /// Policy manager for OPA policies
    policy_manager: Arc<RwLock<Option<Arc<crate::policies::SurfacePolicyManager>>>>,
    /// Gateway-level policy manager for gateway-wide OPA policies
    gateway_policy_manager: Arc<RwLock<Option<Arc<crate::policies::GatewayPolicyManager>>>>,
    /// Settings store for surfaces to access secrets
    settings_store: Arc<crate::storage::SettingsStore>,
    /// Notification store for integration triggering
    notification_store: Arc<RwLock<Option<Arc<crate::integrations::FileSystemNotificationStore>>>>,
    /// DID Auth session store for challenge-response authentication
    didauth_session_store: Arc<crate::didauth::DidAuthSessionStore>,
    /// Unified source authentication middleware
    source_auth_middleware: Arc<RwLock<Option<Arc<crate::source_auth::SourceAuthMiddleware>>>>,
    /// Direct-TLS inbound client auth (CA bundle + mode) — enables peer-cert capture on listeners
    direct_client_auth: Arc<RwLock<Option<Arc<crate::server::DirectClientAuth>>>>,
    /// Resolved-surface snapshot cache shared with the inbound request
    /// pipeline. Set by orchestrator after surface store init.
    resolved_surface_cache: Arc<RwLock<Option<Arc<crate::surfaces::ResolvedSurfaceCache>>>>,
    /// DID:webvh identity store for channel DID injection
    #[cfg(feature = "didwebvh")]
    didwebvh_identity_store: Arc<RwLock<Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>>>,
    /// DID:webvh log storage for channel DID log access
    #[cfg(feature = "didwebvh")]
    didwebvh_log_storage: Arc<RwLock<Option<Arc<dyn crate::storage::DidLogStorage>>>>,
    /// Serializes listener reloads. Both the full reload (`reload_channels`) and the
    /// single-channel reload (`reload_single_channel_with_fallback`) rebind ports and
    /// mutate the shared listener maps, so a promotion re-derive and a concurrent
    /// surface-store change must not run them at once (a port-bind race yields a hard
    /// bind failure). Shared across all clones via `Arc`.
    reload_lock: Arc<tokio::sync::Mutex<()>>,
}

impl SurfaceTaskManager {
    pub fn new(
        config: Arc<GatewayConfig>,
        bootstrap_config: Arc<crate::config::BootstrapConfig>,
        config_cache: Arc<crate::storage::ConfigCache>,
        ws_state: Option<Arc<crate::server::WsState>>,
        vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
        listener_manager: Option<Arc<crate::gateways::ConnectionPointListenerManager>>,
        settings_store: Arc<crate::storage::SettingsStore>,
        didauth_session_store: Arc<crate::didauth::DidAuthSessionStore>,
    ) -> Self {
        Self {
            port_listener_handles: Arc::new(RwLock::new(HashMap::new())),
            port_listener_states: Arc::new(RwLock::new(HashMap::new())),
            outbound_channel_states: Arc::new(std::sync::RwLock::new(HashMap::new())),
            channel_handles: Arc::new(RwLock::new(HashMap::new())),
            task_ids: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(RwLock::new(config)),
            bootstrap_config,
            config_cache,
            ws_state,
            vc_issuer,
            listener_manager: Arc::new(RwLock::new(listener_manager)),
            // Initialize router storage as empty - will be set by orchestrator after routers are created
            identity_http_router: Arc::new(RwLock::new(None)),
            identity_https_router: Arc::new(RwLock::new(None)),
            onboarding_http_router: Arc::new(RwLock::new(None)),
            onboarding_https_router: Arc::new(RwLock::new(None)),
            did_http_router: Arc::new(RwLock::new(None)),
            did_https_router: Arc::new(RwLock::new(None)),
            vault_http_router: Arc::new(RwLock::new(None)),
            vault_https_router: Arc::new(RwLock::new(None)),
            mcp_proxy_store: Arc::new(RwLock::new(None)),
            a2a_proxy_store: Arc::new(RwLock::new(None)),
            mcp_server_manager: Arc::new(RwLock::new(None)),
            secrets_store: Arc::new(RwLock::new(None)),
            policy_manager: Arc::new(RwLock::new(None)),
            gateway_policy_manager: Arc::new(RwLock::new(None)),
            settings_store,
            notification_store: Arc::new(RwLock::new(None)),
            didauth_session_store,
            source_auth_middleware: Arc::new(RwLock::new(None)),
            direct_client_auth: Arc::new(RwLock::new(None)),
            resolved_surface_cache: Arc::new(RwLock::new(None)),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: Arc::new(RwLock::new(None)),
            #[cfg(feature = "didwebvh")]
            didwebvh_log_storage: Arc::new(RwLock::new(None)),
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Set the Identity API and supporting routers (called by orchestrator after router creation)
    pub async fn set_identity_routers(
        &self,
        identity_http: Option<axum::Router>,
        identity_https: Option<axum::Router>,
        onboarding_http: Option<axum::Router>,
        onboarding_https: Option<axum::Router>,
        did_http: Option<axum::Router>,
        did_https: Option<axum::Router>,
        vault_http: Option<axum::Router>,
        vault_https: Option<axum::Router>,
    ) {
        *self
            .identity_http_router
            .write()
            .await = identity_http;
        *self
            .identity_https_router
            .write()
            .await = identity_https;
        *self
            .onboarding_http_router
            .write()
            .await = onboarding_http;
        *self
            .onboarding_https_router
            .write()
            .await = onboarding_https;
        *self
            .did_http_router
            .write()
            .await = did_http;
        *self
            .did_https_router
            .write()
            .await = did_https;
        *self
            .vault_http_router
            .write()
            .await = vault_http;
        *self
            .vault_https_router
            .write()
            .await = vault_https;
    }

    /// Set MCP and related services (called by orchestrator)
    pub async fn set_services(
        &self,
        mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
        a2a_proxy_store: Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,
        mcp_server_manager: Option<Arc<crate::mcp_proxies::handlers::McpServerManager>>,
        secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
        policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
        gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    ) {
        *self
            .mcp_proxy_store
            .write()
            .await = mcp_proxy_store;
        *self
            .a2a_proxy_store
            .write()
            .await = a2a_proxy_store;
        *self
            .mcp_server_manager
            .write()
            .await = mcp_server_manager;
        *self
            .secrets_store
            .write()
            .await = secrets_store;
        *self
            .policy_manager
            .write()
            .await = policy_manager;
        *self
            .gateway_policy_manager
            .write()
            .await = gateway_policy_manager;
    }

    /// Get the current configuration
    pub async fn get_config(&self) -> Arc<GatewayConfig> {
        self.config
            .read()
            .await
            .clone()
    }

    /// Set the listener manager (called after it's created during startup)
    pub async fn set_listener_manager(
        &self,
        listener_manager: Arc<crate::gateways::ConnectionPointListenerManager>,
    ) {
        let mut mgr = self
            .listener_manager
            .write()
            .await;
        *mgr = Some(listener_manager);
        info!("✓ Listener manager set in SurfaceTaskManager - fabric:// protocol now available");
    }

    /// Set notification store (called during startup)
    pub async fn set_notification_store(
        &self,
        notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    ) {
        *self
            .notification_store
            .write()
            .await = notification_store;
        info!("✓ Notification store set in SurfaceTaskManager");
    }

    /// Set the unified source authentication middleware
    pub async fn set_source_auth_middleware(
        &self,
        source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
    ) {
        *self
            .source_auth_middleware
            .write()
            .await = source_auth_middleware;
        info!("✓ Source auth middleware set in SurfaceTaskManager");
    }

    /// Set the direct-TLS inbound client auth (used when starting/reloading listeners)
    pub async fn set_direct_client_auth(
        &self,
        direct_client_auth: Option<Arc<crate::server::DirectClientAuth>>,
    ) {
        *self
            .direct_client_auth
            .write()
            .await = direct_client_auth;
        info!("✓ Direct-TLS client auth set in SurfaceTaskManager");
    }

    /// Wire the resolved-surface snapshot cache so full port-listener
    /// reloads can hand the same shared cache to every spawned port
    /// listener. Called once by the orchestrator after the cache is
    /// constructed and pre-populated.
    pub async fn set_resolved_surface_cache(
        &self,
        cache: Arc<crate::surfaces::ResolvedSurfaceCache>,
    ) {
        *self
            .resolved_surface_cache
            .write()
            .await = Some(cache);
        info!("✓ Resolved-surface cache set in SurfaceTaskManager");
    }

    /// Set DID:webvh stores (called during startup after identity state is initialized)
    #[cfg(feature = "didwebvh")]
    pub async fn set_didwebvh_stores(
        &self,
        identity_store: Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
        log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
    ) {
        *self
            .didwebvh_identity_store
            .write()
            .await = identity_store;
        *self
            .didwebvh_log_storage
            .write()
            .await = log_storage;
        info!("✓ DID:webvh stores set in SurfaceTaskManager");
    }

    /// Update configuration and restart channel tasks
    /// Returns (channels_count, is_fallback, warning_message)
    pub async fn reload_channels(
        &self,
        new_config: Arc<GatewayConfig>,
        tls_acceptor: TlsAcceptor,
        client: reqwest::Client,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(usize, bool, Option<String>)> {
        // Serialize against any concurrent single-channel or full reload so two reloads
        // never rebind the same port at once (F1).
        let _reload_guard = self.reload_lock.lock().await;
        info!("Reloading channel configuration...");

        // Step 1: Abort all existing port listener tasks
        {
            let mut handles = self
                .channel_handles
                .write()
                .await;
            let mut task_ids_map = self.task_ids.write().await;
            info!("Stopping {} existing per-channel listener tasks", handles.len());

            // Abort all per-channel handles (legacy; usually empty in the
            // port-listener model).
            for (channel_name, handle) in handles.drain() {
                info!("Aborting per-channel listener: {}", channel_name);
                handle.abort();
            }

            // Clear task IDs map
            task_ids_map.clear();
        }

        // Step 1b: Abort the previous port listeners so their TCP sockets
        // are released before we rebind below. Without this the new
        // listeners hit "Address already in use (os error 48)" because
        // the old tasks are still owning 8080/8081/8443.
        {
            let mut port_handles = self
                .port_listener_handles
                .write()
                .await;
            info!("Stopping {} existing port listener task(s)", port_handles.len());
            for (port, handle) in port_handles.drain() {
                info!("Aborting port listener on port {}", port);
                handle.abort();
            }
        }
        {
            let mut port_states = self
                .port_listener_states
                .write()
                .await;
            port_states.clear();
        }

        // Drop cached outbound channel state so the rebuilt outbound
        // listeners repopulate it from the new config. `run_outbound_port_server`
        // reuses any existing `OutboundSurfaceState` by `config_id` (so a
        // channel spanning multiple ports shares one state); without this
        // clear, a stale surface — e.g. a transit point whose `target_endpoint`
        // was switched from `fabric://…` back to a direct URL — would survive
        // the reload and the gateway would keep routing to the old destination.
        {
            let mut outbound_states = self
                .outbound_channel_states
                .write()
                .expect("outbound_channel_states lock poisoned");
            outbound_states.clear();
        }

        // Step 2: Drop stale TaskInfo entries proactively. Aborting a
        // port listener cancels the `axum_server::serve(...).await`
        // point, so the post-await cleanup in `run_port_server` that
        // would normally call `unregister_task` never executes. Without
        // this clear, every reload accumulates duplicate AP rows
        // (their task_ids embed a fresh UUID, so re-registration does
        // not overwrite). Then sleep briefly so the OS releases the
        // listening sockets before we rebind them below.
        if let Some(ref monitor) = task_monitor {
            let cleared = monitor
                .clear_all_tasks()
                .await;
            if cleared > 0 {
                info!("Cleared {} stale task(s) from monitor before reload", cleared);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Step 2: Update configuration
        {
            let mut config_lock = self.config.write().await;
            *config_lock = new_config.clone();
        }

        // Step 3: Save successful configuration to cache
        if let Err(e) = self
            .config_cache
            .save(&new_config, "dynamodb")
            .await
        {
            warn!("Failed to save configuration to cache: {}", e);
        }

        // Step 4: Load network configuration and extract ports
        let network_config = self
            .bootstrap_config
            .load_network_config()
            .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;

        let configured_ports = network_config.get_ports();
        info!("Using ports from network config: {:?}", configured_ports);

        // Helper function to map external listen_address to internal port
        let map_address_to_port = |listen_addr: &str| -> Option<u16> { network_config.map_url_to_port(listen_addr) };

        // Helper that restricts outbound route registration to outbound listeners.
        let map_outbound_address_to_port = |listen_addr: &str| -> Option<u16> {
            network_config.map_url_to_port_for_type(listen_addr, Some("outbound"))
        };

        let active_surfaces: Vec<crate::config::agent_surface::AgentSurface> = new_config
            .surfaces
            .iter()
            .filter(|surface| surface.status == crate::config::agent_surface::SurfaceStatus::Active)
            .cloned()
            .collect();
        let channels_count = active_surfaces.len();

        // Group channels by the port they'll use (inbound). Stored as
        // `AgentSurface` so `variants` / `default_variant_id` survive into the
        // runtime listener.
        let mut channels_by_port: HashMap<u16, Vec<crate::config::agent_surface::AgentSurface>> = HashMap::new();
        for surface in &active_surfaces {
            let listen_address = surface.listen_address();
            let surface_name = &surface.name;
            // Map channel's listen_address to internal port (inbound traffic)
            if let Some(port) = map_address_to_port(listen_address) {
                // Only include channel if its mapped port is in the configured ports
                if configured_ports.contains(&port) {
                    channels_by_port
                        .entry(port)
                        .or_default()
                        .push(surface.clone());
                } else {
                    warn!(
                        "Channel '{}' maps to port {} which is not in configured ports {:?} - skipping",
                        surface_name, port, configured_ports
                    );
                }
            } else {
                warn!(
                    "Could not map channel '{}' listen_address '{}' to any internal port - skipping",
                    surface_name, listen_address
                );
            }
        }

        // Group outbound-enabled channels by their outbound listener port.
        // Each VC may override the channel-wide outbound_listen_address with
        // its own `listen_address`, so the same channel can appear in
        // multiple ports' buckets paired with only the subset of VCs
        // assigned to that port. Restrict the configured-port set to
        // outbound listeners so a VC whose address points at an inbound
        // URL surfaces as a misconfiguration rather than being silently
        // bucketed onto a port that doesn't run an outbound server.
        let outbound_ports = network_config.get_outbound_ports();
        let outbound_channels_by_port =
            crate::config::group_outbound_vcs_by_port(&active_surfaces, &outbound_ports, map_outbound_address_to_port);

        info!("Grouped {} channels across {} configured ports", channels_count, channels_by_port.len());

        // Store handles and states for port listeners
        let mut new_port_handles = HashMap::new();
        let mut new_port_states = HashMap::new();

        // Spawn ONE listener task per configured port that handles routing to all channels on that port
        // Iterate over ALL configured ports, not just those with channels

        // Get stored routers for merging into port listeners
        let identity_http_router = self
            .identity_http_router
            .read()
            .await
            .clone();
        let identity_https_router = self
            .identity_https_router
            .read()
            .await
            .clone();
        let onboarding_http_router = self
            .onboarding_http_router
            .read()
            .await
            .clone();
        let onboarding_https_router = self
            .onboarding_https_router
            .read()
            .await
            .clone();
        let did_http_router = self
            .did_http_router
            .read()
            .await
            .clone();
        let did_https_router = self
            .did_https_router
            .read()
            .await
            .clone();
        let vault_http_router = self
            .vault_http_router
            .read()
            .await
            .clone();
        let vault_https_router = self
            .vault_https_router
            .read()
            .await
            .clone();
        let mcp_proxy_store = self
            .mcp_proxy_store
            .read()
            .await
            .clone();
        let a2a_proxy_store = self
            .a2a_proxy_store
            .read()
            .await
            .clone();
        let mcp_server_manager = self
            .mcp_server_manager
            .read()
            .await
            .clone();
        let secrets_store = self
            .secrets_store
            .read()
            .await
            .clone();
        let policy_manager = self
            .policy_manager
            .read()
            .await
            .clone();

        for port in configured_ports {
            // Get channels for this port (may be empty)
            let channels = channels_by_port
                .get(&port)
                .cloned()
                .unwrap_or_default();
            let port_task_id = format!("port-{}-{}", port, uuid::Uuid::new_v4());
            let tls_acceptor = tls_acceptor.clone();
            let client = client.clone();
            let config = new_config.clone();
            let bootstrap_config_clone = self.bootstrap_config.clone();
            let metrics = metrics_store.clone();
            let task_mon = task_monitor.clone();
            let task_id_clone = port_task_id.clone();
            let ws_state_clone = self.ws_state.clone();
            let vc_issuer_clone = self.vc_issuer.clone();
            let channels_clone = channels.clone(); // Clone for the async block
            let listener_mgr_clone = self.listener_manager.clone();
            let network_config_clone = Arc::new(network_config.clone());

            // Create a oneshot channel to receive the state from the spawned task
            let (state_sender, state_receiver) = tokio::sync::oneshot::channel();

            // Determine if this port should use TLS based on network config
            let listener_info = network_config
                .listeners
                .iter()
                .find(|l| l.port == port);

            let use_tls = listener_info
                .map(|l| l.protocol.to_lowercase() == "https")
                .unwrap_or(false);

            // Check whether this is an outbound listener.
            let listener_type = listener_info
                .map(|l| l.listener_type.as_str())
                .unwrap_or("inbound");

            if listener_type == "outbound" {
                // ── Outbound listener ────────────────────────────────────────
                // Use the dedicated outbound_channels_by_port map (built from outbound_listen_address).
                let outbound_channels = outbound_channels_by_port
                    .get(&port)
                    .cloned()
                    .unwrap_or_default();

                if outbound_channels.is_empty() {
                    info!("Outbound listener on port {} has no enabled outbound channels — skipping", port);
                    // Still need to insert a dummy handle so the port counts as running.
                    let handle = tokio::spawn(std::future::pending::<()>());
                    new_port_handles.insert(port, handle.abort_handle());
                    continue;
                }

                let bind_address = listener_info
                    .map(|l| l.bind_address.clone())
                    .unwrap_or_else(|| "127.0.0.1".to_string());

                let secrets_store_clone = secrets_store.clone();
                let policy_manager_clone = policy_manager.clone();
                let gateway_policy_manager_clone = self
                    .gateway_policy_manager
                    .read()
                    .await
                    .clone();
                let trust_registry_clone =
                    crate::gateways::connection_points::message_processor::get_trust_registry_listener_manager();
                let metrics_clone = metrics_store.clone();

                let outbound_states = self
                    .outbound_channel_states
                    .clone();
                let direct_client_auth_clone = self
                    .direct_client_auth
                    .read()
                    .await
                    .clone();
                let consent_strategies = self
                    .source_auth_middleware
                    .read()
                    .await
                    .as_ref()
                    .map(|middleware| middleware.provider_store());

                let handle = tokio::spawn(async move {
                    if let Err(e) = super::server::run_outbound_port_server(
                        bind_address,
                        port,
                        outbound_channels,
                        config,
                        network_config_clone,
                        metrics_clone,
                        secrets_store_clone,
                        policy_manager_clone,
                        gateway_policy_manager_clone,
                        trust_registry_clone,
                        vc_issuer_clone,
                        task_mon,
                        use_tls,
                        outbound_states,
                        direct_client_auth_clone,
                        listener_mgr_clone,
                        consent_strategies,
                    )
                    .await
                    {
                        error!("Outbound port listener error for port {}: {}", port, e);
                    }
                });

                new_port_handles.insert(port, handle.abort_handle());
                continue;
            }

            info!(
                "Reloading port listener on 0.0.0.0:{} for {} channel(s), protocol: {}",
                port,
                channels.len(),
                if use_tls {
                    "HTTPS"
                } else {
                    "HTTP"
                }
            );

            // Determine which routers to merge into this port based on TLS setting
            let identity_router = if use_tls {
                identity_https_router.clone()
            } else {
                identity_http_router.clone()
            };
            let onboarding_router = if use_tls {
                onboarding_https_router.clone()
            } else {
                onboarding_http_router.clone()
            };
            let did_router = if use_tls {
                did_https_router.clone()
            } else {
                did_http_router.clone()
            };
            let vault_router = if use_tls {
                vault_https_router.clone()
            } else {
                vault_http_router.clone()
            };

            let mcp_proxy_store_clone = mcp_proxy_store.clone();
            let a2a_proxy_store_clone = a2a_proxy_store.clone();
            let mcp_server_manager_clone = mcp_server_manager.clone();
            let secrets_store_clone = secrets_store.clone();
            let policy_manager_clone = policy_manager.clone();
            let gateway_policy_manager_clone = self
                .gateway_policy_manager
                .read()
                .await
                .clone();
            let settings_store_clone = self.settings_store.clone();
            let notification_store_clone = self
                .notification_store
                .read()
                .await
                .clone();
            let didauth_session_store_clone = self
                .didauth_session_store
                .clone();
            let source_auth_middleware_clone = self
                .source_auth_middleware
                .read()
                .await
                .clone();
            let direct_client_auth_clone = self
                .direct_client_auth
                .read()
                .await
                .clone();
            let resolved_surface_cache_clone = self
                .resolved_surface_cache
                .read()
                .await
                .clone()
                .unwrap_or_else(|| Arc::new(crate::surfaces::ResolvedSurfaceCache::new()));
            #[cfg(feature = "didwebvh")]
            let didwebvh_identity_store_clone = self
                .didwebvh_identity_store
                .read()
                .await
                .clone();
            #[cfg(feature = "didwebvh")]
            let didwebvh_log_storage_clone = self
                .didwebvh_log_storage
                .read()
                .await
                .clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = super::server::run_port_server(
                    port,
                    channels_clone,
                    tls_acceptor,
                    client,
                    config,
                    bootstrap_config_clone,
                    metrics,
                    task_mon.clone(),
                    Some(task_id_clone.clone()),
                    ws_state_clone,
                    vc_issuer_clone,
                    listener_mgr_clone,
                    Some(state_sender),
                    identity_router,     // Pass Identity API router
                    onboarding_router,   // Pass Onboarding router
                    did_router,          // Pass DID router
                    vault_router,        // Pass Vault router
                    secrets_store_clone, // Pass secrets store
                    network_config_clone,
                    use_tls,
                    policy_manager_clone,         // Pass policy manager
                    gateway_policy_manager_clone, // Pass gateway policy manager
                    mcp_proxy_store_clone,        // Pass MCP proxy store
                    a2a_proxy_store_clone,        // Pass A2A proxy store
                    mcp_server_manager_clone,     // Pass MCP server manager
                    settings_store_clone,         // Pass settings store
                    notification_store_clone,     // Pass notification store
                    didauth_session_store_clone,  // Pass DID Auth session store
                    source_auth_middleware_clone, // Pass unified source auth middleware
                    direct_client_auth_clone,     // Pass direct-TLS client auth
                    resolved_surface_cache_clone, // Phase D — pre-resolved surface snapshots
                    #[cfg(feature = "didwebvh")]
                    didwebvh_identity_store_clone,
                    #[cfg(feature = "didwebvh")]
                    didwebvh_log_storage_clone,
                )
                .await
                {
                    error!("Port listener error for port {}: {}", port, e);
                }
            });

            // Store the abort handle for this port listener
            new_port_handles.insert(port, handle.abort_handle());

            // Wait for the state to be sent back (with a timeout)
            if let Ok(state) = tokio::time::timeout(tokio::time::Duration::from_secs(5), state_receiver).await {
                if let Ok(state) = state {
                    new_port_states.insert(port, state);
                } else {
                    warn!("Port listener {} failed to send state", port);
                }
            } else {
                warn!("Timeout waiting for port listener {} state", port);
            }

            // Note: Individual channel task IDs are managed by the port listener itself
            // We don't create or track them here - the port listener registers them with the task monitor
        }

        // Step 5: Store new handles and port listener states
        {
            let mut port_handles = self
                .port_listener_handles
                .write()
                .await;
            *port_handles = new_port_handles;
        }
        {
            let mut port_states = self
                .port_listener_states
                .write()
                .await;
            *port_states = new_port_states;
        }

        // Clear channel handles and task IDs since they're now managed by port listeners
        {
            let mut handles = self
                .channel_handles
                .write()
                .await;
            handles.clear();
        }
        {
            let mut task_ids_map = self.task_ids.write().await;
            task_ids_map.clear();
        }

        info!("Successfully reloaded {} channels", channels_count);
        Ok((channels_count, false, None))
    }

    /// Reload channels with fallback to cached configuration on failure
    pub async fn reload_channels_with_fallback(
        &self,
        new_config_result: anyhow::Result<Arc<GatewayConfig>>,
        tls_acceptor: TlsAcceptor,
        client: reqwest::Client,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(usize, bool, Option<String>)> {
        match new_config_result {
            Ok(new_config) => {
                // Try to reload with new configuration
                self.reload_channels(new_config, tls_acceptor, client, metrics_store, task_monitor)
                    .await
            }
            Err(load_error) => {
                // Failed to load new config, try to use cached config
                warn!("Failed to load new configuration: {}. Attempting to use cached configuration.", load_error);

                match self.config_cache.load().await {
                    Ok(cached) => {
                        info!(
                            cached_at = %cached.cached_at,
                            channels = cached.config.surfaces.len(),
                            "Using cached configuration as fallback"
                        );

                        let warning = format!(
                            "Failed to load new configuration from DynamoDB. Using cached configuration from {}. Error: {}",
                            cached.cached_at, load_error
                        );

                        // Reload with cached config
                        let new_config = Arc::new(cached.config);
                        match self
                            .reload_channels(new_config, tls_acceptor, client, metrics_store, task_monitor)
                            .await
                        {
                            Ok((channels_count, _, _)) => Ok((channels_count, true, Some(warning))),
                            Err(e) => {
                                error!("Failed to reload even with cached configuration: {}", e);
                                Err(e)
                            }
                        }
                    }
                    Err(cache_error) => {
                        error!(
                            load_error = %load_error,
                            cache_error = %cache_error,
                            "Failed to load new configuration and no cached configuration available"
                        );
                        anyhow::bail!(
                            "Failed to load new configuration: {}. Also failed to load cached configuration: {}",
                            load_error,
                            cache_error
                        )
                    }
                }
            }
        }
    }

    /// Reload a single channel by name
    /// Updates the channel in the running port listener's state WITHOUT restarting the listener
    /// Returns (is_fallback, warning_message)
    pub async fn reload_single_channel(
        &self,
        channel_name: &str,
        new_surface: crate::config::agent_surface::AgentSurface,
        _tls_acceptor: TlsAcceptor,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(bool, Option<String>)> {
        debug!("Reloading single channel: {}", channel_name);

        // Surface accessors mirror the legacy ChannelMapping field shapes;
        // the surface itself is the source of truth and is what we publish
        // into config + listener state.
        let surface_name = new_surface.name.clone();
        let surface_listen_address = new_surface
            .listen_address()
            .to_string();
        let surface_target_endpoint = new_surface
            .target_endpoint()
            .to_string();
        let surface_outbound_listen_address = new_surface
            .transit
            .as_ref()
            .and_then(|t| {
                t.outbound_listen_address
                    .clone()
            });
        let surface_has_outbound = new_surface
            .transit
            .as_ref()
            .is_some_and(|t| !t.points.is_empty());

        // Step 1: Update the channel in the configuration first
        let port: u16;
        let previous_surface: Option<crate::config::agent_surface::AgentSurface>;
        {
            let mut config_lock = self.config.write().await;
            let mut new_config = (**config_lock).clone();

            // Find and replace the channel by config_id, or add it if it doesn't exist
            if let Some(config_id) = new_surface.config_id() {
                if let Some(idx) = new_config
                    .surfaces
                    .iter()
                    .position(|r| r.config_id() == Some(config_id))
                {
                    previous_surface = Some(new_config.surfaces[idx].clone());
                    new_config.surfaces[idx] = new_surface.clone();
                    info!("Updated existing channel with config_id '{}': {}", config_id, surface_name);
                    crate::channel_info!(config_id, "Updated existing channel: {}", surface_name);
                } else {
                    previous_surface = None;
                    new_config
                        .surfaces
                        .push(new_surface.clone());
                    info!("Added new channel with config_id '{}': {}", config_id, surface_name);
                    crate::channel_info!(config_id, "Added new channel: {}", surface_name);
                }
            } else {
                // All channels MUST have config_id - this should never happen
                error!("Channel '{}' has no config_id - this should never happen!", surface_name);
                return Err(anyhow::anyhow!("Channel '{}' has no config_id", surface_name));
            }

            // Load network configuration to map addresses to ports
            let network_config = self
                .bootstrap_config
                .load_network_config()
                .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;

            // Get the port for this channel
            port = network_config
                .map_url_to_port(&surface_listen_address)
                .ok_or_else(|| {
                    anyhow::anyhow!("Could not map channel listen_address to internal port: {}", surface_listen_address)
                })?;

            *config_lock = Arc::new(new_config.clone());

            // Save updated configuration to cache
            if let Err(e) = self
                .config_cache
                .save(&new_config, "single_channel_reload")
                .await
            {
                warn!("Failed to save configuration to cache: {}", e);
            }
        }

        info!("Channel '{}' uses port {} - updating state dynamically (no restart)", channel_name, port);
        if let Some(config_id) = new_surface.config_id() {
            crate::channel_info!(config_id, "Channel uses port {} - updating state dynamically (no restart)", port);
        }

        // Step 2: Get the port listener state for this port
        let port_states = self
            .port_listener_states
            .read()
            .await;
        let state = port_states
            .get(&port)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No port listener found for port {}. This should not happen - port listeners should be permanent.",
                    port
                )
            })?;

        // Step 3: Build the new SurfaceInfo for this channel
        let vc_issuer = self.vc_issuer.clone();

        // Compile identity engines for this channel
        let channel_surface = new_surface.clone();
        let engines = crate::proxy::compile_identity_engines_from_surface(&channel_surface, vc_issuer.as_ref())
            .map_err(|e| {
                error!(channel = %surface_name, error = %e, "Failed to compile identity engines");
                if let Some(config_id) = new_surface.config_id() {
                    crate::channel_error!(config_id, "Failed to compile identity engines: {}", e);
                }
                anyhow::anyhow!("Failed to compile identity engines for channel {}: {}", surface_name, e)
            })?;
        let identity_rules_engine = engines.rules_engine;
        let identity_selector = engines.selector;
        let protected_rules_engine = engines.protected_rules_engine;
        let protected_selector = engines.protected_selector;
        let external_rules_engine = engines.external_rules_engine;
        let external_selector = engines.external_selector;
        if identity_rules_engine.is_some() {
            info!(channel = %surface_name, "Compiled identity rules engine from managed_identity");
            if let Some(config_id) = new_surface.config_id() {
                crate::channel_info!(config_id, "Compiled identity rules engine from managed_identity");
            }
        }
        if identity_selector.is_some() {
            info!(channel = %surface_name, "Compiled identity selector from managed_identity JSON Schema");
            if let Some(config_id) = new_surface.config_id() {
                crate::channel_info!(config_id, "Compiled identity selector from managed_identity JSON Schema");
            }
        }

        // Use config_id for task ID to ensure stability across name changes
        let channel_task_id = if let Some(config_id) = new_surface.config_id() {
            format!("task-{}-{}", config_id, uuid::Uuid::new_v4())
        } else {
            // Fallback to name if no config_id (should never happen)
            format!("task-{}-{}", surface_name, uuid::Uuid::new_v4())
        };

        // Step 3a: Drop every stale TaskInfo for this config_id (AP + every
        // TP) before we register the new ones. The previous implementation
        // only unregistered the AP task and left old TP tasks behind, so a
        // surface that lost or renamed a transit point would accumulate
        // ghost rows in the dashboard on every reload.
        if let Some(ref monitor) = task_monitor
            && let Some(config_id) = new_surface.config_id()
        {
            let removed = monitor
                .unregister_all_tasks_for_config_id(config_id)
                .await;
            if removed > 0 {
                info!("Unregistered {} old task(s) for channel with config_id '{}' before reload", removed, config_id);
            }
        }

        // Register task for monitoring if enabled
        if let Some(ref monitor) = task_monitor {
            let now = chrono::Utc::now();
            let task_info = crate::observability::TaskInfo {
                task_id: channel_task_id.clone(),
                config_id: new_surface
                    .config_id()
                    .map(str::to_string), // Use config_id for tracking
                channel_name: surface_name.clone(),
                transit_point: None,
                listen_address: surface_listen_address.clone(),
                target_endpoint: surface_target_endpoint.clone(),
                started_at: now,
                status: crate::observability::TaskStatus::Running,
                total_connections: 0,
                active_connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
                last_activity: None,
                error_count: 0,
                recent_bytes_sent: 0,
                recent_bytes_received: 0,
                recent_window_start: now,
            };
            monitor
                .register_task(task_info)
                .await;

            // Also register one task per outbound virtual channel (transit
            // point) so per-TP throughput, latency, and errors are visible
            // alongside the inbound access-point task. They share `config_id`
            // so `unregister_all_tasks_for_config_id` cleans them up together
            // when the channel is removed.
            if surface_has_outbound {
                for tp in channel_surface.transit_points() {
                    // `alias` is guaranteed non-empty after compat
                    // back-fill (legacy surfaces) and the surface API's
                    // alias-pattern validation (new surfaces).
                    let tp_task_id = if let Some(cid) = new_surface.config_id() {
                        format!("task-{}-tp-{}", cid, tp.alias)
                    } else {
                        format!("task-{}-tp-{}-{}", surface_name, tp.alias, uuid::Uuid::new_v4())
                    };
                    // Effective outbound listener: per-VC override →
                    // channel-wide outbound → inbound fallback. Mirrors
                    // the same precedence used by `group_outbound_vcs_by_port`
                    // so the dashboard reflects where traffic actually binds.
                    let tp_listen = tp
                        .listen_address
                        .clone()
                        .or_else(|| surface_outbound_listen_address.clone())
                        .unwrap_or_else(|| surface_listen_address.clone());
                    let tp_task = crate::observability::TaskInfo {
                        task_id: tp_task_id,
                        config_id: new_surface
                            .config_id()
                            .map(str::to_string),
                        channel_name: surface_name.clone(),
                        transit_point: Some(tp.alias.clone()),
                        listen_address: tp_listen,
                        target_endpoint: tp.target_endpoint.clone(),
                        started_at: now,
                        status: crate::observability::TaskStatus::Running,
                        total_connections: 0,
                        active_connections: 0,
                        bytes_sent: 0,
                        bytes_received: 0,
                        last_activity: None,
                        error_count: 0,
                        recent_bytes_sent: 0,
                        recent_bytes_received: 0,
                        recent_window_start: now,
                    };
                    monitor
                        .register_task(tp_task)
                        .await;
                }
            }
        }

        // Step 3b: Compile engines for each enabled surface variant
        let mut variant_engines = std::collections::HashMap::new();

        // `channel_surface` (declared at the start of this fn) is the canonical
        // surface; reuse it for variant compilation + validation. An empty
        // `variants` Vec is valid (single-surface mode using `target.endpoint`).

        // VALIDATION: when `default_variant_id` IS set, it must reference
        // one of the variants. `None` is allowed even with a non-empty
        // `variants[]` — semantics: alias-less URLs resolve to the bare
        // base surface (the implicit "base" default).
        if !channel_surface
            .variants
            .is_empty()
            && let Some(default_id) = channel_surface
                .default_variant_id
                .as_ref()
            && !channel_surface
                .variants
                .iter()
                .any(|v| &v.id == default_id)
        {
            let error_msg = format!(
                "CONFIGURATION ERROR: Surface '{}' (config_id: {:?}) has default_variant_id='{}' but no variant with that ID exists. \
                Available variant IDs: {:?}",
                surface_name,
                new_surface.config_id(),
                default_id,
                channel_surface
                    .variants
                    .iter()
                    .map(|v| &v.id)
                    .collect::<Vec<_>>()
            );
            error!(
                surface = %surface_name,
                config_id = ?new_surface.config_id(),
                default_variant_id = %default_id,
                "❌ {}",
                error_msg
            );
            if let Some(config_id) = new_surface.config_id() {
                crate::channel_error!(config_id, "❌ LOAD FAILED: {}", error_msg);
            }
            return Err(anyhow::anyhow!(error_msg));
        }

        info!(
            surface = %surface_name,
            config_id = ?new_surface.config_id(),
            variant_count = channel_surface.variants.len(),
            default_variant_id = ?channel_surface.default_variant_id,
            "Compiling engines for {} surface variant(s)",
            channel_surface.variants.len()
        );

        for variant in &channel_surface.variants {
            // Skip disabled variants
            if !variant.enabled {
                info!(
                    surface = %surface_name,
                    variant_id = %variant.id,
                    "Skipping disabled surface variant"
                );
                continue;
            }

            // Build the resolved per-variant surface directly
            let variant_surface = match channel_surface.resolve_variant(Some(&variant.alias)) {
                Ok(s) => s,
                Err(e) => {
                    error!(channel = %surface_name, variant_id = %variant.id, error = %e, "Failed to resolve variant");
                    if let Some(config_id) = new_surface.config_id() {
                        crate::channel_error!(config_id, "Failed to resolve variant '{}': {}", variant.id, e);
                    }
                    return Err(anyhow::anyhow!(
                        "Failed to resolve variant '{}' for channel {}: {}",
                        variant.id,
                        surface_name,
                        e
                    ));
                }
            };

            // Compile identity engines for this variant
            let variant_engines_compiled = crate::proxy::compile_identity_engines_from_surface(&variant_surface, vc_issuer.as_ref())
                .map_err(|e| {
                    error!(channel = %surface_name, variant_id = %variant.id, error = %e, "Failed to compile identity engines for variant");
                    if let Some(config_id) = new_surface.config_id() {
                        crate::channel_error!(config_id, "Failed to compile identity engines for variant '{}': {}", variant.id, e);
                    }
                    anyhow::anyhow!("Failed to compile identity engines for channel {} variant {}: {}", surface_name, variant.id, e)
                })?;
            if variant_engines_compiled
                .rules_engine
                .is_some()
            {
                info!(channel = %surface_name, variant_id = %variant.id, "Compiled identity rules engine for variant");
                if let Some(config_id) = new_surface.config_id() {
                    crate::channel_info!(config_id, "Compiled identity rules engine for variant '{}'", variant.id);
                }
            }
            if variant_engines_compiled
                .selector
                .is_some()
            {
                info!(channel = %surface_name, variant_id = %variant.id, "Compiled identity selector for variant");
                if let Some(config_id) = new_surface.config_id() {
                    crate::channel_info!(config_id, "Compiled identity selector for variant '{}'", variant.id);
                }
            }

            // Store compiled engines for this variant
            variant_engines.insert(
                variant.id.clone(),
                crate::state::proxy::VariantEngines {
                    identity_rules_engine: variant_engines_compiled.rules_engine,
                    identity_selector: variant_engines_compiled.selector,
                    protected_rules_engine: variant_engines_compiled.protected_rules_engine,
                    protected_selector: variant_engines_compiled.protected_selector,
                    external_rules_engine: variant_engines_compiled.external_rules_engine,
                    external_selector: variant_engines_compiled.external_selector,
                },
            );
        }

        let new_channel_info = crate::state::SurfaceInfo {
            surface: Arc::new(channel_surface.clone()),
            identity_rules_engine,
            identity_selector,
            protected_rules_engine,
            protected_selector,
            external_rules_engine,
            external_selector,
            task_id: channel_task_id.clone(),
            variant_engines,
        };

        // Step 4: Update the channels in the port listener state
        {
            let mut channels = state.channels.write().await;

            // Find and replace or add the channel
            if let Some(config_id) = new_surface.config_id() {
                if let Some(idx) = channels
                    .iter()
                    .position(|ch| ch.surface.config_id() == Some(config_id))
                {
                    channels[idx] = new_channel_info;
                    info!("Updated channel '{}' in port {} listener state", surface_name, port);
                } else {
                    channels.push(new_channel_info);
                    info!("Added channel '{}' to port {} listener state", surface_name, port);
                }
            } else {
                // All channels MUST have config_id
                error!("Channel '{}' has no config_id - cannot update listener state", surface_name);
                return Err(anyhow::anyhow!("Channel '{}' has no config_id", surface_name));
            }
        }

        info!("Successfully updated channel '{}' on port {}", channel_name, port);
        if let Some(config_id) = new_surface.config_id() {
            crate::channel_info!(config_id, "✅ Successfully reloaded channel on port {}", port);
        }

        // Step 5: Live-update outbound channel state (if this channel has outbound enabled).
        if let Some(config_id) = new_surface.config_id()
            && surface_has_outbound
        {
            let states = self
                .outbound_channel_states
                .read()
                .expect("outbound_channel_states lock poisoned");
            if let Some(shared_state) = states.get(config_id) {
                // Apply default variant overrides so fields like
                // managed_identity and trust_registry_injection are promoted.
                let outbound_surface = channel_surface
                    .resolve_variant(None)
                    .unwrap_or_else(|_| channel_surface.clone());
                // Recompile identity engines (lenient — log errors but don't fail reload).
                let outbound_engines = crate::proxy::compile_identity_engines_from_surface(&outbound_surface, self.vc_issuer.as_ref())
                    .map_err(|e| {
                        error!(channel = %surface_name, error = %e, "Failed to compile outbound identity engines on reload");
                        e
                    })
                    .unwrap_or(crate::proxy::CompiledIdentityEngines {
                        rules_engine: None,
                        selector: None,
                        protected_rules_engine: None,
                        protected_selector: None,
                        external_rules_engine: None,
                        external_selector: None,
                    });

                let mut cs = shared_state
                    .write()
                    .expect("outbound channel_state lock poisoned");
                // Store the raw surface, as startup does: resolving a variant
                // clears the catalog, and `$alias` Transit routing needs it.
                cs.surface = Arc::new(channel_surface.clone());
                cs.identity_rules_engine = outbound_engines.rules_engine;
                cs.identity_selector = outbound_engines.selector;
                drop(cs);
                info!(
                    surface = %surface_name,
                    config_id = %config_id,
                    "Live-updated outbound channel state"
                );
            }
        }

        // Step 6: Restart the outbound port listener to rebuild Axum routes.
        // The router has static routes baked in at startup, so adding/removing/renaming
        // virtual channels or changing the route prefix requires a listener restart.
        let previous_surface_has_outbound = previous_surface
            .as_ref()
            .is_some_and(|s| {
                s.transit
                    .as_ref()
                    .is_some_and(|t| !t.points.is_empty())
            });
        if surface_has_outbound || previous_surface_has_outbound {
            self.restart_outbound_listener_for_channel(&new_surface, previous_surface.as_ref(), metrics_store)
                .await?;
        }

        Ok((false, None))
    }

    /// Surgically remove a single channel from the running gateway by
    /// `config_id` without restarting any port listener. Used by the
    /// surface-delete fast path so deleting one surface does not tear
    /// down every other channel's tasks. Returns `Ok(true)` if the
    /// channel was found and removed, `Ok(false)` if it was not present
    /// (caller can fall back to a full reload if needed).
    pub async fn remove_single_channel(
        &self,
        config_id: &str,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<bool> {
        // Step 1: drop from the in-memory GatewayConfig snapshot so future
        // full reloads see the deletion. Capture the listen_address while
        // we still hold the channel record so we can locate the port
        // listener that owns it.
        let listen_address = {
            let mut config_lock = self.config.write().await;
            let mut new_config = (**config_lock).clone();
            let pos = new_config
                .surfaces
                .iter()
                .position(|c| c.config_id() == Some(config_id));
            let Some(idx) = pos else {
                debug!("remove_single_channel: config_id '{}' not in current config", config_id);
                return Ok(false);
            };
            let removed = new_config
                .surfaces
                .remove(idx);
            *config_lock = Arc::new(new_config.clone());
            if let Err(e) = self
                .config_cache
                .save(&new_config, "single_channel_remove")
                .await
            {
                warn!("Failed to save configuration to cache after removal: {}", e);
            }
            removed
                .listen_address()
                .to_string()
        };

        // Step 2: drop from the live port listener's channel list. We try
        // the mapped port first (cheap O(1) lookup) then fall back to a
        // full sweep so a stale listen_address mismatch still cleans up.
        let network_config = self
            .bootstrap_config
            .load_network_config()
            .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;
        let preferred_port = network_config.map_url_to_port(&listen_address);
        let port_states = self
            .port_listener_states
            .read()
            .await;
        let mut removed_from_port: Option<u16> = None;
        if let Some(port) = preferred_port
            && let Some(state) = port_states.get(&port)
        {
            let mut channels = state.channels.write().await;
            if let Some(idx) = channels
                .iter()
                .position(|ch| ch.surface.config_id() == Some(config_id))
            {
                channels.remove(idx);
                removed_from_port = Some(port);
            }
        }
        if removed_from_port.is_none() {
            for (port, state) in port_states.iter() {
                let mut channels = state.channels.write().await;
                if let Some(idx) = channels
                    .iter()
                    .position(|ch| ch.surface.config_id() == Some(config_id))
                {
                    channels.remove(idx);
                    removed_from_port = Some(*port);
                    break;
                }
            }
        }
        drop(port_states);

        // Step 3: drop the outbound channel state if this channel had
        // outbound enabled.
        {
            let mut states = self
                .outbound_channel_states
                .write()
                .expect("outbound_channel_states lock poisoned");
            states.remove(config_id);
        }

        // Step 4: clean up every TaskInfo for this channel (AP + TPs).
        if let Some(ref monitor) = task_monitor {
            let removed = monitor
                .unregister_all_tasks_for_config_id(config_id)
                .await;
            if removed > 0 {
                info!(
                    "Removed {} task(s) for channel with config_id '{}' (port={:?})",
                    removed, config_id, removed_from_port
                );
            }
        }

        info!("Removed channel with config_id '{}' from running gateway", config_id);
        Ok(true)
    }

    /// Restart the outbound port listener that serves a given channel.
    ///
    /// The outbound Axum router bakes virtual-channel aliases into its route
    /// table at startup.  When virtual channels are added, removed, or renamed
    /// the listener must be rebuilt so the new routes take effect.
    ///
    /// This method:
    /// 1. Resolves the outbound port from `outbound_listen_address`.
    /// 2. Collects every outbound-enabled channel on that port.
    /// 3. Aborts the old listener and spawns a replacement.
    async fn restart_outbound_listener_for_channel(
        &self,
        channel: &crate::config::agent_surface::AgentSurface,
        previous_channel: Option<&crate::config::agent_surface::AgentSurface>,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    ) -> anyhow::Result<()> {
        let network_config = self
            .bootstrap_config
            .load_network_config()
            .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;

        let outbound_ports = network_config.get_outbound_ports();
        if outbound_ports.is_empty() {
            warn!(surface = %channel.name, "No outbound listeners are configured — outbound routes may be stale");
            return Ok(());
        }

        let map_outbound_address_to_port = |listen_addr: &str| -> Option<u16> {
            network_config.map_url_to_port_for_type(listen_addr, Some("outbound"))
        };

        let mut ports_to_restart = std::collections::BTreeSet::new();
        let mut collect_ports_for_surface = |surface: &crate::config::agent_surface::AgentSurface| {
            let Some(transit) = surface.transit.as_ref() else {
                return;
            };
            let surface_outbound_listen_address = transit
                .outbound_listen_address
                .as_deref();
            for tp in &transit.points {
                let effective_addr = tp
                    .listen_address
                    .as_deref()
                    .or(surface_outbound_listen_address);
                let Some(addr) = effective_addr else {
                    warn!(
                        surface = %surface.name,
                        alias = %tp.alias,
                        "Transit point has no outbound listen address — route will not be mounted"
                    );
                    continue;
                };
                match map_outbound_address_to_port(addr) {
                    Some(port) => {
                        ports_to_restart.insert(port);
                    }
                    None => {
                        warn!(
                            surface = %surface.name,
                            alias = %tp.alias,
                            listen_address = %addr,
                            "Could not map transit-point listen_address to an outbound listener — route will not be mounted"
                        );
                    }
                }
            }
        };
        collect_ports_for_surface(channel);
        if let Some(previous_channel) = previous_channel {
            collect_ports_for_surface(previous_channel);
        }

        if ports_to_restart.is_empty() {
            warn!(surface = %channel.name, "No transit points map to an outbound listener — outbound routes may be stale");
            return Ok(());
        }

        // Collect all outbound-enabled channels from current config and bucket
        // each transit point by its effective listener address. This keeps
        // reload behavior aligned with startup and supports per-TP listeners.
        let config_lock = self.config.read().await;
        let outbound_channels_by_port = crate::config::group_outbound_vcs_by_port(
            &config_lock.surfaces,
            &outbound_ports,
            map_outbound_address_to_port,
        );
        let config_clone = Arc::new((**config_lock).clone());
        drop(config_lock);

        for outbound_port in ports_to_restart {
            let listener_info = network_config
                .listeners
                .iter()
                .find(|l| l.port == outbound_port);

            let listener_type = listener_info.map(|l| l.listener_type.as_str());
            if listener_type != Some("outbound") {
                warn!(
                    surface = %channel.name,
                    port = outbound_port,
                    listener_type = ?listener_type,
                    "Refusing to rebuild outbound listener: configured listener on this port is not outbound"
                );
                continue;
            }

            let outbound_channels = outbound_channels_by_port
                .get(&outbound_port)
                .cloned()
                .unwrap_or_default();
            if outbound_channels.is_empty() {
                warn!(
                    surface = %channel.name,
                    port = outbound_port,
                    "No outbound channels remain for listener — stopping outbound listener to clear stale routes"
                );
                let mut port_handles = self
                    .port_listener_handles
                    .write()
                    .await;
                if let Some(handle) = port_handles.remove(&outbound_port) {
                    handle.abort();
                }
                let handle = tokio::spawn(std::future::pending::<()>());
                port_handles.insert(outbound_port, handle.abort_handle());
                continue;
            }

            let bind_address = listener_info
                .map(|l| l.bind_address.clone())
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let use_tls = listener_info
                .map(|l| l.protocol.to_lowercase() == "https")
                .unwrap_or(false);
            let outbound_channel_count = outbound_channels.len();

            {
                let mut port_handles = self
                    .port_listener_handles
                    .write()
                    .await;
                if let Some(handle) = port_handles.remove(&outbound_port) {
                    info!(port = outbound_port, "Aborting outbound port listener to rebuild routes");
                    handle.abort();
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            let secrets_store_clone = self
                .secrets_store
                .read()
                .await
                .clone();
            let policy_manager_clone = self
                .policy_manager
                .read()
                .await
                .clone();
            let gateway_policy_manager_clone = self
                .gateway_policy_manager
                .read()
                .await
                .clone();
            let trust_registry_clone =
                crate::gateways::connection_points::message_processor::get_trust_registry_listener_manager();
            let outbound_states = self
                .outbound_channel_states
                .clone();
            let vc_issuer_clone = self.vc_issuer.clone();
            let network_config_clone = Arc::new(network_config.clone());
            let config_clone = config_clone.clone();
            let direct_client_auth_clone = self
                .direct_client_auth
                .read()
                .await
                .clone();
            let metrics_store = metrics_store.clone();
            let listener_mgr_clone = self.listener_manager.clone();
            let consent_strategies = self
                .source_auth_middleware
                .read()
                .await
                .as_ref()
                .map(|middleware| middleware.provider_store());

            let handle = tokio::spawn(async move {
                if let Err(e) = super::server::run_outbound_port_server(
                    bind_address,
                    outbound_port,
                    outbound_channels,
                    config_clone,
                    network_config_clone,
                    metrics_store,
                    secrets_store_clone,
                    policy_manager_clone,
                    gateway_policy_manager_clone,
                    trust_registry_clone,
                    vc_issuer_clone,
                    None, // task_monitor
                    use_tls,
                    outbound_states,
                    direct_client_auth_clone,
                    listener_mgr_clone,
                    consent_strategies,
                )
                .await
                {
                    error!("Outbound port listener error for port {}: {}", outbound_port, e);
                }
            });

            {
                let mut port_handles = self
                    .port_listener_handles
                    .write()
                    .await;
                port_handles.insert(outbound_port, handle.abort_handle());
            }

            info!(
                surface = %channel.name,
                port = outbound_port,
                outbound_channel_count,
                "Restarted outbound port listener with updated routes"
            );
        }

        Ok(())
    }

    /// Stop a channel by name (used when renaming channels)
    pub async fn stop_channel_by_name(
        &self,
        channel_name: &str,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> bool {
        let mut handles = self
            .channel_handles
            .write()
            .await;
        let mut task_ids_map = self.task_ids.write().await;
        if let Some(handle) = handles.remove(channel_name) {
            info!("Stopping channel task: {}", channel_name);
            // Unregister from task monitor if available - unregister ALL tasks for this channel
            if let Some(ref monitor) = task_monitor {
                // First remove the current task ID from our map
                if let Some(task_id) = task_ids_map.remove(channel_name) {
                    info!("Removing current task_id {} for channel {} from task_ids map", task_id, channel_name);
                }

                // Then unregister ALL tasks for this channel (including any stale ones from previous reloads)
                let unregistered_count = monitor
                    .unregister_all_tasks_for_channel(channel_name)
                    .await;
                if unregistered_count > 0 {
                    info!("✅ Unregistered {} task(s) for channel '{}' from monitor", unregistered_count, channel_name);
                } else {
                    warn!("⚠️ No tasks found in monitor for channel '{}'", channel_name);
                }
            } else {
                warn!("⚠️ No task monitor available to unregister tasks for channel '{}'", channel_name);
            }
            handle.abort();
            info!("✅ Channel '{}' task handle aborted", channel_name);
            true
        } else {
            warn!("⚠️ Channel '{}' not found in channel_handles - may not be running", channel_name);

            // Even if the handle isn't found, still try to clean up any stale task monitor entries
            if let Some(ref monitor) = task_monitor {
                let unregistered_count = monitor
                    .unregister_all_tasks_for_channel(channel_name)
                    .await;
                if unregistered_count > 0 {
                    info!(
                        "✅ Cleaned up {} stale task(s) for channel '{}' from monitor",
                        unregistered_count, channel_name
                    );
                }
            }

            false
        }
    }

    /// Stop a channel by its config_id (identifier-based, not name-based)
    #[allow(dead_code)]
    pub async fn stop_channel_by_config_id(
        &self,
        config_id: &str,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> bool {
        // Find the channel name from config_id
        let channel_name = match self
            .find_channel_name_by_config_id(config_id)
            .await
        {
            Some(name) => name,
            None => {
                warn!("⚠️ Channel with config_id '{}' not found", config_id);
                // Still try to clean up any stale task monitor entries
                if let Some(ref _monitor) = task_monitor {
                    // Since we don't have the channel name, we can't clean up by channel name
                    // This is a limitation, but it's better to log the issue
                    warn!("⚠️ Cannot clean up tasks for config_id '{}' without channel name", config_id);
                }
                return false;
            }
        };

        // Delegate to stop_channel_by_name with the resolved name
        self.stop_channel_by_name(&channel_name, task_monitor)
            .await
    }

    /// Find current channel name by config_id
    pub async fn find_channel_name_by_config_id(
        &self,
        config_id: &str,
    ) -> Option<String> {
        let config_lock = self.config.read().await;
        config_lock
            .surfaces
            .iter()
            .find(|r| r.config_id() == Some(config_id))
            .map(|r| r.name.clone())
    }

    /// Reload a single channel with fallback to cached configuration
    pub async fn reload_single_channel_with_fallback(
        &self,
        channel_name: &str,
        new_surface_result: anyhow::Result<crate::config::agent_surface::AgentSurface>,
        tls_acceptor: TlsAcceptor,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(bool, Option<String>)> {
        // Serialize against any concurrent full or single-channel reload (F1).
        let _reload_guard = self.reload_lock.lock().await;
        match new_surface_result {
            Ok(new_surface) => {
                // Try to reload the single channel
                self.reload_single_channel(channel_name, new_surface, tls_acceptor, metrics_store, task_monitor)
                    .await
            }
            Err(load_error) => {
                // Failed to load new channel, try to use cached config
                warn!(
                    "Failed to load channel '{}': {}. Attempting to use cached configuration.",
                    channel_name, load_error
                );

                match self.config_cache.load().await {
                    Ok(_cached) => {
                        // This function should not be called without a config_id in the error case
                        // Log error and return the load_error
                        error!(
                            "Cannot use fallback for channel '{}' - original error did not provide config_id",
                            channel_name
                        );
                        Err(load_error)
                    }
                    Err(cache_error) => {
                        error!(
                            load_error = %load_error,
                            cache_error = %cache_error,
                            channel = channel_name,
                            "Failed to load channel and no cached configuration available"
                        );
                        anyhow::bail!(
                            "Failed to load channel '{}': {}. Also failed to load cached configuration: {}",
                            channel_name,
                            load_error,
                            cache_error
                        )
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::agent_surface::AgentSurface;

    fn surface_with_variant() -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "s1",
            "name": "outbound",
            "description": "",
            "status": "active",
            "tags": [],
            "access_point": {
                "listen_address": "0.0.0.0:8443", "route": "/api", "protocol": "mcp",
                "publish_to_did_document": false, "terminate_trace_id": false
            },
            "target": {
                "endpoint": "https://tools.example.com/mcp", "mcp_tool_policies_enabled": false,
                "identity_injection": {"inject_vp": false}, "mpp_auto_pay": false
            },
            "transit": {
                "points": [{
                    "id": "tp-1", "name": "Search", "alias": "search",
                    "target_endpoint": "https://search.example.com/mcp", "protocol": "mcp",
                    "identity_injection": {"inject_vp": false}
                }]
            },
            "variants": [{
                "id": "v-prod", "alias": "prod", "name": "Prod", "enabled": true,
                "overrides": {"target": {"endpoint": "https://prod.example.com/mcp"}}
            }]
        }))
        .expect("test surface must deserialize")
    }

    /// Outbound state must hold the raw surface: resolving a variant clears the
    /// catalog, and an empty catalog silently routes `$alias` to the base Target.
    #[test]
    fn outbound_state_keeps_the_variant_catalog_that_resolution_drops() {
        let surface = surface_with_variant();
        assert_eq!(
            surface
                .resolve_variant(Some("prod"))
                .expect("the raw surface still routes $prod")
                .target
                .endpoint,
            "https://prod.example.com/mcp"
        );

        let compiled_from = surface
            .resolve_variant(None)
            .expect("default resolution succeeds");
        assert!(
            compiled_from
                .variants
                .is_empty(),
            "resolution clears the catalog, which is why it must not be what we store"
        );
        assert_eq!(
            compiled_from
                .resolve_variant(Some("prod"))
                .expect("an empty catalog does not reject the alias")
                .target
                .endpoint,
            "https://tools.example.com/mcp",
            "storing the resolved surface silently sent $prod to the base Target"
        );
    }
}
