//! Server functions for running proxy port listeners and channel servers

use axum::{
    Router,
    http::{HeaderValue, request::Parts as RequestParts},
};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{debug, error, info, warn};

use crate::config::GatewayConfig;
use crate::state::{MultiSurfaceProxyState, SurfaceInfo};

// ── Credential delegation global stores ──────────────────────────────────────
// Follows the same OnceLock pattern used for mpp_transaction_store and
// trust_registry_listener_manager in gateways/connection_points/message_processor.rs

static GLOBAL_CREDENTIAL_PROVIDER_STORE: OnceLock<
    Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>,
> = OnceLock::new();
static GLOBAL_DELEGATION_VAULT_STORE: OnceLock<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> =
    OnceLock::new();
static GLOBAL_GATEWAY_BASE_URL: OnceLock<String> = OnceLock::new();
static GLOBAL_TRANSIT_TOKEN_ISSUER: OnceLock<Arc<crate::proxy::transit_token::TransitTokenIssuer>> = OnceLock::new();
static GLOBAL_CERTIFICATES_STORE: OnceLock<Arc<dyn crate::certificates::CertificateStore>> = OnceLock::new();

fn parse_cors_origins(cors_origins: &[String]) -> Arc<Vec<HeaderValue>> {
    Arc::new(
        cors_origins
            .iter()
            .filter_map(|origin| match origin.parse::<HeaderValue>() {
                Ok(value) => Some(value),
                Err(error) => {
                    warn!(origin = %origin, error = %error, "Ignoring invalid CORS origin in network config");
                    None
                }
            })
            .collect(),
    )
}

/// Any origin may read a public discovery document (`GET`/`HEAD` of a public
/// path); every other request, including a `POST` to a path that only ends
/// like one, needs an allowlisted origin. `method` is the method the request
/// will use: for a preflight, its `Access-Control-Request-Method`.
fn is_proxy_cors_origin_allowed(
    origin: &HeaderValue,
    method: &str,
    path: &str,
    origins: &[HeaderValue],
) -> bool {
    if crate::proxy::paths::is_public_request(method, path) {
        return true;
    }

    if origins.is_empty() {
        return false;
    }

    debug!("Checking proxy CORS origin: {:?} against allowed origins: {:?}", origin, origins);
    origins.contains(origin)
}

/// The method a request will use: a preflight's requested method, else its own.
fn cors_request_method(request_parts: &RequestParts) -> String {
    if request_parts.method == axum::http::Method::OPTIONS
        && let Some(requested) = request_parts
            .headers
            .get(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|value| value.to_str().ok())
    {
        return requested.to_string();
    }
    request_parts
        .method
        .as_str()
        .to_string()
}

fn proxy_cors_layer(cors_origins: &[String]) -> CorsLayer {
    let origins = parse_cors_origins(cors_origins);

    CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(AllowOrigin::async_predicate(move |origin: HeaderValue, request_parts: &RequestParts| {
            let origins = Arc::clone(&origins);
            let path = request_parts
                .uri
                .path()
                .to_string();
            let method = cors_request_method(request_parts);
            async move { is_proxy_cors_origin_allowed(&origin, &method, &path, &origins) }
        }))
        .allow_headers(Any)
}

pub fn init_certificates_store(store: Arc<dyn crate::certificates::CertificateStore>) {
    let _ = GLOBAL_CERTIFICATES_STORE.set(store);
    info!(target: "certificates", "Global certificate store initialized for proxy pipeline");
}

pub fn get_certificates_store() -> Option<Arc<dyn crate::certificates::CertificateStore>> {
    GLOBAL_CERTIFICATES_STORE
        .get()
        .cloned()
}

pub fn init_credential_delegation_stores(
    provider_store: Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>,
    vault_store: Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>,
    base_url: String,
) {
    let _ = GLOBAL_CREDENTIAL_PROVIDER_STORE.set(provider_store);
    let _ = GLOBAL_DELEGATION_VAULT_STORE.set(vault_store);
    let _ = GLOBAL_GATEWAY_BASE_URL.set(base_url);
    info!(target: "credential_delegation", "Global credential delegation stores initialized for proxy pipeline");
}

pub fn get_credential_provider_store()
-> Option<Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>> {
    GLOBAL_CREDENTIAL_PROVIDER_STORE
        .get()
        .cloned()
}

pub fn get_delegation_vault_store() -> Option<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> {
    GLOBAL_DELEGATION_VAULT_STORE
        .get()
        .cloned()
}

pub fn get_gateway_base_url() -> Option<String> {
    GLOBAL_GATEWAY_BASE_URL
        .get()
        .cloned()
}

pub fn init_transit_token_issuer(issuer: Arc<crate::proxy::transit_token::TransitTokenIssuer>) {
    let _ = GLOBAL_TRANSIT_TOKEN_ISSUER.set(issuer);
    info!(target: "transit_token", "Global transit token issuer initialized for proxy pipeline");
}

pub fn get_transit_token_issuer() -> Option<Arc<crate::proxy::transit_token::TransitTokenIssuer>> {
    GLOBAL_TRANSIT_TOKEN_ISSUER
        .get()
        .cloned()
}

/// Build the AP `listen_address` shown in the Tasks UI by appending the
/// surface route to the listener host. Returns `"fabric"` for fabric-only
/// surfaces (empty host).
pub(crate) fn join_host_and_route(
    host: &str,
    route: &str,
) -> String {
    if host.is_empty() {
        return if route.is_empty() || route == "/" {
            "fabric".to_string()
        } else if route.starts_with('/') {
            format!("fabric{}", route)
        } else {
            format!("fabric/{}", route)
        };
    }
    let host_trim = host.trim_end_matches('/');
    if route.is_empty() || route == "/" {
        host_trim.to_string()
    } else if route.starts_with('/') {
        format!("{}{}", host_trim, route)
    } else {
        format!("{}/{}", host_trim, route)
    }
}

/// Run a listener for a specific port that handles multiple channels with different routes
/// Returns the MultiSurfaceProxyState for this port so channels can be updated dynamically
/// Extract the hostname (no port, lowercase) from a URL string.
/// Returns `None` for malformed URLs without `://`.
fn extract_hostname(url: &str) -> Option<String> {
    url.split("://")
        .nth(1)
        .and_then(|after| after.split('/').next())
        .map(|host_port| {
            host_port
                .split(':')
                .next()
                .unwrap_or(host_port)
                .to_lowercase()
        })
}

/// Find the first outbound listener whose external URLs share a hostname with
/// the inbound listener on `inbound_port`. Returns `None` when no overlap exists
/// (i.e. inbound and outbound have fully separate domains).
///
/// Used by `run_port_server` to decide whether to register the `/outbound/*`
/// reverse-proxy on the inbound port.
pub(crate) fn find_shared_outbound_listener(
    network_config: &crate::config::NetworkConfig,
    inbound_port: u16,
) -> Option<&crate::config::network::Listener> {
    let inbound_hostnames: std::collections::HashSet<String> = network_config
        .listeners
        .iter()
        .filter(|l| l.listener_type == "inbound" && l.port == inbound_port)
        .flat_map(|l| l.external_urls.iter())
        .filter_map(|url| extract_hostname(url))
        .collect();

    network_config
        .listeners
        .iter()
        .filter(|l| l.listener_type == "outbound")
        .find(|l| {
            l.external_urls
                .iter()
                .filter_map(|url| extract_hostname(url))
                .any(|h| inbound_hostnames.contains(&h))
        })
}

pub async fn run_port_server(
    port: u16,
    surfaces: Vec<crate::config::agent_surface::AgentSurface>,
    _tls_acceptor: TlsAcceptor,
    client: reqwest::Client,
    config: Arc<GatewayConfig>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    task_id: Option<String>,
    ws_state: Option<Arc<crate::server::WsState>>,
    vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    listener_manager: Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    state_sender: Option<tokio::sync::oneshot::Sender<Arc<crate::state::MultiSurfaceProxyState>>>,
    identity_api_router: Option<axum::Router>,
    onboarding_router: Option<axum::Router>,
    did_router: Option<axum::Router>,
    secrets_router: Option<axum::Router>,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    network_config: Arc<crate::config::NetworkConfig>,
    use_tls: bool,
    policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
    a2a_proxy_store: Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,
    mcp_server_manager: Option<Arc<crate::mcp_proxies::handlers::McpServerManager>>,
    _settings_store: Arc<crate::storage::SettingsStore>,
    _notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    didauth_session_store: Arc<crate::didauth::DidAuthSessionStore>,
    source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
    direct_client_auth: Option<Arc<crate::server::DirectClientAuth>>,
    resolved_surface_cache: Arc<crate::surfaces::ResolvedSurfaceCache>,
    #[cfg(feature = "didwebvh")] didwebvh_identity_store: Option<
        Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>,
    >,
    #[cfg(feature = "didwebvh")] didwebvh_log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
) -> anyhow::Result<()> {
    let _task_id = task_id.unwrap_or_else(|| format!("port-{}-{}", port, uuid::Uuid::new_v4()));

    info!("Starting port listener on 0.0.0.0:{} for {} channel(s)", port, surfaces.len());

    // Build channel info for each channel on this port
    let mut channel_infos = Vec::new();

    for surface in surfaces.iter() {
        let channel_surface = surface.clone();
        let surface_name = channel_surface.name.clone();
        let surface_config_id: Option<String> = channel_surface
            .config_id()
            .map(|s| s.to_string());
        let surface_listen_address = channel_surface
            .listen_address()
            .to_string();
        let surface_route = channel_surface
            .route()
            .to_string();
        let surface_target_endpoint = channel_surface
            .target_endpoint()
            .to_string();

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
                surface_config_id,
                default_id,
                channel_surface
                    .variants
                    .iter()
                    .map(|v| &v.id)
                    .collect::<Vec<_>>()
            );
            error!(
                surface = %surface_name,
                config_id = ?surface_config_id,
                default_variant_id = %default_id,
                "❌ {}",
                error_msg
            );
            return Err(anyhow::anyhow!(error_msg));
        }

        info!(
            surface = %surface_name,
            config_id = ?surface_config_id,
            variant_count = channel_surface.variants.len(),
            default_variant_id = ?channel_surface.default_variant_id,
            "Compiling engines for {} surface variant(s)",
            channel_surface.variants.len()
        );

        // Register this channel's route prefix for OpenTelemetry tracing
        crate::observability::register_channel_prefix(surface_route.clone(), format!("[CHANNEL] {}", surface_name));

        // Register task for monitoring if enabled
        if let Some(ref monitor) = task_monitor {
            let now = chrono::Utc::now();
            let channel_task_id = format!(
                "task-{}-{}",
                surface_config_id
                    .as_ref()
                    .unwrap_or(&surface_name),
                uuid::Uuid::new_v4()
            );
            let ap_listen_display = join_host_and_route(&surface_listen_address, &surface_route);
            let task_info = crate::observability::TaskInfo {
                task_id: channel_task_id.clone(),
                config_id: surface_config_id.clone(),
                channel_name: surface_name.clone(),
                transit_point: None,
                listen_address: ap_listen_display,
                target_endpoint: surface_target_endpoint.clone(),
                started_at: now,
                status: crate::observability::TaskStatus::Starting,
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

            // Register one TaskInfo per outbound virtual channel (transit
            // point) so the dashboard renders independent throughput,
            // active-connections, and error rows under the parent surface
            // group. They share `config_id` so cleanup is consolidated.
            if channel_surface
                .transit
                .as_ref()
                .is_some_and(|t| !t.points.is_empty())
            {
                let surface_outbound_listen = channel_surface
                    .transit
                    .as_ref()
                    .and_then(|t| {
                        t.outbound_listen_address
                            .clone()
                    });
                for tp in channel_surface.transit_points() {
                    let tp_task_id = if let Some(cid) = &surface_config_id {
                        format!("task-{}-tp-{}", cid, tp.alias)
                    } else {
                        format!("task-{}-tp-{}-{}", surface_name, tp.alias, uuid::Uuid::new_v4())
                    };
                    let tp_listen = tp
                        .listen_address
                        .clone()
                        .or_else(|| surface_outbound_listen.clone())
                        .unwrap_or_else(|| surface_listen_address.clone());
                    let tp_task = crate::observability::TaskInfo {
                        task_id: tp_task_id,
                        config_id: surface_config_id.clone(),
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

            // Compile identity engines from managed_identity configuration
            let engines = crate::proxy::compile_identity_engines_from_surface(&channel_surface, vc_issuer.as_ref())
                .map_err(|e| {
                    error!(channel = %surface_name, error = %e, "Failed to compile identity engines");
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
            }
            if identity_selector.is_some() {
                info!(channel = %surface_name, "Compiled identity selector from managed_identity JSON Schema");
            }
            if external_selector.is_some() {
                info!(channel = %surface_name, "Compiled external identity selector from identity_slots.external");
            }

            // Compile engines for each enabled surface variant
            let mut variant_engines = std::collections::HashMap::new();

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
                        anyhow::anyhow!("Failed to compile identity engines for channel {} variant {}: {}", surface_name, variant.id, e)
                    })?;
                if variant_engines_compiled
                    .rules_engine
                    .is_some()
                {
                    info!(channel = %surface_name, variant_id = %variant.id, "Compiled identity rules engine for variant");
                }
                if variant_engines_compiled
                    .selector
                    .is_some()
                {
                    info!(channel = %surface_name, variant_id = %variant.id, "Compiled identity selector for variant");
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

            channel_infos.push(SurfaceInfo {
                surface: Arc::new(channel_surface),
                identity_rules_engine,
                identity_selector,
                protected_rules_engine,
                protected_selector,
                external_rules_engine,
                external_selector,
                variant_engines,
                task_id: channel_task_id,
            });
        }
    }

    let channel_infos_arc = Arc::new(RwLock::new(channel_infos));

    // Use the global transaction store (created unconditionally in orchestrator.rs)
    // This single store handles ALL x402 operations:
    // - HTTP payment middleware (GW1 role: create payment, send to facilitator)
    // - DIDComm message handlers (GW2 role: receive verify/settle requests)
    // - Admin API (serves UI data)
    // - Settlement worker (processes transactions where facilitator_gateway_id == this gateway)
    let transaction_store = crate::gateways::connection_points::message_processor::get_transaction_store();
    if transaction_store.is_none() {
        warn!("Transaction store not initialized - x402 payment processing will fail");
    }

    // Transaction store workers (cleanup, crash recovery, settlement) are spawned in orchestrator.rs
    // No duplicate workers needed here - all x402 operations use the single global store

    let state = Arc::new(MultiSurfaceProxyState {
        config: Arc::clone(&config),
        network_config: Arc::clone(&network_config),
        client: client.clone(),
        channels: channel_infos_arc.clone(),
        metrics_store: metrics_store.clone(),
        task_monitor: task_monitor.clone(),
        ws_state,
        listener_manager: listener_manager.clone(),
        secrets_store: secrets_store.clone(),
        certificates_store: crate::proxy::server::get_certificates_store(),
        vc_issuer: vc_issuer.clone(),
        policy_manager: policy_manager.clone(),
        gateway_policy_manager: gateway_policy_manager.clone(),
        didauth_session_store: Arc::clone(&didauth_session_store),
        transaction_store: transaction_store.clone(),
        mpp_transaction_store: crate::gateways::connection_points::message_processor::get_mpp_transaction_store(),
        trust_registry_listener_manager:
            crate::gateways::connection_points::message_processor::get_trust_registry_listener_manager(),
        source_auth_middleware: source_auth_middleware.clone(),

        #[cfg(feature = "didwebvh")]
        didwebvh_identity_store: didwebvh_identity_store.clone(),

        #[cfg(feature = "didwebvh")]
        didwebvh_log_manager: didwebvh_log_storage
            .as_ref()
            .map(|s| Arc::new(crate::identity::didwebvh::log::DidLogManager::new(s.clone()))),

        credential_provider_store: crate::proxy::server::get_credential_provider_store(),
        delegation_vault_store: crate::proxy::server::get_delegation_vault_store(),
        gateway_base_url: crate::proxy::server::get_gateway_base_url(),
        transit_token_issuer: crate::proxy::server::get_transit_token_issuer(),
        mcp_proxy_store: mcp_proxy_store.clone(),
        a2a_proxy_store: a2a_proxy_store.clone(),
        resolved_surface_cache: resolved_surface_cache.clone(),
    });

    // Send the state back to the caller if requested
    if let Some(sender) = state_sender {
        let _ = sender.send(state.clone());
    }

    // Settlement worker is spawned in orchestrator.rs - no duplicate needed here

    // Build the Axum router from network configuration
    let mut app = Router::new();

    if let Some(profile) = network_config
        .sts
        .mcp_issuer
        .as_ref()
    {
        profile.validate_network(&network_config)?;
        app = app.merge(profile.discovery_router()?);
        app = app.merge(
            Router::new()
                .route(
                    "/.well-known/oauth-protected-resource",
                    axum::routing::get(crate::mcp::resource_server::surface_metadata),
                )
                .route(
                    "/.well-known/oauth-protected-resource/{*path}",
                    axum::routing::get(crate::mcp::resource_server::surface_metadata),
                )
                .with_state(state.as_ref().clone()),
        );
    }

    // Note: SPA-route collision validation is performed once at startup in
    // server::orchestrator before any port is spawned, where a hard exit can
    // be issued. We intentionally do NOT re-run it here so a hot-reload that
    // introduces a collision rejects the reload (caller logs the error) but
    // does not kill the live process.

    // Merge DID router first (at root level) to ensure did:web routes are accessible
    if let Some(ref did_router_ref) = did_router {
        info!("Merging DID resolution router at root level");
        app = app.merge(did_router_ref.clone());
    }

    // Note: Secrets/Vault router will be merged AFTER regular routes to take precedence

    // x402 Admin API is mounted inside the identity router (built in orchestrator)
    // so it inherits the global `require_session_auth` layer. All /api/* data
    // calls go through the same protected pipeline — no special cases.

    // Separate fallback routes from regular routes
    let mut fallback_routes = Vec::new();
    let mut regular_routes = Vec::new();

    for (route_name, route_config) in &network_config.routes {
        if route_config.route_type == crate::config::RouteType::Static && route_config.fallback {
            fallback_routes.push((route_name, route_config));
        } else {
            regular_routes.push((route_name, route_config));
        }
    }

    // Process regular routes first
    for (route_name, route_config) in regular_routes {
        match route_config.route_type {
            crate::config::RouteType::IdentityApi => {
                if let Some(ref identity_router) = identity_api_router {
                    info!("Adding Identity API routes at prefix: {}", route_config.prefix);
                    if route_config.prefix == "/" {
                        // Merge at root
                        app = app.merge(identity_router.clone());
                    } else {
                        // Nest under prefix
                        app = app.nest(&route_config.prefix, identity_router.clone());
                    }
                } else {
                    info!("Skipping Identity API route '{}': router not provided", route_name);
                }
            }
            crate::config::RouteType::Onboarding => {
                if let Some(ref onboarding_router_ref) = onboarding_router {
                    info!("Adding Onboarding routes at prefix: {}", route_config.prefix);
                    if route_config.prefix == "/" {
                        // Merge at root
                        app = app.merge(onboarding_router_ref.clone());
                    } else {
                        // Nest under prefix
                        app = app.nest(&route_config.prefix, onboarding_router_ref.clone());
                    }
                } else {
                    info!("Skipping Onboarding route '{}': router not provided", route_name);
                }
            }
            crate::config::RouteType::ConnectionPoint => {
                info!("Adding connection point DID routes '{}' at prefix: {}", route_name, route_config.prefix);

                // Create a connection point store
                let cp_store = std::sync::Arc::new(
                    crate::gateways::FileSystemConnectionPointStore::new(std::path::PathBuf::from(
                        &bootstrap_config
                            .storage_paths
                            .connection_points,
                    ))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to create connection point store: {}", e))?,
                );

                // Create a router for connection point DID documents only (no state needed)
                let cp_router = Router::new()
                    .route(
                        "/{cp_id}/did.json",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_document::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .route(
                        "/{cp_id}/did.jsonl",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_jsonl::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .route(
                        "/{cp_id}/did-witness.json",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_witness::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .layer(axum::Extension(bootstrap_config.clone()))
                    .layer(axum::Extension(cp_store));

                app = app.merge(
                    Router::new()
                        .nest(&route_config.prefix, cp_router)
                        .with_state(state.as_ref().clone()),
                );
            }
            crate::config::RouteType::Redirect => {
                if let Some(ref target) = route_config.target {
                    info!("Adding redirect route '{}': {} -> {}", route_name, route_config.prefix, target);

                    let target_url = target.clone();
                    let redirect_handler = move || async move { axum::response::Redirect::permanent(&target_url) };

                    app = app.route(&route_config.prefix, axum::routing::get(redirect_handler));
                } else {
                    warn!("Redirect route '{}' missing 'target' field", route_name);
                }
            }
            crate::config::RouteType::Static => {
                if let Some(ref static_path) = route_config.path {
                    let resolved = std::fs::canonicalize(static_path)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|e| format!("<unresolved: {}>", e));
                    let cwd = std::env::current_dir()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "?".to_string());
                    info!(
                        "[WWW Hosting on port {}] static file server '{}' at prefix: {} (path: {} | cwd: {} | resolved: {})",
                        port, route_name, route_config.prefix, static_path, cwd, resolved
                    );

                    use hyper::header::CACHE_CONTROL;
                    use hyper::http::HeaderValue;
                    use tower_http::services::ServeDir;
                    use tower_http::set_header::SetResponseHeaderLayer;

                    let serve_dir = Router::new()
                        .fallback_service(
                            ServeDir::new(static_path)
                                .append_index_html_on_directories(true)
                                .fallback(tower_http::services::ServeFile::new(format!("{}/index.html", static_path))),
                        )
                        .layer(SetResponseHeaderLayer::if_not_present(
                            CACHE_CONTROL,
                            HeaderValue::from_static("public, max-age=3600, must-revalidate"),
                        ))
                        .layer(SetResponseHeaderLayer::if_not_present(
                            axum::http::header::X_FRAME_OPTIONS,
                            HeaderValue::from_static("DENY"),
                        ))
                        .layer(SetResponseHeaderLayer::if_not_present(
                            axum::http::header::CONTENT_SECURITY_POLICY,
                            HeaderValue::from_static("frame-ancestors 'none'"),
                        ))
                        .layer(SetResponseHeaderLayer::if_not_present(
                            axum::http::header::X_CONTENT_TYPE_OPTIONS,
                            HeaderValue::from_static("nosniff"),
                        ))
                        .layer(SetResponseHeaderLayer::if_not_present(
                            axum::http::header::REFERRER_POLICY,
                            HeaderValue::from_static("strict-origin-when-cross-origin"),
                        ))
                        .layer(SetResponseHeaderLayer::if_not_present(
                            axum::http::header::STRICT_TRANSPORT_SECURITY,
                            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
                        ));

                    if route_config.fallback {
                        info!("Setting '{}' as fallback static handler", route_name);
                        app = app.fallback_service(serve_dir);
                    } else if route_config.prefix == "/" {
                        app = app.nest_service("/", serve_dir);
                    } else {
                        app = app.nest_service(&route_config.prefix, serve_dir);
                    }
                } else {
                    warn!("Static route '{}' missing 'path' field", route_name);
                }
            }
            crate::config::RouteType::Proxy => {
                info!("Adding proxy route '{}' at prefix: {}", route_name, route_config.prefix);

                // Register this prefix for OpenTelemetry tracing
                crate::observability::register_channel_prefix(
                    route_config.prefix.clone(),
                    format!("[CHANNEL] {}", route_name),
                );

                // Add route for this proxy path
                let prefix = route_config.prefix.clone();
                let proxy_router = Router::new()
                    .route(
                        &format!("{}/{{{}}}", prefix, "*path"),
                        axum::routing::any(super::handler::multi_channel_proxy_handler),
                    )
                    .layer(proxy_cors_layer(&network_config.cors))
                    .with_state(state.as_ref().clone());

                app = app.merge(proxy_router);
            }
        }
    }

    // Add proxy routes for each channel prefix
    for channel_prefix in &network_config.channels {
        info!("Adding channel proxy route '{}' at prefix: {}", channel_prefix.name, channel_prefix.prefix);

        // Register this prefix for OpenTelemetry tracing
        crate::observability::register_channel_prefix(
            channel_prefix.prefix.clone(),
            format!("[CHANNEL] {}", channel_prefix.name),
        );

        let prefix = channel_prefix.prefix.clone();
        let mut proxy_router = Router::new()
            .route(
                &format!("{}/{{{}}}", prefix, "*path"),
                axum::routing::any(super::handler::multi_channel_proxy_handler),
            )
            .route(&prefix, axum::routing::any(super::handler::multi_channel_proxy_handler));

        // Surface variant URL grammar (plan §2.3): also accept `{prefix}$<alias>`
        // and `{prefix}$<alias>/{rest}` for every variant alias on every channel
        // bound to this prefix. axum's matchit can't match a `$alias` mid-segment,
        // so we register one route per known alias instead.
        let mut registered_alias_routes: std::collections::HashSet<String> = std::collections::HashSet::new();
        for surface in &surfaces {
            if surface.access_point.route != prefix {
                continue;
            }
            for vc in &surface.variants {
                // Register both the literal `$alias` and the percent-encoded
                // `%24alias` form (plan §2.3 — `%24` MUST be tolerated).
                for sigil in ["$", "%24"] {
                    let alias_route = format!("{}{}{}", prefix, sigil, vc.alias);
                    if registered_alias_routes.insert(alias_route.clone()) {
                        proxy_router = proxy_router
                            .route(&alias_route, axum::routing::any(super::handler::multi_channel_proxy_handler))
                            .route(
                                &format!("{}/{{{}}}", alias_route, "*path"),
                                axum::routing::any(super::handler::multi_channel_proxy_handler),
                            );
                    }
                }
            }
        }

        let proxy_router = proxy_router
            .layer(axum::middleware::from_fn(crate::observability::trace_http_request))
            .layer(proxy_cors_layer(&network_config.cors))
            .with_state(state.as_ref().clone());

        app = app.merge(proxy_router);
    }

    // Add MCP proxy routes for each configured MCP proxy path
    let mcp_proxy_paths = network_config
        .mcp_proxies
        .as_ref();

    if let Some(mcp_proxies) = mcp_proxy_paths {
        // Shared SSE session manager for all MCP proxy routes
        let sse_session_mgr = crate::mcp::sse_server::SseSessionManager::new(None);

        for mcp_proxy_prefix in mcp_proxies {
            info!("Adding MCP proxy route '{}' at prefix: {}", mcp_proxy_prefix.name, mcp_proxy_prefix.prefix);

            // Register this prefix for OpenTelemetry tracing
            crate::observability::register_mcp_prefix(
                mcp_proxy_prefix
                    .prefix
                    .clone(),
                format!("[MCP] {}", mcp_proxy_prefix.name),
            );

            if let (Some(store), Some(manager)) = (mcp_proxy_store.as_ref(), mcp_server_manager.as_ref()) {
                let prefix = mcp_proxy_prefix
                    .prefix
                    .clone();
                let route_path = format!("{}/{{{}}}", prefix, "*path");
                let mut mcp_router =
                    Router::new()
                        .route(
                            &route_path,
                            axum::routing::get(
                                crate::mcp_proxies::handlers::handle_mcp_get::<
                                    crate::mcp_proxies::FileSystemMcpProxyStore,
                                >,
                            )
                            .delete(
                                crate::mcp_proxies::handlers::handle_mcp_get::<
                                    crate::mcp_proxies::FileSystemMcpProxyStore,
                                >,
                            ),
                        )
                        .route(
                            &route_path,
                            axum::routing::post(
                                crate::mcp_proxies::handlers::handle_mcp_post::<
                                    crate::mcp_proxies::FileSystemMcpProxyStore,
                                >,
                            ),
                        )
                        .layer(axum::Extension(store.clone()))
                        .layer(axum::Extension(manager.clone()))
                        .layer(axum::Extension(network_config.clone()))
                        .layer(axum::Extension(sse_session_mgr.clone()));

                if let Some(issuer) = vc_issuer.as_ref() {
                    mcp_router =
                        mcp_router.layer(axum::Extension(crate::mcp::resource_server::ResourceServerAuthContext {
                            issuer: issuer.clone(),
                            keys: Arc::new(crate::jwt_bearer::JwksClient::new()),
                        }));
                }
                app = app.merge(mcp_router);
            } else {
                warn!("MCP proxy route '{}' skipped: store or manager not initialized", mcp_proxy_prefix.name);
            }
        }
    }

    // x402 e2e test endpoints — gated on `facilitator_mode.enable_test_endpoints`.
    // These are unauthenticated conformance surfaces (incl. POST /close) and
    // must stay off in non-test deployments.
    if config
        .facilitator_mode
        .enable_test_endpoints
    {
        info!("Adding x402 multi-chain test endpoints: /protected (EVM + Solana), /health, /close");

        let test_endpoints_config = match bootstrap_config.load_test_endpoints_config() {
            Ok(cfg) => Arc::new(cfg),
            Err(e) => {
                warn!("Failed to load test endpoints config: {}. Test endpoints will use default values.", e);
                Arc::new(crate::config::TestEndpointsConfig {
                    evm: None,
                    solana_devnet: None,
                    solana_mainnet: None,
                })
            }
        };

        let x402_test_router = axum::Router::new()
            .route("/protected", axum::routing::get(crate::x402::protected_eip3009))
            .route("/protected-permit2", axum::routing::get(crate::x402::protected_permit2))
            .route("/protected-solana-devnet", axum::routing::get(crate::x402::protected_solana_devnet))
            .route("/protected-solana-mainnet", axum::routing::get(crate::x402::protected_solana_mainnet))
            .route("/health", axum::routing::get(crate::x402::test_health))
            .route("/close", axum::routing::post(crate::x402::test_close))
            .with_state(test_endpoints_config);

        app = app.merge(x402_test_router);
    } else {
        info!("x402 test endpoints disabled (facilitator_mode.enable_test_endpoints=false)");
    }

    // Proxy {TP_OUTBOUND_PATH_PREFIX}/* to the outbound listener when inbound and outbound share a hostname.
    //
    // On a shared-domain deployment the reverse-proxy routes all traffic to the inbound port
    // regardless of path. Requests that start with {TP_OUTBOUND_PATH_PREFIX} are destined for a transit
    // point — they need to reach the outbound listener. Rather than registering per-TP routes
    // at startup (which require a restart every time a TP is added), register a single wildcard
    // proxy that forwards any {TP_OUTBOUND_PATH_PREFIX}/* request to localhost:{outbound_port}. The outbound
    // listener already has all the specific TP routes and handles them correctly.
    //
    // The proxy is only registered when at least one outbound listener shares a hostname with
    // this inbound port's external URLs (detected by hostname intersection).
    {
        if let Some(outbound_listener) = find_shared_outbound_listener(&network_config, port) {
            let outbound_target = format!("http://{}:{}", outbound_listener.bind_address, outbound_listener.port);
            let proxy_client = client.clone();
            info!(
                inbound_port = port,
                outbound_port = outbound_listener.port,
                outbound_target = %outbound_target,
                "Shared-domain detected: registering outbound transit-point proxy on inbound listener -> outbound listener"
            );

            let outbound_target_arc = std::sync::Arc::new(outbound_target);
            let proxy_handler = move |req: axum::extract::Request| {
                let target = outbound_target_arc.clone();
                let http_client = proxy_client.clone();
                async move {
                    let path_and_query = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/")
                        .to_string();
                    let url = format!("{}{}", target, path_and_query);
                    let method = reqwest::Method::from_bytes(
                        req.method()
                            .as_str()
                            .as_bytes(),
                    )
                    .unwrap_or(reqwest::Method::POST);
                    let mut builder = http_client.request(method, &url);
                    for (key, value) in req.headers() {
                        // Transparent tunnel: forward everything except hop-by-hop headers and
                        // `host` (set automatically by reqwest). Do NOT use
                        // `should_forward_request_header` here — that strips `x-transit-token`,
                        // which the outbound pipeline needs for transit-token validation.
                        let lower = key
                            .as_str()
                            .to_ascii_lowercase();
                        if !crate::a2a::is_hop_by_hop_header(&lower)
                            && lower != "host"
                            && let Ok(v) = value.to_str()
                        {
                            builder = builder.header(key.as_str(), v);
                        }
                    }
                    let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                        .await
                        .unwrap_or_default();
                    builder = builder.body(body);
                    match builder.send().await {
                        Ok(resp) => {
                            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
                            let mut response_builder = axum::response::Response::builder().status(status);
                            for (key, value) in resp.headers() {
                                if !crate::a2a::is_hop_by_hop_header(key.as_str()) {
                                    response_builder = response_builder.header(key.as_str(), value.as_bytes());
                                }
                            }
                            let bytes = resp
                                .bytes()
                                .await
                                .unwrap_or_default();
                            response_builder
                                .body(axum::body::Body::from(bytes))
                                .unwrap_or_else(|_| {
                                    axum::response::Response::builder()
                                        .status(axum::http::StatusCode::BAD_GATEWAY)
                                        .body(axum::body::Body::empty())
                                        .unwrap()
                                })
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, url = %url, "Outgoing proxy forward failed");
                            axum::response::Response::builder()
                                .status(axum::http::StatusCode::BAD_GATEWAY)
                                .body(axum::body::Body::empty())
                                .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
                        }
                    }
                }
            };

            let outbound_prefix = crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX;
            app = app
                .route(outbound_prefix, axum::routing::any(proxy_handler.clone()))
                .route(&format!("{}/{{*path}}", outbound_prefix), axum::routing::any(proxy_handler));
        }
    }

    // Merge Secrets/Vault router AFTER all regular routes (to override any wildcards/fallbacks in nested routers)
    // This ensures /api/v1/secrets/ and /api/v1/apikeys/ take precedence over identity router's fallback
    if let Some(ref secrets_router_ref) = secrets_router {
        info!("Merging Secrets/Vault API router (after regular routes, before fallbacks)");
        app = app.merge(secrets_router_ref.clone());
    }

    // Merge x402 HTTP Facilitator API router if enabled in gateway config
    if config
        .facilitator_mode
        .facilitator_via_http
    {
        info!("Merging x402 HTTP Facilitator API router at /api/x402 (standard spec endpoints)");
        let http_facilitator_state = crate::x402::HttpFacilitatorState {
            channels: state.channels.clone(),
        };
        let http_facilitator_router = crate::x402::create_http_facilitator_router().with_state(http_facilitator_state);
        app = app.nest("/api/x402", http_facilitator_router);
    }

    // Process fallback routes last so they don't override specific routes
    for (route_name, route_config) in fallback_routes {
        if let Some(ref static_path) = route_config.path {
            let resolved = std::fs::canonicalize(static_path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|e| format!("<unresolved: {}>", e));
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".to_string());
            info!(
                "[WWW Hosting on port {}] static file server '{}' at prefix: {} (path: {} | cwd: {} | resolved: {})",
                port, route_name, route_config.prefix, static_path, cwd, resolved
            );

            use hyper::header::CACHE_CONTROL;
            use hyper::http::HeaderValue;
            use tower::ServiceBuilder;
            use tower_http::services::ServeDir;
            use tower_http::set_header::SetResponseHeaderLayer;

            let serve_dir = ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::if_not_present(
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=3600, must-revalidate"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    axum::http::header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    axum::http::header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("frame-ancestors 'none'"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    axum::http::header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    axum::http::header::REFERRER_POLICY,
                    HeaderValue::from_static("strict-origin-when-cross-origin"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    axum::http::header::STRICT_TRANSPORT_SECURITY,
                    HeaderValue::from_static("max-age=31536000; includeSubDomains"),
                ))
                .service(
                    ServeDir::new(static_path)
                        .append_index_html_on_directories(true)
                        .fallback(tower_http::services::ServeFile::new(format!("{}/index.html", static_path))),
                );

            app = app.fallback_service(serve_dir);
        }
    }

    // Add OpenTelemetry tracing middleware for all proxy requests
    let app = app.layer(axum::middleware::from_fn(crate::observability::trace_http_request));

    // Unconditional access log: every inbound request, regardless of routing.
    let app = app.layer(axum::middleware::from_fn(crate::observability::access_log));

    // Forwarded client-cert capture (XFCC etc.) — no-op when
    // `client_auth.trusted_proxies` is empty.
    let app = app.layer(axum::middleware::from_fn_with_state(
        std::sync::Arc::new(config.tls.client_auth.clone()),
        crate::source_auth::peer_cert::forwarded_peer_cert,
    ));

    // Promote a direct-TLS peer cert (captured by PeerCertAcceptor when
    // `client_auth.direct` is enabled) into the canonical PeerCertInfo
    // extension. No-op when the upstream extension is absent.
    let app = app.layer(axum::middleware::from_fn(crate::source_auth::peer_cert::promote_direct_peer_cert));

    // Bind to 0.0.0.0:{port} to accept connections on all interfaces for this port
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("Valid 0.0.0.0:port format");

    info!("Port listener binding to {} for {} channels", bind_addr, surfaces.len());
    for surface in &surfaces {
        info!("  Channel '{}' route '{}' -> {}", surface.name, surface.route(), surface.target_endpoint());
    }

    // Update status to running for all channels
    if let Some(ref monitor) = task_monitor {
        let channel_infos = channel_infos_arc.read().await;
        for channel_info in channel_infos.iter() {
            monitor
                .update_status(&channel_info.task_id, crate::observability::TaskStatus::Running)
                .await;
        }
    }

    // Serve with or without TLS based on protocol
    let result = if use_tls {
        info!("Port {} using TLS (HTTPS)", port);
        // Load TLS config (with optional client auth verifier).
        let tls_config = crate::server::load_server_config(
            &config.tls.cert_path,
            &config.tls.key_path,
            direct_client_auth
                .as_deref()
                .cloned(),
        )?;

        // Create TLS listener using axum_server. If direct client auth is
        // enabled, wrap the acceptor so peer certs are captured into a
        // per-request extension.
        let rustls_acceptor = axum_server::tls_rustls::RustlsAcceptor::new(
            axum_server::tls_rustls::RustlsConfig::from_config(tls_config),
        );
        if direct_client_auth.is_some() {
            let acceptor = crate::source_auth::peer_cert::PeerCertAcceptor::new(rustls_acceptor);
            axum_server::bind(bind_addr)
                .acceptor(acceptor)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
        } else {
            axum_server::bind(bind_addr)
                .acceptor(rustls_acceptor)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
        }
    } else {
        info!("Port {} using plain HTTP (no TLS)", port);
        // Create plain TCP listener
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
    };

    // Cleanup: Unregister tasks when server stops
    if let Some(ref monitor) = task_monitor {
        let channel_infos = channel_infos_arc.read().await;
        info!("Port listener {} stopped, unregistering {} channel tasks", port, channel_infos.len());
        for channel_info in channel_infos.iter() {
            info!("Unregistering task {} for channel '{}'", channel_info.task_id, channel_info.surface.name);
            monitor
                .unregister_task(&channel_info.task_id)
                .await;
        }
    }

    result?;
    Ok(())
}

/// Get the shared outbound channel state for `config_id`.
///
/// Existing listeners keep a clone of this shared state, so reloads must update
/// the state itself. If we replace the `Arc`, those listeners keep using the old
/// transit-point target or identity engines until restart. Route shape changes
/// such as `listen_path` are baked into Axum and require rebuilding the outbound
/// listener routes.
fn get_or_create_outbound_channel_state(
    states: &mut std::collections::HashMap<String, Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>>>,
    config_id: &str,
    outbound_surface: &crate::config::agent_surface::AgentSurface,
    identity_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    identity_selector: Option<Arc<crate::identity::IdentitySelector>>,
) -> Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>> {
    if let Some(existing) = states.get(config_id) {
        let mut existing_state = existing
            .write()
            .expect("outbound channel_state lock poisoned");
        existing_state.surface = Arc::new(outbound_surface.clone());
        existing_state.identity_rules_engine = identity_rules_engine;
        existing_state.identity_selector = identity_selector;
        drop(existing_state);
        existing.clone()
    } else {
        let new_state = Arc::new(std::sync::RwLock::new(crate::state::OutboundSurfaceState {
            surface: Arc::new(outbound_surface.clone()),
            identity_rules_engine,
            identity_selector,
        }));
        states.insert(config_id.to_string(), new_state.clone());
        new_state
    }
}

/// Run a simple outbound-only port listener.
///
/// This is the server-side counterpart of the outbound pipeline.  Unlike
/// [`run_port_server`] (which serves a complex multi-channel inbound router)
/// this function is intentionally minimal:
/// - One route per `(channel, virtual_channel)` pair.
/// - No identity API, no MCP proxies, no payment routes.
/// - Each route carries a dedicated [`OutboundProxyState`].
///
/// The caller is responsible for only passing channels that have `outbound.enabled = true`.
///
/// Returns a map of `config_id → Arc<RwLock<OutboundSurfaceState>>` so the caller
/// can store them for live updates (e.g. from `reload_single_channel`).
pub async fn run_outbound_port_server(
    bind_address: String,
    port: u16,
    channels: Vec<(crate::config::agent_surface::AgentSurface, Vec<crate::config::agent_surface::TransitPoint>)>,
    config: Arc<crate::config::GatewayConfig>,
    network_config: Arc<crate::config::NetworkConfig>,
    metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    trust_registry_listener_manager: Option<Arc<crate::trust_registries::TrustRegistryListenerManager>>,
    vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    use_tls: bool,
    outbound_channel_states: Arc<
        std::sync::RwLock<
            std::collections::HashMap<String, Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>>>,
        >,
    >,
    direct_client_auth: Option<Arc<crate::server::DirectClientAuth>>,
    listener_manager: Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    consent_identity_strategies: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
) -> anyhow::Result<()> {
    use axum::{Router, routing::any};

    info!("Starting outbound port listener on {}:{} for {} channel(s)", bind_address, port, channels.len());

    // Liveness probe for the channel/outbound listener (e.g. port 5000). This
    // listener has no identity router, so `/alive` is registered directly here
    // for ECS/ALB target-group health checks. Always 200 while the process is up.
    let mut app = Router::new().route("/alive", axum::routing::get(crate::identity::handlers::alive_check));
    let mut metadata_surfaces = Vec::new();

    // Every route path registered on this listener. Save-time validation
    // rejects colliding `listen_path`s, but config edited on disk (or missed
    // by older validation) can still contain duplicates — registering one
    // twice makes `Router::route`/`merge` panic and kills the whole
    // listener rebuild. Duplicates are skipped with an error instead: the
    // first registrant keeps the route.
    let mut registered_routes: std::collections::HashSet<String> =
        std::collections::HashSet::from(["/alive".to_string()]);

    for (surface, tps_for_this_port) in &channels {
        let Some(ref transit) = surface.transit else {
            continue;
        };
        if transit.points.is_empty() {
            continue;
        }

        // Resolve default-variant overrides (base mode) so any
        // managed_identity / trust_registry_injection promoted at the
        // surface level still applies to outbound traffic.
        let outbound_surface = surface
            .resolve_variant(None)
            .unwrap_or_else(|_| surface.clone());
        for e in outbound_surface.validate_outbound() {
            tracing::warn!(channel = %outbound_surface.name, "Outbound validation warning: {}", e);
        }
        let route_prefix = outbound_surface
            .route()
            .trim_end_matches('/');

        // Compile identity engines (lenient — log errors but don't fail startup).
        let outbound_engines = crate::proxy::compile_identity_engines_from_surface(&outbound_surface, vc_issuer.as_ref())
            .map_err(|e| {
                tracing::error!(channel = %outbound_surface.name, error = %e, "Failed to compile outbound identity engines");
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
        let identity_rules_engine = outbound_engines.rules_engine;
        let identity_selector = outbound_engines.selector;

        // Create or reuse shared channel state. A channel whose VCs span
        // multiple outbound ports must reference the *same* state across
        // all ports so hot-reload (which keys updates by config_id)
        // propagates rule-engine changes everywhere. Without this dedupe,
        // the second port to start would clobber the first port's entry
        // in `outbound_channel_states` and orphan its handlers.
        let channel_state = if let Some(config_id) = outbound_surface.config_id() {
            let config_id = config_id.to_string();
            let mut states = outbound_channel_states
                .write()
                .expect("outbound_channel_states lock poisoned");
            get_or_create_outbound_channel_state(
                &mut states,
                &config_id,
                surface,
                identity_rules_engine,
                identity_selector,
            )
        } else {
            Arc::new(std::sync::RwLock::new(crate::state::OutboundSurfaceState {
                surface: Arc::new(surface.clone()),
                identity_rules_engine,
                identity_selector,
            }))
        };

        metadata_surfaces.push(channel_state.clone());
        for vc in tps_for_this_port {
            let state = crate::state::OutboundProxyState {
                network_config: network_config.clone(),
                channel_state: channel_state.clone(),
                metrics_store: metrics_store.clone(),
                secrets_store: secrets_store.clone(),
                certificates_store: crate::proxy::server::get_certificates_store(),
                policy_manager: policy_manager.clone(),
                gateway_policy_manager: gateway_policy_manager.clone(),
                trust_registry_listener_manager: trust_registry_listener_manager.clone(),
                listener_manager: listener_manager.clone(),
                vc_issuer: vc_issuer.clone(),
                transit_token_issuer: get_transit_token_issuer(),
                delegation_vault_store: get_delegation_vault_store(),
                credential_provider_store: get_credential_provider_store(),
                consent_identity_strategies: consent_identity_strategies.clone(),
                mcp_continuations: crate::mcp::continuations::config::global().map(|runtime| Arc::new(runtime.clone())),
                gateway_base_url: get_gateway_base_url(),
                task_monitor: task_monitor.clone(),
                max_response_bytes: config.a2a.max_body_size,
                vc_alias_override: vc
                    .listen_path
                    .as_ref()
                    .map(|_| vc.alias.clone()),
            };

            // Route registration:
            //   * Always register `{TP_OUTBOUND_PATH_PREFIX}/<channel-route>/<alias>` so the
            //     `{TP_OUTBOUND_PATH_PREFIX}` prefix is a consistent convention on every
            //     outbound listener regardless of `listen_path`.
            //   * When `vc.listen_path` is also set, additionally register
            //     that custom path (the handler uses `vc_alias_override` to
            //     resolve the VC without parsing the request path).
            let outbound_prefix = crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX;
            let (outbound_base, outbound_wildcard) = if route_prefix.is_empty() || route_prefix == "/" {
                (format!("{}/{}", outbound_prefix, vc.alias), format!("{}/{}/{{*path}}", outbound_prefix, vc.alias))
            } else {
                (
                    format!("{}{}/{}", outbound_prefix, route_prefix, vc.alias),
                    format!("{}{}/{}/{{*path}}", outbound_prefix, route_prefix, vc.alias),
                )
            };

            info!(
                surface = %outbound_surface.name,
                alias = %vc.alias,
                target = %vc.target_endpoint,
                route = %outbound_wildcard,
                listen_path = ?vc.listen_path,
                "Registering outbound virtual channel route"
            );

            let mut vc_routes = vec![outbound_base, outbound_wildcard];

            if let Some(ref custom) = vc.listen_path {
                let trimmed = custom
                    .trim_end_matches('/')
                    .to_string();
                let trimmed = if trimmed.is_empty() {
                    "/".to_string()
                } else {
                    trimmed
                };
                let listen_wildcard = format!("{}/{{*path}}", trimmed);
                info!(
                    surface = %outbound_surface.name,
                    alias = %vc.alias,
                    route = %listen_wildcard,
                    "Registering outbound virtual channel listen_path route"
                );
                vc_routes.push(trimmed);
                vc_routes.push(listen_wildcard);
            }

            for variant in &surface.variants {
                for separator in ["$", "%24"] {
                    let variant_route =
                        format!("{outbound_prefix}{route_prefix}{separator}{}/{}", variant.alias, vc.alias);
                    vc_routes.push(format!("{variant_route}/{{*path}}"));
                    vc_routes.push(variant_route);
                    if let Some(custom) = vc.listen_path.as_deref() {
                        let custom = custom.trim_end_matches('/');
                        let variant_route = format!("{custom}{separator}{}", variant.alias);
                        vc_routes.push(format!("{variant_route}/{{*path}}"));
                        vc_routes.push(variant_route);
                    }
                }
            }

            // Register each route only once — a duplicate would panic axum's
            // router and take the listener (re)build down with it.
            for route in vc_routes {
                if !registered_routes.insert(route.clone()) {
                    tracing::error!(
                        surface = %outbound_surface.name,
                        alias = %vc.alias,
                        route = %route,
                        port,
                        "Duplicate outbound route on this listener — skipping; traffic on this route is served by the surface that registered it first"
                    );
                    continue;
                }
                app = app.route(&route, any(super::outbound_handler::outbound_proxy_handler).with_state(state.clone()));
            }
        }
    }

    if network_config
        .sts
        .mcp_issuer
        .is_some()
    {
        let metadata_state = crate::mcp::resource_server::TransitMetadataState {
            network: network_config.clone(),
            surfaces: metadata_surfaces,
            port,
        };
        app = app.merge(
            Router::new()
                .route(
                    "/.well-known/oauth-protected-resource",
                    axum::routing::get(crate::mcp::resource_server::transit_metadata),
                )
                .route(
                    "/.well-known/oauth-protected-resource/{*path}",
                    axum::routing::get(crate::mcp::resource_server::transit_metadata),
                )
                .with_state(metadata_state),
        );
    }

    // Bind address — use the configured bind_address, not 0.0.0.0.
    let bind_addr: std::net::SocketAddr = format!("{}:{}", bind_address, port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid outbound bind address {}:{}: {}", bind_address, port, e))?;

    info!("Outbound port listener binding to {}", bind_addr);

    let app = app.layer(axum::middleware::from_fn(crate::observability::trace_http_request));
    let app = app.layer(axum::middleware::from_fn(crate::observability::access_log));
    let app = app.layer(axum::middleware::from_fn_with_state(
        std::sync::Arc::new(config.tls.client_auth.clone()),
        crate::source_auth::peer_cert::forwarded_peer_cert,
    ));
    let app = app.layer(axum::middleware::from_fn(crate::source_auth::peer_cert::promote_direct_peer_cert));

    if use_tls {
        let tls_config = crate::server::load_server_config(
            &config.tls.cert_path,
            &config.tls.key_path,
            direct_client_auth
                .as_deref()
                .cloned(),
        )?;
        let rustls_acceptor = axum_server::tls_rustls::RustlsAcceptor::new(
            axum_server::tls_rustls::RustlsConfig::from_config(tls_config),
        );
        if direct_client_auth.is_some() {
            let acceptor = crate::source_auth::peer_cert::PeerCertAcceptor::new(rustls_acceptor);
            axum_server::bind(bind_addr)
                .acceptor(acceptor)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
        } else {
            axum_server::bind(bind_addr)
                .acceptor(rustls_acceptor)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
        }
    } else {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await
    }
    .map_err(|e| anyhow::anyhow!("Outbound port listener error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cors_origins_keeps_valid_origins() {
        let origins =
            parse_cors_origins(&["https://copilotstudio.microsoft.com".to_string(), "not a header\nvalue".to_string()]);

        assert_eq!(origins.len(), 1);
        assert_eq!(origins[0], HeaderValue::from_static("https://copilotstudio.microsoft.com"));
    }

    #[test]
    fn proxy_cors_allows_any_origin_for_public_discovery_paths() {
        let origin = HeaderValue::from_static("https://copilotstudio.microsoft.com");
        let origins = Vec::new();

        assert!(is_proxy_cors_origin_allowed(
            &origin,
            "GET",
            "/agents/copilot-worker/.well-known/agent-card.json",
            &origins,
        ));
        assert!(is_proxy_cors_origin_allowed(&origin, "HEAD", "/agents/copilot-worker/discovery", &origins,));
    }

    #[test]
    fn proxy_cors_keeps_allowlist_for_a_non_read_on_a_discovery_like_path() {
        let origin = HeaderValue::from_static("https://evil.example");
        let origins = vec![HeaderValue::from_static("https://dashboard.example.com")];

        assert!(!is_proxy_cors_origin_allowed(&origin, "POST", "/agents/copilot-worker/agent.json", &origins));
        assert!(!is_proxy_cors_origin_allowed(&origin, "POST", "/agents/copilot-worker/discovery", &origins));
        assert!(is_proxy_cors_origin_allowed(
            &HeaderValue::from_static("https://dashboard.example.com"),
            "POST",
            "/agents/copilot-worker/agent.json",
            &origins,
        ));
    }

    #[tokio::test]
    async fn proxy_cors_preflight_is_judged_by_the_requested_method() {
        use axum::http::{Request, StatusCode, header};
        use tower::ServiceExt;
        let app = Router::new()
            .route("/{*path}", axum::routing::any(|| async { StatusCode::OK }))
            .layer(proxy_cors_layer(&["https://dashboard.example.com".to_string()]));
        let preflight = |method: &'static str| {
            Request::builder()
                .method("OPTIONS")
                .uri("/agents/copilot-worker/agent.json")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
                .body(axum::body::Body::empty())
                .unwrap()
        };

        let get = app
            .clone()
            .oneshot(preflight("GET"))
            .await
            .unwrap();
        let post = app
            .oneshot(preflight("POST"))
            .await
            .unwrap();

        assert!(
            get.headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert!(
            !post
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }

    #[test]
    fn proxy_cors_keeps_allowlist_for_non_discovery_paths() {
        let origin = HeaderValue::from_static("https://copilotstudio.microsoft.com");
        let origins = vec![HeaderValue::from_static("https://dashboard.example.com")];

        assert!(!is_proxy_cors_origin_allowed(&origin, "POST", "/agents/copilot-worker/rpc", &origins));
    }

    #[tokio::test]
    async fn channel_alive_route_returns_ok() {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        // Mirrors the `/alive` route registered on the outbound/channel listener
        // in `run_outbound_port_server` (used by ECS/ALB health checks on the
        // channel port, e.g. 5000).
        let app = Router::new().route("/alive", axum::routing::get(crate::identity::handlers::alive_check));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/alive")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        assert_eq!(&body[..], br#"{"status":"OK"}"#);
    }

    #[test]
    fn join_empty_host_empty_route_returns_fabric() {
        assert_eq!(join_host_and_route("", ""), "fabric");
    }

    #[test]
    fn join_empty_host_slash_route_returns_fabric() {
        assert_eq!(join_host_and_route("", "/"), "fabric");
    }

    #[test]
    fn join_empty_host_with_absolute_route() {
        assert_eq!(join_host_and_route("", "/api/v1"), "fabric/api/v1");
    }

    #[test]
    fn join_empty_host_with_relative_route() {
        assert_eq!(join_host_and_route("", "api/v1"), "fabric/api/v1");
    }

    #[test]
    fn join_host_with_empty_route() {
        assert_eq!(join_host_and_route("https://example.com", ""), "https://example.com");
    }

    #[test]
    fn join_host_with_slash_route() {
        assert_eq!(join_host_and_route("https://example.com", "/"), "https://example.com");
    }

    #[test]
    fn join_host_with_absolute_route() {
        assert_eq!(join_host_and_route("https://example.com", "/api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_with_relative_route() {
        assert_eq!(join_host_and_route("https://example.com", "api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_with_absolute_route() {
        assert_eq!(join_host_and_route("https://example.com/", "/api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_with_relative_route() {
        assert_eq!(join_host_and_route("https://example.com/", "api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_empty_route() {
        assert_eq!(join_host_and_route("https://example.com/", ""), "https://example.com");
    }

    const SURFACE_TARGET_ENDPOINT: &str = "http://surface-target.example.com";

    fn outbound_surface_with_transit_point(
        surface_id: &str,
        tp_target_endpoint: &str,
        tp_listen_path: Option<&str>,
    ) -> crate::config::agent_surface::AgentSurface {
        use crate::config::agent_surface::{
            AccessPoint, AgentSurface, SharedTransitConfig, SurfaceProtocol, Target, TransitConfig, TransitPoint,
            TransitProtocol,
        };

        AgentSurface {
            surface_id: surface_id.to_string(),
            name: "outbound-channel".to_string(),
            access_point: AccessPoint {
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/surfaces/order".to_string(),
                protocol: SurfaceProtocol::A2a,
                ..Default::default()
            },
            target: Target {
                endpoint: SURFACE_TARGET_ENDPOINT.to_string(),
                ..Default::default()
            },
            transit: Some(TransitConfig {
                points: vec![TransitPoint {
                    id: "tp-partner-a".to_string(),
                    name: "Partner A".to_string(),
                    alias: "partner-a".to_string(),
                    target_endpoint: tp_target_endpoint.to_string(),
                    protocol: TransitProtocol::A2a,
                    mcp_protocol_mode: None,
                    mcp_http: None,
                    header_metadata_mapping: None,
                    target_auth: None,
                    policy: None,
                    response_policy: None,
                    mcp_tool_gating: None,
                    payment_policy: None,
                    networking: None,
                    rate_limit: None,
                    identity_injection: Default::default(),
                    managed_identity: None,
                    transit_credentials: None,
                    workload_binding: None,
                    gateway_url: "https://gw.internal:9000/outgoing/surfaces/order/partner-a".to_string(),
                    agent_card_path: None,
                    listen_address: None,
                    listen_path: tp_listen_path.map(str::to_string),
                    require_transit_token: true,
                    extension_inspection: crate::config::types::ExtensionInspectionConfig::default(),
                }],
                outbound_listen_address: None,
                shared: SharedTransitConfig::default(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn outbound_state_creates_entry_for_new_config_id() {
        let mut states = std::collections::HashMap::new();
        let surface = outbound_surface_with_transit_point("cfg-1", "http://localhost:9000", None);

        let created_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &surface, None, None);

        assert_eq!(states.len(), 1);
        assert!(states.contains_key("cfg-1"));
        assert_eq!(
            created_state
                .read()
                .unwrap()
                .surface
                .config_id(),
            Some("cfg-1")
        );
    }

    #[test]
    fn outbound_state_keeps_variant_catalog_on_reload() {
        let mut states = std::collections::HashMap::new();
        let mut surface = outbound_surface_with_transit_point("cfg-1", "https://base.example/mcp", None);
        let handler_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &surface, None, None);
        for revision in ["initial", "updated"] {
            let mut default_point = surface.transit_points()[0].clone();
            default_point.target_endpoint = format!("https://default.example/{revision}");
            let mut candidate_point = default_point.clone();
            candidate_point.target_endpoint = format!("https://candidate.example/{revision}");
            surface.variants = serde_json::from_value(serde_json::json!([
                {"id": "default", "alias": "default", "name": "Default", "overrides": {
                    "transit": {"points": [default_point]}
                }},
                {"id": "candidate", "alias": "candidate", "name": "Candidate", "overrides": {
                    "transit": {"points": [candidate_point]}
                }}
            ]))
            .unwrap();
            surface.default_variant_id = Some("default".into());
            let reloaded = get_or_create_outbound_channel_state(&mut states, "cfg-1", &surface, None, None);
            assert!(Arc::ptr_eq(&handler_state, &reloaded));
            let live = handler_state
                .read()
                .unwrap()
                .surface
                .clone();
            assert_eq!(live.variants.len(), 2);
            assert_eq!(
                live.default_variant_id
                    .as_deref(),
                Some("default")
            );
            assert_eq!(
                live.resolve_variant(None)
                    .unwrap()
                    .transit_points()[0]
                    .target_endpoint,
                default_point.target_endpoint
            );
            assert_eq!(
                live.resolve_variant(Some("candidate"))
                    .unwrap()
                    .transit_points()[0]
                    .target_endpoint,
                candidate_point.target_endpoint
            );
            assert!(
                live.resolve_variant(Some("missing"))
                    .is_err()
            );
        }
    }

    #[test]
    fn outbound_state_updates_transit_point_target_in_place() {
        let mut states = std::collections::HashMap::new();
        let original_tp_target = "https://partner-old.example.com/a2a";
        let reloaded_tp_target = "https://partner-new.example.com/a2a";

        // First registration creates the shared Arc that route handlers hold.
        let original_surface = outbound_surface_with_transit_point("cfg-1", original_tp_target, None);
        assert_eq!(original_surface.target_endpoint(), SURFACE_TARGET_ENDPOINT);
        assert_eq!(original_surface.transit_points()[0].target_endpoint, original_tp_target);
        let handler_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &original_surface, None, None);

        assert_eq!(states.len(), 1);
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            original_tp_target
        );

        // Reloading the same config id updates the TP target in the same Arc.
        let reloaded_surface = outbound_surface_with_transit_point("cfg-1", reloaded_tp_target, None);
        assert_eq!(reloaded_surface.target_endpoint(), SURFACE_TARGET_ENDPOINT);
        assert_eq!(reloaded_surface.transit_points()[0].target_endpoint, reloaded_tp_target);
        let reloaded_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &reloaded_surface, None, None);

        assert_eq!(states.len(), 1);
        assert!(Arc::ptr_eq(&handler_state, &reloaded_state));
        assert_eq!(
            reloaded_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            reloaded_tp_target
        );
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            reloaded_tp_target
        );

        let updated_surface = reloaded_state
            .read()
            .unwrap()
            .surface
            .clone();
        assert_eq!(updated_surface.target_endpoint(), SURFACE_TARGET_ENDPOINT);
    }

    #[test]
    fn outbound_state_updates_transit_point_listen_path_in_place() {
        let mut states = std::collections::HashMap::new();
        let tp_target = "https://partner.example.com/a2a";
        let original_listen_path = "/old-partner-webhook";
        let reloaded_listen_path = "/new-partner-webhook";

        // Existing route handlers hold this shared state while Axum routes are rebuilt separately.
        let original_surface = outbound_surface_with_transit_point("cfg-1", tp_target, Some(original_listen_path));
        assert_eq!(
            original_surface.transit_points()[0]
                .listen_path
                .as_deref(),
            Some(original_listen_path)
        );
        let handler_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &original_surface, None, None);

        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .listen_path
                .as_deref(),
            Some(original_listen_path)
        );

        // Reloading the same config id replaces the TP list in the same Arc.
        let reloaded_surface = outbound_surface_with_transit_point("cfg-1", tp_target, Some(reloaded_listen_path));
        assert_eq!(
            reloaded_surface.transit_points()[0]
                .listen_path
                .as_deref(),
            Some(reloaded_listen_path)
        );
        let reloaded_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &reloaded_surface, None, None);

        assert_eq!(states.len(), 1);
        assert!(Arc::ptr_eq(&handler_state, &reloaded_state));
        assert_eq!(
            reloaded_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .listen_path
                .as_deref(),
            Some(reloaded_listen_path)
        );
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .listen_path
                .as_deref(),
            Some(reloaded_listen_path)
        );
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            tp_target
        );
    }

    #[test]
    fn outbound_state_keeps_config_ids_isolated() {
        let mut states = std::collections::HashMap::new();
        let surface_a = outbound_surface_with_transit_point("cfg-a", "http://localhost:9000", None);
        let surface_b = outbound_surface_with_transit_point("cfg-b", "http://localhost:9001", None);

        let state_a = get_or_create_outbound_channel_state(&mut states, "cfg-a", &surface_a, None, None);
        let state_b = get_or_create_outbound_channel_state(&mut states, "cfg-b", &surface_b, None, None);

        assert_eq!(states.len(), 2);
        assert!(!Arc::ptr_eq(&state_a, &state_b));
        assert_eq!(
            state_a
                .read()
                .unwrap()
                .surface
                .config_id(),
            Some("cfg-a")
        );
        assert_eq!(
            state_b
                .read()
                .unwrap()
                .surface
                .config_id(),
            Some("cfg-b")
        );
    }

    // ── find_shared_outbound_listener + extract_hostname ──────────────────

    fn make_network_config_with_listeners(
        inbound_urls: Vec<&str>,
        outbound_urls: Vec<&str>,
    ) -> crate::config::NetworkConfig {
        serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.example.com" },
            "webauthn": { "rp_id": "test", "external_origin": "https://test.example.com" },
            "integration": { "types": [], "categories": [] },
            "listeners": [
                {
                    "id": "inbound-http",
                    "name": "Inbound",
                    "bind_address": "0.0.0.0",
                    "port": 8080,
                    "protocol": "http",
                    "external_urls": inbound_urls,
                    "listener_type": "inbound"
                },
                {
                    "id": "outbound-http",
                    "name": "Outbound",
                    "bind_address": "0.0.0.0",
                    "port": 9000,
                    "protocol": "http",
                    "external_urls": outbound_urls,
                    "listener_type": "outbound"
                }
            ],
            "routes": {}
        }))
        .expect("make_network_config_with_listeners")
    }

    #[test]
    fn extract_hostname_strips_scheme_port_and_path() {
        assert_eq!(extract_hostname("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(extract_hostname("http://example.com:8080/foo"), Some("example.com".to_string()));
        assert_eq!(extract_hostname("https://Example.COM"), Some("example.com".to_string()));
        assert_eq!(extract_hostname("no-scheme"), None);
    }

    #[test]
    fn find_shared_outbound_listener_returns_none_for_distinct_domains() {
        let config = make_network_config_with_listeners(
            vec!["https://inbound.example.com", "http://localhost:8080"],
            vec!["https://outbound.example.com"],
        );
        assert!(find_shared_outbound_listener(&config, 8080).is_none());
    }

    #[test]
    fn find_shared_outbound_listener_returns_outbound_when_hostname_overlaps() {
        // robert-fabric-1 appears in both inbound and outbound
        let config = make_network_config_with_listeners(
            vec!["https://shared.example.com", "http://localhost:8080"],
            vec!["https://outbound.example.com", "https://shared.example.com", "http://localhost:9000"],
        );
        let found = find_shared_outbound_listener(&config, 8080);
        assert!(found.is_some(), "should find shared outbound listener");
        assert_eq!(found.unwrap().port, 9000);
    }

    #[test]
    fn find_shared_outbound_listener_ignores_port_differences_in_url() {
        // Same hostname, different port numbers — still considered shared
        let config = make_network_config_with_listeners(
            vec!["https://shared.example.com:443"],
            vec!["https://shared.example.com:9000"],
        );
        assert!(find_shared_outbound_listener(&config, 8080).is_some());
    }

    #[test]
    fn find_shared_outbound_listener_returns_none_for_localhost_only_inbound() {
        // localhost on inbound does NOT match a public-only outbound URL
        let config =
            make_network_config_with_listeners(vec!["http://localhost:8080"], vec!["https://outbound.example.com"]);
        // localhost:8080 inbound vs outbound.example.com → no overlap
        assert!(find_shared_outbound_listener(&config, 8080).is_none());
    }

    #[test]
    fn find_shared_outbound_listener_is_case_insensitive() {
        let config =
            make_network_config_with_listeners(vec!["https://Shared.Example.COM"], vec!["https://shared.example.com"]);
        assert!(find_shared_outbound_listener(&config, 8080).is_some());
    }

    #[test]
    fn tp_outbound_path_prefix_is_outbound() {
        assert_eq!(
            crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX,
            "/outbound",
            "changing this constant is a breaking change for all deployed transit points"
        );
    }
}
