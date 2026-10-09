use anyhow::Context;
use axum::Router;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::auth::periodic_session_cleanup;
use crate::config::GatewayConfig;
use crate::gateways::connection_points::ConnectionPointStore;
use crate::gateways::filesystem::GatewayStore;
use crate::gateways::types::GatewayType;
use crate::mcp_proxies::filesystem::McpProxyStore;
use crate::mediators::filesystem::MediatorStore;
use crate::observability::periodic_metrics_update;
use crate::surfaces::AgentSurfaceStore;
use crate::trust_registries::store::TrustRegistryStore;

// Re-export SurfaceTaskManager for backward compatibility
pub use crate::proxy::SurfaceTaskManager;

/// Initialise the unified [`crate::source_auth::SourceAuthMiddleware`].
///
/// Builds the middleware from the secrets store, API key validator, DID Auth session
/// store, and JWT strategy store.
///
/// Returns `None` (with a warning) if the JWT verification strategy store cannot be
/// created; the gateway continues to start but source authentication will be unavailable.
async fn init_source_auth_middleware(
    secrets_storage_path: &str,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    secrets_cache: crate::a2a::auth::SecretsCache,
    api_key_validator: Option<Arc<dyn crate::api_keys::ApiKeyValidator>>,
    didauth_session_store: Arc<crate::didauth::DidAuthSessionStore>,
    cert_store: Option<Arc<dyn crate::certificates::CertificateStore>>,
) -> Option<Arc<crate::source_auth::SourceAuthMiddleware>> {
    let storage_path = PathBuf::from(secrets_storage_path)
        .parent()
        .map(|p| p.join("jwt_verification_strategies"))
        .unwrap_or_else(|| PathBuf::from("_storage/jwt_verification_strategies"));

    match crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(storage_path.clone()).await {
        Ok(store) => {
            info!("Source auth: JWT verification strategy store initialised at {}", storage_path.display());
            let store_arc: Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage> = Arc::new(store);
            {
                let s = store_arc.clone();
                crate::config::register_counter("credentials.jwt", move || {
                    let s = s.clone();
                    async move {
                        s.list()
                            .await
                            .map(|v| v.len())
                            .unwrap_or(0)
                    }
                });
            }
            let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new());
            Some(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
                didauth_session_store,
                store_arc,
                jwks_client,
                secrets_store,
                secrets_cache,
                api_key_validator,
                cert_store,
            )))
        }
        Err(e) => {
            warn!(
                "Failed to initialise source auth middleware (JWT strategy store at {}): {}",
                storage_path.display(),
                e
            );
            None
        }
    }
}

/// Register live entity counters for appliance resource-limit enforcement.
///
/// Each counter reports the current number of entities for a leaf dimension so
/// [`crate::config::enforce_add`] can compare against the configured limit at
/// create time. Multi-store umbrellas (`secrets`, `credentials`, `connections`,
/// `proxies`) are summed from their registered leaves; single-store umbrellas
/// (`surfaces`, `policies`) register a direct total alongside their per-type
/// leaves. Counters for `credentials.jwt`, `secrets.apikeys`, and
/// `secrets.certificates` are registered at those stores' own construction sites.
#[allow(clippy::too_many_arguments)]
fn register_resource_limit_counters(
    secrets_store: &Arc<dyn crate::secrets::SecretsStore>,
    agent_surface_store: &Option<Arc<crate::surfaces::FileSystemAgentSurfaceStore>>,
    policy_definition_store: &Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    mediator_store: &Option<Arc<crate::mediators::FileSystemMediatorStore>>,
    connection_point_store: &Option<Arc<crate::gateways::FileSystemConnectionPointStore>>,
    trust_registry_store: &Option<Arc<crate::trust_registries::FileSystemTrustRegistryStore>>,
    credential_provider_store: &Option<Arc<crate::credential_providers::storage::FileSystemCredentialProviderStore>>,
    delegation_vault_store: &Option<Arc<crate::delegation_vault::storage::FileSystemDelegationVaultStore>>,
    mcp_proxy_store: &Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
    a2a_proxy_store: &Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,
    integration_storage: &Option<Arc<crate::storage::IntegrationStorage>>,
) {
    use crate::config::register_counter;
    use crate::credential_providers::storage::CredentialProviderStorage as _;
    use crate::delegation_vault::storage::DelegationVaultStorage as _;

    // secrets.secret — the general secrets vault.
    {
        let s = secrets_store.clone();
        register_counter("secrets.secret", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }

    // surfaces (+ `agent` leaf). AgentSurfaces are monomorphic, so both the
    // umbrella and the leaf count every stored surface.
    if let Some(store) = agent_surface_store {
        let s = store.clone();
        register_counter("surfaces", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
        let s = store.clone();
        register_counter("surfaces.agent", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }

    // policies (+ per-type). A single store holds every policy type, so the
    // umbrella counts all definitions and the leaves filter by type.
    if let Some(store) = policy_definition_store {
        use crate::policies::policy_definitions::PolicyType;
        let s = store.clone();
        register_counter("policies", move || {
            let s = s.clone();
            async move { s.list().await.len() }
        });
        let s = store.clone();
        register_counter("policies.fabric", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| p.policy_type == PolicyType::Gateway)
                    .count()
            }
        });
        let s = store.clone();
        register_counter("policies.agent-surface", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| p.policy_type == PolicyType::AgentSurface)
                    .count()
            }
        });
    }

    // connections.gateways — the Local Gateway is always excluded so the quota
    // only tracks remote gateways that are being connected to this appliance.
    if let Some(store) = gateway_store {
        let s = store.clone();
        register_counter("connections.gateways", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(count_remote_gateways)
                    .unwrap_or(0)
            }
        });
    }
    // connections.mediators
    if let Some(store) = mediator_store {
        let s = store.clone();
        register_counter("connections.mediators", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // connections.connectionpoints — only user-created connection points count
    // toward the quota; system records (OOB inviter/responder/acceptor, legacy
    // System) are side effects of gateway-to-gateway flows and must not consume
    // the user Connection Point capacity exposed via the API/UI.
    if let Some(store) = connection_point_store {
        let s = store.clone();
        register_counter("connections.connectionpoints", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(count_user_connection_points)
                    .unwrap_or(0)
            }
        });
    }
    // connections.trustregistries
    if let Some(store) = trust_registry_store {
        let s = store.clone();
        register_counter("connections.trustregistries", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }

    // credentials.providers
    if let Some(store) = credential_provider_store {
        let s = store.clone();
        register_counter("credentials.providers", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // credentials.tokens — delegation-vault tokens (no direct create gate, but
    // counted so the `credentials` umbrella total is accurate).
    if let Some(store) = delegation_vault_store {
        let s = store.clone();
        register_counter("credentials.tokens", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }

    // proxies.mcp
    if let Some(store) = mcp_proxy_store {
        let s = store.clone();
        register_counter("proxies.mcp", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // proxies.a2a
    if let Some(store) = a2a_proxy_store {
        use crate::a2a_proxies::A2aProxyStore as _;
        let s = store.clone();
        register_counter("proxies.a2a", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }

    // integrations — notifier definitions.
    if let Some(store) = integration_storage {
        let s = store.clone();
        register_counter("integrations", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
}

fn count_remote_gateways(gateways: Vec<crate::gateways::types::Gateway>) -> usize {
    gateways
        .into_iter()
        .filter(|gateway| gateway.gateway_type == GatewayType::Remote)
        .count()
}

fn count_user_connection_points(
    connection_points: Vec<crate::gateways::connection_points::types::GatewayConnectionPoint>
) -> usize {
    use crate::gateways::connection_points::types::ConnectionPointType;
    connection_points
        .into_iter()
        .filter(|cp| cp.cp_type == ConnectionPointType::User)
        .count()
}

#[cfg(feature = "didwebvh")]
async fn sync_raw_did_log_if_missing(
    storage: &Arc<dyn crate::storage::DidLogStorage>,
    did: &str,
    raw_log: &str,
    success_message: &str,
    already_present_message: &str,
    append_error_prefix: &str,
    check_error_prefix: &str,
) {
    match storage
        .load_all_raw(did)
        .await
    {
        Ok(existing) if existing.is_empty() => {
            for line in raw_log.lines() {
                let line = line.trim();
                if !line.is_empty()
                    && let Err(e) = storage
                        .append_raw(did, line)
                        .await
                {
                    warn!("{}: {}", append_error_prefix, e);
                }
            }
            debug!("{}", success_message);
        }
        Ok(_) => debug!("{}", already_present_message),
        Err(e) => warn!("{}: {}", check_error_prefix, e),
    }
}

#[cfg(feature = "didwebvh")]
async fn sync_gateway_did_log(
    storage: &Arc<dyn crate::storage::DidLogStorage>,
    gateway_did: &str,
    log_src: &std::path::Path,
) {
    if !log_src.exists() {
        return;
    }

    match tokio::fs::read_to_string(log_src).await {
        Ok(content) => {
            sync_raw_did_log_if_missing(
                storage,
                gateway_did,
                &content,
                "Gateway DID registered for resolution via /v1/resolve",
                "Gateway DID already present in log storage",
                "Failed to register gateway DID log entry",
                "Could not check gateway DID log storage",
            )
            .await;
        }
        Err(e) => warn!("Could not read gateway DID log for sync: {}", e),
    }
}

#[cfg(feature = "didwebvh")]
fn extract_did_from_raw_log(raw_log: &str) -> Option<String> {
    raw_log
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|value| {
            value["state"]["id"]
                .as_str()
                .map(str::to_string)
        })
}

#[cfg(feature = "didwebvh")]
async fn sync_issuer_did_logs(
    storage: &Arc<dyn crate::storage::DidLogStorage>,
    issuers_path: &std::path::Path,
) {
    if !issuers_path.exists() {
        return;
    }

    match tokio::fs::read_dir(issuers_path).await {
        Ok(mut dir) => {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let jsonl_path = entry.path().join("did.jsonl");
                if !jsonl_path.exists() {
                    continue;
                }

                match tokio::fs::read_to_string(&jsonl_path).await {
                    Ok(content) => {
                        if let Some(did) = extract_did_from_raw_log(&content) {
                            sync_raw_did_log_if_missing(
                                storage,
                                &did,
                                &content,
                                &format!("Registered issuer DID for resolution: {}", did),
                                &format!("Issuer DID already present in log storage: {}", did),
                                "Failed to register issuer DID log entry",
                                "Could not check issuer DID log storage",
                            )
                            .await;
                        }
                    }
                    Err(e) => warn!("Could not read issuer DID log {:?}: {}", jsonl_path, e),
                }
            }
        }
        Err(e) => warn!("Could not scan issuers directory for DID sync: {}", e),
    }
}

/// A surface storage event deferred while the node is mid-activation. Replayed once
/// the activation re-derive completes so a remote write arriving during the readiness
/// window is applied rather than silently dropped (F1 defer-and-drain).
enum DeferredSurfaceEvent {
    Upsert(Box<crate::config::agent_surface::AgentSurface>),
    Delete(String),
}

/// Buffer of surface events deferred during an activation window, shared between the
/// surface-store subscriber and the activation drain.
type PendingSurfaceEvents = Arc<tokio::sync::Mutex<Vec<DeferredSurfaceEvent>>>;

fn spawn_x402_cleanup_worker(txn_store: Arc<crate::x402::TransactionStore>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // 24 hours
        loop {
            interval.tick().await;

            // Load retention_days from config (default 7 days)
            let retention_days = if let Ok(x402_config) = crate::x402::config_cache::get_or_load_x402_config().await {
                x402_config
                    .transaction_storage
                    .as_ref()
                    .map(|ts| ts.retention_days)
                    .unwrap_or(7)
            } else {
                7
            };

            match txn_store
                .cleanup_old_transactions(retention_days)
                .await
            {
                Ok(count) => {
                    info!(
                        "Transaction cleanup completed: {} old transactions removed (retention: {} days)",
                        count, retention_days
                    );

                    // Trigger integration alerts for cleanup completion
                    crate::integrations::trigger_cleanup_completed(count, retention_days).await;
                }
                Err(e) => {
                    warn!("Transaction cleanup failed: {}", e);
                }
            }
        }
    });
    info!("✓ Transaction cleanup worker started (runs daily)");
}

/// Promote the activation identified by `generation` to health-ready and, under the
/// pending-buffer lock, drain and replay any surface events deferred during the
/// window. Holding the lock across the readiness flip closes the race where an event
/// enqueued by the subscriber immediately after the flip would otherwise be stranded
/// until the next activation.
async fn mark_ready_and_drain_surface_events(
    generation: u64,
    pending: &PendingSurfaceEvents,
    state: &crate::identity::IdentityApiState,
) {
    let drained: Vec<DeferredSurfaceEvent> = {
        let mut buffer = pending.lock().await;
        crate::server::mode::mark_activation_ready(generation);
        buffer.drain(..).collect()
    };
    for event in drained {
        match event {
            DeferredSurfaceEvent::Upsert(surface) => {
                crate::identity::handlers::surfaces::apply_surface_upsert_from_storage(state, *surface).await;
            }
            DeferredSurfaceEvent::Delete(id) => {
                crate::identity::handlers::surfaces::apply_surface_delete_from_storage(state, &id).await;
            }
        }
    }
}

/// Start the Axum-based proxy server
pub async fn run_axum_proxy(
    config: GatewayConfig,
    bootstrap_config: crate::config::BootstrapConfig,
) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let bootstrap_config = Arc::new(bootstrap_config);

    // Capture the boot activation generation before spawning signal handlers, so a
    // promotion/step-down signal arriving during startup supersedes this window and
    // the end-of-startup readiness mark becomes a no-op for the now-stale generation.
    let boot_activation_generation = crate::server::mode::current_activation_generation();

    let mode_rx_for_task = crate::server::mode::subscribe_mode_changes();
    // Signals reach the whole process. The in-process gateways that component
    // tests boot would each add a listener that races the signal test's own and
    // can apply a stale SIGUSR2 after its SIGUSR1, so only the real binary listens.
    #[cfg(not(test))]
    crate::server::mode::spawn_signal_handlers();

    // Load metrics configuration early (needed for OpenTelemetry and CloudWatch)
    let metrics_config = Arc::new(
        crate::config::load_metrics_config(
            &bootstrap_config
                .config_files
                .metrics,
        )
        .unwrap_or_else(|e| {
            warn!(
                "Failed to load metrics config from {}: {}",
                bootstrap_config
                    .config_files
                    .metrics,
                e
            );
            warn!("Continuing with default (disabled) metrics configuration");
            crate::config::MetricsConfig {
                opentelemetry: crate::config::OpenTelemetryConfig {
                    enabled: false,
                    endpoint: "http://localhost:4317".to_string(),
                    protocol: crate::config::metrics_config::OtlpProtocol::default(),
                    auth: None,
                    service_name: env!("CARGO_PKG_NAME").to_string(),
                    environment: "development".to_string(),
                    traces: crate::config::metrics_config::TracesConfig {
                        enabled: false,
                        sample_rate: 1.0,
                        target_crates: vec!["agent_gateway".to_string()],
                        record_caller_identity: false,
                    },
                    metrics: crate::config::MetricsExportConfig {
                        enabled: false,
                        export_interval_seconds: 60,
                        batch_max_queue_size: None,
                        batch_scheduled_delay_ms: None,
                        batch_max_export_size: None,
                    },
                    logs: crate::config::metrics_config::LogsConfig { enabled: false },
                },
                cloudwatch: crate::config::metrics_config::CloudWatchMetricConfig {
                    enabled: false,
                    region: Some("us-east-1".to_string()),
                    namespace: "AgentGateway".to_string(),
                    dimensions: None,
                },
                retention: crate::config::RetentionConfig::default(),
                advanced: crate::config::AdvancedConfig::default(),
            }
        }),
    );

    // Load RBAC configuration early
    let rbac_config = Arc::new(
        crate::config::load_rbac_config(
            &bootstrap_config
                .config_files
                .rbac,
        )
        .unwrap_or_else(|e| {
            warn!(
                "Failed to load RBAC config from {}: {}",
                bootstrap_config
                    .config_files
                    .rbac,
                e
            );
            warn!("Continuing with default (empty) RBAC configuration");
            crate::rbac::RbacConfig::default()
        }),
    );

    // Tenancy hardening config: shared by PAT issue-time enforcement (the
    // access-tokens router) and auth-time enforcement (the session/PAT guard).
    let tenancy_config = Arc::new(
        bootstrap_config
            .tenancy
            .clone(),
    );

    // Load network configuration early - needed for DID domain and WebAuthn settings
    let network_config = bootstrap_config
        .load_network_config()
        .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;

    info!("Loaded network configuration with {} listener(s)", network_config.listeners.len());
    for listener in &network_config.listeners {
        info!(
            "  {} Listener '{}' on {}:{} with {} external URL(s)",
            listener.listener_type,
            listener.name,
            listener.bind_address,
            listener.port,
            listener.external_urls.len()
        );
    }

    // Initialize settings store and load settings from disk
    info!(
        "Initializing settings store with path: {}",
        bootstrap_config
            .storage_paths
            .settings
    );
    let settings_store = Arc::new(crate::storage::SettingsStore::new(
        &bootstrap_config
            .storage_paths
            .settings,
    ));
    settings_store.load().await?;

    // Store settings storage path globally for settings
    crate::storage::init_settings_storage_path(
        bootstrap_config
            .storage_paths
            .settings
            .clone(),
    );
    // Register the settings store globally so the audit vault can read categories.
    crate::storage::settings_store::set_global_settings_store(settings_store.clone());

    // Store integration triggers storage path globally for user/gateway integrations
    crate::storage::init_integration_triggers_storage_path(
        bootstrap_config
            .storage_paths
            .integration_triggers
            .clone(),
    );

    // Store gateways storage path globally for x402 gateway facilitator resolution
    crate::storage::init_gateways_storage_path(
        bootstrap_config
            .storage_paths
            .gateways
            .clone(),
    );

    crate::storage::init_identity_hash_pepper_path(
        bootstrap_config
            .storage_paths
            .identity_hash_pepper
            .clone(),
    );

    crate::identity::credential_identity::initialize_pepper().await;

    crate::gateways::did_cache::init_did_host_policy(
        bootstrap_config
            .did_cache
            .allow_private_hosts,
    );
    if bootstrap_config
        .did_cache
        .allow_private_hosts
    {
        warn!(
            "[did_cache] allow_private_hosts is enabled: did:web / did:webvh resolution may contact private-network hosts"
        );
    }

    // Initialise the process-wide shared DID resolver client (one TLS context
    // + connection pool instead of 7 separate ones — saves ~200-400 MB RSS).
    crate::gateways::did_cache::init_shared_resolver().await?;

    // Get metrics retention minutes from settings (overrides config value if present)
    let metrics_retention_minutes = settings_store.get_metrics_retention_minutes();

    // Initialize WebSocket state for real-time updates (always enabled)
    let ws_state = {
        let state = Arc::new(crate::server::WsState::new(bootstrap_config.websocket_broadcast_buffer));

        // Initialize WebSocket log broadcasting so all log entries are sent via WebSocket
        crate::observability::init_websocket_log_broadcast(state.clone());
        info!("📡 WebSocket log broadcasting initialized");

        Some(state)
    };

    // Initialize task monitor (always enabled, before metrics_store)
    let task_monitor = Some(Arc::new(crate::observability::TaskMonitor::new(Some(settings_store.clone()))));

    // Initialize system metrics store (CPU/memory) with persistent storage
    let system_metrics_store = {
        let store = Arc::new(crate::observability::SystemMetricsStore::new(
            &bootstrap_config
                .storage_paths
                .system_metrics,
        ));
        if let Err(e) = store.load().await {
            warn!("Failed to load system metrics history: {}", e);
        }
        Some(store)
    };

    // Initialize OpenTelemetry metrics provider if enabled
    let otel_meter_provider = if metrics_config
        .opentelemetry
        .enabled
        && metrics_config
            .opentelemetry
            .metrics
            .enabled
    {
        info!("Initializing OpenTelemetry metrics provider");
        let otel_config = crate::observability::OtelConfig::from(&metrics_config.opentelemetry);

        match crate::observability::init_metrics(&otel_config) {
            Ok(provider) => {
                info!("✅ OpenTelemetry metrics provider initialized");
                Some(Arc::new(provider))
            }
            Err(e) => {
                warn!("⚠️  Failed to initialize OpenTelemetry metrics: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Initialize VC issuer early (needed for identity_selector and identity API)
    // Always created now that identity API features are always enabled
    info!("Initializing VC issuer for agent identity management");
    let identity_store: Arc<dyn crate::identity::IdentityStore> = Arc::new(
        crate::identity::FilesystemIdentityStore::new_with_ws(
            &bootstrap_config
                .storage_paths
                .identities,
            ws_state.clone(),
        )
        .await?,
    );

    let vp_challenge_storage_path = PathBuf::from(
        &bootstrap_config
            .storage_paths
            .identities,
    )
    .join("vp_challenges");
    let vp_challenge_store: Arc<dyn crate::identity::VpChallengeStore> =
        Arc::new(crate::identity::FilesystemVpChallengeStore::new(&vp_challenge_storage_path).await?);

    let vc_issuer = Some(Arc::new(
        crate::identity::VCIssuer::new(
            &bootstrap_config
                .storage_paths
                .vc_keys,
            &network_config.did.domain,
            identity_store,
            vp_challenge_store,
            None,
            None,
        )
        .await?,
    ));
    if let Some(ref issuer) = vc_issuer {
        crate::payment_credentials::set_global_payment_vc_issuer(Arc::clone(issuer));
    }

    // Initialize metrics store (always enabled, after vc_issuer so we can get identity_store)
    let metrics_store = if let Some(ws) = &ws_state {
        let identity_store_opt = vc_issuer
            .as_ref()
            .map(|vc| vc.get_identity_store());
        let cloudwatch_config = if metrics_config
            .cloudwatch
            .enabled
        {
            // Clone the CloudWatch config and merge with top-level AWS settings
            let mut region = metrics_config
                .cloudwatch
                .region
                .clone();
            // Use region from cloudwatch config, or fall back to top-level aws_region
            if region
                .as_deref()
                .unwrap_or("")
                .is_empty()
            {
                region = bootstrap_config
                    .aws_region
                    .clone()
                    .or_else(|| Some("us-east-1".to_string()));
            }

            Some((
                crate::config::metrics_config::CloudWatchMetricConfig {
                    enabled: true,
                    namespace: metrics_config
                        .cloudwatch
                        .namespace
                        .clone(),
                    region,
                    dimensions: metrics_config
                        .cloudwatch
                        .dimensions
                        .clone(),
                },
                bootstrap_config
                    .aws_profile
                    .clone(),
            ))
        } else {
            None
        };
        Some(Arc::new(
            crate::metrics::MetricsStore::new_with_ws_and_retention(
                1000,
                ws.clone(),
                metrics_retention_minutes,
                bootstrap_config
                    .storage_paths
                    .metrics
                    .clone(),
                task_monitor.clone(),
                identity_store_opt,
                cloudwatch_config,
                otel_meter_provider.clone(),
                bootstrap_config.metrics_cache_ttl_seconds,
            )
            .await
            .with_settings_store(settings_store.clone()),
        ))
    } else {
        Some(Arc::new(crate::metrics::MetricsStore::new(1000).with_settings_store(settings_store.clone())))
    };

    // Initialize DID Auth session store for channels with filesystem persistence
    let didauth_session_store = Arc::new(
        crate::didauth::DidAuthSessionStore::with_storage(std::path::PathBuf::from(
            bootstrap_config
                .storage_paths
                .sessions
                .clone(),
        ))
        .await
        .context("Failed to create DID Auth session store")?,
    );
    info!("Initialized DID Auth session store with filesystem persistence");
    // Initialize GW2 metrics recording if metrics store is available
    if let Some(ref metrics) = metrics_store {
        crate::gateways::init_metrics_store(metrics.clone()).await;
        info!("✓ GW2 metrics store initialized for connection point message processing");
    }

    // Initialize GW2 task monitor if available for throughput tracking
    if let Some(ref monitor) = task_monitor {
        crate::gateways::init_task_monitor(monitor.clone()).await;
        info!("✓ GW2 task monitor initialized for bytes and throughput tracking");
    }

    // Initialize GW2 WebSocket state if available for payload capture broadcasting
    if let Some(ref ws) = ws_state {
        crate::gateways::init_ws_state(ws.clone()).await;
        info!("✓ GW2 WebSocket state initialized for payload capture broadcasting");
    }

    // Initialize GW2 facilitator mode from gateway config
    crate::gateways::init_facilitator_mode(
        config
            .facilitator_mode
            .clone(),
    )
    .await;
    info!(
        "✓ GW2 facilitator mode initialized (fabric={}, http={})",
        config
            .facilitator_mode
            .facilitator_via_fabric,
        config
            .facilitator_mode
            .facilitator_via_http
    );

    // Initialize transaction store for unified x402 lifecycle tracking
    // EVERY gateway needs this - it handles BOTH roles:
    // - GW1 role: receives HTTP payments, sends DIDComm verify/settle requests
    // - GW2 role: receives DIDComm verify/settle requests from other gateways
    // Load path from x402.json configuration (cached at startup)
    if let Ok(x402_config) = crate::x402::config_cache::get_or_load_x402_config().await {
        // Initialize transaction store from x402.json configuration
        // This is the unified store for verification → settlement lifecycle tracking
        let transaction_storage_path = x402_config
            .transaction_storage
            .as_ref()
            .map(|ts| std::path::PathBuf::from(&ts.filesystem_path))
            .unwrap_or_else(|| {
                std::path::PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .x402_transactions,
                )
            });

        match crate::x402::TransactionStore::new(transaction_storage_path.clone()).await {
            Ok(store) => {
                let store_arc = Arc::new(store);

                // Store globally for access by ALL components (DIDComm, HTTP middleware, Admin API, workers)
                crate::gateways::init_transaction_store(Arc::clone(&store_arc)).await;
                info!(path = ?transaction_storage_path, "✓ Transaction store initialized - handles both GW1 and GW2 roles");

                // Recover unsettled payments on startup (crash recovery)
                // Worker checks facilitator_gateway_id to determine what to settle
                info!("Starting crash recovery for unsettled payments...");
                let txn_store_rec = Arc::clone(&store_arc);
                let recovery_bootstrap_config = Arc::clone(&bootstrap_config);
                let facilitator_enabled = config
                    .facilitator_mode
                    .facilitator_via_fabric
                    || config
                        .facilitator_mode
                        .facilitator_via_http;
                tokio::spawn(async move {
                    crate::x402::recover_unsettled_on_startup(
                        txn_store_rec,
                        recovery_bootstrap_config,
                        facilitator_enabled,
                    )
                    .await;
                });

                // Note: Settlement worker will be started later after gateway_store is available
                // (needs gateway_store to determine local_gateway_id for facilitator delegation logic)
            }
            Err(e) => {
                error!(error = %e, "Failed to initialize transaction store - x402 payment processing will fail");
            }
        }
    } else {
        warn!("Failed to load x402.json config - x402 payment processing disabled");
    }

    // Initialize MPP transaction store for payment audit trail
    {
        let mpp_storage_path = std::path::PathBuf::from(
            &bootstrap_config
                .storage_paths
                .mpp_transactions,
        );

        match crate::mpp::MppTransactionStore::new(mpp_storage_path.clone()).await {
            Ok(store) => {
                let store_arc = Arc::new(store);
                crate::gateways::init_mpp_transaction_store(Arc::clone(&store_arc)).await;
                info!(path = ?mpp_storage_path, "✓ MPP transaction store initialized");

                // Spawn cleanup worker (daily, 7-day retention)
                let mpp_store_clone = Arc::clone(&store_arc);
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
                    loop {
                        interval.tick().await;
                        match mpp_store_clone
                            .cleanup_old_transactions(7)
                            .await
                        {
                            Ok(count) => {
                                info!("MPP transaction cleanup: {} old transactions removed", count);
                            }
                            Err(e) => {
                                warn!("MPP transaction cleanup failed: {}", e);
                            }
                        }
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "Failed to initialize MPP transaction store - MPP audit trail disabled");
            }
        }
    }

    // Initialize secrets store
    let secrets_backend = match bootstrap_config
        .secrets_backend
        .as_str()
    {
        "filesystem" => crate::secrets::SecretsBackend::Filesystem,
        "aws" => crate::secrets::SecretsBackend::Aws,
        _ => {
            warn!("Unknown secrets backend '{}', defaulting to filesystem", bootstrap_config.secrets_backend);
            crate::secrets::SecretsBackend::Filesystem
        }
    };
    let secrets_store = crate::secrets::create_secrets_store(
        secrets_backend,
        Some(
            bootstrap_config
                .storage_paths
                .secrets
                .clone(),
        ),
    )
    .await
    .context("Failed to initialize secrets store")?;
    info!("✓ Secrets store initialized with {} backend", bootstrap_config.secrets_backend);

    // Initialize GW2 VC issuer (separate identity space from GW1)
    // GW2 tracks two types of identities:
    // 1. Caller identity (from GW1 in request extensions)
    // 2. Agent identity (extracted from response extensions)
    // DID cache will be set later after connection point listener is initialized
    if let Some(ref issuer) = vc_issuer {
        crate::gateways::init_vc_issuer(issuer.clone(), None).await;
        info!("✓ GW2 VC issuer initialized for agent identity tracking (DID cache pending)");
    }

    // Load TLS configuration for main proxy
    let tls_config = crate::server::load_tls_config(&config.tls.cert_path, &config.tls.key_path)?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    // Create HTTP client for forwarding requests with robust error handling
    let client = crate::http_client::proxy_with_timeout(std::time::Duration::from_secs(config.a2a.timeout_seconds))?;

    // Initialize configuration cache using path from bootstrap config
    info!(
        "Initializing config cache with path: {}",
        bootstrap_config
            .storage_paths
            .config_cache
    );
    let config_cache = Arc::new(crate::storage::ConfigCache::new(
        &bootstrap_config
            .storage_paths
            .config_cache,
    ));

    // Save initial configuration to cache
    if let Err(e) = config_cache
        .save(&config, "initial")
        .await
    {
        warn!("Failed to save initial configuration to cache: {}", e);
    } else {
        info!("Initial configuration saved to cache");
    }

    // Create shared listener_manager slot that will be populated later
    // This allows channels to access the listener_manager once it's created
    let listener_manager_slot = Arc::new(tokio::sync::RwLock::new(None));

    // Create channel task manager with config cache, shared WebSocket state, and VC issuer
    let channel_manager = Arc::new(SurfaceTaskManager::new(
        config.clone(),
        bootstrap_config.clone(),
        config_cache.clone(),
        ws_state.clone(),
        vc_issuer.clone(),
        None, // We'll set this after listener_manager is created
        settings_store.clone(),
        didauth_session_store.clone(),
    ));

    // Group channels by port and spawn ONE listener task per port
    // Multiple channels can share the same port if they have different routes
    let mut channel_handles = HashMap::new();
    let mut task_ids_map = HashMap::new();

    // Get configured ports from network config
    let configured_ports = network_config.get_ports();
    info!("Server will bind to ports from network config: {:?}", configured_ports);

    // Helper function to map external listen_address to internal port using network config
    let map_address_to_port = |listen_addr: &str| -> Option<u16> { network_config.map_url_to_port(listen_addr) };
    let map_outbound_address_to_port =
        |listen_addr: &str| -> Option<u16> { network_config.map_url_to_port_for_type(listen_addr, Some("outbound")) };

    // Group active channels by the port they'll use.
    // Surfaces are kept as `AgentSurface` end-to-end so that `variants` and
    // `default_variant_id` survive into the runtime listener; the legacy
    // `ChannelMapping` shape is derived inside `run_port_server` only where
    // pre-variant fields are needed.
    let mut channels_by_port: HashMap<u16, Vec<crate::config::agent_surface::AgentSurface>> = HashMap::new();
    for surface in config.surfaces.iter() {
        // Skip disabled channels at startup
        if surface.status == crate::config::agent_surface::SurfaceStatus::Disabled {
            info!("Skipping disabled channel '{}' at startup", surface.name);
            continue;
        }

        // Map channel's listen_address to internal port
        if let Some(port) = map_address_to_port(surface.listen_address()) {
            // Only include channel if its mapped port is in the configured ports
            if configured_ports.contains(&port) {
                channels_by_port
                    .entry(port)
                    .or_default()
                    .push(surface.clone());
            } else {
                warn!(
                    "Channel '{}' maps to port {} which is not in configured ports {:?} - skipping",
                    surface.name, port, configured_ports
                );
            }
        } else {
            warn!(
                "Could not map channel '{}' listen_address '{}' to any internal port - skipping",
                surface.name,
                surface.listen_address()
            );
        }
    }

    let active_count = config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Active)
        .count();
    info!(
        "Initial startup: Mapped {} active channels across {} configured ports",
        active_count,
        channels_by_port.len()
    );

    // Store channels_by_port for later use - will spawn listeners AFTER Identity API router creation
    let channels_by_port_deferred = channels_by_port;

    // Outbound channel bucketing happens later, after the agent surface
    // store has been created, so that surface-derived outbound VCs are
    // included alongside legacy file-based channels.

    // Outbound bucketing happens later (after the agent surface store has
    // been created) so surface-derived outbound VCs are included alongside
    // legacy file-based channels — see `outbound_channels_by_port = { ... }`
    // below.

    // NOTE: Port listener spawning moved to after Identity API router creation (around line 650)
    // This allows us to pass the Identity API router to the port listeners

    // Channel handles and task IDs will be populated after port listeners are spawned

    // Keep track of identity API and monitoring tasks (these don't get reloaded)
    let mut tasks = Vec::new();

    // Start identity API server (always enabled)
    {
        // Use the same metrics store that the channels are using
        let identity_metrics_store = metrics_store
            .clone()
            .unwrap_or_else(|| Arc::new(crate::metrics::MetricsStore::new(1000)));

        // Use the WebSocket state we created earlier
        let ws_state = ws_state.unwrap();

        // Use the vc_issuer we created earlier (should always be present)
        let vc_issuer_for_api = vc_issuer
            .clone()
            .expect("VC issuer should be initialized");

        // Create onboarding session manager
        let onboarding_sessions = Arc::new(crate::identity::handlers::OnboardingSessionManager::new());

        // Initialize Policy Definition store early so the policy manager can resolve
        // opa_policy_definition_id references when compiling surface policies.
        // (This is later assigned to identity_state.policy_definition_store as well.)
        let early_policy_definition_store: Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>> =
            match crate::policies::FileSystemPolicyDefinitionStore::new(
                bootstrap_config
                    .storage_paths
                    .policy_definitions
                    .clone(),
            )
            .await
            {
                Ok(store) => {
                    match store
                        .migrate_legacy_packages()
                        .await
                    {
                        Ok(0) => {}
                        Ok(n) => info!("Migrated {n} legacy channel.policy definition(s) to surface.policy"),
                        Err(e) => warn!("Failed to migrate legacy policy definitions: {}", e),
                    }
                    info!("Policy definition store initialized (early)");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    warn!("Failed to initialize policy definition store early: {}", e);
                    None
                }
            };

        // Create policy manager and initialize policies from channels
        let policy_manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        if let Some(ref store) = early_policy_definition_store {
            policy_manager.set_policy_definition_store(store.clone());
        }
        for surface in &config.surfaces {
            if surface.config_id().is_some()
                && let Err(e) = policy_manager
                    .update_channel_policy(surface)
                    .await
            {
                warn!("Failed to initialize policy for channel {}: {}", surface.name, e);
            }
        }

        // Initialize agent surface store
        let agent_surface_store = match crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
        ))
        .await
        {
            Ok(store) => Some(Arc::new(store)),
            Err(e) => {
                error!("Failed to initialize agent surface store: {}", e);
                None
            }
        };

        // Initialize agent surface template store (builtin + user
        // templates). Builtins are seeded on first start by scanning
        // the directory configured via
        // `[config_files] agent_surface_templates_dir`, resolved
        // relative to the bootstrap config dir when not absolute.
        let surface_template_store = {
            let storage_dir = std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .agent_surface_templates,
            );
            let seed_dir = {
                let raw = std::path::Path::new(
                    &bootstrap_config
                        .config_files
                        .agent_surface_templates_dir,
                );
                if raw.is_absolute() {
                    Some(raw.to_path_buf())
                } else {
                    bootstrap_config
                        .config_dir
                        .as_ref()
                        .map(|d| d.join(raw))
                }
            };
            match crate::surface_templates::FileSystemSurfaceTemplateStore::new(storage_dir, seed_dir).await {
                Ok(store) => Some(Arc::new(store)),
                Err(e) => {
                    error!("Failed to initialize surface template store: {}", e);
                    None
                }
            }
        };

        // Surfaces are translated to ChannelMappings lazily and were not
        // visible during the earlier `update_channel_policy` loop over
        // `config.channels`. Compile their OPA engines now so an active
        // surface that references a `policy_definition_id` is enforceable
        // at startup (and does not produce the misleading "OPA enabled
        // but no policy is loaded" 403 on first request).
        // Phase C — resolved-surface cache. Pre-computes per-variant
        // `AgentSurface` snapshots for every active surface so the
        // request pipeline can look them up by `(surface_id, alias)`
        // without re-running `resolve_variant` per request. Kept in
        // sync by `apply_surface_change` on every surface CRUD path.
        let resolved_surface_cache = Arc::new(crate::surfaces::ResolvedSurfaceCache::new());
        if let Some(ref surface_store) = agent_surface_store {
            match surface_store.list_all().await {
                Ok(surfaces) => {
                    for surface in &surfaces {
                        if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
                            continue;
                        }
                        if let Err(e) = policy_manager
                            .update_channel_policy(surface)
                            .await
                        {
                            warn!("Failed to initialize policy for surface-derived channel {}: {}", surface.name, e);
                        }
                        if let Err(e) = resolved_surface_cache.upsert(surface) {
                            warn!(
                                surface = %surface.surface_id,
                                "Failed to seed resolved-surface cache: {e}"
                            );
                        }
                    }
                }
                Err(e) => warn!("Failed to list surfaces for policy initialization: {}", e),
            }
        }

        // Create identity API state
        let identity_state = crate::identity::IdentityApiState {
            vc_issuer: vc_issuer_for_api.clone(),
            config: Arc::clone(&config),
            network_config: Arc::new(network_config.clone()),
            ws_state: ws_state.clone(),
            settings_store: settings_store.clone(),
            user_settings_store: Arc::new(crate::storage::UserSettingsStore::new(
                &bootstrap_config
                    .storage_paths
                    .settings,
            )),
            metrics_store: identity_metrics_store.clone(),
            channel_manager: channel_manager.clone(),
            tls_acceptor: tls_acceptor.clone(),
            client: client.clone(),
            bootstrap_config: bootstrap_config.clone(),
            rbac_config: rbac_config.clone(),
            task_monitor: task_monitor.clone(),
            onboarding_sessions: onboarding_sessions.clone(),
            policy_manager: policy_manager.clone(),
            gateway_policy_manager: None,  // Will be set after gateway_store is initialized
            notification_store: None,      // Will be set after notification_store is initialized
            policy_definition_store: None, // Will be set after policy_definition_store is initialized
            global_policy_store: None,     // Will be set after global policy store is initialized
            global_policy_manager: None,   // Will be set after global policy manager is initialized
            agent_surface_store: agent_surface_store.clone(),
            gateway_store: None,
            connection_point_store: None,
            mediator_store: None,
            issuer_store: None,
            trust_registry_store: None,
            authority_store: None,
            integration_store: None,
            mcp_proxy_store: None,
            a2a_proxy_store: None,
            secrets_store: None,
            certificate_store: None,
            jwt_verification_strategy_store: None,
            credential_provider_store: None,
            sts_client_store: None,
            resolved_surface_cache: resolved_surface_cache.clone(),
            surface_template_store: surface_template_store.clone(),

            // DID:webvh fields (will be initialized later if feature is enabled)
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_log_storage: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_base_url: None,
        };

        // Once changes of channels are detected (FS updated by another node) -> propagate changes to this node
        let pending_surface_events: PendingSurfaceEvents = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        // A dedicated clone kept alive for the boot-time activation drain (see the
        // end-of-startup readiness mark), independent of the per-mode-task clone.
        let identity_state_for_boot_drain = identity_state.clone();
        if let Some(ref surface_store) = agent_surface_store {
            if let Some(mut surface_events) = surface_store.subscribe() {
                let identity_state_for_surface_events = identity_state.clone();
                let pending_for_surface_events = pending_surface_events.clone();
                tokio::spawn(async move {
                    loop {
                        match surface_events.recv().await {
                            Ok(crate::storage::filesystem::StorageEvent::Upsert {
                                entity,
                                source: crate::storage::filesystem::StorageEventSource::RemoteWrite,
                                ..
                            }) => {
                                // Defer remote surface changes that land mid-activation so
                                // they replay after the re-derive, instead of racing it and
                                // clobbering freshly re-derived state (F1). The is_activating
                                // check + enqueue is done under the same lock the drain flips
                                // readiness under, so an event is never stranded.
                                let mut buffer = pending_for_surface_events
                                    .lock()
                                    .await;
                                if crate::server::mode::is_activating() {
                                    buffer.push(DeferredSurfaceEvent::Upsert(Box::new(entity)));
                                } else {
                                    drop(buffer);
                                    crate::identity::handlers::surfaces::apply_surface_upsert_from_storage(
                                        &identity_state_for_surface_events,
                                        entity,
                                    )
                                    .await;
                                }
                            }
                            Ok(crate::storage::filesystem::StorageEvent::Delete {
                                id,
                                source: crate::storage::filesystem::StorageEventSource::RemoteWrite,
                            }) => {
                                let mut buffer = pending_for_surface_events
                                    .lock()
                                    .await;
                                if crate::server::mode::is_activating() {
                                    buffer.push(DeferredSurfaceEvent::Delete(id));
                                } else {
                                    drop(buffer);
                                    crate::identity::handlers::surfaces::apply_surface_delete_from_storage(
                                        &identity_state_for_surface_events,
                                        &id,
                                    )
                                    .await;
                                }
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!("Agent surface storage subscriber lagged; skipped {} event(s)", skipped);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                warn!("Agent surface storage subscriber closed");
                                break;
                            }
                        }
                    }
                });
                info!("Agent surface storage subscription initialized");
            } else {
                warn!("Agent surface store does not support subscriptions");
            }
        }

        let terms_manager = if network_config.terms {
            let terms_appliance_id = vc_issuer_for_api
                .get_issuer_did()
                .await
                .context("failed to resolve the stable appliance DID for Terms")?;
            Arc::new(
                crate::terms::TermsManager::open_remote(
                    terms_appliance_id,
                    PathBuf::from(
                        &bootstrap_config
                            .storage_paths
                            .terms,
                    ),
                    network_config
                        .affinidi_terms_url
                        .clone()
                        .context("affinidi_terms_url is required when Terms are enabled")?,
                )
                .await?,
            )
        } else {
            Arc::new(
                crate::terms::TermsManager::open(
                    false,
                    String::new(),
                    PathBuf::from(
                        &bootstrap_config
                            .storage_paths
                            .terms,
                    ),
                    None,
                )
                .await?,
            )
        };

        // Initialize authentication based on mode
        let mut auth_state_for_notif: Option<Arc<crate::auth::AuthState>> = None;
        let mut _saml_state_for_notif: Option<Arc<crate::auth::saml::SamlState>> = None;

        // Use the auth_mode from config
        let auth_mode = bootstrap_config
            .auth_mode
            .clone();

        let (auth_state, saml_state) = match auth_mode {
            crate::auth::AuthMode::Passkey => {
                // Initialize passkey authentication
                match initialize_auth_state(&bootstrap_config, &network_config, terms_manager.clone()).await {
                    Ok(state) => {
                        info!("Passkey authentication enabled");
                        let state_arc = Arc::new(state);
                        auth_state_for_notif = Some(state_arc.clone());
                        (Some(state_arc), None)
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to initialize passkey authentication: {}", e));
                    }
                }
            }
            crate::auth::AuthMode::Saml => {
                // Initialize SAML authentication
                let saml_config = crate::auth::SamlConfig::load_from_file(
                    &bootstrap_config
                        .config_files
                        .saml,
                )
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to load SAML configuration from {}: {}",
                        bootstrap_config
                            .config_files
                            .saml,
                        e
                    )
                })?;

                crate::source_auth::client_ip::warn_if_login_throttle_shares_one_limit(
                    "login_throttle",
                    &saml_config.login_throttle,
                    &network_config.client_ip,
                );
                match initialize_saml_state(&bootstrap_config, &saml_config, terms_manager.clone()).await {
                    Ok(state) => {
                        info!("SAML authentication enabled with IdP: {}", saml_config.idp_entity_id);
                        let state_arc = Arc::new(state);
                        _saml_state_for_notif = Some(state_arc.clone());
                        (None, Some(state_arc))
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to initialize SAML authentication: {}", e));
                    }
                }
            }
        };

        // Initialize gateway, mediator, and trust registry stores
        // Get the proxy DID from the VC issuer to use for the self gateway
        let proxy_did = vc_issuer_for_api
            .get_issuer_did()
            .await
            .ok();

        let gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>> =
            match crate::gateways::FileSystemGatewayStore::new(
                PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .gateways,
                ),
                proxy_did,
            )
            .await
            {
                Ok(store) => {
                    match store
                        .migrate_exposure_modes()
                        .await
                    {
                        Ok(0) => {}
                        Ok(n) => info!("Migrated the exposure mode of {n} remote gateway(s)"),
                        Err(e) => warn!("Failed to migrate remote gateway exposure modes: {}", e),
                    }
                    info!("Gateway store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize gateway store: {}", e);
                    None
                }
            };

        let mediator_store: Option<Arc<crate::mediators::FileSystemMediatorStore>> =
            match crate::mediators::FileSystemMediatorStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .mediators,
            ))
            .await
            {
                Ok(store) => {
                    info!("Mediator store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize mediator store: {}", e);
                    None
                }
            };

        let issuer_store: Option<Arc<crate::issuers::FileSystemIssuerStore>> =
            match crate::issuers::FileSystemIssuerStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .issuers,
            ))
            .await
            {
                Ok(store) => {
                    info!("Issuer store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize issuer store: {}", e);
                    None
                }
            };

        let authority_store: Option<Arc<crate::authorities::FileSystemAuthorityStore>> =
            match crate::authorities::FileSystemAuthorityStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .authorities,
            ))
            .await
            {
                Ok(store) => {
                    info!("Authority store initialized");
                    let store = Arc::new(store);
                    crate::gateways::connection_points::init_authority_store(store.clone());
                    Some(store)
                }
                Err(e) => {
                    error!("Failed to initialize authority store: {}", e);
                    None
                }
            };

        // STS managed-connection store (RFC 8693 token exchange clients). Stored
        // as a sibling of the other entity dirs under the storage base.
        let sts_client_store: Option<Arc<dyn crate::sts::store::StsClientStorage>> = {
            let path = PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .authorities,
            )
            .parent()
            .map(|p| p.join("sts_clients"))
            .unwrap_or_else(|| PathBuf::from("_storage/sts_clients"));
            match crate::sts::store::FileSystemStsClientStore::new(path).await {
                Ok(store) => {
                    info!("STS client store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize STS client store: {}", e);
                    None
                }
            }
        };

        // ── Credential Delegation stores ──────────────────────────────────
        let credential_provider_store: Option<
            Arc<crate::credential_providers::storage::FileSystemCredentialProviderStore>,
        > = match crate::credential_providers::storage::FileSystemCredentialProviderStore::new(PathBuf::from(
            &bootstrap_config
                .storage_paths
                .credential_providers,
        ))
        .await
        {
            Ok(store) => {
                info!(target: "credential_delegation", "Credential provider store initialized");
                Some(Arc::new(store))
            }
            Err(e) => {
                error!(target: "credential_delegation", "Failed to initialize credential provider store: {}", e);
                None
            }
        };

        let delegation_vault_store: Option<Arc<crate::delegation_vault::storage::FileSystemDelegationVaultStore>> =
            match crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .delegation_vault,
            ))
            .await
            {
                Ok(store) => {
                    info!(target: "credential_delegation", "Delegation vault store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!(target: "credential_delegation", "Failed to initialize delegation vault store: {}", e);
                    None
                }
            };

        if let Some(config) = bootstrap_config
            .mcp
            .continuations
            .clone()
        {
            config.validate()?;
            let dynamodb = match &config.storage {
                crate::mcp::continuations::config::ContinuationStorageConfig::Dynamodb { .. } => Some(
                    crate::storage::dynamodb_generic_repository::build_dynamodb_client(
                        bootstrap_config
                            .aws_region
                            .as_deref(),
                        bootstrap_config
                            .aws_profile
                            .as_deref(),
                    )
                    .await?,
                ),
                crate::mcp::continuations::config::ContinuationStorageConfig::Embedded { .. } => None,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            crate::mcp::continuations::config::ContinuationRuntime::load(config, secrets_store.as_ref(), dynamodb, now)
                .await?
                .install()?;
        }

        // Initialize global credential delegation stores for proxy pipeline access
        if let (Some(cp_store), Some(dv_store)) = (&credential_provider_store, &delegation_vault_store) {
            let base_url = format!("https://{}", network_config.did.domain);
            crate::proxy::server::init_credential_delegation_stores(
                cp_store.clone(),
                dv_store.clone(),
                base_url.clone(),
            );

            // Initialize GW2 message processor globals for credential delegation
            crate::gateways::connection_points::message_processor::init_credential_provider_store(cp_store.clone())
                .await;
            crate::gateways::connection_points::message_processor::init_delegation_vault_store(dv_store.clone()).await;
            crate::gateways::connection_points::message_processor::init_secrets_store(secrets_store.clone()).await;
            crate::gateways::connection_points::message_processor::init_gateway_base_url(base_url).await;
        }

        // Initialize transit token issuer for the proxy pipeline.
        // Uses the gateway domain as the issuer ID and derives a signing key
        // from the domain (in production, this should use a dedicated secret).
        {
            use sha2::{Digest, Sha256};
            let gateway_domain = &network_config.did.domain;
            let mut hasher = Sha256::new();
            hasher.update(b"transit-token-signing-key:");
            hasher.update(gateway_domain.as_bytes());
            let signing_key = hasher.finalize();

            let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(&signing_key, gateway_domain.clone());
            crate::proxy::server::init_transit_token_issuer(Arc::new(issuer));
        }

        // Initialize delegation vault audit logger
        crate::delegation_vault::audit::init_audit_logger(
            bootstrap_config
                .logging
                .log_directory
                .as_deref(),
        );

        let trust_registry_store: Option<Arc<crate::trust_registries::FileSystemTrustRegistryStore>> =
            match crate::trust_registries::FileSystemTrustRegistryStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .trust_registries,
            ))
            .await
            {
                Ok(store) => {
                    info!("Trust registry store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize trust registry store: {}", e);
                    None
                }
            };

        // Initialize TrustRegistryListenerManager (per-registry connections via connection points)
        let trust_registries_storage_path = PathBuf::from(
            &bootstrap_config
                .storage_paths
                .trust_registries,
        );
        let trust_registry_listener_manager: Option<Arc<crate::trust_registries::TrustRegistryListenerManager>> = {
            let domain = network_config
                .did
                .domain
                .clone();
            Some(Arc::new(crate::trust_registries::TrustRegistryListenerManager::new(
                domain,
                trust_registries_storage_path.clone(),
                Some(secrets_store.clone()),
            )))
        };

        if crate::server::mode::is_standby()
            && let Some(ref listener_mgr) = trust_registry_listener_manager
        {
            listener_mgr.deactivate();
            info!("Standby mode: trust registry listeners deactivated until SIGUSR1");
        }

        let mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>> =
            match crate::mcp_proxies::FileSystemMcpProxyStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .mcp_proxies,
            ))
            .await
            {
                Ok(store) => {
                    info!("MCP Proxy store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize MCP Proxy store: {}", e);
                    None
                }
            };

        let a2a_proxy_store: Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>> =
            match crate::a2a_proxies::FileSystemA2aProxyStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .a2a_proxies,
            ))
            .await
            {
                Ok(store) => {
                    info!("A2A Proxy store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize A2A Proxy store: {}", e);
                    None
                }
            };

        // Policy definition store was already initialized early (above the policy manager).
        // Reuse the same instance to avoid opening the same path twice.
        let policy_definition_store = early_policy_definition_store.clone();

        // Initialize GW2 MCP proxy store if available for proxy:// backend routing
        if let Some(ref mcp_proxy_store_ref) = mcp_proxy_store {
            crate::gateways::init_mcp_proxy_store(mcp_proxy_store_ref.clone()).await;
            info!("✓ GW2 MCP proxy store initialized for proxy:// backend routing");
        }

        // Initialize GW2 A2A proxy store if available for a2a-proxy:// backend routing
        if let Some(ref a2a_proxy_store_ref) = a2a_proxy_store {
            crate::gateways::init_a2a_proxy_store(a2a_proxy_store_ref.clone()).await;
            info!("✓ GW2 A2A proxy store initialized for a2a-proxy:// backend routing");
        }

        // Initialize GW2 trust registry listener manager for agent trust OPA context building
        if let Some(ref listener_mgr) = trust_registry_listener_manager {
            crate::gateways::init_trust_registry_listener_manager(listener_mgr.clone()).await;
            info!("✓ GW2 trust registry listener manager initialized for agent trust OPA");
        }

        // Initialize GW2 issuer store for trust registry validation lookups
        if let Some(ref issuer_store) = issuer_store {
            crate::gateways::init_issuer_store(issuer_store.clone()).await;
            info!("✓ GW2 issuer store initialized for trust registry validation");
        }

        // Startup reconnection: re-establish connections for all Connected trust registries.
        // Deferred to a background task so the HTTP port servers can bind first —
        // the mediator needs to resolve our did:web (served by this gateway) during
        // WebSocket authentication, so the DID document endpoint must be live.
        if let (Some(listener_mgr), Some(tr_store)) = (&trust_registry_listener_manager, &trust_registry_store) {
            // Inject the store into the listener manager so it can reconnect on demand
            listener_mgr
                .set_store(tr_store.clone() as Arc<dyn TrustRegistryStore>)
                .await;
            // Attach the dashboard broadcaster so per-connection stream readers can
            // publish connection-status changes (set before any reader spawns).
            listener_mgr
                .set_ws_state((*ws_state).clone())
                .await;

            let listener_mgr = listener_mgr.clone();
            let tr_store_for_boot = tr_store.clone();
            tokio::spawn(async move {
                if !listener_mgr.is_active() {
                    info!("Trust registry startup reconnection skipped: standby mode");
                    return;
                }

                // Wait for HTTP servers to bind and start serving DID documents.
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

                // Reconcile the cache with disk before reconnecting, mirroring the promotion path.
                if let Err(e) = tr_store_for_boot
                    .refresh_from_disk()
                    .await
                {
                    warn!("Trust registry store refresh at startup failed: {e} — reconnecting from cached state");
                }

                if !listener_mgr.is_active() {
                    info!("Trust registry startup reconnection aborted: no longer active");
                    return;
                }

                let reconnected = listener_mgr
                    .reconnect_all_from_store()
                    .await;
                if reconnected > 0 {
                    info!(
                        "Trust registry: reconnected to {} registr{} at startup",
                        reconnected,
                        if reconnected == 1 {
                            "y"
                        } else {
                            "ies"
                        }
                    );
                }
            });
        }

        // Start trust registry background worker for live connection status updates
        let trust_registry_worker: Option<Arc<crate::trust_registries::TrustRegistryWorker>> =
            if let (Some(listener_mgr), Some(tr_store)) = (&trust_registry_listener_manager, &trust_registry_store) {
                let worker = Arc::new(crate::trust_registries::TrustRegistryWorker::new(listener_mgr.clone()));
                if listener_mgr.is_active() {
                    worker
                        .start_all(tr_store.clone(), (*ws_state).clone())
                        .await;
                    info!("Trust registry background worker started");
                } else {
                    info!("Trust registry background worker deferred until SIGUSR1");
                }
                Some(worker)
            } else {
                None
            };

        // Set trust registry deps on VCIssuer for agent DID auto-registration
        if let (Some(issuer), Some(issuer_store), Some(tr_mgr)) =
            (&vc_issuer, &issuer_store, &trust_registry_listener_manager)
        {
            issuer
                .set_trust_registry_deps(issuer_store.clone(), tr_mgr.clone())
                .await;
            info!("✓ VCIssuer trust registry deps set for agent DID auto-registration");
        }

        // Initialize GW2 policy manager for rate limiting and policies on fabric-forwarded requests
        crate::gateways::init_policy_manager(policy_manager.clone()).await;
        info!("✓ GW2 policy manager initialized for rate limiting and policy enforcement");

        // Initialize GW2 HTTP client for MCP proxy requests with policy support
        crate::gateways::init_http_client(
            client.clone(),
            std::time::Duration::from_secs(config.a2a.timeout_seconds),
            config.a2a.max_body_size,
        )
        .await;
        info!("✓ GW2 HTTP client initialized for MCP proxy requests with policy support");

        // Initialize GW2 agent-surface store so fabric forward-request handlers can
        // resolve surfaces via the in-process cached store (O(1) get) instead
        // of re-opening the filesystem store on every inbound message.
        if let Some(ref store) = agent_surface_store {
            let dyn_store: Arc<dyn crate::surfaces::AgentSurfaceStore> = store.clone();
            crate::gateways::init_agent_surface_store(dyn_store).await;
            info!("✓ GW2 agent-surface store initialized for O(1) surface lookup");
        }

        // Initialize MCP Server manager and load existing proxies
        let mcp_server_manager = Arc::new(crate::mcp_proxies::handlers::McpServerManager::new());

        if let Some(ref store) = mcp_proxy_store {
            match store.list_all().await {
                Ok(proxies) => {
                    let proxy_count = proxies.len();
                    for proxy in proxies {
                        if let Err(e) = mcp_server_manager
                            .create_server(&proxy)
                            .await
                        {
                            warn!("Failed to create MCP server for proxy '{}': {}", proxy.name, e);
                        }
                    }
                    info!("Loaded {} MCP Proxy server(s)", proxy_count);
                }
                Err(e) => {
                    error!("Failed to load MCP Proxies: {}", e);
                }
            }
        }

        let connection_point_store: Option<Arc<crate::gateways::FileSystemConnectionPointStore>> =
            match crate::gateways::FileSystemConnectionPointStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ))
            .await
            {
                Ok(store) => {
                    info!("Connection point store initialized");

                    // Clean up orphaned connection point directories (those without metadata.json)
                    // These are leftover DID secret folders from failed/incomplete connection attempts
                    match store
                        .cleanup_orphaned_directories()
                        .await
                    {
                        Ok(count) => {
                            if count > 0 {
                                info!(
                                    "Cleaned up {} orphaned connection point director{}",
                                    count,
                                    if count == 1 {
                                        "y"
                                    } else {
                                        "ies"
                                    }
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Failed to cleanup orphaned connection point directories: {}", e);
                            // Don't fail startup due to cleanup errors
                        }
                    }

                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize connection point store: {}", e);
                    None
                }
            };

        let notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>> = {
            let auth_storage_ref = auth_state
                .as_ref()
                .map(|state| state.storage.as_ref());
            match crate::integrations::FileSystemNotificationStore::new(
                PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .notifications,
                ),
                PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .notification_templates,
                ),
                auth_storage_ref,
            )
            .await
            {
                Ok(store) => {
                    info!("Notification store initialized");
                    let store_arc = Some(Arc::new(store));

                    // Set notification store in auth state
                    if let Some(auth) = &auth_state_for_notif {
                        let mut notif_store = auth
                            .notification_store
                            .write()
                            .await;
                        *notif_store = store_arc.clone();
                        info!("Notification store set in auth state");
                    }

                    store_arc
                }
                Err(e) => {
                    error!("Failed to initialize notification store: {}", e);
                    None
                }
            }
        };

        // Update identity_state with notification_store
        let mut identity_state = identity_state;
        identity_state.notification_store = notification_store.clone();
        identity_state.policy_definition_store = policy_definition_store.clone();
        identity_state.gateway_store = gateway_store.clone();
        identity_state.connection_point_store = connection_point_store.clone();
        identity_state.mediator_store = mediator_store.clone();
        identity_state.issuer_store = issuer_store.clone();
        identity_state.trust_registry_store = trust_registry_store.clone();
        identity_state.authority_store = authority_store.clone();
        identity_state.mcp_proxy_store = mcp_proxy_store.clone();
        identity_state.a2a_proxy_store = a2a_proxy_store.clone();
        identity_state.secrets_store = Some(secrets_store.clone());
        identity_state.credential_provider_store = credential_provider_store
            .clone()
            .map(|store| store as Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>);
        identity_state.sts_client_store = sts_client_store.clone();

        // Initialize gateway-level OPA policy manager
        let gateway_policy_manager = Arc::new(crate::policies::GatewayPolicyManager::new());
        if let Some(ref store) = policy_definition_store {
            gateway_policy_manager.set_policy_definition_store(store.clone());
        }
        if let Some(ref gw_store) = gateway_store
            && let Ok(gateways) = gw_store.list_all().await
        {
            for gateway in &gateways {
                // Track the self-gateway ID
                if gateway.gateway_type == crate::gateways::types::GatewayType::SelfGateway {
                    gateway_policy_manager.set_self_gateway_id(gateway.id.clone());
                }
                if gateway
                    .opa_policy_config
                    .is_some()
                    && let Err(e) = gateway_policy_manager
                        .update_gateway_policy(gateway)
                        .await
                {
                    error!("Failed to initialize OPA policy for gateway {}: {}", gateway.id, e);

                    // OPA policy is critical for request authorization, fail startup if any gateway policies fail to load
                    std::process::exit(1);
                }
            }
        }
        identity_state.gateway_policy_manager = Some(gateway_policy_manager.clone());

        // Initialize GW2 gateway-level OPA policy manager for fabric-forwarded requests
        crate::gateways::init_gateway_policy_manager(gateway_policy_manager.clone()).await;

        // Initialize appliance-wide (global) policy manager. Enforced deny-overrides
        // ahead of each object's own policy on both the gateway and surface planes.
        match crate::policies::FileSystemGlobalPolicyStore::new(
            bootstrap_config
                .storage_paths
                .global_policies
                .clone(),
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                let global_policy_manager = Arc::new(crate::policies::GlobalPolicyManager::new());
                if let Some(ref def_store) = policy_definition_store {
                    global_policy_manager.set_policy_definition_store(def_store.clone());
                }
                global_policy_manager
                    .refresh(&store.get().await)
                    .await;
                identity_state.global_policy_store = Some(store);
                identity_state.global_policy_manager = Some(global_policy_manager.clone());
                crate::gateways::init_appliance_policy_manager(global_policy_manager).await;
            }
            Err(e) => {
                error!("Failed to initialize appliance-wide policy store: {}", e);
                std::process::exit(1);
            }
        }

        // Initialize DID:webvh support if feature is enabled
        #[cfg(feature = "didwebvh")]
        {
            use crate::identity::didwebvh::FileSystemDidWebVhIdentityStore;
            use crate::storage::{DidLogStorage, FileDidLogStorage};

            // Create DID:webvh identity store
            let didwebvh_identity_path = PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .identities,
            )
            .join("didwebvh");
            match FileSystemDidWebVhIdentityStore::new(&didwebvh_identity_path).await {
                Ok(store) => {
                    info!("✓ DID:webvh identity store initialized");
                    identity_state.didwebvh_identity_store =
                        Some(Arc::new(store) as Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>);
                }
                Err(e) => {
                    error!("Failed to initialize DID:webvh identity store: {}", e);
                }
            }

            // Create DID:webvh log storage
            let didwebvh_log_path = PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .identities,
            )
            .join("didwebvh_logs");
            let storage = Arc::new(FileDidLogStorage::new(&didwebvh_log_path)) as Arc<dyn DidLogStorage>;
            info!("✓ DID:webvh log storage initialized");

            // Register the gateway's own DID in log storage so /v1/resolve can find it.
            // The VCIssuer stores the gateway DID at {vc_keys}/did.jsonl, while the resolver
            // uses FileDidLogStorage keyed by DID. Sync once at startup if not already present.
            if let Some(ref issuer) = vc_issuer {
                let gateway_did = issuer
                    .get_issuer_did()
                    .await
                    .unwrap_or_default();
                if gateway_did.starts_with("did:webvh:") {
                    let log_src = issuer
                        .get_storage_path()
                        .await
                        .join("did.jsonl");
                    sync_gateway_did_log(&storage, &gateway_did, &log_src).await;
                }
            }

            identity_state.didwebvh_log_storage = Some(storage.clone());

            // Startup sync: register existing issuer DIDs so /api/v1/resolve can find them.
            // Mirrors the gateway-DID sync above — reads raw JSONL from disk without re-parsing.
            if let Some(ref log_storage) = identity_state.didwebvh_log_storage {
                let issuer_storage_path = PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .issuers,
                );
                sync_issuer_did_logs(log_storage, &issuer_storage_path).await;
            }

            // Set base URL from did.domain config (used for DID:webvh identifier domain).
            // Note: webauthn.external_origin is for FIDO2 browser origin validation only,
            // not for embedding in DID identifiers.
            let base_url = crate::identity::didwebvh::base_url_for_domain(&network_config.did.domain)
                .trim_end_matches('/')
                .to_string();
            if !network_config
                .did
                .domain
                .contains('.')
            {
                warn!(
                    "did.domain '{}' has no dots — non-compliant with did:webvh v1.0 ABNF (§3.3) \
                     which requires a fully qualified domain name. \
                     Local dev may work, but external DID resolution will fail.",
                    network_config.did.domain
                );
            }
            identity_state.didwebvh_base_url = Some(base_url.clone());
            info!("✓ DID:webvh base URL set to: {}", base_url);

            // Wire up DID:webvh stores to the trust registry listener manager
            if let Some(ref listener_mgr) = trust_registry_listener_manager {
                listener_mgr
                    .set_didwebvh_stores(
                        identity_state
                            .didwebvh_identity_store
                            .clone(),
                        identity_state
                            .didwebvh_log_storage
                            .clone(),
                    )
                    .await;
            }
        }

        // Initialize GW2 notification store if available for integration triggers
        if let Some(ref notif_store) = notification_store {
            crate::gateways::init_notification_store(notif_store.clone()).await;
            info!("✓ GW2 notification store initialized for integration triggers");
        }

        // Initialize integration storage
        let integration_storage: Option<Arc<crate::storage::IntegrationStorage>> = {
            let storage = crate::storage::IntegrationStorage::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .integrations,
            ))
            .await
            .expect("Failed to initialize integration storage");
            info!("Notifier storage initialized");
            let storage_arc = Arc::new(storage);

            // Initialize global integration storage
            crate::storage::init_integration_storage(storage_arc.clone()).await;
            info!("✓ Global integration storage initialized");

            if let Some(txn_store) = crate::gateways::connection_points::message_processor::get_transaction_store() {
                spawn_x402_cleanup_worker(txn_store);
            }

            // Validate all active integrations
            crate::integrations::validation::validate_all_integrations(&storage_arc).await;

            Some(storage_arc)
        };
        identity_state.integration_store = integration_storage.clone();

        // Register appliance resource-limit counters now that every entity store
        // has been constructed. `credentials.jwt`, `secrets.apikeys`, and
        // `secrets.certificates` are registered at their own construction sites.
        register_resource_limit_counters(
            &secrets_store,
            &agent_surface_store,
            &policy_definition_store,
            &gateway_store,
            &mediator_store,
            &connection_point_store,
            &trust_registry_store,
            &credential_provider_store,
            &delegation_vault_store,
            &mcp_proxy_store,
            &a2a_proxy_store,
            &integration_storage,
        );

        // users — resolved from the passkey/SAML auth storage (no dedicated
        // store, so it isn't covered by register_resource_limit_counters).
        if let Some(user_storage) = auth_state
            .as_ref()
            .map(|s| s.storage.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|s| s.storage.clone())
            })
        {
            crate::config::register_counter("users", move || {
                let s = user_storage.clone();
                async move {
                    s.list_users()
                        .await
                        .map(|v| v.len())
                        .unwrap_or(0)
                }
            });
        }

        // Initialize connection point listener manager
        info!("Initializing connection point listener manager");

        // Create message store
        let message_store_path = PathBuf::from(
            &bootstrap_config
                .storage_paths
                .messages,
        );
        let message_store = match crate::gateways::MessageStore::new(message_store_path).await {
            Ok(store) => {
                info!("✓ Message store initialized");
                Some(Arc::new(store))
            }
            Err(e) => {
                error!("Failed to initialize message store: {}", e);
                None
            }
        };

        // Create pending connection store for tracking OOB handshakes
        let pending_conn_storage_path = PathBuf::from(
            &bootstrap_config
                .storage_paths
                .connection_points,
        )
        .join("pending");
        let pending_connection_store =
            match crate::gateways::PendingConnectionStore::new(pending_conn_storage_path).await {
                Ok(store) => {
                    info!("✓ Pending connection store initialized");
                    Arc::new(store)
                }
                Err(e) => {
                    error!("Failed to initialize pending connection store: {}. Using in-memory fallback", e);
                    // Create empty store with temp path as fallback
                    let temp_path = PathBuf::from("_storage/temp/pending");
                    Arc::new(
                        crate::gateways::PendingConnectionStore::new(temp_path)
                            .await
                            .expect("Failed to create fallback pending connection store"),
                    )
                }
            };

        let listener_manager = if let (Some(msg_store), Some(cp_store)) = (&message_store, &connection_point_store) {
            // Configure DID cache from bootstrap config
            let did_cache_config = crate::gateways::did_cache::DIDCacheConfig {
                ttl_seconds: bootstrap_config
                    .did_cache
                    .ttl_seconds,
                max_entries: bootstrap_config
                    .did_cache
                    .max_entries,
                stale_threshold_percent: bootstrap_config
                    .did_cache
                    .stale_threshold_percent,
                storage_path: bootstrap_config
                    .did_cache
                    .storage_path
                    .clone(),
                local_domain: Some(
                    network_config
                        .did
                        .domain
                        .clone(),
                ),
                vc_keys_path: Some(
                    bootstrap_config
                        .storage_paths
                        .vc_keys
                        .clone(),
                ),
                connection_points_storage_path: Some(
                    bootstrap_config
                        .storage_paths
                        .connection_points
                        .clone(),
                ),
            };

            let mut manager = crate::gateways::ConnectionPointListenerManager::new(
                vc_issuer_for_api.clone(),
                msg_store.clone(),
                cp_store.clone(),
                did_cache_config,
            )
            .await?;

            info!(
                "✓ DID cache configured: TTL={}s, max_entries={}, stale_threshold={}%, storage={}, local_domain={}, vc_keys_path={}",
                bootstrap_config
                    .did_cache
                    .ttl_seconds,
                bootstrap_config
                    .did_cache
                    .max_entries,
                bootstrap_config
                    .did_cache
                    .stale_threshold_percent,
                bootstrap_config
                    .did_cache
                    .storage_path,
                network_config.did.domain,
                bootstrap_config
                    .storage_paths
                    .vc_keys
            );

            // Add optional stores for OOB connection handling
            if let Some(ref gw_store) = gateway_store {
                manager = manager.with_gateway_store(gw_store.clone());
            }
            manager = manager.with_pending_connection_store(pending_connection_store.clone());
            if let Some(ref med_store) = mediator_store {
                manager = manager.with_mediator_store(med_store.clone());
            }
            if let Some(ref notif_store) = notification_store {
                manager = manager.with_notification_store(notif_store.clone());
            }
            manager = manager.with_bootstrap_config(bootstrap_config.clone());
            manager = manager.with_network_config(Arc::new(network_config.clone()));

            if crate::server::mode::is_standby() {
                manager.deactivate();
                info!("Standby mode: connection point listeners deactivated until SIGUSR1");
            }

            // Use Arc::new_cyclic to create Arc with weak self-reference in one step
            // This avoids the need for Arc::try_unwrap
            let mut listener_start_rx_opt: Option<
                tokio::sync::mpsc::UnboundedReceiver<
                    crate::gateways::connection_points::ws_listener::ListenerStartCommand,
                >,
            > = None;

            let manager = Arc::new_cyclic(|weak_ref| {
                let (manager_with_channel, rx) = manager.with_self_ref_and_channel(weak_ref.clone());
                listener_start_rx_opt = Some(rx);
                manager_with_channel
            });

            let mut listener_start_rx =
                listener_start_rx_opt.ok_or_else(|| anyhow::anyhow!("Failed to initialize listener start channel"))?;

            // Start DID cache maintenance task
            manager.start_cache_maintenance_task();

            // Load cached DIDs from disk
            let did_cache = manager.get_did_cache();
            match did_cache
                .load_from_disk()
                .await
            {
                Ok(count) if count > 0 => {
                    info!(
                        "✓ Loaded {} cached DID documents from {}",
                        count,
                        bootstrap_config
                            .did_cache
                            .storage_path
                    );
                }
                Ok(_) => {
                    debug!("No cached DID documents found on disk");
                }
                Err(e) => {
                    warn!("Failed to load cached DIDs from disk: {}", e);
                }
            }

            // Pre-warm the cache with active gateway and connection point DIDs
            // This reduces CPU usage by avoiding on-demand DID resolution during message processing
            info!("Pre-warming DID cache with active gateway and connection point DIDs...");
            match did_cache
                .prewarm_cache(&gateway_store, &connection_point_store)
                .await
            {
                Ok(count) if count > 0 => {
                    info!("✓ Pre-warmed DID cache with {} entries - reduced latency for message encryption", count);
                }
                Ok(_) => {
                    debug!("No gateways or connection points to pre-warm");
                }
                Err(e) => {
                    warn!("Failed to pre-warm DID cache: {} (will resolve on-demand)", e);
                }
            }

            // Set DID cache on the VC issuer for VP verification caching
            if let Some(ref issuer) = vc_issuer {
                issuer
                    .set_did_cache(did_cache.clone())
                    .await;
                info!("✓ DID cache set on GW2 VC issuer - agent DIDs will be cached");
            }

            // Spawn background task to process listener start requests
            let manager_for_processor = manager.clone();
            let config_for_processor = bootstrap_config.clone();
            tokio::spawn(async move {
                info!("🎧 Listener start request processor started");
                while let Some(cmd) = listener_start_rx.recv().await {
                    info!("📨 Received listener start request for connection point {}", cmd.connection_point.id);
                    let result = manager_for_processor
                        .start_listener(
                            &cmd.connection_point,
                            cmd.mediator_did,
                            cmd.mediator_url,
                            config_for_processor.clone(),
                        )
                        .await;

                    // Notify the caller of completion (success or failure)
                    if let Some(completion_tx) = cmd.completion_tx {
                        let _ = completion_tx.send(
                            result
                                .clone()
                                .map_err(|e| e.to_string()),
                        );
                    }

                    match result {
                        Ok(_) => {
                            info!("✅ Listener started successfully for connection point {}", cmd.connection_point.id);
                        }
                        Err(e) => {
                            error!(
                                "❌ Failed to start listener for connection point {}: {}",
                                cmd.connection_point.id, e
                            );
                        }
                    }
                }
                warn!("⚠️  Listener start request processor stopped");
            });

            // Auto-start listeners for all existing connection points
            // Spawn this in the background to avoid blocking HTTP server startup
            let cp_store_clone = cp_store.clone();
            let mediator_store_clone = mediator_store.clone();
            let manager_clone = manager.clone();
            let config_clone = bootstrap_config.clone();

            tokio::spawn(async move {
                info!("🚀 Auto-starting WebSocket listeners for existing connection points...");

                if !manager_clone.is_active() {
                    info!("Connection point auto-start skipped: standby mode");
                    return;
                }

                // Small delay to ensure HTTP server is fully started before attempting DID resolution
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                if let Err(e) = cp_store_clone
                    .refresh_from_disk()
                    .await
                {
                    warn!("Connection point store refresh at startup failed: {e} — starting from cached state");
                }
                if !manager_clone.is_active() {
                    info!("Connection point auto-start aborted: no longer active");
                    return;
                }

                match cp_store_clone
                    .list_all()
                    .await
                {
                    Ok(connection_points) => {
                        if connection_points.is_empty() {
                            info!("📭 No existing connection points found - no listeners to start");
                        } else {
                            info!(
                                "📋 Found {} connection points, checking for expired temporary ones...",
                                connection_points.len()
                            );

                            // First pass: clean up expired temporary connection points
                            let now = chrono::Utc::now();
                            let mut expired_count = 0;
                            for cp in &connection_points {
                                // Check if this connection point has expired
                                // Expiry can be in two places:
                                // 1. cp.expires_at field (for inviter-side user-created CPs)
                                // 2. oob_message.expires_at (for acceptor-side temporary CPs)
                                let is_expired = if let Some(struct_expires_at) = cp.expires_at {
                                    struct_expires_at < now
                                } else if let Some(expires_at_value) = cp
                                    .oob_message
                                    .get("expires_at")
                                {
                                    if let Ok(json_expires_at) = serde_json::from_value::<chrono::DateTime<chrono::Utc>>(
                                        expires_at_value.clone(),
                                    ) {
                                        json_expires_at < now
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                if is_expired {
                                    info!(
                                        "🧹 Cleaning up expired connection point: {} (type: {:?}, ID: {})",
                                        cp.name, cp.cp_type, cp.id
                                    );
                                    if let Err(e) = cp_store_clone
                                        .delete(&cp.id)
                                        .await
                                    {
                                        warn!("   Failed to delete expired connection point: {}", e);
                                    } else {
                                        expired_count += 1;
                                    }
                                }
                            }
                            if expired_count > 0 {
                                info!("✓ Cleaned up {} expired connection points", expired_count);
                            }

                            // Re-fetch connection points after cleanup
                            let connection_points = match cp_store_clone
                                .list_all()
                                .await
                            {
                                Ok(cps) => cps,
                                Err(e) => {
                                    error!("Failed to re-fetch connection points after cleanup: {}", e);
                                    return;
                                }
                            };

                            info!("📋 Starting listeners for {} connection points...", connection_points.len());

                            // Get mediator store for retrieving mediator URLs
                            if let Some(ref med_store) = mediator_store_clone {
                                let mut started = 0;
                                let mut failed = 0;

                                for cp in connection_points {
                                    info!(
                                        "🔌 Processing connection point: '{}' (ID: {}, Gateway: {})",
                                        cp.name, cp.id, cp.gateway_id
                                    );

                                    // Check if mediator_id is a DID (starts with "did:") or a UUID
                                    let (mediator_did, mediator_url) = if cp
                                        .mediator_id
                                        .starts_with("did:")
                                    {
                                        // mediator_id is actually a DID - extract URL from it directly
                                        info!("  ├─ Mediator stored as DID: {}", cp.mediator_id);
                                        match crate::gateways::connection_points::extract_mediator_url(&cp.mediator_id)
                                        {
                                            Ok(url) => {
                                                info!("  ├─ Extracted mediator URL: {}", url);
                                                (cp.mediator_id.clone(), url)
                                            }
                                            Err(e) => {
                                                error!(
                                                    "  └─ ❌ Failed to extract mediator URL from DID '{}': {}",
                                                    cp.mediator_id, e
                                                );
                                                failed += 1;
                                                continue;
                                            }
                                        }
                                    } else {
                                        // mediator_id is a UUID - look up in store
                                        match med_store
                                            .get(&cp.mediator_id)
                                            .await
                                        {
                                            Ok(Some(mediator)) => {
                                                info!("  ├─ Found mediator: {} ({})", mediator.name, mediator.did);
                                                match crate::gateways::connection_points::extract_mediator_url(
                                                    &mediator.did,
                                                ) {
                                                    Ok(url) => {
                                                        info!("  ├─ Mediator URL: {}", url);
                                                        (mediator.did.clone(), url)
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "  └─ ❌ Failed to extract mediator URL from DID '{}': {}",
                                                            mediator.did, e
                                                        );
                                                        failed += 1;
                                                        continue;
                                                    }
                                                }
                                            }
                                            Ok(None) => {
                                                warn!("  └─ ⚠️  Mediator {} not found in store", cp.mediator_id);
                                                failed += 1;
                                                continue;
                                            }
                                            Err(e) => {
                                                error!("  └─ ❌ Failed to get mediator: {}", e);
                                                failed += 1;
                                                continue;
                                            }
                                        }
                                    };

                                    // Start the listener
                                    info!("  └─ Starting listener...");
                                    if let Err(e) = manager_clone
                                        .start_listener(&cp, mediator_did, mediator_url, config_clone.clone())
                                        .await
                                    {
                                        error!("     ❌ Failed to start listener for '{}': {}", cp.name, e);
                                        failed += 1;
                                    } else {
                                        info!("     ✅ Listener started successfully for '{}'", cp.name);
                                        started += 1;
                                    }
                                }

                                info!("🏁 Listener startup complete: {} started, {} failed", started, failed);
                            } else {
                                warn!("⚠️  Cannot auto-start listeners: mediator store not available");
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ Failed to list connection points for auto-start: {}", e);
                    }
                }

                // Log final listener count and verify all Active remote gateways have listeners
                let active_listeners = manager_clone
                    .get_active_listeners()
                    .await;
                info!("📊 Total active listeners after startup: {}", active_listeners.len());
                for listener in &active_listeners {
                    info!(
                        "   - {} (Gateway: {}, CP: {})",
                        listener.name, listener.gateway_id, listener.connection_point_id
                    );
                }

                // Verify all Active remote gateways have listeners
                info!("🔍 Verifying all Active remote gateways have listeners...");
                // Get all connection points to find which gateways they belong to
                match cp_store_clone
                    .list_all()
                    .await
                {
                    Ok(all_cps) => {
                        // Group by gateway_id
                        let mut gateway_cps: std::collections::HashMap<String, Vec<_>> =
                            std::collections::HashMap::new();
                        for cp in all_cps {
                            gateway_cps
                                .entry(cp.gateway_id.clone())
                                .or_insert_with(Vec::new)
                                .push(cp);
                        }

                        info!("   Found {} gateways with connection points", gateway_cps.len());

                        for (gateway_id, cps) in gateway_cps {
                            let has_listener = active_listeners
                                .iter()
                                .any(|l| l.gateway_id == gateway_id);

                            if has_listener {
                                info!(
                                    "   ✅ Gateway {} has {} connection point(s) with active listener",
                                    gateway_id,
                                    cps.len()
                                );
                            } else {
                                warn!(
                                    "   ⚠️  Gateway {} has {} connection point(s) but NO active listener!",
                                    gateway_id,
                                    cps.len()
                                );
                                warn!(
                                    "      Connection points: {:?}",
                                    cps.iter()
                                        .map(|cp| &cp.name)
                                        .collect::<Vec<_>>()
                                );
                                warn!("      This gateway will not receive messages!");
                            }
                        }
                    }
                    Err(e) => {
                        error!("   Failed to list connection points for verification: {}", e);
                    }
                }

                // Startup activation pass complete: connection-point listeners are up.
                if !crate::server::mode::is_standby() {
                    info!("Connection-point listeners started; node is ready");
                }
            });

            // Clean up pending OOB gateways from previous sessions
            // Since temporary DID secrets are in-memory only, we cannot restart listeners after server restart
            // These gateways should be cleaned up as they're from incomplete handshakes
            if let Some(ref gw_store) = gateway_store {
                let gw_store_clone = gw_store.clone();
                let pending_store_clone = pending_connection_store.clone();

                tokio::spawn(async move {
                    info!("Checking for pending OOB gateways from previous sessions...");

                    // Small delay after startup
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

                    match gw_store_clone
                        .list_all()
                        .await
                    {
                        Ok(gateways) => {
                            let pending_gateways: Vec<_> = gateways
                                .into_iter()
                                .filter(|gw| gw.status == crate::gateways::types::GatewayStatus::Pending)
                                .collect();

                            if pending_gateways.is_empty() {
                                info!("No pending gateways from previous sessions");
                            } else {
                                warn!("Found {} pending gateway(s) from previous session(s)", pending_gateways.len());
                                warn!("These are from incomplete OOB handshakes that cannot be resumed");

                                for gateway in pending_gateways {
                                    warn!("  - Cleaning up pending gateway: {} (ID: {})", gateway.name, gateway.id);

                                    // Delete the gateway
                                    if let Err(e) = gw_store_clone
                                        .delete(&gateway.id)
                                        .await
                                    {
                                        error!("Failed to delete pending gateway '{}': {}", gateway.name, e);
                                    } else {
                                        info!("  ✓ Deleted pending gateway '{}'", gateway.name);
                                    }

                                    // Also clean up the pending connection if it exists
                                    if let Some(pending_conn) = pending_store_clone
                                        .get_by_temporary_did(&gateway.did)
                                        .await
                                    {
                                        pending_store_clone
                                            .remove(&pending_conn.id)
                                            .await;
                                        info!("  ✓ Cleaned up pending connection state");
                                    }
                                }

                                info!("✓ Pending gateway cleanup complete");
                            }
                        }
                        Err(e) => {
                            error!("Failed to list gateways for pending cleanup: {}", e);
                        }
                    }
                });
            }

            Some(manager)
        } else {
            error!("Cannot initialize listener manager without message store");
            None
        };

        // Update the listener_manager slot so running channels can access it
        if let Some(ref listener_mgr) = listener_manager {
            let mut slot = listener_manager_slot
                .write()
                .await;
            *slot = Some(listener_mgr.clone());
            crate::gateways::init_listener_manager(listener_mgr.clone()).await;
            info!("✓ Listener manager set in shared slot - fabric:// protocol now available for all channels");

            // Start settlement workers now that listener manager and gateway_store are available
            // 1. Settlement worker: Processes pending settlements from transaction store
            // 2. Settlement sync worker: Sends settlement completion notifications via DIDComm
            if let Ok(x402_config) = crate::x402::config_cache::get_or_load_x402_config().await
                && x402_config
                    .settlement_storage
                    .is_some()
                && let Some(txn_store) = crate::gateways::connection_points::message_processor::get_transaction_store()
            {
                // Convert gateway_store to trait object
                let gateway_store_trait: Option<Arc<dyn crate::gateways::filesystem::GatewayStore>> = gateway_store
                    .as_ref()
                    .map(|s| s.clone() as Arc<dyn crate::gateways::filesystem::GatewayStore>);

                // Start settlement worker WITH gateway_store (needed for local_gateway_id)
                if let Some(worker_config) = crate::x402::settlement_worker::get_worker_config_from_x402_config(
                    txn_store.clone(),
                    x402_config.clone(),
                    Arc::clone(&bootstrap_config),
                    gateway_store_trait.clone(),
                )
                .await
                {
                    let _worker_handle = crate::x402::settlement_worker::start_settlement_worker(worker_config);
                    info!(
                        "✓ Settlement worker started (processes local transactions + those where we are the facilitator)"
                    );
                }

                // Start settlement sync worker (sends settlement-complete notifications)
                let _sync_worker_handle = crate::x402::settlement_worker::start_settlement_sync_worker(
                    txn_store,
                    Some(listener_mgr.clone()),
                    gateway_store.clone(), // Use original FileSystemGatewayStore for sync worker
                    60,                    // Poll every 60 seconds
                );
                info!("✓ Settlement sync worker started (sends completion notifications via DIDComm)");
            }
        }

        // Update channel manager with listener_manager (for fabric:// protocol support in new channels)
        if let Some(ref listener_mgr) = listener_manager {
            channel_manager
                .set_listener_manager(listener_mgr.clone())
                .await;
        }

        // Clone trust_registry_listener_manager for dashboard (main reference moves into api_router below)
        let trust_registry_listener_manager_for_dashboard = trust_registry_listener_manager.clone();

        // Create dashboard state (after listener_manager is initialized)
        let dashboard_state = crate::observability::DashboardState {
            config: Arc::clone(&config),
            network_config: Arc::new(network_config.clone()),
            identity_store: vc_issuer_for_api.get_identity_store(),
            metrics_store: identity_metrics_store.clone(),
            vc_issuer: vc_issuer_for_api.clone(),
            ws_state: ws_state.clone(),
            task_monitor: task_monitor.clone(),
            channel_manager: channel_manager.clone(),
            connection_point_listener_manager: listener_manager.clone(),
            mcp_proxy_store: mcp_proxy_store.clone(),
            mcp_server_manager: Some(mcp_server_manager.clone()),
            notification_store: notification_store.clone(),
            auth_state: auth_state.clone(),
            trust_registry_listener_manager: trust_registry_listener_manager_for_dashboard,
            system_metrics_store: system_metrics_store.clone(),
            agent_surface_store: agent_surface_store.clone(),
        };

        // Start periodic delta broadcast: pushes unfiltered dashboard deltas
        // over WebSocket so clients no longer need to HTTP-poll /delta.
        crate::observability::init_dashboard_delta_broadcast(dashboard_state.clone(), 5);

        // Build the unified source authentication middleware
        // First create the api_key_validator since source_auth_middleware depends on it
        let api_keys_storage_path = std::path::PathBuf::from(
            &bootstrap_config
                .storage_paths
                .secrets,
        )
        .parent()
        .map(|p| p.join("api_keys"))
        .unwrap_or_else(|| std::path::PathBuf::from("_storage/api_keys"));
        let api_keys_storage_path_str = api_keys_storage_path
            .to_string_lossy()
            .to_string();
        // Build the RBAC guard threaded through vault sub-routers that require
        // feature-level permissions. Durable audit evidence is not registered
        // when the guard is unavailable.
        let vault_rbac_guard: Option<crate::auth_manager::middleware::RbacGuard> = auth_state_for_notif
            .as_ref()
            .map(|auth| auth.storage.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|saml| saml.storage.clone())
            })
            .map(|storage| crate::auth_manager::middleware::RbacGuard::new(storage, rbac_config.clone()));

        let (api_keys_router, api_key_validator) =
            match crate::api_keys::FileSystemApiKeyStore::new(&api_keys_storage_path_str).await {
                Ok(store) => {
                    info!("API Keys store initialized at {}", api_keys_storage_path_str);
                    let store_arc = std::sync::Arc::new(store);
                    {
                        use crate::api_keys::store::ApiKeyStore as _;
                        let s = store_arc.clone();
                        crate::config::register_counter("secrets.apikeys", move || {
                            let s = s.clone();
                            async move {
                                s.list_all()
                                    .await
                                    .map(|v| v.len())
                                    .unwrap_or(0)
                            }
                        });
                    }
                    let router = agent_surface_store
                        .clone()
                        .map(|surface_store| {
                            let surface_store: Arc<dyn crate::surfaces::AgentSurfaceStore> = surface_store;
                            crate::api_keys::router::create_api_keys_router(
                                store_arc.clone(),
                                surface_store,
                                vault_rbac_guard.clone(),
                            )
                        });
                    let validator: std::sync::Arc<dyn crate::api_keys::ApiKeyValidator> = store_arc;
                    (router, Some(validator))
                }
                Err(e) => {
                    warn!("Failed to initialize API Keys store at {}: {}", api_keys_storage_path_str, e);
                    (None, None)
                }
            };

        let access_tokens_storage_path = std::path::PathBuf::from(
            &bootstrap_config
                .storage_paths
                .secrets,
        )
        .parent()
        .map(|path| path.join("access_tokens"))
        .unwrap_or_else(|| std::path::PathBuf::from("_storage/access_tokens"));
        let (access_tokens_router, pat_authenticator) = match crate::access_tokens::FsAccessTokenStore::new(
            &access_tokens_storage_path,
        )
        .await
        {
            Ok(store) => {
                info!(path = %access_tokens_storage_path.display(), "Access-token store initialized");
                let store = Arc::new(store);
                let router = crate::access_tokens::router::create_access_tokens_router(
                    store.clone(),
                    rbac_config.clone(),
                    tenancy_config.clone(),
                    vault_rbac_guard.clone(),
                );
                let authenticator: Arc<dyn crate::auth_manager::pat::PatAuthenticator> = store;
                (Some(router), Some(authenticator))
            }
            Err(error) => {
                warn!(path = %access_tokens_storage_path.display(), %error, "Failed to initialize access-token store");
                (None, None)
            }
        };

        let secrets_cache_for_auth: crate::a2a::auth::SecretsCache = std::sync::Arc::new(dashmap::DashMap::new());

        // Create certificates store early so source auth middleware can resolve
        // mTLS trust material via certificate IDs.
        let certificates_store: Arc<dyn crate::certificates::CertificateStore> = Arc::new(
            crate::certificates::FilesystemCertificateStore::new(std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .certificates,
            ))
            .await
            .expect("Failed to create certificates store"),
        );
        {
            let s = certificates_store.clone();
            crate::config::register_counter("secrets.certificates", move || {
                let s = s.clone();
                async move {
                    s.list_all()
                        .await
                        .map(|v| v.len())
                        .unwrap_or(0)
                }
            });
        }

        let certificates_router = crate::certificates::router::create_certificates_router(
            certificates_store.clone(),
            vault_rbac_guard.clone(),
        );

        // Make the certificate store available to the proxy pipeline so
        // outbound/inbound handlers can resolve `ManagedIdentityConfig::FromMtls`
        // to a stable did:webvh per stored certificate.
        crate::proxy::server::init_certificates_store(certificates_store.clone());

        let source_auth_middleware = init_source_auth_middleware(
            &bootstrap_config
                .storage_paths
                .secrets,
            Some(secrets_store.clone()),
            secrets_cache_for_auth,
            api_key_validator.clone(),
            didauth_session_store.clone(),
            Some(certificates_store.clone()),
        )
        .await;
        identity_state.certificate_store = Some(certificates_store.clone());
        identity_state.jwt_verification_strategy_store = source_auth_middleware
            .as_ref()
            .map(|middleware| middleware.provider_store());

        // Register with the GW2 message processor (global singleton).
        if let Some(ref sa_mw) = source_auth_middleware {
            crate::gateways::connection_points::message_processor::init_mcp_auth_network(Arc::new(
                network_config.clone(),
            ));
            crate::gateways::connection_points::message_processor::init_source_auth_middleware(sa_mw.clone()).await;
            info!("Source auth middleware registered with GW2 message processor");
        }

        // Resolve inbound client-cert mTLS material once (CA cert DERs) so the
        // listener can build a WebPkiClientVerifier. Shared across inbound
        // and outbound listeners.
        let direct_client_auth: Option<Arc<crate::server::DirectClientAuth>> =
            match crate::source_auth::peer_cert::load_inbound_client_auth(
                Some(&certificates_store),
                &config.tls.client_auth,
            )
            .await
            {
                Ok(Some(da)) => {
                    info!(
                        mode = ?da.mode,
                        ca_count = da.ca_certs.len(),
                        "Inbound mTLS direct client auth enabled"
                    );
                    Some(Arc::new(da))
                }
                Ok(None) => None,
                Err(e) => {
                    if config.tls.client_auth.direct == crate::config::types::DirectClientAuthMode::Required {
                        anyhow::bail!("Inbound mTLS mode is 'required' but client auth failed to initialise: {e}");
                    }
                    error!("Failed to initialise inbound direct client auth: {e}");
                    None
                }
            };

        // Captured for the mode-change task's promotion re-derive (both stores
        // are moved into routers below, so clone the handles the re-derive needs
        // while they are still owned here).
        let identity_state_for_mode = identity_state.clone();
        let gateway_store_for_mode = gateway_store.clone();

        let mcp_replay = if network_config
            .sts
            .mcp_issuer
            .is_some()
        {
            let client = match &network_config.sts.mcp_replay {
                crate::sts::replay::McpReplayConfig::Dynamodb { .. } => Some(
                    crate::storage::dynamodb_generic_repository::build_dynamodb_client(
                        bootstrap_config
                            .aws_region
                            .as_deref(),
                        bootstrap_config
                            .aws_profile
                            .as_deref(),
                    )
                    .await?,
                ),
                crate::sts::replay::McpReplayConfig::Embedded { .. } => None,
            };
            Some(Arc::new(crate::sts::replay::McpReplay::new(&network_config.sts.mcp_replay, client)?))
        } else {
            None
        };

        let api_router = crate::identity::create_identity_api_router(
            identity_state.clone(),
            dashboard_state,
            auth_state,
            saml_state.clone(),
            gateway_store,
            mediator_store,
            trust_registry_store.clone(),
            trust_registry_listener_manager.clone(),
            trust_registry_worker.clone(),
            mcp_proxy_store.clone(),
            a2a_proxy_store.clone(),
            mcp_server_manager.clone(),
            Some(secrets_store.clone()),
            connection_point_store,
            notification_store.clone(),
            listener_manager.clone(),
            message_store.clone(),
            pending_connection_store.clone(),
            integration_storage,
            // Re-use the same store that backs the middleware so hot-reloads are consistent.
            source_auth_middleware
                .as_ref()
                .map(|mw| mw.provider_store()),
            // Pass the JwksClient so the validate-jwks-uri endpoint can probe URIs.
            source_auth_middleware
                .as_ref()
                .map(|mw| mw.jwks_client()),
            issuer_store.clone(),
            authority_store.clone(),
            // Build the x402 admin router here so it sits inside the identity
            // router's global session-auth boundary. All /api/* data calls go
            // through the same protected pipeline — no special cases.
            {
                let txn_store = crate::gateways::connection_points::message_processor::get_transaction_store();
                if txn_store.is_some() {
                    let admin_state = crate::x402::AdminApiState { transaction_store: txn_store };
                    Some(crate::x402::create_admin_router(vault_rbac_guard.clone()).with_state(admin_state))
                } else {
                    None
                }
            },
            // Build the MPP admin API router the same way, so the dashboard's
            // unified Transactions page can read MPP payment records.
            {
                let mpp_txn_store = crate::gateways::connection_points::message_processor::get_mpp_transaction_store();
                if mpp_txn_store.is_some() {
                    let mpp_admin_state = crate::mpp::admin_api::MppAdminApiState {
                        transaction_store: mpp_txn_store,
                    };
                    Some(crate::mpp::admin_api::create_mpp_admin_router().with_state(mpp_admin_state))
                } else {
                    None
                }
            },
            metrics_store.clone(),
            sts_client_store,
            mcp_replay,
            terms_manager.clone(),
            pat_authenticator.clone(),
        );

        // Create secrets API router (secrets_cache is None here since it's created per-proxy instance)
        let secrets_router = crate::secrets::router::create_secrets_router(
            secrets_store.clone(),
            notification_store.clone(),
            None,
            vault_rbac_guard.clone(),
        );

        // certificates_store and certificates_router were created earlier so the
        // source auth middleware could be initialised with access to them.

        // Create vault identity router (for generating DIDs for API keys and certificates)
        let vault_identity_router = if let Some(ref vc_issuer) = vc_issuer {
            crate::vault_identity::create_vault_identity_router(vc_issuer.clone(), vault_rbac_guard.clone())
        } else {
            Router::new() // Empty router if identity API is not enabled
        };

        // Create credential delegation routers (credential providers CRUD + delegation vault).
        // Management routes go inside the session-auth boundary; the OAuth callback
        // (browser redirect target) is the only piece that must remain public.
        let (credential_delegation_mgmt_router, credential_delegation_oauth_router) = if let (
            Some(cp_store),
            Some(dv_store),
        ) =
            (&credential_provider_store, &delegation_vault_store)
        {
            let base_url = format!("https://{}", network_config.did.domain);

            let cp_router = crate::credential_providers::router::create_credential_providers_router(
                cp_store.clone(),
                secrets_store.clone(),
                network_config
                    .oauth_callback_route
                    .clone(),
                vault_rbac_guard.clone(),
                source_auth_middleware
                    .as_ref()
                    .map(|middleware| middleware.provider_store()),
            );

            let dv_state = crate::delegation_vault::handlers::DelegationVaultState {
                vault_store: dv_store.clone(),
                provider_store: cp_store.clone(),
                secrets_store: secrets_store.clone(),
                gateway_base_url: base_url,
                agent_surface_store: identity_state
                    .agent_surface_store
                    .clone()
                    .map(|s| s as Arc<dyn crate::surfaces::AgentSurfaceStore>),
                oauth_callback_route: network_config
                    .oauth_callback_route
                    .clone(),
                vc_signer: vc_issuer
                    .as_ref()
                    .map(|issuer| issuer.get_vc_signer()),
                vc_issuer: vc_issuer.clone(),
                vault_population_notifier: Some(
                    crate::delegation_vault::notifier::global_vault_population_notifier().clone(),
                ),
            };
            if vault_rbac_guard.is_none() {
                warn!(target: "credential_delegation", "Credential delegation audit route not registered because RBAC guard is unavailable");
            }
            let dv_mgmt_router = crate::delegation_vault::router::create_delegation_vault_router(
                dv_state.clone(),
                vault_rbac_guard.clone(),
            );
            let mut dv_oauth_router =
                crate::delegation_vault::router::create_delegation_vault_oauth_router(dv_state.clone());
            if let Some(runtime) = crate::mcp::continuations::config::global()
                && let Some(middleware) = source_auth_middleware.as_ref()
                && network_config
                    .sts
                    .mcp_issuer
                    .is_some()
            {
                dv_oauth_router = dv_oauth_router.merge(crate::delegation_vault::modern_consent::router(
                    crate::delegation_vault::modern_consent::ModernConsentState {
                        vault: dv_state,
                        network: Arc::new(network_config.clone()),
                        identity_strategies: middleware.provider_store(),
                        verifier: Arc::new(crate::jwt_bearer::JwtBearerVerifier::new(middleware.jwks_client())),
                        continuations: runtime.service.clone(),
                        provider_http: crate::http_client::external().map_err(|error| anyhow::anyhow!(error))?,
                    },
                ));
            }

            info!(target: "credential_delegation", "Credential delegation routes registered");
            (
                Router::new()
                    .merge(cp_router)
                    .merge(dv_mgmt_router),
                dv_oauth_router,
            )
        } else {
            warn!(target: "credential_delegation", "Credential delegation disabled — store initialization failed");
            (Router::new(), Router::new())
        };

        // Combine secrets, API keys, certificates, and trust check into vault router
        // Apply session auth middleware to protect vault routes (secrets, apikeys, certificates)
        let session_mgr_for_vault = auth_state_for_notif
            .as_ref()
            .map(|auth| auth.session_manager.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|saml| saml.session_manager.clone())
            });
        let user_storage_for_vault: Option<Arc<crate::auth::storage::PasskeyStorage>> = auth_state_for_notif
            .as_ref()
            .map(|auth| auth.storage.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|saml| saml.storage.clone())
            });

        let vault_router = {
            let mut router = Router::new()
                .merge(secrets_router)
                .merge(certificates_router)
                .merge(vault_identity_router)
                .merge(credential_delegation_mgmt_router);

            if let Some(api_keys_r) = api_keys_router {
                router = router.merge(api_keys_r);
            }

            if let Some(access_tokens_router) = access_tokens_router {
                router = router.merge(access_tokens_router);
            }

            if let Some(sess_mgr) = session_mgr_for_vault {
                info!("Vault API router protected with session auth middleware");
                let guard_state = crate::auth_manager::middleware::AuthGuardState::new(
                    sess_mgr,
                    user_storage_for_vault.clone(),
                    terms_manager.clone(),
                )
                .with_pat_authenticator(pat_authenticator.clone())
                .with_trusted_tenant_header(
                    tenancy_config
                        .trusted_tenant_header
                        .clone()
                        .map(Arc::new),
                );
                router = router.layer(axum::middleware::from_fn_with_state(
                    guard_state,
                    crate::auth_manager::middleware::require_session_auth,
                ));
            }

            // Public routes merged AFTER the auth layer — these must remain unauthenticated.
            // - credential_delegation_oauth_router: OAuth provider redirects the user's
            //   browser here; there is no session at this point.
            router = router.merge(credential_delegation_oauth_router);

            router
        };

        // Create separate onboarding router
        let onboarding_router = crate::identity::create_onboarding_router(identity_state.clone());

        // Extract DID:webvh stores before identity_state is moved
        #[cfg(feature = "didwebvh")]
        let didwebvh_identity_store_shared = identity_state
            .didwebvh_identity_store
            .clone();
        #[cfg(feature = "didwebvh")]
        let didwebvh_log_storage_shared = identity_state
            .didwebvh_log_storage
            .clone();

        // Create separate DID router for did:web resolution at root level
        let did_router = crate::identity::create_did_router(identity_state, issuer_store, trust_registry_store.clone());

        // Store the identity API router to be merged into port listeners instead of starting separate servers
        let mut identity_http_router: Option<axum::Router> = None;
        let mut identity_https_router: Option<axum::Router> = None;
        let mut onboarding_http_router: Option<axum::Router> = None;
        let mut onboarding_https_router: Option<axum::Router> = None;
        let mut did_http_router: Option<axum::Router> = None;
        let mut did_https_router: Option<axum::Router> = None;
        let mut vault_http_router: Option<axum::Router> = None;
        let mut vault_https_router: Option<axum::Router> = None;

        // Determine which ports to merge the Identity API router into based on network_config listeners
        // Use the first inbound HTTP/HTTPS listeners from gateway.json
        let identity_api_http_port = network_config
            .listeners
            .iter()
            .find(|l| l.protocol.to_lowercase() == "http" && l.listener_type == "inbound")
            .map(|l| l.port);

        let identity_api_https_port = network_config
            .listeners
            .iter()
            .find(|l| l.protocol.to_lowercase() == "https" && l.listener_type == "inbound")
            .map(|l| l.port);

        if let Some(http_port) = identity_api_http_port {
            info!("Identity API HTTP router will be merged into port {} listener", http_port);
            identity_http_router = Some(api_router.clone());
            onboarding_http_router = Some(onboarding_router.clone());
            did_http_router = Some(did_router.clone());
            vault_http_router = Some(vault_router.clone());
        }

        if let Some(https_port) = identity_api_https_port {
            info!("Identity API HTTPS router will be merged into port {} listener", https_port);
            identity_https_router = Some(api_router.clone());
            onboarding_https_router = Some(onboarding_router.clone());
            did_https_router = Some(did_router.clone());
            vault_https_router = Some(vault_router.clone());
        }

        // Store routers in channel_manager for use during reload
        channel_manager
            .set_identity_routers(
                identity_http_router.clone(),
                identity_https_router.clone(),
                onboarding_http_router.clone(),
                onboarding_https_router.clone(),
                did_http_router.clone(),
                did_https_router.clone(),
                vault_http_router.clone(),
                vault_https_router.clone(),
            )
            .await;

        // Store services in channel_manager for use during reload
        channel_manager
            .set_services(
                mcp_proxy_store.clone(),
                a2a_proxy_store.clone(),
                Some(mcp_server_manager.clone()),
                Some(secrets_store.clone()),
                Some(policy_manager.clone()),
                Some(gateway_policy_manager.clone()),
            )
            .await;

        // Store notification store in channel_manager
        channel_manager
            .set_notification_store(notification_store.clone())
            .await;

        // Store unified source auth middleware in channel_manager
        channel_manager
            .set_source_auth_middleware(source_auth_middleware.clone())
            .await;

        channel_manager
            .set_direct_client_auth(direct_client_auth.clone())
            .await;

        channel_manager
            .set_resolved_surface_cache(resolved_surface_cache.clone())
            .await;

        // Store DID:webvh stores in channel_manager for use during channel startup
        #[cfg(feature = "didwebvh")]
        channel_manager
            .set_didwebvh_stores(didwebvh_identity_store_shared.clone(), didwebvh_log_storage_shared.clone())
            .await;

        // NOW spawn port listeners with Identity API router
        let mut port_listener_handles = HashMap::new();
        let mut state_receivers = Vec::new();

        // Surfaces are translated to channels lazily inside the inbound
        // per-port loop below, but the *outbound* bucketing was computed
        // early from `config.channels` only — meaning a surface-derived
        // outbound VC never enters `outbound_channels_by_port` and the
        // outbound listener gets the empty-bucket placeholder. Re-bucket
        // here with surfaces folded in so outbound traffic actually
        // routes after a fresh start.
        let outbound_channels_by_port = {
            let outbound_ports = network_config.get_outbound_ports();
            let mut all_surfaces: Vec<crate::config::agent_surface::AgentSurface> = config.surfaces.clone();
            if let Some(ref surface_store) = agent_surface_store
                && let Ok(surfaces) = surface_store.list_all().await
            {
                let existing_surface_ids: std::collections::HashSet<String> = all_surfaces
                    .iter()
                    .map(|s| s.surface_id.clone())
                    .collect();
                for surface in surfaces {
                    if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
                        continue;
                    }
                    if existing_surface_ids.contains(&surface.surface_id) {
                        continue;
                    }
                    all_surfaces.push(surface);
                }
            }

            // Warn loudly about outbound transit points whose listen address
            // does not resolve to an outbound listener. Bucketing silently
            // drops them, leaving their routes unserved — but the gateway must
            // still start so the operator can reach the dashboard/API and fix
            // the misconfiguration. Logging here (not aborting) keeps the fix
            // path open.
            let unresolved = crate::config::find_unresolved_outbound_transit_points(
                &all_surfaces,
                &outbound_ports,
                map_outbound_address_to_port,
            );
            if !unresolved.is_empty() {
                let detail = unresolved
                    .iter()
                    .map(|p| {
                        format!(
                            "    - surface '{}' transit point '{}' (listen_address: {}): {}",
                            p.surface_name,
                            p.alias,
                            p.listen_address
                                .as_deref()
                                .unwrap_or("<none>"),
                            p.reason
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let banner = format!(
                    "\n\
                     ============================================================\n\
                     WARNING: Outbound transit point misconfiguration\n\
                     ============================================================\n\
                     One or more outbound transit points do not resolve to an\n\
                     outbound listener. Their routes will NOT be served until\n\
                     this is fixed. The gateway is continuing to start so the\n\
                     dashboard/API stays reachable for remediation.\n\n\
                     Unresolved transit points:\n{}\n\n\
                     Fix: add the transit point's listen address to the\n\
                     external_urls of an outbound listener (listener_type =\n\
                     \"outbound\") in your gateway.json. The same external URL\n\
                     may be declared on both an inbound and an outbound\n\
                     listener.\n\
                     ============================================================\n",
                    detail
                );
                error!("{}", banner);
                eprintln!("{}", banner);
            }

            crate::config::group_outbound_vcs_by_port(&all_surfaces, &outbound_ports, map_outbound_address_to_port)
        };

        // Fail fast on configuration errors that would shadow dashboard SPA
        // routes — admin must rename the offending prefix and restart.
        // Running with these silently would replace dashboard pages with
        // proxy 404s, which is much worse than refusing to start.
        {
            let mut all_prefixes: Vec<&str> = network_config
                .channels
                .iter()
                .map(|c| c.prefix.as_str())
                .collect();
            for route_cfg in network_config.routes.values() {
                if matches!(route_cfg.route_type, crate::config::RouteType::Proxy) {
                    all_prefixes.push(route_cfg.prefix.as_str());
                }
            }
            let collisions = crate::proxy::paths::check_spa_route_collisions(all_prefixes);
            if !collisions.is_empty() {
                let detail = collisions
                    .iter()
                    .map(|(p, spa)| format!("    - prefix '{}' shadows SPA route '{}'", p, spa))
                    .collect::<Vec<_>>()
                    .join("\n");
                let banner = format!(
                    "\n\
                     ============================================================\n\
                     FATAL: Gateway configuration error\n\
                     ============================================================\n\
                     One or more channel/proxy prefixes collide with reserved\n\
                     dashboard SPA routes. Starting in this state would replace\n\
                     dashboard pages with proxy 404s, so the server is exiting.\n\n\
                     Collisions:\n{}\n\n\
                     Fix: rename each offending prefix (e.g. '/svc/<name>') in\n\
                     your gateway.json and restart.\n\
                     ============================================================\n",
                    detail
                );
                error!("{}", banner);
                eprintln!("{}", banner);
                std::process::exit(2);
            }
        }

        // Iterate over ALL configured ports, not just those with channels
        // This ensures routes from network.json are served even if no channels exist
        for port in configured_ports {
            let listener_info = network_config
                .listeners
                .iter()
                .find(|l| l.port == port);
            let is_outbound = listener_info
                .map(|l| l.listener_type.as_str() == "outbound")
                .unwrap_or(false);

            if is_outbound {
                // Start outbound listener for this port
                let outbound_channels = outbound_channels_by_port
                    .get(&port)
                    .cloned()
                    .unwrap_or_default();

                if outbound_channels.is_empty() {
                    // Bind anyway (no early `continue`): the listener still comes up
                    // and serves the `/alive` liveness route so ECS/ALB target-group
                    // health checks on this port pass even with zero outbound
                    // channels. `run_outbound_port_server` handles an empty channel
                    // list — it simply registers no proxy routes.
                    info!(
                        "Outbound listener on port {} has no enabled outbound channels — binding for /alive health checks only",
                        port
                    );
                }

                let bind_address = listener_info
                    .map(|l| l.bind_address.clone())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let use_tls = listener_info
                    .map(|l| l.protocol.to_lowercase() == "https")
                    .unwrap_or(false);

                let config_clone = Arc::clone(&config);
                let network_config_clone = Arc::new(network_config.clone());
                let metrics_clone = metrics_store.clone();
                let secrets_store_clone = Some(secrets_store.clone());
                let policy_mgr_clone = Some(policy_manager.clone());
                let gateway_policy_mgr_clone = Some(gateway_policy_manager.clone());
                let trust_registry_clone =
                    crate::gateways::connection_points::message_processor::get_trust_registry_listener_manager();
                let vc_issuer_clone = vc_issuer.clone();
                let task_monitor_clone = task_monitor.clone();

                // Share the manager's outbound_channel_states map — do NOT build a fresh
                // one here. reload_single_channel looks up entries by config_id in THIS
                // map; a throwaway map would make every reload miss, so transit-point
                // updates would silently never apply.
                let outbound_states = channel_manager
                    .outbound_channel_states
                    .clone();
                let direct_client_auth_clone = direct_client_auth.clone();
                let listener_mgr_slot_for_outbound = listener_manager_slot.clone();
                let consent_strategies = source_auth_middleware
                    .as_ref()
                    .map(|middleware| middleware.provider_store());

                info!("Starting outbound port listener on port {} for {} channel(s)", port, outbound_channels.len());

                let handle = tokio::spawn(async move {
                    if let Err(e) = crate::proxy::server::run_outbound_port_server(
                        bind_address,
                        port,
                        outbound_channels,
                        config_clone,
                        network_config_clone,
                        metrics_clone,
                        secrets_store_clone,
                        policy_mgr_clone,
                        gateway_policy_mgr_clone,
                        trust_registry_clone,
                        vc_issuer_clone,
                        task_monitor_clone,
                        use_tls,
                        outbound_states,
                        direct_client_auth_clone,
                        listener_mgr_slot_for_outbound,
                        consent_strategies,
                    )
                    .await
                    {
                        error!("Outbound port listener error for port {}: {}", port, e);
                    }
                });

                port_listener_handles.insert(port, handle.abort_handle());
                continue;
            }

            // Clone services for this port
            let settings_store_for_port = settings_store.clone();
            let notification_store_for_port = notification_store.clone();
            let didauth_session_store_clone = didauth_session_store.clone();
            #[cfg(feature = "didwebvh")]
            let didwebvh_identity_store_for_port = didwebvh_identity_store_shared.clone();
            #[cfg(feature = "didwebvh")]
            let didwebvh_log_storage_for_port = didwebvh_log_storage_shared.clone();

            // Get channels for this port (may be empty)
            let mut channels = channels_by_port_deferred
                .get(&port)
                .cloned()
                .unwrap_or_default();

            // Load Agent Surfaces and append any not already covered by
            // `config.channels` for this port. For "local" mode `config.channels`
            // is itself populated from `agent_surface_store.list_all()` (see
            // `main::load_surfaces`), so without dedup every surface would be
            // registered twice and the dashboard would show two AP task rows
            // per surface.
            if let Some(ref surface_store) = agent_surface_store
                && let Ok(surfaces) = surface_store.list_all().await
            {
                let existing_surface_ids: std::collections::HashSet<String> = channels
                    .iter()
                    .map(|s| s.surface_id.clone())
                    .collect();
                for surface in surfaces {
                    if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
                        continue;
                    }
                    if existing_surface_ids.contains(&surface.surface_id) {
                        continue;
                    }
                    if let Some(surface_port) = map_address_to_port(
                        &surface
                            .access_point
                            .listen_address,
                    ) && surface_port == port
                    {
                        info!(
                            "Adding agent surface '{}' (surface_id={}) to port {}",
                            surface.name, surface.surface_id, port
                        );
                        channels.push(surface);
                    }
                }
            }

            let port_task_id = format!("port-{}-{}", port, uuid::Uuid::new_v4());
            let tls_acceptor = tls_acceptor.clone();
            let client = client.clone();
            let config_clone = Arc::clone(&config);
            let bootstrap_config_clone = Arc::clone(&bootstrap_config);
            let metrics = metrics_store.clone();
            let task_mon = task_monitor.clone();
            let task_id_clone = port_task_id.clone();
            let ws_state_clone = ws_state.clone();
            let vc_issuer_clone = vc_issuer.clone();
            let channels_clone = channels.clone();
            let listener_mgr_slot = listener_manager_slot.clone();
            let network_config_clone = Arc::new(network_config.clone());
            let mcp_proxy_store_clone = mcp_proxy_store.clone();
            let a2a_proxy_store_clone = a2a_proxy_store.clone();
            let mcp_server_manager_clone = Some(mcp_server_manager.clone());

            // Create a oneshot channel to receive the state from the spawned task
            let (state_sender, state_receiver) = tokio::sync::oneshot::channel();

            // Determine if this port should get the Identity API router
            let identity_router_for_port = if Some(port) == identity_api_http_port {
                identity_http_router.clone()
            } else if Some(port) == identity_api_https_port {
                identity_https_router.clone()
            } else {
                None
            };

            // Determine if this port should get the Onboarding router
            let onboarding_router_for_port = if Some(port) == identity_api_http_port {
                onboarding_http_router.clone()
            } else if Some(port) == identity_api_https_port {
                onboarding_https_router.clone()
            } else {
                None
            };

            // Determine if this port should get the DID router
            let did_router_for_port = if Some(port) == identity_api_http_port {
                did_http_router.clone()
            } else if Some(port) == identity_api_https_port {
                did_https_router.clone()
            } else {
                None
            };

            // Determine if this port should get the Secrets router
            let secrets_router_for_port = if Some(port) == identity_api_http_port {
                vault_http_router.clone()
            } else if Some(port) == identity_api_https_port {
                vault_https_router.clone()
            } else {
                None
            };

            // Clone secrets_store for this port
            let secrets_store_for_port = Some(secrets_store.clone());

            // Clone policy_manager for this port
            let policy_mgr_clone = Some(policy_manager.clone());

            // Clone gateway_policy_manager for this port
            let gateway_policy_mgr_clone = Some(gateway_policy_manager.clone());

            // Clone source_auth_middleware for this port
            let source_auth_middleware_for_port = source_auth_middleware.clone();
            let direct_client_auth_for_port = direct_client_auth.clone();
            let resolved_surface_cache_for_port = resolved_surface_cache.clone();

            // Determine if this port should use TLS based on network config
            let use_tls = network_config
                .listeners
                .iter()
                .find(|l| l.port == port)
                .map(|l| l.protocol.to_lowercase() == "https")
                .unwrap_or(false);

            info!(
                "Port {} protocol: {}",
                port,
                if use_tls {
                    "HTTPS (TLS)"
                } else {
                    "HTTP (plain)"
                }
            );
            info!("Starting port listener on 0.0.0.0:{} for {} channel(s)", port, channels.len());
            for surface in &channels {
                info!(
                    "  -> Channel '{}' route: {} -> {}",
                    surface.name, surface.access_point.route, surface.target.endpoint
                );
            }

            let handle = tokio::spawn(async move {
                if let Err(e) = crate::proxy::server::run_port_server(
                    port,
                    channels_clone,
                    tls_acceptor,
                    client,
                    config_clone,
                    bootstrap_config_clone,
                    metrics,
                    task_mon.clone(),
                    Some(task_id_clone.clone()),
                    Some(ws_state_clone),
                    vc_issuer_clone,
                    listener_mgr_slot,
                    Some(state_sender),
                    identity_router_for_port,
                    onboarding_router_for_port,
                    did_router_for_port,
                    secrets_router_for_port,
                    secrets_store_for_port,
                    network_config_clone,
                    use_tls,
                    policy_mgr_clone,
                    gateway_policy_mgr_clone,
                    mcp_proxy_store_clone,
                    a2a_proxy_store_clone,
                    mcp_server_manager_clone,
                    settings_store_for_port,
                    notification_store_for_port,
                    didauth_session_store_clone,
                    source_auth_middleware_for_port,
                    direct_client_auth_for_port,
                    resolved_surface_cache_for_port,
                    #[cfg(feature = "didwebvh")]
                    didwebvh_identity_store_for_port,
                    #[cfg(feature = "didwebvh")]
                    didwebvh_log_storage_for_port,
                )
                .await
                {
                    error!("Port listener error for port {}: {}", port, e);
                }
            });

            // Store the abort handle for this port listener
            port_listener_handles.insert(port, handle.abort_handle());

            // Store the receiver to wait for states later
            state_receivers.push((port, state_receiver));

            // Store the handle for each channel in this port listener
            for surface in &channels {
                let config_id = surface
                    .config_id()
                    .unwrap_or(surface.name.as_str())
                    .to_string();
                let channel_task_id = format!("task-{}-{}", config_id, uuid::Uuid::new_v4());
                channel_handles.insert(config_id.clone(), handle.abort_handle());
                task_ids_map.insert(config_id, channel_task_id);
            }
        }

        // Wait for all states to be sent back (with a timeout per state)
        let mut port_listener_states = HashMap::new();
        for (port, state_receiver) in state_receivers {
            if let Ok(state) = tokio::time::timeout(tokio::time::Duration::from_secs(5), state_receiver).await {
                if let Ok(state) = state {
                    port_listener_states.insert(port, state);
                    info!("Captured state for port {} listener", port);
                } else {
                    warn!("Port listener {} failed to send state", port);
                }
            } else {
                warn!("Timeout waiting for port listener {} state", port);
            }
        }

        // Store port listener handles and states in the manager
        {
            let mut handles = channel_manager
                .port_listener_handles
                .write()
                .await;
            *handles = port_listener_handles;
        }
        {
            let mut states = channel_manager
                .port_listener_states
                .write()
                .await;
            *states = port_listener_states;
        }
        {
            let mut handles = channel_manager
                .channel_handles
                .write()
                .await;
            *handles = channel_handles;
        }
        {
            let mut task_ids = channel_manager
                .task_ids
                .write()
                .await;
            *task_ids = task_ids_map;
        }

        // Log file watcher is no longer needed - logs are broadcast directly via WebSocketLogLayer
        // when they're written by the tracing system

        {
            let mut mode_rx = mode_rx_for_task;
            let listener_manager_for_mode = listener_manager.clone();
            let tr_listener_for_mode = trust_registry_listener_manager.clone();
            let tr_worker_for_mode = trust_registry_worker.clone();
            let tr_store_for_mode = trust_registry_store.clone();
            let ws_state_for_mode = ws_state.clone();
            let pending_for_mode = pending_surface_events.clone();

            let mode_task = tokio::spawn(async move {
                loop {
                    match mode_rx.recv().await {
                        Ok(crate::server::mode::ModeChange {
                            mode: crate::server::mode::ServerMode::Active,
                            generation: activation_generation,
                        }) => {
                            // The readiness mark below is tied to this transition's
                            // generation, so it is ignored if a step-down + re-promote
                            // supersedes this window mid-flight.
                            // Re-derive config + policy planes from shared storage
                            // before reactivating listeners, so a promoted standby
                            // never accepts fabric traffic against stale surfaces,
                            // gateway/surface OPA, MCP gating, or global policy.
                            rederive_planes_on_activation(&identity_state_for_mode, &gateway_store_for_mode).await;

                            // Config + policy planes are now fresh: admit direct
                            // traffic (health → 200) without waiting on fabric
                            // listener reconnection below, and replay any surface
                            // events that were deferred during this window.
                            mark_ready_and_drain_surface_events(
                                activation_generation,
                                &pending_for_mode,
                                &identity_state_for_mode,
                            )
                            .await;

                            let g2g_fut = async {
                                if let Some(manager) = &listener_manager_for_mode {
                                    manager
                                        .activate_and_start_all_listeners()
                                        .await;
                                }
                            };
                            let tr_fut = async {
                                if let Some(tr) = &tr_listener_for_mode {
                                    tr.activate();
                                    if let Some(store) = &tr_store_for_mode
                                        && let Err(e) = store
                                            .refresh_from_disk()
                                            .await
                                    {
                                        warn!(
                                            "Trust registry store refresh on activation failed: {e} — reconnecting from cached state"
                                        );
                                    }
                                    if !tr.is_active() {
                                        info!("Trust registry activation aborted after refresh: no longer active");
                                        return;
                                    }
                                    let reconnected = tr
                                        .reconnect_all_from_store()
                                        .await;
                                    if reconnected > 0 {
                                        info!(
                                            "→ Active: reconnected {} trust registr{} after becoming active",
                                            reconnected,
                                            if reconnected == 1 {
                                                "y"
                                            } else {
                                                "ies"
                                            }
                                        );
                                    }
                                    if let (Some(worker), Some(store)) = (&tr_worker_for_mode, &tr_store_for_mode) {
                                        worker
                                            .start_all(store.clone(), (*ws_state_for_mode).clone())
                                            .await;
                                    }
                                }
                            };
                            tokio::join!(g2g_fut, tr_fut);
                        }
                        Ok(crate::server::mode::ModeChange {
                            mode: crate::server::mode::ServerMode::Standby,
                            ..
                        }) => {
                            let g2g_fut = async {
                                if let Some(manager) = &listener_manager_for_mode {
                                    manager
                                        .deactivate_and_stop_all_listeners()
                                        .await;
                                }
                            };
                            let tr_fut = async {
                                if let Some(tr) = &tr_listener_for_mode {
                                    tr.deactivate();
                                    let disconnected = tr.disconnect_all().await;
                                    if disconnected > 0 {
                                        info!(
                                            "→ Standby: disconnected {} trust registr{} after stepping down",
                                            disconnected,
                                            if disconnected == 1 {
                                                "y"
                                            } else {
                                                "ies"
                                            }
                                        );
                                    }
                                }
                            };
                            tokio::join!(g2g_fut, tr_fut);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("mode change receiver lagged; skipped {} event(s)", n);
                        }
                    }
                }
            });
            tasks.push(mode_task);
        }

        // Startup initialization (including inline policy compilation) is complete: a
        // node that booted active is now ready to serve (health → 200). A node that
        // booted standby stays 503 — the compare-exchange only promotes an active node.
        // The mark is tied to the generation captured at startup entry, so a mode
        // signal that arrived mid-startup (bumping the generation) leaves this a no-op
        // and the signal-driven activation owns readiness instead. Any surface events
        // deferred during startup are replayed here.
        mark_ready_and_drain_surface_events(
            boot_activation_generation,
            &pending_surface_events,
            &identity_state_for_boot_drain,
        )
        .await;

        // Start periodic metrics update task to ensure UI refreshes even with no traffic
        let ws_state_for_metrics = ws_state.clone();
        let metrics_store_for_periodic = identity_metrics_store.clone();

        let periodic_metrics_task = tokio::spawn(async move {
            periodic_metrics_update(ws_state_for_metrics, metrics_store_for_periodic).await;
        });

        tasks.push(periodic_metrics_task);

        // Start system metrics (CPU/memory) collection task
        if let Some(ref store) = system_metrics_store {
            let store_for_system = store.clone();
            let system_metrics_task = tokio::spawn(async move {
                crate::observability::periodic_system_metrics_collection(
                    store_for_system,
                    crate::observability::SYSTEM_METRICS_INTERVAL_SECS,
                )
                .await;
            });
            tasks.push(system_metrics_task);
        }

        // Start periodic session cleanup task to remove expired sessions
        // This ensures sessions don't accumulate on disk even if the server runs for extended periods
        let didauth_sessions_for_cleanup = didauth_session_store.clone();
        let saml_sessions_for_cleanup = saml_state
            .as_ref()
            .map(|s| s.session_manager.clone());
        let session_cleanup_task = tokio::spawn(async move {
            periodic_session_cleanup(didauth_sessions_for_cleanup, saml_sessions_for_cleanup).await;
        });

        tasks.push(session_cleanup_task);
    }

    // Wait for all tasks
    for task in tasks {
        task.await?;
    }

    Ok(())
}

/// Re-derive the config + policy planes from shared storage when this node is
/// promoted to Active.
///
/// A standby shares one storage directory with the active writer but keeps its
/// own in-memory caches and pre-compiled managers. Reconnecting fabric/trust
/// listeners is not enough: request-time PEPs read from derived state (channel
/// runtime, surface + gateway OPA engines, MCP gating, appliance-wide policy)
/// that a periodic cache refresh never rebuilds. This reconciles each cached
/// store with disk and then rebuilds every derived plane, so a promoted node
/// serves the active writer's latest state on its first request — even when the
/// periodic `cache_refresh_interval_secs` loop is disabled. Best-effort: a
/// failure in one plane is logged and does not abort the others.
async fn rederive_planes_on_activation(
    identity_state: &crate::identity::IdentityApiState,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
) {
    // 1. Reconcile every cached store this promotion reads from with disk.
    if let Some(store) = identity_state
        .policy_definition_store
        .as_ref()
        && let Err(e) = store
            .refresh_from_disk()
            .await
    {
        warn!("Policy definition store refresh on activation failed: {e}");
    }
    if let Some(store) = identity_state
        .global_policy_store
        .as_ref()
        && let Err(e) = store
            .refresh_from_disk()
            .await
    {
        warn!("Global policy store refresh on activation failed: {e}");
    }
    if let Some(store) = identity_state
        .agent_surface_store
        .as_ref()
        && let Err(e) = store
            .refresh_from_disk()
            .await
    {
        warn!("Agent surface store refresh on activation failed: {e}");
    }
    if let Some(store) = gateway_store.as_ref()
        && let Err(e) = store
            .refresh_from_disk()
            .await
    {
        warn!("Gateway store refresh on activation failed: {e}");
    }

    // 2. Rebuild channels + surfaces from the refreshed surfaces on disk.
    match crate::identity::handlers::config::perform_config_reload(identity_state).await {
        Ok((channels, surfaces, _, _)) => {
            info!("→ Active: reloaded {channels} channel(s) + {surfaces} surface(s) on activation");
        }
        Err(e) => warn!("Configuration reload on activation failed: {e}"),
    }

    // 3. Recompile surface-level policy state (OPA, MCP gating, rate limits,
    //    circuit breakers) + refresh the resolved-surface cache for every
    //    active surface.
    if let Some(store) = identity_state
        .agent_surface_store
        .as_ref()
    {
        match store.list_all().await {
            Ok(surfaces) => {
                for surface in &surfaces {
                    if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
                        continue;
                    }
                    if let Err(e) = identity_state
                        .policy_manager
                        .update_channel_policy(surface)
                        .await
                    {
                        warn!(surface = %surface.name, "Failed to recompile surface policy on activation: {e}");
                    }
                    if let Err(e) = identity_state
                        .resolved_surface_cache
                        .upsert(surface)
                    {
                        warn!(surface = %surface.surface_id, "Failed to refresh resolved-surface cache on activation: {e}");
                    }
                }
            }
            Err(e) => warn!("Failed to list surfaces for policy recompile on activation: {e}"),
        }
    }

    // 4. Recompile gateway-level OPA from the refreshed gateway records.
    if let (Some(manager), Some(store)) = (
        identity_state
            .gateway_policy_manager
            .as_ref(),
        gateway_store.as_ref(),
    ) {
        match store.list_all().await {
            Ok(gateways) => {
                for gateway in &gateways {
                    if gateway.gateway_type == crate::gateways::types::GatewayType::SelfGateway {
                        manager.set_self_gateway_id(gateway.id.clone());
                    }
                    // Call unconditionally: a gateway whose OPA config was removed
                    // on disk (now `None`) must drop its stale engine + enforced
                    // membership, which `update_gateway_policy` self-handles. The
                    // previous `is_some()` guard skipped that cleanup, leaving a
                    // promoted node enforcing an obsolete engine.
                    if let Err(e) = manager
                        .update_gateway_policy(gateway)
                        .await
                    {
                        warn!("Failed to recompile OPA policy for gateway {} on activation: {e}", gateway.id);
                    }
                }
            }
            Err(e) => warn!("Failed to list gateways for OPA recompile on activation: {e}"),
        }
    }

    // 5. Recompile the appliance-wide (global) policy set from the refreshed store.
    if let (Some(manager), Some(store)) = (
        identity_state
            .global_policy_manager
            .as_ref(),
        identity_state
            .global_policy_store
            .as_ref(),
    ) {
        manager
            .refresh(&store.get().await)
            .await;
    }
}

/// Initialize passkey authentication state
async fn initialize_auth_state(
    bootstrap_config: &crate::config::BootstrapConfig,
    network_config: &crate::config::NetworkConfig,
    terms_manager: Arc<crate::terms::TermsManager>,
) -> anyhow::Result<crate::auth::AuthState> {
    // Determine RP ID and origin from config
    // rp_id must be just the hostname (no port) to satisfy WebAuthn spec
    let rp_id = network_config
        .webauthn
        .rp_id
        .clone();

    // Use external_origin from config (required for WebAuthn)
    let rp_origin_str = network_config
        .webauthn
        .external_origin
        .clone();

    let rp_origin =
        url::Url::parse(&rp_origin_str).with_context(|| format!("Failed to parse RP origin URL: {}", rp_origin_str))?;

    // Create auth state
    let storage_path = bootstrap_config
        .storage_paths
        .passkeys
        .clone();
    let avatars_path = bootstrap_config
        .storage_paths
        .avatars
        .clone();
    let session_timeout_minutes = bootstrap_config.session_timeout_minutes;
    let sessions_path = bootstrap_config
        .storage_paths
        .sessions
        .clone();
    let auth_state = crate::auth::AuthState::new(
        rp_id,
        rp_origin,
        storage_path,
        avatars_path,
        session_timeout_minutes,
        sessions_path,
        terms_manager,
    )
    .await?;

    info!(
        "Initialized passkey authentication for origin: {} with rp_id: {}",
        rp_origin_str, network_config.webauthn.rp_id
    );

    Ok(auth_state)
}

/// Initialize SAML authentication state
async fn initialize_saml_state(
    bootstrap_config: &crate::config::BootstrapConfig,
    saml_config: &crate::auth::SamlConfig,
    terms_manager: Arc<crate::terms::TermsManager>,
) -> anyhow::Result<crate::auth::saml::SamlState> {
    use std::sync::Arc;

    // Create SAML service
    let saml_service = Arc::new(crate::auth::saml::SamlService::new(saml_config.clone())?);

    // Create user storage (use same storage as passkeys for unified user management)
    let storage_path = bootstrap_config
        .storage_paths
        .passkeys
        .clone();
    let avatars_path = bootstrap_config
        .storage_paths
        .avatars
        .clone();
    let storage = Arc::new(crate::auth::storage::PasskeyStorage::new(storage_path, avatars_path.clone()).await?);

    // Create session manager with filesystem persistence
    let session_timeout_minutes = bootstrap_config.session_timeout_minutes;
    let sessions_path = bootstrap_config
        .storage_paths
        .sessions
        .clone();
    let session_manager = Arc::new(
        crate::auth::SessionManager::with_storage(session_timeout_minutes, std::path::PathBuf::from(sessions_path))
            .await
            .context("Failed to create SAML session manager")?,
    );

    // Notification store will be set later (similar to passkey auth)
    let notification_store = Arc::new(tokio::sync::RwLock::new(None));

    info!("Initialized SAML authentication with entity ID: {}", saml_config.sp_entity_id);

    Ok(crate::auth::saml::SamlState {
        saml_service,
        storage,
        session_manager,
        avatars_storage_path: avatars_path,
        notification_store,
        terms_manager,
        login_throttle: Arc::new(crate::sts::throttle::TokenEndpointThrottle::per_client_ip(
            &saml_config.login_throttle,
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::{count_remote_gateways, count_user_connection_points};
    use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
    use crate::gateways::types::{Gateway, GatewayType};

    fn cp(cp_type: ConnectionPointType) -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gw-1".to_string(),
            "med-1".to_string(),
            "did:example:cp".to_string(),
            "cp".to_string(),
            "desc".to_string(),
            String::new(),
            String::new(),
            serde_json::json!({}),
            None,
            cp_type,
            String::new(),
        )
    }

    #[test]
    fn remote_gateway_count_excludes_local_gateway() {
        let gateways = vec![
            Gateway::new(
                "This Gateway (Local)".to_string(),
                "Local gateway".to_string(),
                "did:web:local.example".to_string(),
                GatewayType::SelfGateway,
            ),
            Gateway::new(
                "Remote Gateway A".to_string(),
                "Remote gateway".to_string(),
                "did:web:remote-a.example".to_string(),
                GatewayType::Remote,
            ),
            Gateway::new(
                "Remote Gateway B".to_string(),
                "Remote gateway".to_string(),
                "did:web:remote-b.example".to_string(),
                GatewayType::Remote,
            ),
        ];

        assert_eq!(count_remote_gateways(gateways), 2);
    }

    #[test]
    fn connection_point_count_only_includes_user_records() {
        let connection_points = vec![
            cp(ConnectionPointType::User),
            cp(ConnectionPointType::User),
            cp(ConnectionPointType::OobInviter),
            cp(ConnectionPointType::OobResponder),
            cp(ConnectionPointType::OobAcceptor),
            cp(ConnectionPointType::System),
        ];

        assert_eq!(count_user_connection_points(connection_points), 2);
    }

    #[test]
    fn connection_point_count_ignores_system_only_store() {
        let connection_points = vec![cp(ConnectionPointType::OobAcceptor), cp(ConnectionPointType::System)];

        assert_eq!(count_user_connection_points(connection_points), 0);
    }
}
