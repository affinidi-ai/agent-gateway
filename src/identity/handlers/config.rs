use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::config::GatewayConfig;
use crate::identity::state::IdentityApiState;
use crate::storage::ConfigurationStore;
use crate::surfaces::AgentSurfaceStore;

/// Application error type for config handlers
#[derive(Debug)]
#[allow(dead_code)]
pub enum AppError {
    BadRequest(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
        };

        let body = Json(ErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Response for configuration reload
#[derive(Debug, Serialize)]
pub struct ReloadConfigResponse {
    pub channels_count: usize,
    pub surfaces_count: usize,
    pub is_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Reload configuration from DynamoDB
pub async fn reload_configuration(
    State(state): State<IdentityApiState>
) -> Result<Json<ReloadConfigResponse>, AppError> {
    let (channels_count, surfaces_count, is_fallback, warning) = perform_config_reload(&state)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to reload channels: {}", e)))?;

    Ok(Json(ReloadConfigResponse {
        channels_count,
        surfaces_count,
        is_fallback,
        warning,
    }))
}

/// Reusable reload routine: rebuilds the gateway config from the configured
/// source (DynamoDB or local channel store), injects every active
/// `AgentSurface` as a runtime `ChannelMapping`, and tells the channel
/// manager to swap channels in-place.
///
/// Used by the explicit `POST /v1/config/reload` endpoint and by the
/// `/v1/surfaces` mutation handlers to make surface changes visible to the
/// running proxy without a manual reload.
///
/// Returns `(channels_count, surfaces_count, is_fallback, warning)`.
pub(crate) async fn perform_config_reload(
    state: &IdentityApiState
) -> anyhow::Result<(usize, usize, bool, Option<String>)> {
    info!("Configuration reload requested");

    // Drop cached outbound target agent cards so a redeployed surface
    // (new endpoint, new agent_card_path) never serves stale metadata
    // to `step_collect_trust_context`.
    crate::proxy::agent_card_cache::invalidate_all();

    // Rewrite any legacy `channel.policy` definition to `surface.policy` before
    // the surfaces recompile below, so a definition added since startup (or one
    // missed by a partial startup migration) is upgraded through the store's save
    // path instead of failing closed at evaluation time.
    if let Some(store) = state
        .policy_definition_store
        .as_ref()
    {
        match store
            .migrate_legacy_packages()
            .await
        {
            Ok(0) => {}
            Ok(n) => info!("Migrated {n} legacy channel.policy definition(s) to surface.policy on reload"),
            Err(e) => warn!("Failed to migrate legacy policy definitions on reload: {}", e),
        }
    }

    let new_config_result = load_base_gateway_config(state).await;
    let (new_config_result, surfaces_count) = inject_surfaces_into_config(state, new_config_result).await;

    let (channels_count, is_fallback, warning) = state
        .channel_manager
        .reload_channels_with_fallback(
            new_config_result,
            state.tls_acceptor.clone(),
            state.client.clone(),
            Some(state.metrics_store.clone()),
            state.task_monitor.clone(),
        )
        .await?;

    if is_fallback {
        warn!("Using cached configuration as fallback after DynamoDB load failure");
    } else {
        info!("Successfully reloaded {} channels + {} surfaces", channels_count, surfaces_count);
    }

    Ok((channels_count, surfaces_count, is_fallback, warning))
}

/// Build the base `GatewayConfig` from the configured channel source
/// (DynamoDB or the local filesystem channel store).
async fn load_base_gateway_config(state: &IdentityApiState) -> anyhow::Result<Arc<GatewayConfig>> {
    match state
        .bootstrap_config
        .channel_config_source
        .as_str()
    {
        "dynamodb" => {
            let table_name = match state
                .bootstrap_config
                .dynamodb_table
                .as_ref()
            {
                Some(name) => name,
                None => {
                    return Err(anyhow::anyhow!("DynamoDB table name not specified"));
                }
            };

            info!("Reloading channels from DynamoDB table: {}", table_name);

            async {
                let store = crate::storage::DynamoDbConfigStore::new(
                    table_name.clone(),
                    state
                        .bootstrap_config
                        .aws_region
                        .clone(),
                    state
                        .bootstrap_config
                        .aws_profile
                        .clone(),
                )
                .await?;

                let mut config = store.load_config().await?;

                info!("Using TLS, A2A, logging, and extension inspection configurations from bootstrap config");
                config.tls = state
                    .bootstrap_config
                    .tls
                    .clone();
                config.a2a = state
                    .bootstrap_config
                    .a2a
                    .clone();
                config.logging = state
                    .bootstrap_config
                    .logging
                    .clone();
                config.extension_inspection = state
                    .bootstrap_config
                    .extension_inspection
                    .clone();
                Ok(Arc::new(config))
            }
            .await
        }
        "file" => {
            Err(anyhow::anyhow!("File-based configuration loading is deprecated. Use DynamoDB configuration source."))
        }
        "local" => {
            info!(
                "Reloading local configuration from agent-surface storage: {}",
                state
                    .bootstrap_config
                    .storage_paths
                    .agent_surfaces
            );

            async {
                let agent_surface_store = crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(
                    &state
                        .bootstrap_config
                        .storage_paths
                        .agent_surfaces,
                ))
                .await?;

                let mut channels: Vec<crate::config::agent_surface::AgentSurface> = agent_surface_store
                    .list_all()
                    .await?;
                crate::surfaces::strip_unsupported_header_metadata_mappings(&agent_surface_store, &mut channels)
                    .await?;
                info!("Reloaded {} surface(s) from local storage", channels.len());

                let config = GatewayConfig {
                    surfaces: channels,
                    tls: state
                        .bootstrap_config
                        .tls
                        .clone(),
                    a2a: state
                        .bootstrap_config
                        .a2a
                        .clone(),
                    mcp: state
                        .bootstrap_config
                        .mcp
                        .clone(),
                    logging: state
                        .bootstrap_config
                        .logging
                        .clone(),
                    extension_inspection: state
                        .bootstrap_config
                        .extension_inspection
                        .clone(),
                    integration: state
                        .config
                        .integration
                        .clone(),
                    facilitator_mode: state
                        .config
                        .facilitator_mode
                        .clone(),
                    x402_headers: state
                        .config
                        .x402_headers
                        .clone(),
                };

                Ok(Arc::new(config))
            }
            .await
        }
        other => Err(anyhow::anyhow!("Unsupported configuration source: {}", other)),
    }
}

/// Append every active `AgentSurface` to the config as a runtime
/// `ChannelMapping`. Returns the (possibly enriched) config result and the
/// number of surfaces that were injected.
async fn inject_surfaces_into_config(
    state: &IdentityApiState,
    config_result: anyhow::Result<Arc<GatewayConfig>>,
) -> (anyhow::Result<Arc<GatewayConfig>>, usize) {
    let mut surfaces_count = 0;
    let result = match config_result {
        Ok(config) => {
            if let Some(ref surface_store) = state.agent_surface_store {
                match surface_store.list_all().await {
                    Ok(surfaces) => {
                        let mut channels = config.surfaces.clone();
                        let existing_surface_ids: std::collections::HashSet<String> = channels
                            .iter()
                            .map(|s| s.surface_id.clone())
                            .collect();
                        for surface in &surfaces {
                            if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
                                continue;
                            }
                            if existing_surface_ids.contains(&surface.surface_id) {
                                continue;
                            }
                            channels.push(surface.clone());
                            surfaces_count += 1;
                        }
                        info!("Injected {} active surface(s) into reload config", surfaces_count);
                        let mut updated_config = (*config).clone();
                        updated_config.surfaces = channels;
                        Ok(Arc::new(updated_config))
                    }
                    Err(e) => {
                        warn!("Failed to load surfaces during reload: {}", e);
                        Ok(config)
                    }
                }
            } else {
                Ok(config)
            }
        }
        Err(e) => Err(e),
    };
    (result, surfaces_count)
}

/// Response for single channel reload
#[derive(Debug, Serialize)]
pub struct ReloadSingleChannelResponse {
    pub channel_name: String,
    pub is_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Reload a single channel configuration from DynamoDB
pub async fn reload_single_channel(
    Path(config_id): Path<String>,
    State(state): State<IdentityApiState>,
) -> Result<Json<ReloadSingleChannelResponse>, AppError> {
    info!("Single channel reload requested for config_id: {}", config_id);

    let new_channel_result = match state
        .bootstrap_config
        .channel_config_source
        .as_str()
    {
        "dynamodb" => {
            let table_name = match state
                .bootstrap_config
                .dynamodb_table
                .as_ref()
            {
                Some(name) => name,
                None => {
                    return Err(AppError::InternalError("DynamoDB table name not specified".to_string()));
                }
            };

            info!("Reloading channel with config_id '{}' from DynamoDB table: {}", config_id, table_name);

            async {
                let store = crate::storage::DynamoDbConfigStore::new(
                    table_name.clone(),
                    state
                        .bootstrap_config
                        .aws_region
                        .clone(),
                    state
                        .bootstrap_config
                        .aws_profile
                        .clone(),
                )
                .await?;

                store
                    .load_single_channel_by_config_id(&config_id)
                    .await
            }
            .await
        }
        "file" => {
            Err(anyhow::anyhow!("File-based configuration loading is deprecated. Use DynamoDB configuration source."))
        }
        "local" => {
            async {
                let agent_surface_store = crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(
                    &state
                        .bootstrap_config
                        .storage_paths
                        .agent_surfaces,
                ))
                .await?;

                agent_surface_store
                    .get(&config_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Surface with config_id '{}' not found in local storage", config_id))
            }
            .await
        }
        other => Err(anyhow::anyhow!("Unsupported configuration source: {}", other)),
    };

    // Extract channel name for logging (if available)
    let channel_name = new_channel_result
        .as_ref()
        .ok()
        .map(|ch| ch.name.clone())
        .unwrap_or_else(|| config_id.clone());

    let (is_fallback, warning) = state
        .channel_manager
        .reload_single_channel_with_fallback(
            &channel_name,
            new_channel_result,
            state.tls_acceptor.clone(),
            Some(state.metrics_store.clone()),
            state.task_monitor.clone(),
        )
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to reload channel '{}': {}", channel_name, e)))?;

    if is_fallback {
        warn!("Using cached configuration as fallback for channel '{}'", channel_name);
    } else {
        debug!("Successfully reloaded channel '{}' from DynamoDB", channel_name);
    }

    Ok(Json(ReloadSingleChannelResponse {
        channel_name,
        is_fallback,
        warning,
    }))
}

/// Channel prefix configuration for UI
#[derive(Debug, Serialize, Clone)]
pub struct ChannelPrefixInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
}

/// Channel routing configuration response
#[derive(Debug, Serialize)]
pub struct ChannelRoutingConfigResponse {
    /// Available listen addresses from **inbound** listeners only (with duplicates).
    /// Used by the AP panel to populate the Listen Address dropdown.
    pub available_listen_addresses: Vec<String>,
    /// Available outbound listen addresses (from outbound-type listeners only).
    /// The TP panel uses count comparison with `available_listen_addresses` (which
    /// now only contains inbound URLs) to detect shared-domain addresses.
    pub available_outbound_listen_addresses: Vec<String>,
    /// Channel path prefixes with names (for UI dropdown)
    pub channel_path_prefix: Vec<ChannelPrefixInfo>,
    /// MCP Proxy path prefixes with names (for UI dropdown)
    pub mcp_proxy_path_prefix: Vec<ChannelPrefixInfo>,
    /// OAuth callback route prefix (e.g. "/oauth/callback")
    pub oauth_callback_route: String,
}

/// Get channel routing configuration
pub async fn get_surface_routing_config(
    State(state): State<IdentityApiState>
) -> Result<Json<ChannelRoutingConfigResponse>, AppError> {
    // Load network configuration
    let network_config = state
        .bootstrap_config
        .load_network_config()
        .map_err(|e| AppError::InternalError(format!("Failed to load network configuration: {}", e)))?;

    // Load MCP proxy paths from the top-level `mcp_proxies` location
    let mcp_proxy_paths = network_config
        .mcp_proxies
        .as_ref()
        .map(|paths| {
            paths
                .iter()
                .map(|c| ChannelPrefixInfo {
                    id: c.id.clone(),
                    name: c.name.clone(),
                    prefix: c.prefix.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let config = ChannelRoutingConfigResponse {
        available_listen_addresses: network_config.get_inbound_external_urls(),
        available_outbound_listen_addresses: network_config.get_outbound_external_urls(),
        channel_path_prefix: network_config
            .get_channel_prefix_configs()
            .iter()
            .map(|c| ChannelPrefixInfo {
                id: c.id.clone(),
                name: c.name.clone(),
                prefix: c.prefix.clone(),
            })
            .collect(),
        mcp_proxy_path_prefix: mcp_proxy_paths,
        oauth_callback_route: network_config
            .oauth_callback_route
            .clone(),
    };

    Ok(Json(config))
}

/// x402 Token configuration for a specific network
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402TokenConfig {
    /// Token symbol (e.g., "USDC", "KTTY")
    pub symbol: String,
    /// Denomination unit (e.g., "USD", "KTTY")
    pub denomination: String,
    /// Number of decimal places (e.g., 6 for USDC, 9 for SOL)
    pub decimals: u8,
    /// Human-readable description (e.g., "$1.00 USD = 1000000 units")
    pub description: String,
    /// Contract address or token mint address
    pub contract_address: String,
    /// Asset transfer method (e.g., "spl_transfer", "eip3009", "permit2")
    pub asset_transfer_method: String,
    /// Token contract version (e.g., "2" for USDC EIP-3009) - used for EIP-712 domain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// x402 Network configuration
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402NetworkConfig {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rpc_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    pub native_currency: String,
    pub native_denomination: String,
    pub block_explorer: String,
    /// List of supported tokens on this network
    /// Each token includes denomination, decimals, contract address, and transfer method
    pub x402_tokens: Vec<X402TokenConfig>,
}

/// EIP-3009 default configuration for a network
/// DEPRECATED: Use X402TokenConfig instead
#[allow(dead_code)]
#[deprecated(since = "0.1.0", note = "Use X402TokenConfig instead")]
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct Eip3009Defaults {
    /// Token contract name (e.g., "USDC") - used for EIP-712 domain
    pub name: String,
    /// Token contract version (e.g., "2") - used for EIP-712 domain
    pub version: String,
    /// Asset transfer method (e.g., "eip3009" or "permit2")
    pub asset_transfer_method: String,
}

/// SPL token default configuration for Solana networks
/// DEPRECATED: Use X402TokenConfig instead
#[allow(dead_code)]
#[deprecated(since = "0.1.0", note = "Use X402TokenConfig instead")]
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct SplDefaults {
    /// SPL token name (e.g., "USDC")
    pub name: String,
    /// Token decimals (e.g., 6 for USDC, 9 for SOL)
    pub decimals: u8,
    /// Asset transfer method (e.g., "spl_transfer")
    pub asset_transfer_method: String,
}

/// x402 Payment scheme
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402PaymentScheme {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// x402 Verification mode
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402VerificationModeConfig {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// x402 Settlement mode
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402SettlementModeConfig {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// x402 Recipient address configuration
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402RecipientAddress {
    pub id: String,
    pub name: String,
    pub description: String,
    pub addresses: std::collections::HashMap<String, String>,
}

/// x402 Headers configuration
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402HeadersConfig {
    pub payment_required: String,
    pub payment_signature: String,
    pub payment_response: String,
}

/// x402 Defaults
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402DefaultsConfig {
    pub verification_mode: String,
    pub settlement_mode: String,
    pub min_confirmations: u32,
    pub facilitator_timeout_secs: u64,
}

/// x402 configuration response
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct X402ConfigResponse {
    pub networks: Vec<X402NetworkConfig>,
    pub payment_schemes: Vec<X402PaymentScheme>,
    pub verification_modes: Vec<X402VerificationModeConfig>,
    pub settlement_modes: Vec<X402SettlementModeConfig>,
    pub recipient_addresses: Vec<X402RecipientAddress>,
    pub headers: X402HeadersConfig,
    pub defaults: X402DefaultsConfig,
}

/// Get x402 configuration
pub async fn get_payment_policy(State(state): State<IdentityApiState>) -> Result<Json<X402ConfigResponse>, AppError> {
    // Get x402 config path from bootstrap config
    let config_path = std::path::PathBuf::from(
        &state
            .bootstrap_config
            .config_files
            .x402,
    );

    debug!("Loading x402 configuration from: {:?}", config_path);

    // Read and parse x402.json
    let config_content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| {
            warn!("Failed to read x402.json (file may not exist): {}", e);
            // Return default configuration if file doesn't exist
            AppError::InternalError(format!("x402.json not found: {}", e))
        })?;

    let config: X402ConfigResponse = serde_json::from_str(&config_content)
        .map_err(|e| AppError::InternalError(format!("Failed to parse x402.json: {}", e)))?;

    debug!(
        "Loaded x402 configuration with {} networks, {} recipients",
        config.networks.len(),
        config
            .recipient_addresses
            .len()
    );

    Ok(Json(config))
}

/// Networking / inbound-mTLS configuration (startup-only).
///
/// Reflects the current `tls.client_auth` settings loaded from the bootstrap
/// configuration. This is a startup-only setting (per `AGENTS.md` rule 7);
/// changes require editing the bootstrap config and restarting the gateway,
/// so this endpoint does not expose a paired `PUT`.
#[derive(Debug, Serialize)]
pub struct NetworkingConfigResponse {
    pub client_auth: crate::config::types::ClientAuthConfig,
}

/// Returns the gateway's effective inbound client-auth (mTLS) configuration.
pub async fn get_networking_config(
    State(state): State<IdentityApiState>
) -> Result<Json<NetworkingConfigResponse>, AppError> {
    Ok(Json(NetworkingConfigResponse {
        client_auth: state
            .config
            .tls
            .client_auth
            .clone(),
    }))
}
