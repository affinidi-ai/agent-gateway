use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::error;

use crate::identity::IdentityStore;
use crate::identity::display_name::{ManagedDisplayName, resolve_managed_display_name, surfaces_by_did};
use crate::identity::filesystem::IdentityOrigin;
use crate::integrations::filesystem::NotificationStore;
use crate::mcp_proxies::filesystem::McpProxyStore;
use crate::metrics::MetricsStore;
use crate::observability::caller_names::{CallerNameService, DisplayNameSource};
use crate::observability::identity_view::{
    CredentialPrincipal, PrincipalNames, credential_principal, group_key, naming_for,
};
use crate::{config::GatewayConfig, observability::system_metrics::SystemInfo};

// Store proxy start time
static PROXY_START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

pub fn init_start_time() {
    PROXY_START_TIME.get_or_init(SystemTime::now);
}

#[derive(Clone)]
pub struct DashboardState {
    pub config: Arc<GatewayConfig>,
    pub network_config: Arc<crate::config::NetworkConfig>,
    pub identity_store: Arc<dyn IdentityStore>,
    pub metrics_store: Arc<MetricsStore>,
    pub vc_issuer: Arc<crate::identity::VCIssuer>,
    pub ws_state: Arc<crate::server::WsState>,
    pub task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    pub channel_manager: Arc<crate::server::SurfaceTaskManager>,
    pub connection_point_listener_manager: Option<Arc<crate::gateways::ConnectionPointListenerManager>>,
    pub mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
    #[allow(dead_code)]
    pub mcp_server_manager: Option<Arc<crate::mcp_proxies::handlers::McpServerManager>>,
    pub notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    pub auth_state: Option<Arc<crate::auth::AuthState>>,
    #[allow(dead_code)]
    pub trust_registry_listener_manager: Option<Arc<crate::trust_registries::TrustRegistryListenerManager>>,
    pub system_metrics_store: Option<Arc<crate::observability::SystemMetricsStore>>,
    pub agent_surface_store: Option<Arc<crate::surfaces::FileSystemAgentSurfaceStore>>,
}

#[derive(Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_identities: usize,
    pub identities: Vec<IdentityInfo>,
    pub channels: Vec<SurfaceInfo>,
    pub ports: PortInfo,
    pub metrics: MetricsData,
    pub proxy_info: ProxyInfo,
    pub tasks: Option<TasksInfo>,
    pub connection_point_tasks: Option<ConnectionPointTasksInfo>,
    pub mcp_proxy_tasks: Option<McpProxyTasksInfo>,
    pub unread_count: usize,
}

/// Delta/incremental update response - only returns what changed
#[derive(Serialize, Deserialize)]
pub struct DashboardDelta {
    /// Server timestamp of this response
    pub timestamp: i64,
    /// What changed since last request
    pub changes: DashboardChanges,
}

#[derive(Serialize, Deserialize, Default)]
pub struct DashboardChanges {
    /// Metrics updates (always included)
    pub metrics: Option<MetricsDelta>,
    /// Log updates (only if logs changed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<LogsDelta>,
    /// Channel updates (only if channels changed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<ChannelsDelta>,
    /// Identity updates (only if identities changed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identities: Option<IdentitiesDelta>,
    /// Tasks updates (only if tasks changed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<TasksDelta>,
    /// Unread notification count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_count: Option<usize>,
}

impl DashboardChanges {
    /// Compute a lightweight fingerprint of the meaningful data in this delta,
    /// ignoring time-series bucket timestamps (which shift every cycle).
    /// Used to suppress duplicate WS broadcasts when nothing really changed.
    pub fn content_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();

        if let Some(m) = &self.metrics {
            for p in &m.new_time_series_points {
                // Hash only counts, not timestamp
                (p.count, p.rule_accepts, p.rule_denies, p.failed, p.gateway_faults).hash(&mut h);
            }
            m.new_latency_points
                .len()
                .hash(&mut h);
            for p in &m.new_latency_points {
                p.avg_latency_ms
                    .to_bits()
                    .hash(&mut h);
                p.sample_count.hash(&mut h);
            }
            m.total_connections
                .hash(&mut h);
            m.avg_latency
                .map(|v| v.to_bits())
                .hash(&mut h);
            m.channel_stats
                .len()
                .hash(&mut h);
        }

        self.logs
            .is_some()
            .hash(&mut h);
        if let Some(logs) = &self.logs {
            logs.new_entries
                .len()
                .hash(&mut h);
        }
        self.channels
            .is_some()
            .hash(&mut h);
        self.identities
            .is_some()
            .hash(&mut h);
        self.tasks
            .is_some()
            .hash(&mut h);
        self.unread_count.hash(&mut h);

        h.finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct MetricsDelta {
    /// New time series points since last request
    pub new_time_series_points: Vec<crate::metrics::TimeSeriesPoint>,
    /// New latency time series points since last request
    pub new_latency_points: Vec<crate::metrics::LatencyTimeSeriesPoint>,
    /// Bucket interval used (in seconds) - frontend should reset if this changes
    pub bucket_seconds: i64,
    /// Updated counter values (all connection types)
    pub total_connections: usize,
    pub avg_latency: Option<f64>,
    pub avg_request_latency: Option<f64>,
    pub avg_response_latency: Option<f64>,
    /// Updated channel stats (agent-to-agent)
    pub channel_stats: Vec<crate::metrics::SurfaceStats>,
    pub identity_channel_stats: Vec<crate::metrics::IdentityChannelStats>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LogEntry {
    /// Unix timestamp in milliseconds when log was written
    pub timestamp: i64,
    /// Log message without timestamp/color codes
    pub message: String,
    /// Log level (INFO, WARN, ERROR, DEBUG, TRACE)
    pub level: String,
    /// Byte offset of this line in the log file (used for ordering)
    pub file_position: u64,
}

#[derive(Serialize, Deserialize)]
pub struct LogsDelta {
    /// New log entries since last sync
    pub new_entries: Vec<LogEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct ChannelsDelta {
    pub added: Vec<SurfaceInfo>,
    pub updated: Vec<SurfaceInfo>,
    pub removed: Vec<String>, // config_ids
}

#[derive(Serialize, Deserialize)]
pub struct IdentitiesDelta {
    pub total_identities: usize,
    pub added: Vec<IdentityInfo>,
    pub updated: Vec<IdentityInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct TasksDelta {
    pub tasks: TasksInfo,
    pub connection_point_tasks: Option<ConnectionPointTasksInfo>,
    pub mcp_proxy_tasks: Option<McpProxyTasksInfo>,
}

/// Query parameters for incremental updates
#[derive(Deserialize)]
pub struct DashboardQuery {
    /// Unix timestamp of last request (for filtering new data)
    #[serde(default)]
    pub since: Option<i64>,
    /// Session token for user-specific data (e.g., notifications)
    #[serde(default)]
    pub session_token: Option<String>,
    /// Requested bucket interval in seconds (e.g., 30, 60, 300)
    #[serde(default)]
    pub bucket_seconds: Option<i64>,
    /// Filter to specific channel by config_id
    #[serde(default)]
    pub surface_id: Option<String>,
    /// Filter to specific gateway by ID
    #[serde(default)]
    pub gateway_id: Option<String>,
    /// Filter to specific identity by DID
    #[serde(default)]
    pub identity_did: Option<String>,
    /// Surface dashboard transit-point slice. Accepted values:
    ///   * unset / empty → aggregated (AP + every TP)
    ///   * `__ap__`      → Access Point only (`transit_point` is `None`)
    ///   * `<alias>`     → only the named Transit Point
    #[serde(default)]
    pub transit_point: Option<String>,
    /// Byte offset of the last log entry received by the client.
    /// When provided, the server returns only entries after this position.
    #[serde(default)]
    pub since_log_position: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct ProxyInfo {
    pub did: String,
    /// Dedicated DID used for trust registry DIDComm communications.
    /// This is a separate identity from the main gateway DID.
    /// Trust registry administrators should allow-list this DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_registry_did: Option<String>,
    pub uptime_seconds: u64,
    pub uptime_formatted: String,
    pub extensions_enabled: bool,
    pub watched_extensions: Vec<String>,
    pub proxy_domain: String,
    pub log_entries: Vec<LogEntry>,
    pub did_document: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct MetricsData {
    pub total_connections: usize,
    pub avg_latency: Option<f64>,
    pub avg_request_latency: Option<f64>,
    pub avg_response_latency: Option<f64>,
    pub connections_window_minutes: u64,
    pub latency_window_minutes: u64,
    pub bucket_seconds: i64,
    pub time_series: Vec<crate::metrics::TimeSeriesPoint>,
    pub channel_stats: Vec<crate::metrics::SurfaceStats>,
    pub source_dest_stats: Vec<crate::metrics::SourceDestStats>,
    pub latency_stats: Vec<crate::metrics::LatencyStats>,
    pub latency_time_series: Vec<crate::metrics::LatencyTimeSeriesPoint>,
    pub identity_channel_stats: Vec<crate::metrics::IdentityChannelStats>,
}

#[derive(Serialize, Deserialize)]
pub struct IdentityInfo {
    pub did: String,
    pub created_at: String,
    pub identity_hash: String,
    pub agent_identity: serde_json::Value,
    pub usage_count: u64,
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_config_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_name: Option<String>,
    pub is_local: bool,
    pub verified: bool,
    #[serde(default)]
    pub channel_usage: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<IdentityOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_source: Option<DisplayNameSource>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub display_name_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_principal: Option<CredentialPrincipal>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub name_conflict: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group_key: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Serialize, Deserialize)]
pub struct SurfaceInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_id: Option<String>,
    pub name: String,
    pub description: String,
    pub listen_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    pub target_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fabric_target_name: Option<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<serde_json::Value>,
    pub rule_count: usize,
    pub accept_count: u64,
    pub deny_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<crate::config::CustomMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_custom_metadata: Option<crate::config::CustomMetadata>,
    pub gateway_faults: usize,
    pub last_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_type: Option<crate::config::SurfaceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<crate::config::ChannelProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<crate::config::RateLimitConfig>,
    #[serde(default)]
    pub opa_enabled: bool,
    #[serde(default)]
    pub mcp_tool_policies: Vec<crate::config::McpToolPolicy>,
    #[serde(default)]
    pub mcp_tool_policies_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<crate::config::TimeoutConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<crate::config::RetryConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<crate::config::CircuitBreakerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror: Option<crate::config::MirrorConfig>,
    /// Whether this channel is published in the gateway's DID document
    #[serde(default)]
    pub publish_to_did_document: bool,
    /// x402 payment configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_policy: Option<crate::config::X402Config>,
    /// MPP payment configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpp_policy: Option<crate::mpp::MppConfig>,
    /// Supported A2A extensions (e.g., UCP)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_extensions: Vec<String>,
    /// Primary A2A extension for this channel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_extension: Option<String>,
    /// Number of unique agent identities that have been extracted in this channel
    #[serde(default)]
    pub identity_count: usize,
    /// Last activity timestamp for this channel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<String>,
    /// Target authentication configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_auth: Option<crate::config::TargetAuthConfig>,
    /// Trust Recorder — writes records to configured trust registries on
    /// the MA→AP response leg. Mirrors `access_point.trust_recorder`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_recorder: Option<crate::config::types::TrustRecorderConfig>,
    /// Unified source authentication configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<crate::source_auth::SourceAuthConfig>,
    /// Managed identity configuration (payload-extraction based DID assignment)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_identity: Option<crate::source_auth::ManagedIdentityConfig>,
    /// Issuer ID — agents created through this channel are registered under this issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<String>,
    /// Outbound listen address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_listen_address: Option<String>,
    /// Outbound credential bindings for delegation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound_credentials: Vec<crate::config::OutboundCredentialBinding>,
}

#[derive(Serialize, Deserialize)]
pub struct PortInfo {
    pub proxy_channels: Vec<String>,
    pub identity_http: Option<u16>,
    pub identity_https: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct TasksInfo {
    pub summary: crate::observability::TaskStatsSummary,
    pub tasks: Vec<crate::observability::TaskInfo>,
    pub metrics: Vec<crate::observability::TaskMetrics>,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionPointTasksInfo {
    pub summary: ConnectionPointTasksSummary,
    pub tasks: Vec<ConnectionPointTaskInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionPointTasksSummary {
    pub total_listeners: usize,
    pub connected: usize,
    pub reconnecting: usize,
    pub failed: usize,
    pub total_messages: u64,
    pub total_errors: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionPointTaskInfo {
    pub id: String,
    pub name: String,
    pub task_type: String,
    pub gateway_did: String,
    pub mediator_did: String,
    pub status: String,
    pub started_at: String,
    pub last_activity: Option<String>,
    pub message_count: u64,
    pub error_count: u64,
    pub reconnect_attempts: u64,
}

#[derive(Serialize, Deserialize)]
pub struct McpProxyTasksInfo {
    pub summary: McpProxyTasksSummary,
    pub tasks: Vec<McpProxyTaskInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct McpProxyTasksSummary {
    pub total_proxies: usize,
    pub active: usize,
    pub disabled: usize,
}

#[derive(Serialize, Deserialize)]
pub struct McpProxyTaskInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub proxy_path: String,
    pub base_url: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Translate a raw `transit_point` query-string value into a
/// `TransitPointFilter`. The wire format is intentionally tiny so it is
/// easy to thread through `?transit_point=…` URLs:
///   * unset / empty       → `Aggregated`
///   * the literal `__ap__` → `AccessPoint` (Access Point only)
///   * any other value     → `TransitPoint(value)`
pub(crate) fn parse_tp_filter(raw: Option<&str>) -> crate::metrics::TransitPointFilter {
    use crate::metrics::TransitPointFilter;
    match raw.map(str::trim) {
        None | Some("") => TransitPointFilter::Aggregated,
        Some("__ap__") => TransitPointFilter::AccessPoint,
        Some(alias) => TransitPointFilter::TransitPoint(alias.to_string()),
    }
}

/// Apply a transit-point predicate to a list of `LogEntry`s in place.
///   * unset / empty       → keep everything
///   * `__ap__`            → drop entries containing `[TP:`
///   * `<alias>`           → keep only entries containing `[TP:<alias>]`
pub(crate) fn apply_tp_log_filter(
    entries: &mut Vec<LogEntry>,
    raw: Option<&str>,
) {
    match raw.map(str::trim) {
        None | Some("") => {}
        Some("__ap__") => {
            entries.retain(|e| !e.message.contains("[TP:"));
        }
        Some(alias) => {
            let needle = format!("[TP:{}]", alias);
            entries.retain(|e| e.message.contains(&needle));
        }
    }
}

/// Computes a full (unfiltered) dashboard delta for the WS broadcast.
/// Delegates to `compute_dashboard_delta` with no filters so all sections
/// (metrics, logs, channels, identities, tasks) are included.
async fn compute_broadcast_delta(
    state: &DashboardState,
    since_epoch: Option<i64>,
    since_log_position: Option<u64>,
) -> DashboardDelta {
    let query = DashboardQuery {
        since: since_epoch,
        session_token: None,
        bucket_seconds: Some(
            state
                .metrics_store
                .get_bucket_seconds(),
        ),
        surface_id: None,
        gateway_id: None,
        identity_did: None,
        transit_point: None,
        since_log_position,
    };
    match compute_dashboard_delta(state, &query).await {
        Ok(delta) => delta,
        Err(e) => {
            tracing::warn!("Failed to compute broadcast delta: {}", e);
            DashboardDelta {
                timestamp: Utc::now().timestamp(),
                changes: DashboardChanges::default(),
            }
        }
    }
}

/// Core logic for computing a dashboard delta. Used by the HTTP handler and
/// the periodic WebSocket broadcast task.
pub async fn compute_dashboard_delta(
    state: &DashboardState,
    query: &DashboardQuery,
) -> Result<DashboardDelta, String> {
    let now = Utc::now();
    let since_timestamp = query
        .since
        .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or(now - chrono::Duration::hours(1)));

    let mut changes = DashboardChanges::default();

    // Determine bucket interval from query or use auto
    let bucket_seconds = query
        .bucket_seconds
        .unwrap_or(0);
    let actual_bucket_seconds = if bucket_seconds > 0 {
        bucket_seconds
    } else {
        // Auto mode: select bucket based on window
        let window_minutes = state
            .metrics_store
            .get_connections_window_minutes();
        if window_minutes < 10 {
            30 // 30 seconds
        } else if window_minutes < 60 {
            60 // 1 minute
        } else {
            300 // 5 minutes
        }
    };

    // Check if filters are active
    let has_filters = query.surface_id.is_some()
        || query.gateway_id.is_some()
        || query.identity_did.is_some()
        || query
            .transit_point
            .as_deref()
            .is_some_and(|s| !s.is_empty());

    let tp_filter = parse_tp_filter(query.transit_point.as_deref());

    // Get time series - use filtered version if filters are active, otherwise get all data
    let filtered_time_series = if has_filters {
        state
            .metrics_store
            .get_filtered_time_series(
                actual_bucket_seconds,
                query.surface_id.as_deref(),
                query.gateway_id.as_deref(),
                query.identity_did.as_deref(),
                &tp_filter,
            )
            .await
    } else {
        state
            .metrics_store
            .get_time_series_seconds(actual_bucket_seconds)
            .await
    };

    // Get latency time series - use filtered version if filters are active
    let filtered_latency_series = if has_filters {
        state
            .metrics_store
            .get_filtered_latency_time_series(
                actual_bucket_seconds,
                query.surface_id.as_deref(),
                query.gateway_id.as_deref(),
                query.identity_did.as_deref(),
                &tp_filter,
            )
            .await
    } else {
        state
            .metrics_store
            .get_latency_time_series(actual_bucket_seconds)
            .await
    };

    // Filter to only new/changed buckets if 'since' provided
    let new_time_series = if let Some(since) = since_timestamp {
        // Calculate what the last bucket timestamp would have been
        // Round 'since' down to bucket boundary to get last known bucket
        let since_epoch = since.timestamp();
        let last_bucket = (since_epoch / actual_bucket_seconds) * actual_bucket_seconds;

        // Only send buckets AFTER OR INCLUDING the last known bucket
        // (The last bucket may have gotten new data since the last sync)
        let filtered: Vec<_> = filtered_time_series
            .into_iter()
            .filter(|point| {
                DateTime::parse_from_rfc3339(&point.timestamp)
                    .map(|dt| dt.timestamp() >= last_bucket)
                    .unwrap_or(false)
            })
            .collect();

        // Fill in zero buckets from last_bucket to now if no data exists
        // This keeps the graph marching forward even with no traffic
        if !filtered.is_empty() {
            let first_new_bucket = DateTime::parse_from_rfc3339(&filtered[0].timestamp)
                .map(|dt| dt.timestamp())
                .unwrap_or(since_epoch);

            // Fill gaps between last_bucket and first new data
            let mut gap_buckets = Vec::new();
            let mut bucket_time = last_bucket + actual_bucket_seconds;
            while bucket_time < first_new_bucket {
                let bucket_dt = DateTime::from_timestamp(bucket_time, 0).unwrap_or_else(Utc::now);
                gap_buckets.push(crate::metrics::TimeSeriesPoint {
                    timestamp: bucket_dt.to_rfc3339(),
                    count: 0,
                    rule_accepts: 0,
                    rule_denies: 0,
                    failed: 0,
                    gateway_faults: 0,
                });
                bucket_time += actual_bucket_seconds;
            }

            // Prepend gap buckets
            gap_buckets.extend(filtered);
            gap_buckets
        } else {
            // No data at all, fill from last_bucket to now
            let mut zero_buckets = Vec::new();
            let now_epoch = now.timestamp();
            let mut bucket_time = last_bucket + actual_bucket_seconds;

            // Don't create too many buckets (cap at 100)
            let max_buckets = 100;
            let mut count = 0;

            while bucket_time <= now_epoch && count < max_buckets {
                let bucket_dt = DateTime::from_timestamp(bucket_time, 0).unwrap_or_else(Utc::now);
                zero_buckets.push(crate::metrics::TimeSeriesPoint {
                    timestamp: bucket_dt.to_rfc3339(),
                    count: 0,
                    rule_accepts: 0,
                    rule_denies: 0,
                    failed: 0,
                    gateway_faults: 0,
                });
                bucket_time += actual_bucket_seconds;
                count += 1;
            }

            zero_buckets
        }
    } else {
        // First sync: return all buckets
        filtered_time_series
    };

    let new_latency_points = if let Some(since) = since_timestamp {
        // Calculate what the last bucket timestamp would have been
        // Round 'since' down to bucket boundary to get last known bucket
        let since_epoch = since.timestamp();
        let last_bucket = (since_epoch / actual_bucket_seconds) * actual_bucket_seconds;

        // Only send buckets AFTER OR INCLUDING the last known bucket
        // (The last bucket may have gotten new data since the last sync)
        filtered_latency_series
            .into_iter()
            .filter(|point| {
                DateTime::parse_from_rfc3339(&point.timestamp)
                    .map(|dt| dt.timestamp() >= last_bucket)
                    .unwrap_or(false)
            })
            .collect()
    } else {
        filtered_latency_series
    };

    // When filters are active, only include filtered time series data
    // Aggregate stats (channel_stats, etc.) are unfiltered so only include them when no filters
    let has_filters = query.surface_id.is_some() || query.gateway_id.is_some() || query.identity_did.is_some();

    changes.metrics = Some(MetricsDelta {
        new_time_series_points: new_time_series,
        new_latency_points,
        bucket_seconds: actual_bucket_seconds,
        total_connections: if has_filters {
            0
        } else {
            state
                .metrics_store
                .get_total_connections()
                .await
        },
        avg_latency: if has_filters {
            None
        } else {
            state
                .metrics_store
                .get_average_latency()
                .await
        },
        avg_request_latency: if has_filters {
            None
        } else {
            state
                .metrics_store
                .get_average_request_latency()
                .await
        },
        avg_response_latency: if has_filters {
            None
        } else {
            state
                .metrics_store
                .get_average_response_latency()
                .await
        },
        channel_stats: if has_filters {
            Vec::new()
        } else {
            state
                .metrics_store
                .get_channel_stats()
                .await
        },
        identity_channel_stats: if let Some(ref channel_id) = query.surface_id {
            // Filter identity stats for this channel
            state
                .metrics_store
                .get_identity_channel_stats()
                .await
                .into_iter()
                .filter(|stat| &stat.channel_config_id == channel_id)
                .collect()
        } else {
            state
                .metrics_store
                .get_identity_channel_stats()
                .await
        },
    });

    // Logs: prefer file_position-based delta over timestamp-based
    // When filtering by channel, read more logs and filter them
    let log_read_limit = if query.surface_id.is_some() {
        2000
    } else {
        300
    };

    if let Some(since_pos) = query.since_log_position {
        // Position-based delta: read entries after the given byte offset
        let log_dir = state
            .config
            .logging
            .log_directory
            .clone();
        let channel_filter = query.surface_id.clone();
        let tp_filter_raw = query.transit_point.clone();

        if let Ok(mut new_entries) =
            tokio::task::spawn_blocking(move || read_log_entries_since(&log_dir, since_pos, log_read_limit)).await
            && let Some(ref mut entries) = new_entries
        {
            // Filter logs by channel if channel_id is specified
            if let Some(channel_id) = &channel_filter {
                let channel_prefix = format!("[CHANNEL:{}]", channel_id);
                entries.retain(|entry| {
                    entry
                        .message
                        .contains(&channel_prefix)
                });
                if entries.len() > 300 {
                    *entries = entries.split_off(entries.len() - 300);
                }
            }
            // Surface transit-point slice on top of channel filter.
            apply_tp_log_filter(entries, tp_filter_raw.as_deref());

            if !entries.is_empty() {
                changes.logs = Some(LogsDelta { new_entries: entries.clone() });
            }
        }
    } else {
        // No position available: read the last N entries from the end of the file.
        // The frontend deduplicates by file_position so overlap is harmless.
        let log_dir = state
            .config
            .logging
            .log_directory
            .clone();
        let channel_filter = query.surface_id.clone();
        let tp_filter_raw = query.transit_point.clone();

        if let Ok(all_lines) = tokio::task::spawn_blocking(move || read_log_file(&log_dir, log_read_limit)).await {
            let mut structured_logs: Vec<LogEntry> = all_lines
                .iter()
                .filter_map(|(offset, line)| {
                    let mut entry = parse_log_entry(line)?;
                    entry.file_position = *offset;
                    Some(entry)
                })
                .collect();

            // Filter logs by channel if channel_id is specified
            if let Some(channel_id) = &channel_filter {
                let channel_prefix = format!("[CHANNEL:{}]", channel_id);
                structured_logs.retain(|entry| {
                    entry
                        .message
                        .contains(&channel_prefix)
                });
                if structured_logs.len() > 300 {
                    structured_logs = structured_logs.split_off(structured_logs.len() - 300);
                }
            }
            // Surface transit-point slice on top of channel filter.
            apply_tp_log_filter(&mut structured_logs, tp_filter_raw.as_deref());

            if !structured_logs.is_empty() {
                changes.logs = Some(LogsDelta { new_entries: structured_logs });
            }
        }
    }

    // Channels: Include only if any channel modified since 'since' timestamp
    let current_config = state
        .channel_manager
        .get_config()
        .await;
    let all_channels = build_channel_list(&current_config, &state.metrics_store).await;

    if let Some(since) = since_timestamp {
        // Filter channels modified since the given timestamp
        let modified_channels: Vec<SurfaceInfo> = all_channels
            .into_iter()
            .filter(|ch| {
                ch.last_activity
                    .as_ref()
                    .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                    .map(|dt| dt.with_timezone(&Utc) > since)
                    .unwrap_or(false)
            })
            .collect();

        if !modified_channels.is_empty() {
            changes.channels = Some(ChannelsDelta {
                added: vec![],
                updated: modified_channels,
                removed: vec![],
            });
        }
    } else {
        // First sync: return all channels
        changes.channels = Some(ChannelsDelta {
            added: all_channels,
            updated: vec![],
            removed: vec![],
        });
    }

    // Identities: Include only if any identity modified since 'since' timestamp
    let all_identities = build_identity_list(
        &state.identity_store,
        &current_config,
        &state.metrics_store,
        state
            .agent_surface_store
            .as_ref(),
    )
    .await
    .map_err(|(_status, msg)| msg)?;

    if let Some(since) = since_timestamp {
        let renamed: std::collections::HashSet<String> = CallerNameService::global()
            .changed_since(since)
            .into_iter()
            .collect();
        let modified_identities = identities_changed_since(all_identities, since, &renamed);

        if !modified_identities.is_empty() {
            changes.identities = Some(IdentitiesDelta {
                total_identities: modified_identities.len(),
                added: modified_identities,
                updated: vec![],
            });
        }
    } else {
        // First sync: return all identities
        changes.identities = Some(IdentitiesDelta {
            total_identities: all_identities.len(),
            added: all_identities,
            updated: vec![],
        });
    }

    // Tasks: Always include all tasks (not filtered by timestamp)
    // The frontend needs the complete task list to properly display all active tasks
    if let Some(task_monitor) = &state.task_monitor {
        let summary = task_monitor
            .get_summary()
            .await;
        let all_tasks = task_monitor
            .get_all_tasks()
            .await;
        let metrics = task_monitor
            .get_all_metrics()
            .await;

        // Get connection point listener information if available
        let connection_point_tasks = if let Some(listener_manager) = &state.connection_point_listener_manager {
            let listeners = listener_manager
                .get_active_listeners()
                .await;

            let mut total_messages = 0u64;
            let mut total_errors = 0u64;
            let mut connected = 0usize;
            let mut reconnecting = 0usize;
            let mut failed = 0usize;

            let mut tasks = Vec::new();

            for listener in listeners {
                let metrics = listener.metrics.read().await;

                total_messages += metrics.message_count;
                total_errors += metrics.error_count;

                match metrics.status {
                    crate::gateways::ConnectionStatus::Connected => connected += 1,
                    crate::gateways::ConnectionStatus::Reconnecting => reconnecting += 1,
                    crate::gateways::ConnectionStatus::Failed => failed += 1,
                }

                let status = match metrics.status {
                    crate::gateways::ConnectionStatus::Connected => "connected",
                    crate::gateways::ConnectionStatus::Reconnecting => "reconnecting",
                    crate::gateways::ConnectionStatus::Failed => "failed",
                };

                // Map connection point type to user-friendly task type
                let task_type = match &listener.cp_type {
                    crate::gateways::connection_points::ConnectionPointType::User => "User-Created",
                    crate::gateways::connection_points::ConnectionPointType::OobInviter => "OOB Inviter",
                    crate::gateways::connection_points::ConnectionPointType::OobResponder => "OOB Responder",
                    crate::gateways::connection_points::ConnectionPointType::OobAcceptor => "OOB Acceptor",
                    crate::gateways::connection_points::ConnectionPointType::System => "System",
                };

                tasks.push(ConnectionPointTaskInfo {
                    id: listener.id.clone(),
                    name: listener.name.clone(),
                    task_type: task_type.to_string(),
                    gateway_did: listener.gateway_did.clone(),
                    mediator_did: listener.mediator_did.clone(),
                    status: status.to_string(),
                    started_at: metrics
                        .started_at
                        .to_rfc3339(),
                    last_activity: metrics
                        .last_activity
                        .map(|dt| dt.to_rfc3339()),
                    message_count: metrics.message_count,
                    error_count: metrics.error_count,
                    reconnect_attempts: metrics.reconnect_attempts,
                });
            }

            Some(ConnectionPointTasksInfo {
                summary: ConnectionPointTasksSummary {
                    total_listeners: tasks.len(),
                    connected,
                    reconnecting,
                    failed,
                    total_messages,
                    total_errors,
                },
                tasks,
            })
        } else {
            None
        };

        // Get MCP proxy information if available
        let mcp_proxy_tasks = if let Some(proxy_store) = &state.mcp_proxy_store {
            match proxy_store.list_all().await {
                Ok(proxies) => {
                    let mut active = 0usize;
                    let mut disabled = 0usize;

                    let mut tasks = Vec::new();

                    for proxy in proxies {
                        match proxy.status {
                            crate::mcp_proxies::types::McpProxyStatus::Active => active += 1,
                            crate::mcp_proxies::types::McpProxyStatus::Disabled => disabled += 1,
                        }

                        let status = match proxy.status {
                            crate::mcp_proxies::types::McpProxyStatus::Active => "active",
                            crate::mcp_proxies::types::McpProxyStatus::Disabled => "disabled",
                        };

                        tasks.push(McpProxyTaskInfo {
                            id: proxy.id.clone(),
                            name: proxy.name.clone(),
                            description: proxy.description.clone(),
                            status: status.to_string(),
                            proxy_path: proxy.full_path(),
                            base_url: proxy.base_url.clone(),
                            created_at: proxy.created_at.to_rfc3339(),
                            updated_at: proxy.updated_at.to_rfc3339(),
                        });
                    }

                    Some(McpProxyTasksInfo {
                        summary: McpProxyTasksSummary {
                            total_proxies: tasks.len(),
                            active,
                            disabled,
                        },
                        tasks,
                    })
                }
                Err(e) => {
                    tracing::warn!("Failed to list MCP proxies for dashboard: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Always include task information (not filtered by timestamp)
        changes.tasks = Some(TasksDelta {
            tasks: TasksInfo {
                summary,
                tasks: all_tasks,
                metrics,
            },
            connection_point_tasks,
            mcp_proxy_tasks,
        });
    }

    // Unread notifications: Get count if session_token provided and auth_state/notification_store available
    if let (Some(session_token), Some(auth_state), Some(notif_store)) =
        (&query.session_token, &state.auth_state, &state.notification_store)
    {
        if let Some((_username, user_id)) = auth_state
            .session_manager
            .validate_session(session_token)
            .await
        {
            match notif_store
                .count_unread(&user_id)
                .await
            {
                Ok(count) => changes.unread_count = Some(count),
                Err(e) => {
                    error!("Failed to count unread notifications: {}", e);
                    changes.unread_count = Some(0);
                }
            }
        } else {
            changes.unread_count = Some(0);
        }
    }

    Ok(DashboardDelta {
        timestamp: now.timestamp(),
        changes,
    })
}

/// API endpoint to get incremental dashboard updates (delta/changes only).
/// Deprecated: deltas are now pushed via WebSocket. This endpoint remains
/// for backward compatibility.
pub async fn get_dashboard_delta(
    State(state): State<DashboardState>,
    Query(query): Query<DashboardQuery>,
) -> Result<Json<DashboardDelta>, (axum::http::StatusCode, String)> {
    compute_dashboard_delta(&state, &query)
        .await
        .map(Json)
        .map_err(|msg| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, msg))
}

/// Lightweight wrapper for pre-serializing the WS delta message without the
/// intermediate `serde_json::Value` heap allocation that `json!()` would create.
#[derive(Serialize)]
struct WsDeltaEnvelope<'a> {
    #[serde(rename = "type")]
    msg_type: &'static str,
    delta: &'a DashboardDelta,
}

/// Spawns a background task that periodically computes the global (unfiltered)
/// dashboard delta and broadcasts it to all connected WebSocket clients.
///
/// The broadcast now includes all delta sections (metrics, logs, channels,
/// identities, tasks) so clients no longer need to HTTP-poll `/delta`.
pub fn init_dashboard_delta_broadcast(
    dashboard_state: DashboardState,
    refresh_interval_secs: u64,
) {
    let ws_state = dashboard_state
        .ws_state
        .clone();
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(refresh_interval_secs);
        // Track our own `since` timestamp for the delta window.
        // Initialised to "now" so the first broadcast is a small incremental
        // delta rather than a full dump of all history.
        let mut last_broadcast_epoch: Option<i64> = Some(chrono::Utc::now().timestamp());
        // Track the highest log file_position so the next broadcast
        // only includes entries written after this point.
        let mut last_log_position: Option<u64> = None;
        // Track previous broadcast payload to suppress duplicate sends.
        // We hash only the meaningful data (counts, values) — not timestamps
        // which shift every cycle.
        let mut prev_hash: u64 = 0;

        loop {
            tokio::time::sleep(interval).await;

            // Skip computation when nobody is listening.
            // Keep last_broadcast_epoch so we only send a small catch-up
            // delta when a client reconnects instead of a full dump.
            if ws_state.receiver_count() == 0 {
                continue;
            }

            let delta = compute_broadcast_delta(&dashboard_state, last_broadcast_epoch, last_log_position).await;
            last_broadcast_epoch = Some(delta.timestamp);

            // Skip broadcasting when nothing meaningful changed.
            let hash = delta.changes.content_hash();
            if hash == prev_hash {
                continue;
            }
            prev_hash = hash;

            // Advance the log cursor for the next broadcast.
            if let Some(ref logs) = delta.changes.logs
                && let Some(max_pos) = logs
                    .new_entries
                    .iter()
                    .map(|e| e.file_position)
                    .max()
            {
                last_log_position = Some(max_pos);
            }

            // Serialize directly to String via a thin wrapper struct.
            // This avoids the intermediate serde_json::Value heap tree
            // that json!() would allocate.
            let envelope = WsDeltaEnvelope {
                msg_type: "dashboard_delta",
                delta: &delta,
            };
            match serde_json::to_string(&envelope) {
                Ok(json_str) => {
                    // Drop `delta` before broadcasting so its memory
                    // is freed before the Arc<String> is cloned.
                    drop(delta);
                    ws_state.broadcast(crate::server::WsUpdate::DashboardDelta {
                        json: std::sync::Arc::new(json_str),
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to serialize dashboard delta: {}", e);
                }
            }
        }
    });
}

/// API endpoint to get dashboard statistics (full response - for compatibility)
pub async fn get_dashboard_stats(
    State(state): State<DashboardState>,
    Query(query): Query<DashboardQuery>,
) -> Result<Json<DashboardStats>, (axum::http::StatusCode, String)> {
    // Get all identities with full agent identity data
    let current_config = state
        .channel_manager
        .get_config()
        .await;
    let identities = build_identity_list(
        &state.identity_store,
        &current_config,
        &state.metrics_store,
        state
            .agent_surface_store
            .as_ref(),
    )
    .await
    .unwrap_or_else(|e| {
        error!("Failed to list identities: {}", e.1);
        vec![]
    });

    let total_identities = identities.len();

    // Get channel information from channel manager (fresh config)
    let channels: Vec<SurfaceInfo> = {
        let mut channel_infos = Vec::new();

        // Get channel stats to get gateway fault counts
        let channel_stats = state
            .metrics_store
            .get_channel_stats()
            .await;
        let channel_stats_map: std::collections::HashMap<String, &crate::metrics::SurfaceStats> = channel_stats
            .iter()
            .map(|s| (s.channel_config_id.clone(), s))
            .collect();

        // Get identity_channel_stats to count unique identities per channel
        let identity_channel_stats = state
            .metrics_store
            .get_identity_channel_stats()
            .await;

        // Count unique identities per channel (same logic as IdentitiesTab)
        // We need to track which identity records match each channel, not just count hash strings
        let mut identity_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for r in current_config
            .surfaces
            .iter()
            .filter(|s| s.status != crate::config::agent_surface::SurfaceStatus::Deleted)
        {
            let channel_config_id = r
                .config_id()
                .unwrap_or("unknown");

            // Get identity_hash values for this channel from stats
            let channel_identity_hashes: std::collections::HashSet<String> = identity_channel_stats
                .iter()
                .filter(|stat| stat.channel_config_id == channel_config_id)
                .map(|stat| stat.identity_hash.clone())
                .collect();

            // Count unique identities that match this channel
            // Match by: identity_hash in stats OR did in stats OR created by this channel
            let count = identities
                .iter()
                .filter(|identity| {
                    // Check if this identity's hash or DID appears in the channel's stats
                    channel_identity_hashes.contains(&identity.identity_hash) ||
                    channel_identity_hashes.contains(&identity.did) ||
                    // Also include identities created by this channel (even if no usage yet)
                    identity.channel_config_id.as_deref() == Some(channel_config_id)
                })
                .count();

            identity_counts.insert(channel_config_id.to_string(), count);
        }

        for r in current_config
            .surfaces
            .iter()
            .filter(|s| s.status != crate::config::agent_surface::SurfaceStatus::Deleted)
        {
            // Count total rules from managed_identity.extension_rules
            let r_managed_identity = r.managed_identity();
            let rule_count = r_managed_identity
                .as_ref()
                .and_then(|mi| match mi {
                    crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.extension_rules.as_ref(),
                    _ => None,
                })
                .map_or(0, |rules| rules.rules.len());

            let channel_config_id = r
                .config_id()
                .unwrap_or("unknown");

            // Get rule metrics for this channel
            let (_rule_accept_count, deny_count) = match state
                .metrics_store
                .get_rule_metrics(channel_config_id)
                .await
            {
                Some(metrics) => (metrics.accept_count, metrics.deny_count),
                None => (0, 0),
            };

            // Get actual connection counts from channel stats
            let (accept_count, gateway_faults) = channel_stats_map
                .get(channel_config_id)
                .map(|stats| (stats.successful as u64, stats.gateway_faults))
                .unwrap_or((0, 0));

            // Get last connection status for this channel
            let last_status = state
                .metrics_store
                .get_last_status(channel_config_id)
                .await
                .map(|status| match status {
                    crate::metrics::ConnectionStatus::Success => "success".to_string(),
                    crate::metrics::ConnectionStatus::Failed => "failed".to_string(),
                    crate::metrics::ConnectionStatus::GatewayFault => "gateway_fault".to_string(),
                });

            // Serialize extension_rules from managed_identity for frontend
            let extension_rules = r_managed_identity
                .as_ref()
                .and_then(|mi| match mi {
                    crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.extension_rules.as_ref(),
                    _ => None,
                })
                .map(|rules| serde_json::to_value(rules).unwrap_or(serde_json::json!({})));

            // Get latest payload for this channel
            let latest_payload = state
                .metrics_store
                .get_latest_channel_payload(channel_config_id)
                .await;

            // Get identity count for this channel (already computed above)
            let identity_count = identity_counts
                .get(channel_config_id)
                .copied()
                .unwrap_or(0);

            // Get last activity timestamp from channel stats
            let last_activity = channel_stats_map
                .get(channel_config_id)
                .and_then(|stats| stats.last_activity)
                .map(|dt| dt.to_rfc3339());

            channel_infos.push(SurfaceInfo {
                config_id: r
                    .config_id()
                    .map(|s| s.to_string()),
                name: r.name.clone(),
                description: r.description.clone(),
                listen_address: r.listen_address().to_string(),
                route: Some(r.route().to_string()),
                target_endpoint: r
                    .target_endpoint()
                    .to_string(),
                fabric_target_name: r
                    .target
                    .fabric_target_name
                    .clone(),
                enabled: r.status == crate::config::agent_surface::SurfaceStatus::Active,
                extension_rules,
                rule_count,
                accept_count,
                deny_count,
                custom_metadata: r.custom_metadata().cloned(),
                response_custom_metadata: r
                    .response_custom_metadata()
                    .cloned(),
                gateway_faults,
                last_status,
                latest_payload,
                channel_type: Some(r.channel_type()),
                protocol: Some(r.channel_protocol()),
                rate_limit: r
                    .access_point
                    .rate_limit
                    .clone(),
                opa_enabled: r.opa_enabled(),
                mcp_tool_policies: r.mcp_tool_policies_legacy(),
                mcp_tool_policies_enabled: r
                    .target
                    .mcp_tool_policies_enabled,
                timeout: r.timeout().cloned(),
                retry: r.retry().cloned(),
                circuit_breaker: r.circuit_breaker().cloned(),
                mirror: r.mirror().cloned(),
                publish_to_did_document: r
                    .access_point
                    .publish_to_did_document,
                payment_policy: r.x402_config().cloned(),
                mpp_policy: r.mpp_config().cloned(),
                supported_extensions: r
                    .access_point
                    .supported_extensions
                    .clone(),
                primary_extension: r
                    .access_point
                    .primary_extension
                    .clone(),
                identity_count,
                last_activity,
                target_auth: r.target_auth().cloned(),
                trust_recorder: r.trust_recorder().cloned(),
                source_auth: r.source_auth().cloned(),
                managed_identity: r_managed_identity,
                issuer_id: r.issuer_id.clone(),
                outbound_listen_address: r
                    .transit
                    .as_ref()
                    .and_then(|t| {
                        t.outbound_listen_address
                            .clone()
                    }),
                outbound_credentials: r.outbound_credentials(),
            });
        }
        channel_infos
    };

    // Get port information
    let ports = PortInfo {
        proxy_channels: current_config
            .surfaces
            .iter()
            .filter(|s| {
                s.status != crate::config::agent_surface::SurfaceStatus::Deleted
                    && s.status != crate::config::agent_surface::SurfaceStatus::Disabled
            })
            .map(|s| s.listen_address().to_string())
            .collect(),
        identity_http: state
            .network_config
            .listeners
            .iter()
            .find(|l| l.protocol.to_lowercase() == "http")
            .map(|l| l.port),
        identity_https: state
            .network_config
            .listeners
            .iter()
            .find(|l| l.protocol.to_lowercase() == "https")
            .map(|l| l.port),
    };

    // Get metrics data
    // Determine bucket interval from query or use auto
    let bucket_seconds = query
        .bucket_seconds
        .unwrap_or_else(|| {
            // Auto mode: select bucket based on window
            let window_minutes = state
                .metrics_store
                .get_connections_window_minutes();
            if window_minutes < 10 {
                30 // 30 seconds
            } else if window_minutes < 60 {
                60 // 1 minute
            } else {
                300 // 5 minutes
            }
        });

    // Check if filters are active
    let has_filters = query.surface_id.is_some()
        || query.gateway_id.is_some()
        || query.identity_did.is_some()
        || query
            .transit_point
            .as_deref()
            .is_some_and(|s| !s.is_empty());

    let tp_filter = parse_tp_filter(query.transit_point.as_deref());

    // Get time series - use filtered version if filters are active, otherwise get all data
    let filtered_time_series = if has_filters {
        state
            .metrics_store
            .get_filtered_time_series(
                bucket_seconds,
                query.surface_id.as_deref(),
                query.gateway_id.as_deref(),
                query.identity_did.as_deref(),
                &tp_filter,
            )
            .await
    } else {
        state
            .metrics_store
            .get_time_series_seconds(bucket_seconds)
            .await
    };

    // Get latency time series - use filtered version if filters are active
    let filtered_latency_series = if has_filters {
        state
            .metrics_store
            .get_filtered_latency_time_series(
                bucket_seconds,
                query.surface_id.as_deref(),
                query.gateway_id.as_deref(),
                query.identity_did.as_deref(),
                &tp_filter,
            )
            .await
    } else {
        state
            .metrics_store
            .get_latency_time_series(bucket_seconds)
            .await
    };

    // When filters are active, don't include unfiltered aggregate stats

    let metrics = MetricsData {
        total_connections: if has_filters {
            0
        } else {
            state
                .metrics_store
                .get_total_connections()
                .await
        },
        avg_latency: if has_filters {
            None
        } else {
            state
                .metrics_store
                .get_average_latency()
                .await
        },
        avg_request_latency: if has_filters {
            None
        } else {
            state
                .metrics_store
                .get_average_request_latency()
                .await
        },
        avg_response_latency: if has_filters {
            None
        } else {
            state
                .metrics_store
                .get_average_response_latency()
                .await
        },
        connections_window_minutes: state
            .metrics_store
            .get_connections_window_minutes(),
        latency_window_minutes: state
            .metrics_store
            .get_latency_window_minutes(),
        bucket_seconds,
        time_series: filtered_time_series,
        channel_stats: if has_filters {
            Vec::new()
        } else {
            state
                .metrics_store
                .get_channel_stats()
                .await
        },
        source_dest_stats: if has_filters {
            Vec::new()
        } else {
            state
                .metrics_store
                .get_source_dest_stats()
                .await
        },
        latency_stats: if has_filters {
            Vec::new()
        } else {
            state
                .metrics_store
                .get_latency_stats()
                .await
        },
        latency_time_series: filtered_latency_series,
        identity_channel_stats: if let Some(ref channel_id) = query.surface_id {
            // Filter identity stats for this channel
            state
                .metrics_store
                .get_identity_channel_stats()
                .await
                .into_iter()
                .filter(|stat| &stat.channel_config_id == channel_id)
                .collect()
        } else {
            state
                .metrics_store
                .get_identity_channel_stats()
                .await
        },
    };

    // Calculate uptime
    let start_time = PROXY_START_TIME
        .get()
        .copied()
        .unwrap_or_else(SystemTime::now);
    let uptime_seconds = SystemTime::now()
        .duration_since(start_time)
        .unwrap_or_default()
        .as_secs();

    let uptime_formatted = format_uptime(uptime_seconds);

    // Get proxy DID from VC issuer
    let proxy_did = state
        .vc_issuer
        .get_issuer_did()
        .await
        .unwrap_or_else(|_| {
            format!(
                "did:web:{}",
                state
                    .network_config
                    .did
                    .domain
            )
        });

    // Get DID document from VC issuer
    let did_document = state
        .vc_issuer
        .get_did_document()
        .await
        .unwrap_or_else(|_| {
            serde_json::json!({
                "error": "Failed to load DID document"
            })
        });

    // Read last 300 lines of log file if configured - use spawn_blocking to avoid blocking executor.
    // When the request scopes to a channel (or surface TP slice), read more
    // lines so post-filter the user still sees a useful tail.
    let log_read_limit = if query.surface_id.is_some() {
        2000
    } else {
        300
    };
    let log_dir = state
        .config
        .logging
        .log_directory
        .clone();
    let channel_filter = query.surface_id.clone();
    let tp_filter_raw = query.transit_point.clone();
    let log_entries: Vec<LogEntry> = tokio::task::spawn_blocking(move || {
        let log_lines = read_log_file(&log_dir, log_read_limit);
        log_lines
            .iter()
            .filter_map(|(offset, line)| {
                let mut entry = parse_log_entry(line)?;
                entry.file_position = *offset;
                Some(entry)
            })
            .collect::<Vec<LogEntry>>()
    })
    .await
    .unwrap_or_else(|_| vec![]);
    let mut log_entries = log_entries;
    if let Some(channel_id) = &channel_filter {
        let channel_prefix = format!("[CHANNEL:{}]", channel_id);
        log_entries.retain(|entry| {
            entry
                .message
                .contains(&channel_prefix)
        });
    }
    apply_tp_log_filter(&mut log_entries, tp_filter_raw.as_deref());
    if log_entries.len() > 300 {
        log_entries = log_entries.split_off(log_entries.len() - 300);
    }

    // Trust registry DID is now per-registry, no single shared DID to display
    let trust_registry_did: Option<String> = None;

    // Get proxy info
    let proxy_info = ProxyInfo {
        did: proxy_did,
        trust_registry_did,
        uptime_seconds,
        uptime_formatted,
        extensions_enabled: state
            .config
            .extension_inspection
            .enabled,
        watched_extensions: state
            .config
            .extension_inspection
            .watch_extensions
            .clone(),
        proxy_domain: state
            .network_config
            .did
            .domain
            .clone(),
        log_entries,
        did_document,
    };

    // Get task information if task monitor is available
    let tasks = if let Some(task_monitor) = &state.task_monitor {
        let summary = task_monitor
            .get_summary()
            .await;
        let all_tasks = task_monitor
            .get_all_tasks()
            .await;
        let metrics = task_monitor
            .get_all_metrics()
            .await;

        tracing::debug!(
            "Dashboard API - Task metrics: {} tasks with metrics: {:?}",
            metrics.len(),
            metrics
                .iter()
                .map(|m| (m.task_id.clone(), m.throughput_bytes_per_sec))
                .collect::<Vec<_>>()
        );

        Some(TasksInfo {
            summary,
            tasks: all_tasks,
            metrics,
        })
    } else {
        tracing::warn!("Dashboard API - No task_monitor available");
        None
    };

    // Get connection point listener information if available
    let connection_point_tasks = if let Some(listener_manager) = &state.connection_point_listener_manager {
        let listeners = listener_manager
            .get_active_listeners()
            .await;

        let mut total_messages = 0u64;
        let mut total_errors = 0u64;
        let mut connected = 0usize;
        let mut reconnecting = 0usize;
        let mut failed = 0usize;

        let mut tasks = Vec::new();

        for listener in listeners {
            let metrics = listener.metrics.read().await;

            total_messages += metrics.message_count;
            total_errors += metrics.error_count;

            match metrics.status {
                crate::gateways::ConnectionStatus::Connected => connected += 1,
                crate::gateways::ConnectionStatus::Reconnecting => reconnecting += 1,
                crate::gateways::ConnectionStatus::Failed => failed += 1,
            }

            let status = match metrics.status {
                crate::gateways::ConnectionStatus::Connected => "connected",
                crate::gateways::ConnectionStatus::Reconnecting => "reconnecting",
                crate::gateways::ConnectionStatus::Failed => "failed",
            };

            // Map connection point type to user-friendly task type
            let task_type = match &listener.cp_type {
                crate::gateways::connection_points::ConnectionPointType::User => "User-Created",
                crate::gateways::connection_points::ConnectionPointType::OobInviter => "OOB Inviter",
                crate::gateways::connection_points::ConnectionPointType::OobResponder => "OOB Responder",
                crate::gateways::connection_points::ConnectionPointType::OobAcceptor => "OOB Acceptor",
                crate::gateways::connection_points::ConnectionPointType::System => "System",
            };

            tasks.push(ConnectionPointTaskInfo {
                id: listener.id.clone(),
                name: listener.name.clone(),
                task_type: task_type.to_string(),
                gateway_did: listener.gateway_did.clone(),
                mediator_did: listener.mediator_did.clone(),
                status: status.to_string(),
                started_at: metrics
                    .started_at
                    .to_rfc3339(),
                last_activity: metrics
                    .last_activity
                    .map(|dt| dt.to_rfc3339()),
                message_count: metrics.message_count,
                error_count: metrics.error_count,
                reconnect_attempts: metrics.reconnect_attempts,
            });
        }

        Some(ConnectionPointTasksInfo {
            summary: ConnectionPointTasksSummary {
                total_listeners: tasks.len(),
                connected,
                reconnecting,
                failed,
                total_messages,
                total_errors,
            },
            tasks,
        })
    } else {
        None
    };

    // Get MCP proxy information if available
    let mcp_proxy_tasks = if let Some(proxy_store) = &state.mcp_proxy_store {
        match proxy_store.list_all().await {
            Ok(proxies) => {
                let mut active = 0usize;
                let mut disabled = 0usize;

                let mut tasks = Vec::new();

                for proxy in proxies {
                    match proxy.status {
                        crate::mcp_proxies::types::McpProxyStatus::Active => active += 1,
                        crate::mcp_proxies::types::McpProxyStatus::Disabled => disabled += 1,
                    }

                    let status = match proxy.status {
                        crate::mcp_proxies::types::McpProxyStatus::Active => "active",
                        crate::mcp_proxies::types::McpProxyStatus::Disabled => "disabled",
                    };

                    tasks.push(McpProxyTaskInfo {
                        id: proxy.id.clone(),
                        name: proxy.name.clone(),
                        description: proxy.description.clone(),
                        status: status.to_string(),
                        proxy_path: proxy.full_path(),
                        base_url: proxy.base_url.clone(),
                        created_at: proxy.created_at.to_rfc3339(),
                        updated_at: proxy.updated_at.to_rfc3339(),
                    });
                }

                Some(McpProxyTasksInfo {
                    summary: McpProxyTasksSummary {
                        total_proxies: tasks.len(),
                        active,
                        disabled,
                    },
                    tasks,
                })
            }
            Err(e) => {
                tracing::warn!("Failed to list MCP proxies for dashboard: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Get unread notification count if session_token provided and auth_state/notification_store available
    let unread_count = if let (Some(session_token), Some(auth_state), Some(notif_store)) =
        (&query.session_token, &state.auth_state, &state.notification_store)
    {
        if let Some((_username, user_id)) = auth_state
            .session_manager
            .validate_session(session_token)
            .await
        {
            notif_store
                .count_unread(&user_id)
                .await
                .unwrap_or(0)
        } else {
            0
        }
    } else {
        0
    };

    Ok(Json(DashboardStats {
        total_identities,
        identities,
        channels,
        ports,
        metrics,
        proxy_info,
        tasks,
        connection_point_tasks,
        mcp_proxy_tasks,
        unread_count,
    }))
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Identities created, last used, or whose caller name changed after `since`.
/// Newly issued identities have `last_used_at = None` until the first usage
/// event, so falling back to `created_at` surfaces them on the very first
/// request that creates them.
pub(crate) fn identities_changed_since(
    identities: Vec<IdentityInfo>,
    since: DateTime<Utc>,
    renamed_dids: &std::collections::HashSet<String>,
) -> Vec<IdentityInfo> {
    identities
        .into_iter()
        .filter(|id| {
            let ts = id
                .last_used_at
                .as_deref()
                .unwrap_or(id.created_at.as_str());
            renamed_dids.contains(&id.did)
                || DateTime::parse_from_rfc3339(ts)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc) > since)
                    .unwrap_or(false)
        })
        .collect()
}

async fn build_identity_list(
    identity_store: &Arc<dyn IdentityStore>,
    current_config: &crate::config::GatewayConfig,
    metrics_store: &Arc<MetricsStore>,
    agent_surface_store: Option<&Arc<crate::surfaces::FileSystemAgentSurfaceStore>>,
) -> Result<Vec<IdentityInfo>, (axum::http::StatusCode, String)> {
    build_identity_list_with(
        identity_store,
        &current_config.surfaces,
        metrics_store,
        agent_surface_store,
        CallerNameService::global(),
    )
    .await
}

pub(crate) async fn build_identity_list_with(
    identity_store: &Arc<dyn IdentityStore>,
    config_surfaces: &[crate::config::agent_surface::AgentSurface],
    metrics_store: &Arc<MetricsStore>,
    agent_surface_store: Option<&Arc<crate::surfaces::FileSystemAgentSurfaceStore>>,
    caller_names: &Arc<CallerNameService>,
) -> Result<Vec<IdentityInfo>, (axum::http::StatusCode, String)> {
    let records = identity_store
        .list_all()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load identities: {}", e)))?;

    // Includes both config surfaces and stored agent surfaces so identities
    // bound to a surface display the surface name instead of an empty cell.
    let stored_surfaces = match agent_surface_store {
        Some(store) => crate::surfaces::AgentSurfaceStore::list_all(store.as_ref())
            .await
            .unwrap_or_default(),
        None => vec![],
    };
    let mut surfaces_by_id: std::collections::HashMap<&str, &crate::config::agent_surface::AgentSurface> =
        config_surfaces
            .iter()
            .map(|s| (s.surface_id.as_str(), s))
            .collect();
    for s in &stored_surfaces {
        surfaces_by_id
            .entry(s.surface_id.as_str())
            .or_insert(s);
    }
    let managed_surfaces_by_did = surfaces_by_did(&records);

    // Get metrics to compute actual usage counts and determine active channels
    let identity_stats = metrics_store
        .get_identity_channel_stats()
        .await;

    // Build map of identity_hash -> (total_usage, primary_channel_config_id)
    // Primary channel is the one with the most usage
    let mut identity_metrics: std::collections::HashMap<String, (usize, Option<String>)> =
        std::collections::HashMap::new();

    for stat in identity_stats {
        let entry = identity_metrics
            .entry(stat.identity_hash.clone())
            .or_insert((0, None));
        entry.0 += stat.total_count;

        // Set the channel with the most usage as primary
        if entry.1.is_none() {
            entry.1 = Some(stat.channel_config_id.clone());
        }
        // If we already have a primary channel, keep the one with higher usage
        // (This is simplified - we'd need to track per-channel counts for perfect accuracy,
        // but the first one encountered will generally be a good representative)
    }

    let no_surfaces = std::collections::BTreeSet::new();
    let mut identities: Vec<IdentityInfo> = records
        .into_iter()
        .map(|r| {
            // Determine channel: prefer the one from identity store (where created),
            // but if missing, use the primary channel from metrics (where it's being used)
            let (usage_count, metrics_channel_id) = identity_metrics
                .get(&r.identity_hash)
                .map(|(count, chan)| (*count as u64, chan.clone()))
                .unwrap_or((r.usage_count, None));

            let channel_config_id = r
                .channel_config_id
                .clone()
                .or(metrics_channel_id);
            let surface = channel_config_id
                .as_deref()
                .and_then(|id| {
                    surfaces_by_id
                        .get(id)
                        .copied()
                });
            let channel_name = surface.map(|s| s.name.clone());

            let origin = r.effective_origin();
            let managed_surface = surface.filter(|_| origin == Some(IdentityOrigin::Managed));
            let managed_name: Option<ManagedDisplayName> = managed_surface.map(|s| {
                resolve_managed_display_name(
                    s,
                    managed_surfaces_by_did
                        .get(&r.did)
                        .unwrap_or(&no_surfaces),
                )
            });
            let caller_name = (origin == Some(IdentityOrigin::ExternalCaller))
                .then(|| caller_names.lookup_or_spawn(&r.did))
                .flatten();
            let naming = naming_for(origin, managed_name.as_ref(), caller_name.as_ref());
            let is_managed = origin == Some(IdentityOrigin::Managed);
            let surface_id = channel_config_id
                .clone()
                .filter(|_| is_managed);
            let surface_name = managed_surface
                .map(|s| s.name.trim().to_string())
                .filter(|name| !name.is_empty());
            let principal = if is_managed {
                credential_principal(&r.identity_fields)
            } else {
                None
            };

            IdentityInfo {
                group_key: group_key(origin, surface_id.as_deref(), &r.did),
                did: r.did.clone(),
                created_at: r.created_at.to_rfc3339(),
                identity_hash: r.identity_hash.clone(),
                agent_identity: serde_json::to_value(&r.identity_fields).unwrap_or_default(),
                usage_count,
                last_used_at: r
                    .last_used_at
                    .map(|dt| dt.to_rfc3339()),
                channel_config_id,
                channel_name,
                is_local: r.is_local,
                verified: r.verified,
                channel_usage: r
                    .channel_usage
                    .iter()
                    .map(|cu| {
                        serde_json::json!({
                            "channel_config_id": cu.channel_config_id,
                            "usage_count": cu.usage_count,
                            "last_used_at": cu.last_used_at.to_rfc3339(),
                        })
                    })
                    .collect(),
                origin,
                display_name: naming.display_name,
                display_name_source: naming.display_name_source,
                display_name_verified: naming.display_name_verified,
                surface_id,
                surface_name,
                credential_principal: principal,
                name_conflict: naming.name_conflict,
            }
        })
        .collect();

    let principal_names = PrincipalNames::load(
        identities
            .iter()
            .filter_map(|i| {
                i.credential_principal
                    .as_ref()
            }),
    )
    .await;
    for identity in &mut identities {
        identity.credential_principal = identity
            .credential_principal
            .take()
            .map(|p| principal_names.named(p));
    }
    Ok(identities)
}

/// Helper function to build channel list
async fn build_channel_list(
    current_config: &crate::config::GatewayConfig,
    metrics_store: &Arc<MetricsStore>,
) -> Vec<SurfaceInfo> {
    let channel_stats = metrics_store
        .get_channel_stats()
        .await;
    let channel_stats_map: std::collections::HashMap<String, &crate::metrics::SurfaceStats> = channel_stats
        .iter()
        .map(|s| (s.channel_config_id.clone(), s))
        .collect();

    let mut channel_infos = Vec::new();

    for r in current_config
        .surfaces
        .iter()
        .filter(|s| s.status != crate::config::agent_surface::SurfaceStatus::Deleted)
    {
        let r_managed_identity = r.managed_identity();
        let rule_count = r_managed_identity
            .as_ref()
            .and_then(|mi| match mi {
                crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.extension_rules.as_ref(),
                _ => None,
            })
            .map_or(0, |rules| rules.rules.len());

        let channel_config_id = r
            .config_id()
            .unwrap_or("unknown");

        let (_rule_accept_count, deny_count) = match metrics_store
            .get_rule_metrics(channel_config_id)
            .await
        {
            Some(metrics) => (metrics.accept_count, metrics.deny_count),
            None => (0, 0),
        };

        let (accept_count, gateway_faults) = channel_stats_map
            .get(channel_config_id)
            .map(|stats| (stats.successful as u64, stats.gateway_faults))
            .unwrap_or((0, 0));

        let last_status = metrics_store
            .get_last_status(channel_config_id)
            .await
            .map(|status| match status {
                crate::metrics::ConnectionStatus::Success => "success".to_string(),
                crate::metrics::ConnectionStatus::Failed => "failed".to_string(),
                crate::metrics::ConnectionStatus::GatewayFault => "gateway_fault".to_string(),
            });

        let extension_rules = r_managed_identity
            .as_ref()
            .and_then(|mi| match mi {
                crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.extension_rules.as_ref(),
                _ => None,
            })
            .map(|rules| serde_json::to_value(rules).unwrap_or(serde_json::json!({})));

        let latest_payload = metrics_store
            .get_latest_channel_payload(channel_config_id)
            .await;

        let last_activity = channel_stats_map
            .get(channel_config_id)
            .and_then(|stats| stats.last_activity)
            .map(|dt| dt.to_rfc3339());

        channel_infos.push(SurfaceInfo {
            config_id: r
                .config_id()
                .map(|s| s.to_string()),
            name: r.name.clone(),
            description: r.description.clone(),
            listen_address: r.listen_address().to_string(),
            route: Some(r.route().to_string()),
            target_endpoint: r
                .target_endpoint()
                .to_string(),
            fabric_target_name: r
                .target
                .fabric_target_name
                .clone(),
            enabled: r.status == crate::config::agent_surface::SurfaceStatus::Active,
            extension_rules,
            rule_count,
            accept_count,
            deny_count,
            custom_metadata: r.custom_metadata().cloned(),
            response_custom_metadata: r
                .response_custom_metadata()
                .cloned(),
            gateway_faults,
            last_status,
            latest_payload,
            channel_type: Some(r.channel_type()),
            protocol: Some(r.channel_protocol()),
            rate_limit: r
                .access_point
                .rate_limit
                .clone(),
            opa_enabled: r.opa_enabled(),
            mcp_tool_policies: r.mcp_tool_policies_legacy(),
            mcp_tool_policies_enabled: r
                .target
                .mcp_tool_policies_enabled,
            timeout: r.timeout().cloned(),
            retry: r.retry().cloned(),
            circuit_breaker: r.circuit_breaker().cloned(),
            mirror: r.mirror().cloned(),
            publish_to_did_document: r
                .access_point
                .publish_to_did_document,
            payment_policy: r.x402_config().cloned(),
            mpp_policy: r.mpp_config().cloned(),
            supported_extensions: r
                .access_point
                .supported_extensions
                .clone(),
            primary_extension: r
                .access_point
                .primary_extension
                .clone(),
            identity_count: 0, // Not calculated in delta endpoint
            last_activity,
            target_auth: r.target_auth().cloned(),
            trust_recorder: r.trust_recorder().cloned(),
            source_auth: r.source_auth().cloned(),
            managed_identity: r_managed_identity,
            issuer_id: r.issuer_id.clone(),
            outbound_listen_address: r
                .transit
                .as_ref()
                .and_then(|t| {
                    t.outbound_listen_address
                        .clone()
                }),
            outbound_credentials: r.outbound_credentials(),
        });
    }

    channel_infos
}

/// Read log entries after the given byte offset in the active log file.
///
/// Seeks directly to `after_position`, skips to the next complete line,
/// then reads all remaining entries. If more than `max_lines` entries exist,
/// only the **last** (freshest) `max_lines` are returned so the UX always
/// shows the end of the file.
fn read_log_entries_since(
    log_directory: &Option<String>,
    after_position: u64,
    max_lines: usize,
) -> Option<Vec<LogEntry>> {
    use std::io::{BufRead, Seek, SeekFrom};
    use std::path::PathBuf;

    let log_dir = log_directory.as_ref()?;
    let log_path = PathBuf::from(log_dir).join("agent-gateway.log");

    if !log_path.exists() {
        return None;
    }

    let mut file = std::fs::File::open(&log_path).ok()?;
    let file_len = file
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0);

    if after_position >= file_len {
        return None;
    }

    // Seek and discard the (likely partial) first line
    let _ = file.seek(SeekFrom::Start(after_position));
    let mut reader = std::io::BufReader::new(&file);
    let mut partial = String::new();
    let partial_len = reader
        .read_line(&mut partial)
        .unwrap_or(0);
    let mut offset = after_position + partial_len as u64;

    let mut entries = Vec::new();
    for content in reader
        .lines()
        .map_while(Result::ok)
    {
        let line_offset = offset;
        offset += content.len() as u64 + 1;

        if let Some(mut entry) = parse_log_entry(&content) {
            entry.file_position = line_offset;
            entries.push(entry);
        }
    }

    // Keep only the last max_lines (freshest from end of file)
    if entries.len() > max_lines {
        entries = entries.split_off(entries.len() - max_lines);
    }

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Parse a log line into a structured LogEntry
/// Supports two formats:
/// 1. JSON: {"timestamp":"2024-01-07T10:30:45.123Z","level":"INFO","fields":{"message":"..."}}
/// 2. Plain text: "2024-01-07T10:30:45.123Z INFO message text" (with optional ANSI codes)
fn parse_log_entry(line: &str) -> Option<LogEntry> {
    // Try JSON format first (starts with '{')
    if line
        .trim_start()
        .starts_with('{')
    {
        return parse_json_log_entry(line);
    }

    // Fall back to plain text format
    parse_plain_text_log_entry(line)
}

/// Parse JSON-formatted log entry
fn parse_json_log_entry(line: &str) -> Option<LogEntry> {
    let json: serde_json::Value = serde_json::from_str(line).ok()?;

    let timestamp_str = json
        .get("timestamp")?
        .as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
        .ok()?
        .timestamp_millis();

    let level = json
        .get("level")?
        .as_str()?
        .to_string();

    // Message can be in "fields.message" or directly in "message"
    let message = json
        .get("fields")
        .and_then(|f| f.get("message"))
        .and_then(|m| m.as_str())
        .or_else(|| {
            json.get("message")
                .and_then(|m| m.as_str())
        })
        .unwrap_or("")
        .to_string();

    Some(LogEntry {
        timestamp,
        level,
        message,
        file_position: 0,
    })
}

/// Parse plain text log entry with optional ANSI codes
fn parse_plain_text_log_entry(line: &str) -> Option<LogEntry> {
    // Find the first space - this separates timestamp from rest
    let first_space = line.find(' ')?;

    // Extract and clean timestamp (remove ANSI codes)
    let timestamp_part = &line[..first_space];
    let clean_timestamp = strip_ansi_codes(timestamp_part);

    // Parse timestamp
    let timestamp = DateTime::parse_from_rfc3339(&clean_timestamp)
        .ok()?
        .timestamp_millis();

    // Get the rest of the line after timestamp, ignoring level-column padding
    let rest = line[first_space + 1..].trim_start();

    // Find the next space to separate level from message
    let second_space = rest.find(' ')?;

    // Extract level (strip ANSI codes from level)
    let level_part = &rest[..second_space];
    let level = strip_ansi_codes(level_part);

    // Message is everything after level - KEEP ANSI CODES for colored output
    let message = rest[second_space + 1..].to_string();

    Some(LogEntry {
        timestamp,
        level,
        message,
        file_position: 0,
    })
}

/// Strip ANSI color codes from a string
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Skip until we find 'm'
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::parse_plain_text_log_entry;

    mod identity_naming {
        use std::collections::{HashMap, HashSet};
        use std::sync::Arc;
        use std::time::Duration;

        use async_trait::async_trait;
        use chrono::Utc;
        use serde_json::{Value, json};

        use super::super::{IdentityInfo, build_identity_list_with, identities_changed_since};
        use crate::config::agent_surface::AgentSurface;
        use crate::identity::IdentityStore;
        use crate::identity::filesystem::{AgentIdentityRecord, IdentityOrigin};
        use crate::identity::test_helpers::{MockIdentityStore, test_surface_identity_record};
        use crate::metrics::MetricsStore;
        use crate::observability::caller_names::{CallerNameService, CallerNameSources};

        const CALLER_DID: &str = "did:web:acme.com:billing";

        struct FakeSources;

        #[async_trait]
        impl CallerNameSources for FakeSources {
            async fn resolve_did_document(
                &self,
                did: &str,
            ) -> Result<Value, String> {
                Ok(json!({ "id": did, "alsoKnownAs": ["acme.com/@billing"] }))
            }

            async fn verify_agent_name(
                &self,
                _name: &str,
            ) -> Result<String, String> {
                Ok(CALLER_DID.to_string())
            }

            async fn fetch_agent_card(
                &self,
                _url: &str,
            ) -> Result<Value, String> {
                Err("no card".to_string())
            }
        }

        fn surface(
            id: &str,
            name: &str,
        ) -> AgentSurface {
            AgentSurface {
                surface_id: id.to_string(),
                name: name.to_string(),
                ..Default::default()
            }
        }

        fn managed(
            did: &str,
            surface_id: &str,
        ) -> AgentIdentityRecord {
            let mut record = test_surface_identity_record(did, surface_id);
            record.origin = Some(IdentityOrigin::Managed);
            record
        }

        fn caller(did: &str) -> AgentIdentityRecord {
            let mut record = test_surface_identity_record(did, "oxygen");
            record.origin = Some(IdentityOrigin::ExternalCaller);
            record.is_local = false;
            record
                .identity_fields
                .insert("certificate_id".to_string(), json!("NITROGEN"));
            record
        }

        async fn list(
            records: Vec<AgentIdentityRecord>,
            surfaces: &[AgentSurface],
            caller_names: &Arc<CallerNameService>,
        ) -> HashMap<String, IdentityInfo> {
            let store = MockIdentityStore::new();
            for record in records {
                store
                    .create(record)
                    .await
                    .unwrap();
            }
            let store: Arc<dyn IdentityStore> = Arc::new(store);
            build_identity_list_with(&store, surfaces, &Arc::new(MetricsStore::new(10)), None, caller_names)
                .await
                .unwrap()
                .into_iter()
                .map(|i| (i.did.clone(), i))
                .collect()
        }

        fn names() -> Arc<CallerNameService> {
            Arc::new(CallerNameService::new(Arc::new(FakeSources)))
        }

        async fn wait_for_caller_name(caller_names: &Arc<CallerNameService>) {
            for _ in 0..200 {
                if caller_names
                    .lookup_or_spawn(CALLER_DID)
                    .is_some()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("caller name never resolved");
        }

        #[tokio::test]
        async fn test_managed_row_carries_surface_name_origin_and_principal() {
            let mut record = managed("did:example:oxygen", "oxygen");
            record
                .identity_fields
                .insert("certificate_id".to_string(), json!("NITROGEN"));
            let rows = list(vec![record], &[surface("oxygen", "OXYGEN")], &names()).await;
            let row = serde_json::to_value(&rows["did:example:oxygen"]).unwrap();
            assert_eq!(row["origin"], json!("managed"));
            assert_eq!(row["display_name"], json!("OXYGEN"));
            assert_eq!(row["display_name_source"], json!("surface_name"));
            assert_eq!(row["surface_id"], json!("oxygen"));
            assert_eq!(row["surface_name"], json!("OXYGEN"));
            assert_eq!(row["credential_principal"], json!({ "kind": "certificate", "id": "NITROGEN" }));
            assert_eq!(row["group_key"], json!("surface:oxygen"));
            assert!(
                row.get("display_name_verified")
                    .is_none()
            );
            assert!(
                row.get("name_conflict")
                    .is_none()
            );
        }

        #[tokio::test]
        async fn test_conflicting_did_has_conflict_marker_and_no_name() {
            let mut record = managed("did:example:shared", "oxygen");
            record
                .channel_usage
                .push(crate::identity::filesystem::ChannelUsage {
                    channel_config_id: "helium".to_string(),
                    usage_count: 1,
                    last_used_at: Utc::now(),
                });
            let rows = list(vec![record], &[surface("oxygen", "OXYGEN"), surface("helium", "HELIUM")], &names()).await;
            let row = &rows["did:example:shared"];
            assert!(row.name_conflict);
            assert_eq!(row.display_name, None);
            let json = serde_json::to_value(row).unwrap();
            assert_eq!(json["name_conflict"], json!(true));
            assert!(
                json.get("display_name")
                    .is_none()
            );
        }

        #[tokio::test]
        async fn test_external_row_uses_caller_name_and_never_surface_fields() {
            let caller_names = names();
            let rows = list(vec![caller(CALLER_DID)], &[surface("oxygen", "OXYGEN")], &caller_names).await;
            let first = serde_json::to_value(&rows[CALLER_DID]).unwrap();
            assert_eq!(first["origin"], json!("external_caller"));
            assert_eq!(first["group_key"], json!(format!("did:{CALLER_DID}")));
            for absent in ["display_name", "surface_id", "surface_name", "credential_principal", "name_conflict"] {
                assert!(first.get(absent).is_none(), "{absent} must be omitted for a caller row: {first}");
            }

            wait_for_caller_name(&caller_names).await;
            let rows = list(vec![caller(CALLER_DID)], &[surface("oxygen", "OXYGEN")], &caller_names).await;
            let named = serde_json::to_value(&rows[CALLER_DID]).unwrap();
            assert_eq!(named["display_name"], json!("acme.com/@billing"));
            assert_eq!(named["display_name_source"], json!("agent_name"));
            assert_eq!(named["display_name_verified"], json!(true));
            assert!(
                named
                    .get("surface_name")
                    .is_none()
            );
        }

        #[tokio::test]
        async fn test_managed_row_ignores_resolved_caller_name_for_same_did() {
            let caller_names = names();
            caller_names.lookup_or_spawn(CALLER_DID);
            wait_for_caller_name(&caller_names).await;
            let rows = list(vec![managed(CALLER_DID, "oxygen")], &[surface("oxygen", "OXYGEN")], &caller_names).await;
            assert_eq!(
                rows[CALLER_DID]
                    .display_name
                    .as_deref(),
                Some("OXYGEN")
            );
            assert!(!rows[CALLER_DID].display_name_verified);
        }

        #[tokio::test]
        async fn test_legacy_row_json_omits_new_fields() {
            let rows = list(vec![test_surface_identity_record("did:example:legacy", "gone")], &[], &names()).await;
            let json = serde_json::to_value(&rows["did:example:legacy"]).unwrap();
            let keys: HashSet<&str> = json
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            let expected: HashSet<&str> = [
                "did",
                "created_at",
                "identity_hash",
                "agent_identity",
                "usage_count",
                "last_used_at",
                "channel_config_id",
                "is_local",
                "verified",
                "channel_usage",
                "group_key",
            ]
            .into();
            assert_eq!(keys, expected);
            assert_eq!(json["group_key"], json!("did:did:example:legacy"));
        }

        #[test]
        fn test_identity_info_deserializes_payload_without_new_fields() {
            let info: IdentityInfo = serde_json::from_value(json!({
                "did": "did:example:a", "created_at": "2026-01-01T00:00:00Z", "identity_hash": "h",
                "agent_identity": {}, "usage_count": 0, "last_used_at": null, "is_local": true, "verified": false
            }))
            .unwrap();
            assert_eq!(info.origin, None);
            assert!(!info.name_conflict);
            assert_eq!(info.group_key, "");
        }

        #[tokio::test]
        async fn test_delta_includes_did_whose_caller_name_changed() {
            let caller_names = names();
            let mut record = caller(CALLER_DID);
            record.last_used_at = Some(Utc::now() - chrono::Duration::hours(2));
            record.created_at = Utc::now() - chrono::Duration::hours(2);
            let since = Utc::now() - chrono::Duration::minutes(1);

            let rows: Vec<IdentityInfo> = list(vec![record.clone()], &[], &caller_names)
                .await
                .into_values()
                .collect();
            let renamed: HashSet<String> = caller_names
                .changed_since(since)
                .into_iter()
                .collect();
            assert!(identities_changed_since(rows, since, &renamed).is_empty());

            wait_for_caller_name(&caller_names).await;
            let rows: Vec<IdentityInfo> = list(vec![record], &[], &caller_names)
                .await
                .into_values()
                .collect();
            let renamed: HashSet<String> = caller_names
                .changed_since(since)
                .into_iter()
                .collect();
            let delta = identities_changed_since(rows, since, &renamed);
            assert_eq!(delta.len(), 1);
            assert_eq!(
                delta[0]
                    .display_name
                    .as_deref(),
                Some("acme.com/@billing")
            );
        }
    }

    #[test]
    fn parses_padded_info_log_level() {
        let entry = parse_plain_text_log_entry("2026-09-17T12:34:56.123456Z  INFO gateway started")
            .expect("INFO log should parse");

        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.message, "gateway started");
    }

    #[test]
    fn parses_padded_warn_log_level() {
        let entry = parse_plain_text_log_entry("2026-09-17T12:34:56.123456Z  WARN request denied")
            .expect("WARN log should parse");

        assert_eq!(entry.level, "WARN");
        assert_eq!(entry.message, "request denied");
    }

    #[test]
    fn parses_unpadded_error_log_level() {
        let entry = parse_plain_text_log_entry("2026-09-17T12:34:56.123456Z ERROR upstream unavailable")
            .expect("ERROR log should parse");

        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.message, "upstream unavailable");
    }

    #[test]
    fn parses_unpadded_debug_log_level() {
        let entry = parse_plain_text_log_entry("2026-09-17T12:34:56.123456Z DEBUG request details")
            .expect("DEBUG log should parse");

        assert_eq!(entry.level, "DEBUG");
        assert_eq!(entry.message, "request details");
    }
}

/// Read the last N lines from the log file, returning (byte_offset, line) pairs.
fn read_log_file(
    log_directory: &Option<String>,
    max_lines: usize,
) -> Vec<(u64, String)> {
    use std::io::{BufRead, Read, Seek, SeekFrom};
    use std::path::PathBuf;

    let log_dir = match log_directory {
        Some(dir) => dir,
        None => {
            return vec![(0, "Logging to stdout only - no log file configured".to_string())];
        }
    };

    let log_path = PathBuf::from(log_dir).join("agent-gateway.log");

    if !log_path.exists() {
        return vec![(0, format!("Log file not found: {:?}", log_path))];
    }

    match std::fs::File::open(&log_path) {
        Ok(mut file) => {
            // Read only the tail of the file to avoid loading hundreds of MB into memory.
            // Seek backwards from the end, reading a chunk that is very likely to contain
            // at least `max_lines` lines (assuming ~512 bytes per log line on average).
            let file_len = file
                .metadata()
                .map(|m| m.len())
                .unwrap_or(0);
            let tail_bytes = (max_lines as u64) * 512;

            if file_len > tail_bytes {
                let seek_pos = file_len - tail_bytes;
                let _ = file.seek(SeekFrom::Start(seek_pos));
                // Read and discard the first (likely partial) line after seeking
                let mut reader = std::io::BufReader::new(&file);
                let mut partial = String::new();
                let partial_len = reader
                    .read_line(&mut partial)
                    .unwrap_or(0);
                let mut offset = seek_pos + partial_len as u64;

                let mut lines: Vec<(u64, String)> = Vec::new();
                for content in reader
                    .lines()
                    .map_while(Result::ok)
                {
                    let line_offset = offset;
                    offset += content.len() as u64 + 1;
                    lines.push((line_offset, content));
                }

                let start = lines
                    .len()
                    .saturating_sub(max_lines);
                lines[start..].to_vec()
            } else {
                // File is small enough to read entirely
                let mut content = String::new();
                let _ = file.read_to_string(&mut content);
                let mut offset: u64 = 0;
                let mut lines: Vec<(u64, String)> = Vec::new();
                for line_str in content.lines() {
                    lines.push((offset, line_str.to_string()));
                    offset += line_str.len() as u64 + 1;
                }
                let start = lines
                    .len()
                    .saturating_sub(max_lines);
                lines[start..].to_vec()
            }
        }
        Err(e) => {
            vec![(0, format!("Failed to read log file: {}", e))]
        }
    }
}

/// Channel-specific metrics data
#[derive(Serialize, Deserialize)]
pub struct ChannelMetricsData {
    pub channel_config_id: String,
    pub time_series: Vec<crate::metrics::TimeSeriesPoint>,
    pub latency_time_series: Vec<crate::metrics::LatencyTimeSeriesPoint>,
}

/// API endpoint to get channel-specific metrics by config_id
pub async fn get_surface_metrics(
    State(state): State<DashboardState>,
    axum::extract::Path(channel_config_id): axum::extract::Path<String>,
) -> Result<Json<ChannelMetricsData>, (axum::http::StatusCode, String)> {
    // Get time series data for this channel by config_id
    let time_series = state
        .metrics_store
        .get_time_series_by_channel(&channel_config_id)
        .await;
    let latency_time_series = state
        .metrics_store
        .get_latency_time_series_by_channel(&channel_config_id)
        .await;

    Ok(Json(ChannelMetricsData {
        channel_config_id,
        time_series,
        latency_time_series,
    }))
}

/// Hierarchical metrics response
#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct HierarchicalMetricsData {
    pub connections: std::collections::HashMap<String, crate::metrics::SurfaceMetricsData>,
}

/// Flattened channel metrics data for frontend (without trace_id level)
#[derive(Serialize, Deserialize)]
pub struct FlattenedChannelMetricsData {
    pub sources: std::collections::HashMap<
        String,
        std::collections::HashMap<String, std::collections::HashMap<String, Vec<crate::metrics::ConnectionDataPoint>>>,
    >, // source -> identity -> destination -> datapoints (flattened from all trace_ids)
    pub rule_triggers: Vec<crate::metrics::RuleValidationDataPoint>,
}

/// Flattened hierarchical metrics response for frontend
#[derive(Serialize, Deserialize)]
pub struct FlattenedHierarchicalMetricsData {
    pub connections: std::collections::HashMap<String, FlattenedChannelMetricsData>,
}

/// API endpoint to get hierarchical metrics data
pub async fn get_hierarchical_metrics(
    State(state): State<DashboardState>
) -> Result<Json<FlattenedHierarchicalMetricsData>, (axum::http::StatusCode, String)> {
    let connections = state
        .metrics_store
        .get_hierarchical_connections()
        .await;

    // Flatten trace_id level for frontend compatibility
    let mut flattened_connections = std::collections::HashMap::new();

    for (channel_id, channel_data) in connections {
        let mut flattened_sources = std::collections::HashMap::new();

        for (source, identities) in channel_data.sources {
            let mut flattened_identities = std::collections::HashMap::new();

            for (identity, destinations) in identities {
                let mut flattened_destinations = std::collections::HashMap::new();

                for (destination, trace_ids) in destinations {
                    // Flatten all trace_ids into a single Vec
                    let mut all_datapoints = Vec::new();
                    for (_trace_id, datapoints) in trace_ids {
                        all_datapoints.extend(datapoints);
                    }
                    flattened_destinations.insert(destination, all_datapoints);
                }

                flattened_identities.insert(identity, flattened_destinations);
            }

            flattened_sources.insert(source, flattened_identities);
        }

        flattened_connections.insert(
            channel_id,
            FlattenedChannelMetricsData {
                sources: flattened_sources,
                rule_triggers: channel_data.rule_triggers,
            },
        );
    }

    Ok(Json(FlattenedHierarchicalMetricsData {
        connections: flattened_connections,
    }))
}

/// API endpoint to get UCP operation statistics for a channel
pub async fn get_ucp_operation_stats(
    State(state): State<DashboardState>,
    axum::extract::Path(channel_config_id): axum::extract::Path<String>,
) -> Result<Json<Vec<crate::metrics::types::UcpOperationStats>>, (axum::http::StatusCode, String)> {
    let stats = state
        .metrics_store
        .get_ucp_operation_stats(&channel_config_id)
        .await;
    Ok(Json(stats))
}

/// Query parameters for the system-metrics endpoint.
#[derive(Deserialize)]
pub struct SystemMetricsQuery {
    /// Optional time range string: "1h", "6h", "12h", "24h".
    /// Defaults to returning all available samples when omitted.
    #[serde(default)]
    pub time_range: Option<String>,
    /// Optional ISO-8601 timestamp.  When provided, only samples **after**
    /// this timestamp are returned (exclusive).  Takes precedence over
    /// `time_range` when both are supplied.
    #[serde(default)]
    pub since: Option<String>,
}

/// API endpoint to get system CPU/memory metrics history.
pub async fn get_system_metrics(
    State(state): State<DashboardState>,
    Query(query): Query<SystemMetricsQuery>,
) -> Result<Json<crate::observability::SystemMetricsResponse>, (axum::http::StatusCode, String)> {
    // `since` (ISO-8601 timestamp) takes precedence; fall back to `time_range`.
    let since = query
        .since
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .or_else(|| {
            query
                .time_range
                .as_deref()
                .and_then(|range| {
                    let duration = match range {
                        "10m" => Some(chrono::Duration::minutes(10)),
                        "1h" => Some(chrono::Duration::hours(1)),
                        "6h" => Some(chrono::Duration::hours(6)),
                        "12h" => Some(chrono::Duration::hours(12)),
                        "24h" => Some(chrono::Duration::hours(24)),
                        _ => None,
                    };
                    duration.map(|d| chrono::Utc::now() - d)
                })
        });

    match &state.system_metrics_store {
        Some(store) => Ok(Json(
            store
                .get_response_since(since)
                .await,
        )),
        None => Ok(Json(crate::observability::SystemMetricsResponse {
            system_info: SystemInfo {
                name: None,
                kernel_version: None,
                os_version: None,
                host_name: None,
                uptime_seconds: 0,
            },
            samples: vec![],
            current: None,
        })),
    }
}
