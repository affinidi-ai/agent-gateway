//! Type definitions for metrics tracking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type alias for trace ID to datapoints mapping
pub type TraceDataPoints = HashMap<String, Vec<ConnectionDataPoint>>;

/// Type alias for destination to trace datapoints mapping
pub type DestinationTraceMap = HashMap<String, TraceDataPoints>;

/// Type alias for identity to destination mapping
pub type IdentityDestinationMap = HashMap<String, DestinationTraceMap>;

/// Type alias for source to identity mapping
pub type SourceIdentityMap = HashMap<String, IdentityDestinationMap>;

/// Direction of the connection flow
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionDirection {
    /// Request from source to target
    Request,
    /// Response from target to source
    Response,
}

fn default_direction() -> ConnectionDirection {
    ConnectionDirection::Request
}

/// Type of metric being recorded
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MetricType {
    /// Metrics from channel (agent-to-agent) communication
    Channel,
    /// Metrics from MCP proxy usage
    McpProxy,
}

fn default_metric_type() -> MetricType {
    MetricType::Channel
}

/// Slice predicate for the surface dashboard. Lets a query target the
/// channel as a whole (Aggregated) or just the inbound Access Point
/// (`AccessPoint`) or a single outbound Transit Point by alias
/// (`TransitPoint`). Maps directly onto `ConnectionMetric.transit_point`
/// where `None` == AP and `Some(alias)` == TP.
#[derive(Debug, Clone, Default)]
pub enum TransitPointFilter {
    #[default]
    Aggregated,
    AccessPoint,
    TransitPoint(String),
}

impl TransitPointFilter {
    /// Returns true when the given metric should be included by this
    /// filter.
    pub fn matches(
        &self,
        transit_point: Option<&str>,
    ) -> bool {
        match self {
            TransitPointFilter::Aggregated => true,
            TransitPointFilter::AccessPoint => transit_point.is_none(),
            TransitPointFilter::TransitPoint(alias) => transit_point == Some(alias.as_str()),
        }
    }
}

/// Connection status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Success,
    Failed,
    GatewayFault,
}

/// Connection metrics entry (legacy format for in-memory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetric {
    pub timestamp: DateTime<Utc>,
    pub channel_config_id: String,
    pub source: String,
    pub destination: String,
    pub status: ConnectionStatus,
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_hash: Option<String>,
    #[serde(default = "default_direction")]
    pub direction: ConnectionDirection,
    pub trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ucp_operation: Option<String>, // UCP operation type
    /// Transit Point alias when this metric was emitted by an outbound
    /// (G2A) hop. `None` means the metric was emitted by the inbound
    /// Access Point. Used to slice surface dashboards per-AP/per-TP.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transit_point: Option<String>,
    /// Active surface variant alias. Identifies which variant of the
    /// channel handled the connection so dashboards can slice
    /// per-variant. `None` for channels with no variants or recorders
    /// that don't supply one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub variant_alias: Option<String>,
    #[serde(default = "default_metric_type")]
    pub metric_type: MetricType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_request_latency_ms: Option<u64>, // Gateway pre-processing time (auth, policy, extensions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_response_latency_ms: Option<u64>, // Gateway response processing time (URL rewrite, VP injection, validation)
    // Total latency from receiving request to returning response
    #[serde(default)]
    pub total_latency_ms: u64,
    // Enhanced distributed tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<String>,
    // Enhanced metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,
}

/// Hierarchical connection data point for storage efficiency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDataPoint {
    pub timestamp: DateTime<Utc>,
    pub status: ConnectionStatus,
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_hash: Option<String>,
    #[serde(default = "default_direction")]
    pub direction: ConnectionDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ucp_operation: Option<String>, // UCP operation type (e.g., "discovery", "checkout", "payment")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transit_point: Option<String>,
    /// Active surface variant alias. See `ConnectionMetric::variant_alias`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub variant_alias: Option<String>,
    #[serde(default = "default_metric_type")]
    pub metric_type: MetricType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_request_latency_ms: Option<u64>, // Gateway pre-processing time (auth, policy, extensions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_response_latency_ms: Option<u64>, // Gateway response processing time (URL rewrite, VP injection, validation)
    // Total latency from receiving request to returning response
    #[serde(default)]
    pub total_latency_ms: u64,
    // Enhanced distributed tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<String>,
    // Enhanced metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,
}

/// Rule validation data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationDataPoint {
    pub timestamp: DateTime<Utc>,
    pub accepted: bool,
}

/// Time-series data point for graphing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: String,
    pub count: usize,
    pub rule_accepts: usize,
    pub rule_denies: usize,
    pub failed: usize,
    pub gateway_faults: usize,
}

/// Latency time-series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyTimeSeriesPoint {
    pub timestamp: String,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub sample_count: usize,
}

/// Channel connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceStats {
    pub channel_config_id: String,
    pub total_connections: usize,
    pub successful: usize,
    pub failed: usize,
    pub gateway_faults: usize,
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
}

/// Identity-channel connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChannelStats {
    pub identity_hash: String,
    pub channel_config_id: String,
    pub total_count: usize,
    pub success_count: usize,
    pub deny_count: usize,
    pub fault_count: usize,
}

/// Latency statistics by channel and source-destination pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub channel_config_id: String,
    pub source: String,
    pub destination: String,
    pub avg_latency_ms: f64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub sample_count: usize,
}

/// Rule validation metrics per channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetric {
    pub channel_config_id: String,
    pub accept_count: u64,
    pub deny_count: u64,
}

/// Timestamped rule validation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationEvent {
    pub timestamp: DateTime<Utc>,
    pub channel_config_id: String,
    pub accepted: bool,
}

/// Channel metrics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceMetricsData {
    #[serde(default)]
    pub sources: SourceIdentityMap, // source -> identity -> destination -> trace_id -> datapoints
    #[serde(default)]
    pub rule_triggers: Vec<RuleValidationDataPoint>,
}

/// Complete metrics data for persistence (hierarchical format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsData {
    #[serde(default)]
    pub connections: HashMap<String, SurfaceMetricsData>,
}

/// Result of truncating old metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruncateMetricsResult {
    pub connections_removed: usize,
    pub events_removed: usize,
    pub connections_retained: usize,
    pub events_retained: usize,
}

/// Source-destination statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDestStats {
    pub channel_config_id: String,
    pub source: String,
    pub destination: String,
    pub total_connections: usize,
    pub successful: usize,
    pub failed: usize,
    pub count: usize, // Alias for total_connections
}

/// UCP operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcpOperationStats {
    pub operation: String, // e.g., "discovery", "checkout", "payment"
    pub count: usize,
    pub successful: usize,
    pub failed: usize,
    pub percentage: f64, // Percentage of total UCP traffic
}
