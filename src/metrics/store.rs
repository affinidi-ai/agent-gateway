//! Metrics store implementation

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::trace;

use crate::metrics::types::*;

pub struct MetricsStore {
    /// Recent connections (limited to last 1000)
    connections: Arc<RwLock<Vec<ConnectionMetric>>>,
    /// Maximum number of connections to keep in memory
    max_connections: usize,
    /// Optional WebSocket state for broadcasting updates
    ws_state: Option<Arc<crate::server::WsState>>,
    /// Path to metrics storage file
    storage_path: Option<std::path::PathBuf>,
    /// Rule validation metrics per channel
    rule_metrics: Arc<RwLock<HashMap<String, RuleMetric>>>,
    /// Timestamped rule validation events (limited to last 1000)
    rule_validation_events: Arc<RwLock<Vec<RuleValidationEvent>>>,
    /// Metrics retention time in minutes
    metrics_retention_minutes: u64,
    /// Last connection status by channel name
    last_status_by_channel: Arc<RwLock<HashMap<String, ConnectionStatus>>>,
    /// Settings store for configurable windows
    settings_store: Option<Arc<crate::storage::SettingsStore>>,
    /// Last captured payload by identity hash
    last_payloads: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    /// Latest payload by channel name (for display in channel list)
    latest_channel_payloads: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    /// Backend for persisting metrics
    backend: Option<Arc<dyn crate::metrics::backends::MetricsBackend>>,
    /// Handle for the periodic save task
    save_task_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Flag indicating metrics have changed since last save
    dirty: Arc<tokio::sync::RwLock<bool>>,
    /// Cached channel stats
    cached_channel_stats: Arc<RwLock<Vec<SurfaceStats>>>,
    /// Timestamp of last channel stats cache update
    channel_stats_cache_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Cached identity channel stats
    cached_identity_channel_stats: Arc<RwLock<Vec<IdentityChannelStats>>>,
    /// Timestamp of last identity channel stats cache update
    identity_channel_stats_cache_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Cached scalar metrics (total connections, latencies)
    cached_total_connections: Arc<RwLock<usize>>,
    cached_avg_request_latency: Arc<RwLock<Option<f64>>>,
    cached_avg_response_latency: Arc<RwLock<Option<f64>>>,
    cached_scalar_metrics_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Cached time series data for dashboard (configurable TTL via config.toml)
    cached_time_series: Arc<RwLock<Vec<TimeSeriesPoint>>>,
    cached_time_series_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    cached_time_series_interval: Arc<RwLock<i64>>,
    /// Cached recent connections (configurable TTL via config.toml)
    cached_recent_connections: Arc<RwLock<Vec<ConnectionMetric>>>,
    cached_recent_connections_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Channel for batching metrics writes to avoid lock contention
    #[allow(dead_code)]
    metrics_tx: tokio::sync::mpsc::UnboundedSender<ConnectionMetric>,
    /// Cache TTL in milliseconds (configurable)
    cache_ttl_ms: i64,
}

impl MetricsStore {
    /// Create a new metrics store
    pub fn new(max_connections: usize) -> Self {
        // Create channel for batching metrics writes
        let (metrics_tx, metrics_rx) = tokio::sync::mpsc::unbounded_channel();

        let connections = Arc::new(RwLock::new(Vec::new()));
        let last_status = Arc::new(RwLock::new(HashMap::new()));
        let dirty = Arc::new(tokio::sync::RwLock::new(false));

        // Spawn background worker to batch process metrics
        let connections_clone = connections.clone();
        let last_status_clone = last_status.clone();
        let dirty_clone = dirty.clone();
        tokio::spawn(Self::metrics_batch_worker(
            metrics_rx,
            connections_clone,
            last_status_clone,
            dirty_clone,
            max_connections,
        ));

        Self {
            connections,
            max_connections,
            ws_state: None,
            storage_path: None,
            rule_metrics: Arc::new(RwLock::new(HashMap::new())),
            rule_validation_events: Arc::new(RwLock::new(Vec::new())),
            metrics_retention_minutes: 360, // Default 6 hours in minutes
            last_status_by_channel: last_status,
            settings_store: None,
            last_payloads: Arc::new(RwLock::new(HashMap::new())),
            latest_channel_payloads: Arc::new(RwLock::new(HashMap::new())),
            backend: None,
            save_task_handle: Arc::new(tokio::sync::Mutex::new(None)),
            dirty,
            cached_channel_stats: Arc::new(RwLock::new(Vec::new())),
            channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_identity_channel_stats: Arc::new(RwLock::new(Vec::new())),
            identity_channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_total_connections: Arc::new(RwLock::new(0)),
            cached_avg_request_latency: Arc::new(RwLock::new(None)),
            cached_avg_response_latency: Arc::new(RwLock::new(None)),
            cached_scalar_metrics_time: Arc::new(RwLock::new(None)),
            cached_time_series: Arc::new(RwLock::new(Vec::new())),
            cached_time_series_time: Arc::new(RwLock::new(None)),
            cached_time_series_interval: Arc::new(RwLock::new(10)),
            cached_recent_connections: Arc::new(RwLock::new(Vec::new())),
            cached_recent_connections_time: Arc::new(RwLock::new(None)),
            metrics_tx,
            cache_ttl_ms: 1000, // Default 1 second
        }
    }

    /// Store the last captured payload for an identity
    ///
    /// Capped to 100 entries to bound memory usage. When full, the oldest
    /// entry (by insertion order) is evicted.
    pub async fn store_last_payload(
        &self,
        identity_hash: String,
        payload: serde_json::Value,
    ) {
        let mut payloads = self
            .last_payloads
            .write()
            .await;
        payloads.insert(identity_hash, payload);

        // Evict oldest entries if over capacity
        const MAX_PAYLOAD_ENTRIES: usize = 100;
        if payloads.len() > MAX_PAYLOAD_ENTRIES {
            let excess = payloads.len() - MAX_PAYLOAD_ENTRIES;
            let keys_to_remove: Vec<String> = payloads
                .keys()
                .take(excess)
                .cloned()
                .collect();
            for key in keys_to_remove {
                payloads.remove(&key);
            }
        }
    }

    /// Get the last captured payload for an identity
    pub async fn get_last_payload(
        &self,
        identity_hash: &str,
    ) -> Option<serde_json::Value> {
        let payloads = self
            .last_payloads
            .read()
            .await;
        payloads
            .get(identity_hash)
            .cloned()
    }

    /// Store the latest payload for a channel (most recent regardless of identity)
    pub async fn store_latest_channel_payload(
        &self,
        channel_config_id: String,
        payload: serde_json::Value,
    ) {
        let mut payloads = self
            .latest_channel_payloads
            .write()
            .await;
        payloads.insert(channel_config_id, payload);
    }

    /// Get the latest payload for a channel
    pub async fn get_latest_channel_payload(
        &self,
        channel_config_id: &str,
    ) -> Option<serde_json::Value> {
        let payloads = self
            .latest_channel_payloads
            .read()
            .await;
        payloads
            .get(channel_config_id)
            .cloned()
    }

    /// Create a new metrics store with WebSocket broadcasting
    #[allow(dead_code)]
    pub async fn new_with_ws(
        max_connections: usize,
        ws_state: Arc<crate::server::WsState>,
        storage_path: String,
    ) -> Self {
        Self::new_with_ws_and_retention(max_connections, ws_state, 6, storage_path, None, None, None, None, 1).await
    }

    /// Create a new metrics store with WebSocket broadcasting and custom retention
    pub async fn new_with_ws_and_retention(
        max_connections: usize,
        ws_state: Arc<crate::server::WsState>,
        retention_minutes: u64,
        storage_dir: String,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
        identity_store: Option<Arc<dyn crate::identity::IdentityStore>>,
        cloudwatch_config: Option<(crate::config::metrics_config::CloudWatchMetricConfig, Option<String>)>,
        otel_meter_provider: Option<Arc<opentelemetry_sdk::metrics::SdkMeterProvider>>,
        cache_ttl_seconds: u64,
    ) -> Self {
        // Treat storage_dir as a directory and append metrics.json
        let mut storage_path_buf = std::path::PathBuf::from(storage_dir);
        storage_path_buf.push("metrics.json");
        let storage_path = Some(storage_path_buf.clone());

        // Create multi-backend with File, Prometheus, and optionally CloudWatch
        let file_backend = Arc::new(crate::metrics::backends::FileMetricsBackend::new(storage_path_buf.clone()));
        let prometheus_backend = match (task_monitor.clone(), identity_store.clone()) {
            (Some(tm), Some(is)) => Arc::new(
                crate::metrics::backends::PrometheusMetricsBackend::with_task_monitor_and_identity_store(tm, is),
            ),
            _ => Arc::new(crate::metrics::backends::PrometheusMetricsBackend::new()),
        };

        let mut multi_backend = crate::metrics::backends::MultiBackend::new()
            .add_backend(file_backend)
            .add_backend(prometheus_backend);

        // Add CloudWatch backend if enabled

        if let Some((cw_config, aws_profile)) = cloudwatch_config
            && cw_config.enabled
        {
            tracing::info!("CloudWatch metrics enabled - namespace: {}", cw_config.namespace);
            let mut cloudwatch_backend = crate::metrics::backends::CloudWatchMetricsBackend::new(
                cw_config.namespace,
                cw_config.dimensions.clone(),
            )
            .with_enabled(true)
            .with_region(cw_config.region)
            .with_profile(aws_profile);

            // Add task_monitor and identity_store if available (same as Prometheus)
            if let Some(tm) = task_monitor.clone() {
                cloudwatch_backend = cloudwatch_backend.with_task_monitor(tm);
            }
            if let Some(is) = identity_store {
                cloudwatch_backend = cloudwatch_backend.with_identity_store(is);
            }

            let cloudwatch_backend = Arc::new(
                cloudwatch_backend
                    .with_aws_client()
                    .await,
            );
            multi_backend = multi_backend.add_backend(cloudwatch_backend);
        }

        // Add OpenTelemetry backend if provided
        if let Some(meter_provider) = otel_meter_provider {
            tracing::info!("OpenTelemetry metrics backend enabled");
            let otel_backend = Arc::new(crate::metrics::backends::OpenTelemetryMetricsBackend::new(&meter_provider));
            multi_backend = multi_backend.add_backend(otel_backend);
        }

        // Create channel for batching metrics writes
        let (metrics_tx, metrics_rx) = tokio::sync::mpsc::unbounded_channel();

        let connections = Arc::new(RwLock::new(Vec::new()));
        let last_status = Arc::new(RwLock::new(HashMap::new()));
        let dirty = Arc::new(tokio::sync::RwLock::new(false));

        // Spawn background worker to batch process metrics
        let connections_clone = connections.clone();
        let last_status_clone = last_status.clone();
        let dirty_clone = dirty.clone();
        tokio::spawn(Self::metrics_batch_worker(
            metrics_rx,
            connections_clone,
            last_status_clone,
            dirty_clone,
            max_connections,
        ));

        let store = Self {
            connections,
            max_connections,
            ws_state: Some(ws_state),
            storage_path,
            rule_metrics: Arc::new(RwLock::new(HashMap::new())),
            rule_validation_events: Arc::new(RwLock::new(Vec::new())),
            metrics_retention_minutes: retention_minutes,
            last_status_by_channel: last_status,
            settings_store: None,
            last_payloads: Arc::new(RwLock::new(HashMap::new())),
            latest_channel_payloads: Arc::new(RwLock::new(HashMap::new())),
            backend: Some(Arc::new(multi_backend)),
            save_task_handle: Arc::new(tokio::sync::Mutex::new(None)),
            dirty,
            cached_channel_stats: Arc::new(RwLock::new(Vec::new())),
            channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_identity_channel_stats: Arc::new(RwLock::new(Vec::new())),
            identity_channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_total_connections: Arc::new(RwLock::new(0)),
            cached_avg_request_latency: Arc::new(RwLock::new(None)),
            cached_avg_response_latency: Arc::new(RwLock::new(None)),
            cached_scalar_metrics_time: Arc::new(RwLock::new(None)),
            cached_time_series: Arc::new(RwLock::new(Vec::new())),
            cached_time_series_time: Arc::new(RwLock::new(None)),
            cached_time_series_interval: Arc::new(RwLock::new(10)),
            cached_recent_connections: Arc::new(RwLock::new(Vec::new())),
            cached_recent_connections_time: Arc::new(RwLock::new(None)),
            metrics_tx,
            cache_ttl_ms: (cache_ttl_seconds * 1000) as i64,
        };

        // Load existing metrics from backend
        if let Some(ref backend) = store.backend {
            match backend.load().await {
                Ok(snapshot) => {
                    *store
                        .connections
                        .write()
                        .await = snapshot.connections;
                    *store
                        .rule_validation_events
                        .write()
                        .await = snapshot.rule_validation_events;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load metrics from {}: {}", backend.name(), e);
                }
            }
        }

        // Start periodic save task (every 5 seconds)
        store.start_periodic_save(std::time::Duration::from_secs(5));

        store
    }

    /// Set the settings store for configurable windows
    pub fn with_settings_store(
        mut self,
        settings_store: Arc<crate::storage::SettingsStore>,
    ) -> Self {
        self.settings_store = Some(settings_store);
        self
    }

    /// Background worker that batches metrics writes to reduce lock contention
    async fn metrics_batch_worker(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<ConnectionMetric>,
        connections: Arc<RwLock<Vec<ConnectionMetric>>>,
        last_status: Arc<RwLock<HashMap<String, ConnectionStatus>>>,
        dirty: Arc<tokio::sync::RwLock<bool>>,
        max_connections: usize,
    ) {
        const MAX_BATCH_SIZE: usize = 100;

        while let Some(metric) = rx.recv().await {
            let mut batch = vec![metric];

            // Drain channel for batching (up to MAX_BATCH_SIZE or until empty)
            // Use try_recv() for zero latency - no timeouts, no waiting
            while batch.len() < MAX_BATCH_SIZE {
                match rx.try_recv() {
                    Ok(m) => batch.push(m),
                    Err(_) => break, // Channel empty or closed
                }
            }

            // Process batch with ALL locks acquired once
            let mut connections_guard = connections.write().await;
            let mut status_map = last_status.write().await;

            // Add all metrics from batch
            for metric in &batch {
                connections_guard.push(metric.clone());
                status_map.insert(
                    metric
                        .channel_config_id
                        .clone(),
                    metric.status,
                );
            }

            // Enforce max connections limit
            if connections_guard.len() > max_connections {
                let to_remove = connections_guard.len() - max_connections;
                connections_guard.drain(0..to_remove);
            }

            drop(status_map);
            drop(connections_guard);

            // Mark as dirty
            *dirty.write().await = true;

            // Invalidate all caches after writing new data
            // This prevents read operations from acquiring locks to recompute
            // Next read will see stale cache and recompute with fresh data
            // Note: We don't update caches here to avoid complexity - let readers do it
        }
    }

    /// Record a new connection
    pub async fn record_connection(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_with_ucp(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            None, // ucp_operation
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Record a new connection with UCP operation tracking
    pub async fn record_connection_with_ucp(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        ucp_operation: Option<String>,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_with_bytes_and_ucp(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            0, // bytes_sent
            0, // bytes_received
            ucp_operation,
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Record a new connection with bytes tracking for throughput
    pub async fn record_connection_with_bytes(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        bytes_sent: u64,
        bytes_received: u64,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_with_bytes_and_ucp(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            bytes_sent,
            bytes_received,
            None, // ucp_operation
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Record a new connection with bytes and UCP operation tracking
    pub async fn record_connection_with_bytes_and_ucp(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        bytes_sent: u64,
        bytes_received: u64,
        ucp_operation: Option<String>,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        // Default to None transit_point (Access Point traffic). Outbound
        // (Transit Point) hops use `record_connection_with_transit_point`.
        self.record_connection_full(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            bytes_sent,
            bytes_received,
            ucp_operation,
            None, // transit_point
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Record a new connection emitted by an outbound (Transit Point)
    /// hop. `transit_point` is the TP alias and is required so the
    /// dashboard can slice metrics per-AP / per-TP / aggregated.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_connection_with_transit_point(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        bytes_sent: u64,
        bytes_received: u64,
        ucp_operation: Option<String>,
        transit_point: String,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_full(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            bytes_sent,
            bytes_received,
            ucp_operation,
            Some(transit_point),
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Internal recorder used by all `record_connection_*` variants.
    #[allow(clippy::too_many_arguments)]
    async fn record_connection_full(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        bytes_sent: u64,
        bytes_received: u64,
        ucp_operation: Option<String>,
        transit_point: Option<String>,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        let metric = ConnectionMetric {
            timestamp: Utc::now(),
            channel_config_id: channel_config_id.clone(),
            source: source.clone(),
            destination: destination.clone(),
            status,
            trace_id: trace_id.clone(),
            latency_ms,
            direction,
            identity_hash: identity_hash.clone(),
            ucp_operation: ucp_operation.clone(),
            transit_point,
            variant_alias,
            metric_type: crate::metrics::MetricType::Channel,
            // Channel-specific latency
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            // Enhanced distributed tracing
            correlation_id: None,
            agent_identity: None,
            // Enhanced metrics
            request_bytes: Some(bytes_sent),
            response_bytes: Some(bytes_received),
            retry_count: None,
        };

        let connections_len = {
            let mut connections = self.connections.write().await;

            // Deduplicate: Check if we just recorded this exact same request within the last 100ms.
            // This prevents duplicate recordings from the same request being processed twice.
            // We include trace_id so that distinct requests with the same parameters are counted.
            let is_duplicate = connections
                .iter()
                .rev()
                .take(10)
                .any(|existing| {
                    existing.trace_id == trace_id
                        && existing.direction == direction
                        && (metric.timestamp - existing.timestamp)
                            .num_milliseconds()
                            .abs()
                            < 100
                });

            if is_duplicate {
                // Skip recording this duplicate
                return;
            }

            connections.push(metric);

            // Remove connections older than retention period (not based on count)
            // This ensures our 60-minute rolling window has stable data
            let retention_cutoff = Utc::now() - chrono::Duration::minutes(self.metrics_retention_minutes as i64);
            connections.retain(|conn| conn.timestamp >= retention_cutoff);

            // Also enforce max_connections count limit to bound memory usage
            if connections.len() > self.max_connections {
                let to_remove = connections.len() - self.max_connections;
                connections.drain(0..to_remove);
            }

            // Mark metrics as dirty since we added a new connection
            *self.dirty.write().await = true;

            connections.len()
        };

        // Track in Prometheus metrics (real-time counters only)
        // Note: We only update counters here for real-time tracking.
        // Gauge metrics (active_connections, unique_identities, etc.) are updated
        // periodically via the backend persist() method to avoid inconsistencies.
        crate::metrics::backends::prometheus::track_connection(status, latency_ms, bytes_sent, bytes_received);

        // Update last status for this channel
        {
            let mut last_status = self
                .last_status_by_channel
                .write()
                .await;
            last_status.insert(channel_config_id, status);
        }

        // Broadcast metrics update via WebSocket if available
        if let Some(ws_state) = &self.ws_state {
            ws_state.broadcast(crate::server::WsUpdate::MetricsUpdated {
                metrics: serde_json::json!({
                    "total_connections": connections_len,
                    "latest": {
                        "timestamp": Utc::now().to_rfc3339(),
                    }
                }),
            });
        }

        trace!("Recorded connection (total: {})", connections_len);
    }

    pub async fn record_user_login(
        &self,
        user_role: &str,
    ) {
        // Track user login events in Prometheus
        crate::metrics::backends::prometheus::track_user_login(user_role);
        *self.dirty.write().await = true;
    }

    pub async fn record_user_event(
        &self,
        event: &str,
        user_role: &str,
    ) {
        crate::metrics::backends::prometheus::track_user_event(event, user_role);
        *self.dirty.write().await = true;
    }

    /// Get time series data for connections (grouped by time interval)
    #[allow(dead_code)]
    pub async fn get_time_series(
        &self,
        interval_minutes: i64,
    ) -> Vec<TimeSeriesPoint> {
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        if connections.is_empty() && events.is_empty() {
            return vec![];
        }

        // Filter to connections window
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();
        let window_start = now - chrono::Duration::minutes(window_minutes as i64);

        // Group connections by time interval (only within window)
        let mut time_buckets: HashMap<String, (usize, usize, usize, usize, usize)> = HashMap::new();

        for conn in connections.iter() {
            // Skip connections outside window
            if conn.timestamp < window_start {
                continue;
            }

            // Round timestamp to interval
            let minutes_since_epoch = conn.timestamp.timestamp() / 60;
            let bucket_minutes = (minutes_since_epoch / interval_minutes) * interval_minutes;
            let bucket_time = DateTime::from_timestamp(bucket_minutes * 60, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_insert((0, 0, 0, 0, 0));
            entry.0 += 1; // connection count

            // Track failed and gateway faults separately
            if matches!(conn.status, ConnectionStatus::Failed) {
                entry.3 += 1; // failed count
            } else if matches!(conn.status, ConnectionStatus::GatewayFault) {
                entry.4 += 1; // gateway fault count
            }
        }

        // Add rule validation events to time buckets
        for event in events.iter() {
            // Skip events outside window
            if event.timestamp < window_start {
                continue;
            }

            let minutes_since_epoch = event.timestamp.timestamp() / 60;
            let bucket_minutes = (minutes_since_epoch / interval_minutes) * interval_minutes;
            let bucket_time = DateTime::from_timestamp(bucket_minutes * 60, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_insert((0, 0, 0, 0, 0));
            if event.accepted {
                entry.1 += 1; // accept count
            } else {
                entry.2 += 1; // deny count
            }
        }

        // Convert to sorted vector
        let mut time_series: Vec<TimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(timestamp, (count, accepts, denies, failed, gateway_faults))| TimeSeriesPoint {
                timestamp,
                count,
                rule_accepts: accepts,
                rule_denies: denies,
                failed,
                gateway_faults,
            })
            .collect();

        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        time_series
    }

    /// Get time series data with automatic interval selection based on data range
    #[allow(dead_code)]
    pub async fn get_time_series_auto(&self) -> Vec<TimeSeriesPoint> {
        let connections = self.connections.read().await;

        if connections.is_empty() {
            return vec![];
        }

        // Use connections_window to limit the time range we're bucketing
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();
        let window_start = now - chrono::Duration::minutes(window_minutes as i64);

        // Filter connections to window and find actual data range
        let windowed_connections: Vec<_> = connections
            .iter()
            .filter(|c| c.timestamp >= window_start)
            .collect();

        if windowed_connections.is_empty() {
            drop(connections);
            return vec![];
        }

        // Calculate time range of windowed data
        let oldest = windowed_connections
            .first()
            .map(|c| c.timestamp)
            .unwrap_or(now);
        let newest = windowed_connections
            .last()
            .map(|c| c.timestamp)
            .unwrap_or(now);
        let duration_minutes = (newest - oldest).num_minutes();

        // Select interval based on data range
        let interval_minutes = if duration_minutes < 10 {
            // Less than 10 minutes: use 30-second intervals
            drop(connections);
            return self
                .get_time_series_seconds(30)
                .await;
        } else if duration_minutes < 60 {
            // 10 minutes to 1 hour: use 1-minute intervals
            1
        } else {
            // More than 1 hour: use 5-minute intervals
            5
        };

        drop(connections);
        self.get_time_series(interval_minutes)
            .await
    }

    /// Get time series data for connections (grouped by second interval)
    /// Uses epoch-aligned time buckets with automatic interval selection
    pub async fn get_time_series_seconds(
        &self,
        interval_seconds: i64,
    ) -> Vec<TimeSeriesPoint> {
        // Protect against division by zero
        if interval_seconds <= 0 {
            eprintln!("ERROR: Invalid interval_seconds={}, must be > 0", interval_seconds);
            return vec![];
        }

        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_time_series_time
                .read()
                .await;
            let cached_interval = *self
                .cached_time_series_interval
                .read()
                .await;
            if let Some(last_update) = *cache_time
                && cached_interval == interval_seconds
                && (Utc::now() - last_update).num_milliseconds() < self.cache_ttl_ms
            {
                return self
                    .cached_time_series
                    .read()
                    .await
                    .clone();
            }
        }

        // Cache miss - compute time series
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        if connections.is_empty() && events.is_empty() {
            return vec![];
        }

        // Use connections window instead of all data
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();

        // Calculate bucket boundaries aligned to fixed epoch positions.
        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / interval_seconds) * interval_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / interval_seconds;
        let aligned_start = aligned_end - (desired_buckets * interval_seconds);
        let num_buckets = (desired_buckets + 1) as usize;
        let window_start = DateTime::from_timestamp(aligned_start, 0).unwrap_or_else(Utc::now);

        // Initialize all buckets with zeros, using fixed epoch-aligned timestamps
        let mut time_buckets: HashMap<String, (usize, usize, usize, usize, usize)> = HashMap::new();

        for i in 0..num_buckets {
            let bucket_seconds = aligned_start + (i as i64 * interval_seconds);
            let bucket_time_aligned = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);
            let bucket_key = bucket_time_aligned.to_rfc3339();
            time_buckets.insert(bucket_key, (0, 0, 0, 0, 0));
        }

        // Populate buckets with actual connection data
        for conn in connections.iter() {
            // Skip connections outside window
            if conn.timestamp < window_start {
                continue;
            }

            // Round timestamp to interval
            let seconds_since_epoch = conn.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            if let Some(entry) = time_buckets.get_mut(&bucket_key) {
                entry.0 += 1; // connection count

                // Track failed and gateway faults separately
                if matches!(conn.status, ConnectionStatus::Failed) {
                    entry.3 += 1; // failed count
                } else if matches!(conn.status, ConnectionStatus::GatewayFault) {
                    entry.4 += 1; // gateway fault count
                }
            }
        }

        // Add rule validation events to time buckets
        for event in events.iter() {
            // Skip events outside window
            if event.timestamp < window_start {
                continue;
            }

            let seconds_since_epoch = event.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            if let Some(entry) = time_buckets.get_mut(&bucket_key) {
                if event.accepted {
                    entry.1 += 1; // accept count
                } else {
                    entry.2 += 1; // deny count
                }
            }
        }

        // Convert to sorted vector
        let mut time_series: Vec<TimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(timestamp, (count, accepts, denies, failed, gateway_faults))| TimeSeriesPoint {
                timestamp,
                count,
                rule_accepts: accepts,
                rule_denies: denies,
                failed,
                gateway_faults,
            })
            .collect();

        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        drop(connections);
        drop(events);

        // Update cache
        *self
            .cached_time_series
            .write()
            .await = time_series.clone();
        *self
            .cached_time_series_time
            .write()
            .await = Some(Utc::now());
        *self
            .cached_time_series_interval
            .write()
            .await = interval_seconds;

        time_series
    }

    /// Get statistics by channel
    pub async fn get_channel_stats(&self) -> Vec<SurfaceStats> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .channel_stats_cache_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    // Cache is fresh, return it
                    return self
                        .cached_channel_stats
                        .read()
                        .await
                        .clone();
                }
            }
        }

        // Cache miss or stale - recompute
        let connections = self.connections.read().await;

        #[allow(clippy::type_complexity)]
        let mut channel_map: HashMap<
            String,
            (usize, usize, usize, usize, Option<chrono::DateTime<chrono::Utc>>),
        > = HashMap::new();

        for conn in connections.iter() {
            let entry = channel_map
                .entry(conn.channel_config_id.clone())
                .or_insert((0, 0, 0, 0, None));
            entry.0 += 1; // total
            match conn.status {
                ConnectionStatus::Success => entry.1 += 1,
                ConnectionStatus::Failed => entry.2 += 1,
                ConnectionStatus::GatewayFault => entry.3 += 1,
            }
            // Update last_activity to the most recent timestamp
            if entry.4.is_none() || entry.4.unwrap() < conn.timestamp {
                entry.4 = Some(conn.timestamp);
            }
        }
        drop(connections); // Release lock

        let stats: Vec<_> = channel_map
            .into_iter()
            .map(|(channel_config_id, (total, success, failed, gateway_faults, last_activity))| SurfaceStats {
                channel_config_id,
                total_connections: total,
                successful: success,
                failed,
                gateway_faults,
                last_activity,
            })
            .collect();

        // Update cache
        {
            let mut cache = self
                .cached_channel_stats
                .write()
                .await;
            *cache = stats.clone();
            let mut cache_time = self
                .channel_stats_cache_time
                .write()
                .await;
            *cache_time = Some(Utc::now());
        }

        stats
    }

    /// Get connection counts by source-destination pairs
    pub async fn get_source_dest_stats(&self) -> Vec<SourceDestStats> {
        let connections = self.connections.read().await;

        #[derive(Default)]
        struct Stats {
            total: usize,
            successful: usize,
            failed: usize,
        }

        let mut stats_map: HashMap<(String, String, String), Stats> = HashMap::new();

        for conn in connections.iter() {
            let key = (conn.channel_config_id.clone(), conn.source.clone(), conn.destination.clone());
            let stats = stats_map
                .entry(key)
                .or_default();
            stats.total += 1;
            match conn.status {
                super::types::ConnectionStatus::Success => stats.successful += 1,
                super::types::ConnectionStatus::Failed | super::types::ConnectionStatus::GatewayFault => {
                    stats.failed += 1
                }
            }
        }

        stats_map
            .into_iter()
            .map(|((channel_config_id, source, destination), stats)| SourceDestStats {
                channel_config_id,
                source,
                destination,
                total_connections: stats.total,
                successful: stats.successful,
                failed: stats.failed,
                count: stats.total,
            })
            .collect()
    }

    /// Get connection statistics by identity hash and channel
    pub async fn get_identity_channel_stats(&self) -> Vec<IdentityChannelStats> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .identity_channel_stats_cache_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    // Cache is fresh, return it
                    return self
                        .cached_identity_channel_stats
                        .read()
                        .await
                        .clone();
                }
            }
        }

        // Cache miss or stale - recompute
        let connections = self.connections.read().await;

        // Group by (identity_hash, channel_config_id) and count success/deny/fault
        let mut stats_map: HashMap<(String, String), (usize, usize, usize)> = HashMap::new();

        for conn in connections.iter() {
            if let Some(ref identity) = conn.identity_hash {
                let key = (identity.clone(), conn.channel_config_id.clone());
                let entry = stats_map
                    .entry(key)
                    .or_insert((0, 0, 0));

                match conn.status {
                    ConnectionStatus::Success => entry.0 += 1,
                    ConnectionStatus::Failed => entry.1 += 1,
                    ConnectionStatus::GatewayFault => entry.2 += 1,
                }
            }
        }
        drop(connections); // Release lock

        let stats: Vec<_> = stats_map
            .into_iter()
            .map(|((identity_hash, channel_config_id), (success, deny, fault))| IdentityChannelStats {
                identity_hash,
                channel_config_id,
                total_count: success + deny + fault,
                success_count: success,
                deny_count: deny,
                fault_count: fault,
            })
            .collect();

        // Update cache
        {
            let mut cache = self
                .cached_identity_channel_stats
                .write()
                .await;
            *cache = stats.clone();
            let mut cache_time = self
                .identity_channel_stats_cache_time
                .write()
                .await;
            *cache_time = Some(Utc::now());
        }

        stats
    }

    /// Get UCP operation statistics for a specific channel
    pub async fn get_ucp_operation_stats(
        &self,
        channel_config_id: &str,
    ) -> Vec<super::types::UcpOperationStats> {
        let connections = self.connections.read().await;

        // Filter for this channel and count operations
        let mut operation_map: HashMap<String, (usize, usize, usize)> = HashMap::new();
        let mut total_ucp_requests = 0;

        for conn in connections.iter() {
            if conn.channel_config_id == channel_config_id
                && let Some(ref ucp_op) = conn.ucp_operation
            {
                total_ucp_requests += 1;
                let operation = ucp_op.clone();
                let entry = operation_map
                    .entry(operation)
                    .or_insert((0, 0, 0));
                entry.0 += 1; // total count

                match conn.status {
                    ConnectionStatus::Success => entry.1 += 1,
                    ConnectionStatus::Failed | ConnectionStatus::GatewayFault => entry.2 += 1,
                }
            }
        }

        // Convert to UcpOperationStats with percentages
        operation_map
            .into_iter()
            .map(|(operation, (count, successful, failed))| {
                let percentage = if total_ucp_requests > 0 {
                    (count as f64 / total_ucp_requests as f64) * 100.0
                } else {
                    0.0
                };

                super::types::UcpOperationStats {
                    operation,
                    count,
                    successful,
                    failed,
                    percentage,
                }
            })
            .collect()
    }

    /// Get total connection count
    pub async fn get_total_connections(&self) -> usize {
        // Check cache first (5 second TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < 5000 {
                    return *self
                        .cached_total_connections
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_total_connections
            .read()
            .await
    }

    /// Get average latency for the configured window (backward compatibility - returns request latency)
    pub async fn get_average_latency(&self) -> Option<f64> {
        self.get_average_request_latency()
            .await
    }

    /// Get average request latency (client to target) for the configured window
    pub async fn get_average_request_latency(&self) -> Option<f64> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    return *self
                        .cached_avg_request_latency
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_avg_request_latency
            .read()
            .await
    }

    /// Get average response latency (target to client) for the configured window
    pub async fn get_average_response_latency(&self) -> Option<f64> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    return *self
                        .cached_avg_response_latency
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_avg_response_latency
            .read()
            .await
    }

    /// Refresh scalar metrics cache (called internally when cache is stale)
    async fn refresh_scalar_metrics_cache(&self) {
        let connections = self.connections.read().await;

        // Get configurable windows from settings
        let conn_window_minutes = if let Some(ref store) = self.settings_store {
            store
                .get()
                .connections_window_minutes
        } else {
            60
        };

        let latency_window_minutes = if let Some(ref store) = self.settings_store {
            store
                .get()
                .latency_window_minutes
        } else {
            60
        };

        let conn_cutoff = Utc::now() - chrono::Duration::minutes(conn_window_minutes as i64);
        let latency_cutoff = Utc::now() - chrono::Duration::minutes(latency_window_minutes as i64);

        // Calculate total connections
        let total = connections
            .iter()
            .filter(|conn| conn.timestamp >= conn_cutoff)
            .count();

        // Calculate average request latency
        let request_latencies: Vec<u64> = connections
            .iter()
            .filter(|conn| conn.timestamp >= latency_cutoff)
            .filter_map(|conn| conn.latency_ms)
            .collect();

        let avg_request = if !request_latencies.is_empty() {
            let sum: u64 = request_latencies.iter().sum();
            Some(sum as f64 / request_latencies.len() as f64)
        } else {
            None
        };

        // Calculate average response latency (from channel_response_latency_ms field)
        let response_latencies: Vec<u64> = connections
            .iter()
            .filter(|conn| conn.timestamp >= latency_cutoff)
            .filter_map(|conn| conn.channel_response_latency_ms)
            .collect();

        let avg_response = if !response_latencies.is_empty() {
            let sum: u64 = response_latencies
                .iter()
                .sum();
            Some(sum as f64 / response_latencies.len() as f64)
        } else {
            None
        };

        drop(connections); // Release lock before updating cache

        // Update all cached values
        *self
            .cached_total_connections
            .write()
            .await = total;
        *self
            .cached_avg_request_latency
            .write()
            .await = avg_request;
        *self
            .cached_avg_response_latency
            .write()
            .await = avg_response;
        *self
            .cached_scalar_metrics_time
            .write()
            .await = Some(Utc::now());
    }

    /// Get current connections window setting
    pub fn get_connections_window_minutes(&self) -> u64 {
        if let Some(ref store) = self.settings_store {
            store
                .get()
                .connections_window_minutes
        } else {
            60 // Default to 60 minutes
        }
    }

    /// Get configured bucket interval in seconds
    pub fn get_bucket_seconds(&self) -> i64 {
        if let Some(ref store) = self.settings_store {
            store.get().bucket_seconds as i64
        } else {
            30 // Default to 30 seconds
        }
    }

    /// Get current latency window setting
    pub fn get_latency_window_minutes(&self) -> u64 {
        if let Some(ref store) = self.settings_store {
            store
                .get()
                .latency_window_minutes
        } else {
            60 // Default to 60 minutes
        }
    }

    /// Get recent connections (last N)
    pub async fn get_recent_connections(
        &self,
        limit: usize,
    ) -> Vec<ConnectionMetric> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_recent_connections_time
                .read()
                .await;
            if let Some(last_update) = *cache_time
                && (Utc::now() - last_update).num_milliseconds() < self.cache_ttl_ms
            {
                return self
                    .cached_recent_connections
                    .read()
                    .await
                    .clone();
            }
        }

        // Cache miss - fetch and update
        let connections = self.connections.read().await;
        let start = if connections.len() > limit {
            connections.len() - limit
        } else {
            0
        };
        let recent = connections[start..].to_vec();
        drop(connections);

        // Update cache
        *self
            .cached_recent_connections
            .write()
            .await = recent.clone();
        *self
            .cached_recent_connections_time
            .write()
            .await = Some(Utc::now());

        recent
    }

    /// Get timestamps of connections matching filters
    #[allow(dead_code)]
    pub async fn get_matching_timestamps(
        &self,
        channel_id: Option<&str>,
        gateway_id: Option<&str>,
        identity_did: Option<&str>,
    ) -> std::collections::HashSet<i64> {
        let connections = self.connections.read().await;
        let mut matching_timestamps = std::collections::HashSet::new();

        for conn in connections.iter() {
            let mut matches = true;

            // Apply channel filter
            if let Some(channel_id) = channel_id
                && conn.channel_config_id != channel_id
            {
                matches = false;
            }

            // Apply gateway filter (check source or destination)
            if let Some(gateway_id) = gateway_id
                && conn.source != gateway_id
                && conn.destination != gateway_id
            {
                matches = false;
            }

            // Apply identity filter
            if let Some(identity_did) = identity_did {
                if let Some(ref hash) = conn.identity_hash {
                    if hash != identity_did {
                        matches = false;
                    }
                } else {
                    matches = false;
                }
            }

            if matches {
                matching_timestamps.insert(conn.timestamp.timestamp());
            }
        }

        matching_timestamps
    }

    /// Build time series from connections matching the specified filters
    pub async fn get_filtered_time_series(
        &self,
        interval_seconds: i64,
        channel_id: Option<&str>,
        _gateway_id: Option<&str>,
        identity_did: Option<&str>,
        tp_filter: &super::types::TransitPointFilter,
    ) -> Vec<TimeSeriesPoint> {
        // Protect against division by zero
        if interval_seconds <= 0 {
            eprintln!("ERROR: Invalid interval_seconds={}, must be > 0", interval_seconds);
            return vec![];
        }

        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        // Filter connections based on criteria
        let filtered_connections: Vec<_> = connections
            .iter()
            .filter(|conn| {
                // When channel_id is specified, only include channel metrics
                let channel_match = channel_id.is_none_or(|id| {
                    conn.metric_type == super::types::MetricType::Channel && conn.channel_config_id == id
                });
                // Note: gateway_id filtering not supported as ConnectionMetric doesn't track gateway
                let identity_match = identity_did.is_none_or(|did| {
                    conn.identity_hash
                        .as_ref()
                        .is_some_and(|hash| hash == did)
                });
                let tp_match = tp_filter.matches(conn.transit_point.as_deref());
                channel_match && identity_match && tp_match
            })
            .collect();

        // Filter events based on channel
        let filtered_events: Vec<_> = events
            .iter()
            .filter(|event| channel_id.is_none_or(|id| event.channel_config_id == id))
            .collect();

        if filtered_connections.is_empty() && filtered_events.is_empty() {
            return vec![];
        }

        // Use connections window
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();

        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / interval_seconds) * interval_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / interval_seconds;
        let aligned_start = aligned_end - (desired_buckets * interval_seconds);
        let num_buckets = (desired_buckets + 1) as usize;

        // Initialize empty buckets
        let mut buckets = vec![(0usize, 0usize, 0usize, 0usize, 0usize); num_buckets];

        // Populate connection counts
        for conn in filtered_connections.iter() {
            let conn_epoch = conn.timestamp.timestamp();
            // Allow connections up to now, not just aligned_end (which is the current bucket start)
            if conn_epoch < aligned_start || conn_epoch > now_epoch {
                continue;
            }

            let bucket_index = ((conn_epoch - aligned_start) / interval_seconds) as usize;
            if bucket_index < num_buckets {
                buckets[bucket_index].0 += 1;
                if matches!(conn.status, ConnectionStatus::Failed) {
                    buckets[bucket_index].3 += 1;
                } else if matches!(conn.status, ConnectionStatus::GatewayFault) {
                    buckets[bucket_index].4 += 1;
                }
            }
        }

        // Add rule validation events
        for event in filtered_events.iter() {
            let event_epoch = event.timestamp.timestamp();
            // Allow events up to now, not just aligned_end
            if event_epoch < aligned_start || event_epoch > now_epoch {
                continue;
            }

            let bucket_index = ((event_epoch - aligned_start) / interval_seconds) as usize;
            if bucket_index < num_buckets {
                if event.accepted {
                    buckets[bucket_index].1 += 1;
                } else {
                    buckets[bucket_index].2 += 1;
                }
            }
        }

        // Convert to TimeSeriesPoint
        buckets
            .into_iter()
            .enumerate()
            .map(|(i, (count, accepts, denies, failed, faults))| {
                let bucket_epoch = aligned_start + (i as i64 * interval_seconds);
                let timestamp = DateTime::from_timestamp(bucket_epoch, 0)
                    .unwrap_or_else(Utc::now)
                    .to_rfc3339();

                TimeSeriesPoint {
                    timestamp,
                    count,
                    rule_accepts: accepts,
                    rule_denies: denies,
                    failed,
                    gateway_faults: faults,
                }
            })
            .collect()
    }

    /// Get latency statistics by channel and source-destination pairs
    pub async fn get_latency_stats(&self) -> Vec<LatencyStats> {
        let connections = self.connections.read().await;

        // Group connections by (channel_config_id, source, destination)
        let mut latency_map: HashMap<(String, String, String), Vec<u64>> = HashMap::new();

        for conn in connections.iter() {
            if let Some(latency) = conn.latency_ms {
                let key = (conn.channel_config_id.clone(), conn.source.clone(), conn.destination.clone());
                latency_map
                    .entry(key)
                    .or_default()
                    .push(latency);
            }
        }

        // Calculate statistics for each group
        latency_map
            .into_iter()
            .map(|((channel_config_id, source, destination), mut latencies)| {
                latencies.sort_unstable();

                let count = latencies.len();
                let sum: u64 = latencies.iter().sum();
                let avg = if count > 0 {
                    sum as f64 / count as f64
                } else {
                    0.0
                };

                let min = *latencies
                    .first()
                    .unwrap_or(&0);
                let max = *latencies.last().unwrap_or(&0);

                let p50 = percentile(&latencies, 50);
                let p95 = percentile(&latencies, 95);
                let p99 = percentile(&latencies, 99);

                LatencyStats {
                    channel_config_id,
                    source,
                    destination,
                    avg_latency_ms: avg,
                    min_latency_ms: min,
                    max_latency_ms: max,
                    p50_latency_ms: p50,
                    p95_latency_ms: p95,
                    p99_latency_ms: p99,
                    sample_count: count,
                }
            })
            .collect()
    }

    /// Build filtered latency time series from connections matching the specified filters
    pub async fn get_filtered_latency_time_series(
        &self,
        bucket_seconds: i64,
        channel_id: Option<&str>,
        _gateway_id: Option<&str>,
        identity_did: Option<&str>,
        tp_filter: &super::types::TransitPointFilter,
    ) -> Vec<LatencyTimeSeriesPoint> {
        // Protect against division by zero
        if bucket_seconds <= 0 {
            eprintln!("ERROR: Invalid bucket_seconds={}, must be > 0", bucket_seconds);
            return vec![];
        }

        let connections = self.connections.read().await;

        // Filter connections based on criteria
        let filtered_connections: Vec<_> = connections
            .iter()
            .filter(|conn| {
                // When channel_id is specified, only include channel metrics
                let channel_match = channel_id.is_none_or(|id| {
                    conn.metric_type == super::types::MetricType::Channel && conn.channel_config_id == id
                });
                // Note: gateway_id filtering not supported as ConnectionMetric doesn't track gateway
                let identity_match = identity_did.is_none_or(|did| {
                    conn.identity_hash
                        .as_ref()
                        .is_some_and(|hash| hash == did)
                });
                let tp_match = tp_filter.matches(conn.transit_point.as_deref());
                channel_match && identity_match && tp_match && conn.latency_ms.is_some()
            })
            .collect();

        if filtered_connections.is_empty() {
            return vec![];
        }

        // Use connections window
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();

        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / bucket_seconds) * bucket_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / bucket_seconds;
        let aligned_start = aligned_end - (desired_buckets * bucket_seconds);
        let num_buckets = (desired_buckets + 1) as usize;

        // Group latencies by bucket
        let mut bucket_latencies: Vec<Vec<u64>> = vec![Vec::new(); num_buckets];

        for conn in filtered_connections.iter() {
            let conn_epoch = conn.timestamp.timestamp();
            // Allow connections up to now, not just aligned_end (which is the current bucket start)
            if conn_epoch < aligned_start || conn_epoch > now_epoch {
                continue;
            }

            let bucket_index = ((conn_epoch - aligned_start) / bucket_seconds) as usize;
            if bucket_index < num_buckets
                && let Some(latency) = conn.latency_ms
            {
                bucket_latencies[bucket_index].push(latency);
            }
        }

        // Calculate percentiles for each bucket
        bucket_latencies
            .into_iter()
            .enumerate()
            .map(|(i, mut latencies)| {
                let bucket_epoch = aligned_start + (i as i64 * bucket_seconds);
                let timestamp = DateTime::from_timestamp(bucket_epoch, 0)
                    .unwrap_or_else(Utc::now)
                    .to_rfc3339();

                if latencies.is_empty() {
                    LatencyTimeSeriesPoint {
                        timestamp,
                        avg_latency_ms: 0.0,
                        p50_latency_ms: 0,
                        p95_latency_ms: 0,
                        p99_latency_ms: 0,
                        min_latency_ms: 0,
                        max_latency_ms: 0,
                        sample_count: 0,
                    }
                } else {
                    latencies.sort_unstable();
                    let sum: u64 = latencies.iter().sum();
                    let avg = sum as f64 / latencies.len() as f64;
                    LatencyTimeSeriesPoint {
                        timestamp,
                        avg_latency_ms: avg,
                        p50_latency_ms: percentile(&latencies, 50),
                        p95_latency_ms: percentile(&latencies, 95),
                        p99_latency_ms: percentile(&latencies, 99),
                        min_latency_ms: *latencies
                            .first()
                            .unwrap_or(&0),
                        max_latency_ms: *latencies.last().unwrap_or(&0),
                        sample_count: latencies.len(),
                    }
                }
            })
            .collect()
    }

    /// Get latency time series with automatic interval selection
    pub async fn get_latency_time_series(
        &self,
        bucket_seconds: i64,
    ) -> Vec<LatencyTimeSeriesPoint> {
        // Protect against division by zero
        if bucket_seconds <= 0 {
            eprintln!("ERROR: Invalid bucket_seconds={}, must be > 0", bucket_seconds);
            return vec![];
        }

        let connections = self.connections.read().await;

        if connections.is_empty() {
            return vec![];
        }

        // Use connections window instead of all historical data
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();
        let window_start = now - chrono::Duration::minutes(window_minutes as i64);

        // Filter connections to window
        let windowed_connections: Vec<_> = connections
            .iter()
            .filter(|c| c.timestamp >= window_start)
            .collect();

        if windowed_connections.is_empty() {
            return vec![];
        }

        // Use the provided bucket_seconds instead of calculating
        let interval_seconds = bucket_seconds;

        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / interval_seconds) * interval_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / interval_seconds;
        let aligned_start = aligned_end - (desired_buckets * interval_seconds);
        let num_buckets = (desired_buckets + 1) as usize;

        // Pre-create all buckets with empty latency vectors, using fixed epoch-aligned timestamps
        let mut time_buckets: Vec<(i64, Vec<u64>)> = Vec::with_capacity(num_buckets);
        for i in 0..num_buckets {
            let bucket_seconds = aligned_start + (i as i64 * interval_seconds);
            time_buckets.push((bucket_seconds, Vec::new()));
        }

        // Populate buckets with latencies from connections in window
        for conn in windowed_connections.iter() {
            if let Some(latency) = conn.latency_ms {
                let seconds_since_epoch = conn.timestamp.timestamp();
                let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;

                // Find the bucket and add latency
                if let Some(bucket) = time_buckets
                    .iter_mut()
                    .find(|(bs, _)| *bs == bucket_seconds)
                {
                    bucket.1.push(latency);
                }
            }
        }

        // Calculate statistics for each bucket
        let time_series: Vec<LatencyTimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(bucket_seconds, mut latencies)| {
                let (avg, p50, p95, p99, min, max, count) = if latencies.is_empty() {
                    // Empty bucket - all zeros
                    (0.0, 0, 0, 0, 0, 0, 0)
                } else {
                    latencies.sort_unstable();

                    let count = latencies.len();
                    let sum: u64 = latencies.iter().sum();
                    let avg = sum as f64 / count as f64;

                    let min = *latencies.first().unwrap();
                    let max = *latencies.last().unwrap();

                    let p50 = percentile(&latencies, 50);
                    let p95 = percentile(&latencies, 95);
                    let p99 = percentile(&latencies, 99);

                    (avg, p50, p95, p99, min, max, count)
                };

                let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);
                let timestamp = bucket_time.to_rfc3339();

                LatencyTimeSeriesPoint {
                    timestamp,
                    avg_latency_ms: avg,
                    p50_latency_ms: p50,
                    p95_latency_ms: p95,
                    p99_latency_ms: p99,
                    min_latency_ms: min,
                    max_latency_ms: max,
                    sample_count: count,
                }
            })
            .collect();

        time_series
    }

    /// Get time series data filtered by channel config ID
    pub async fn get_time_series_by_channel(
        &self,
        channel_config_id: &str,
    ) -> Vec<TimeSeriesPoint> {
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        // Filter connections by channel
        let channel_connections: Vec<&ConnectionMetric> = connections
            .iter()
            .filter(|conn| conn.channel_config_id == channel_config_id)
            .collect();

        // Filter events by channel
        let channel_events: Vec<&RuleValidationEvent> = events
            .iter()
            .filter(|event| event.channel_config_id == channel_config_id)
            .collect();

        if channel_connections.is_empty() && channel_events.is_empty() {
            return vec![];
        }

        // Calculate time range
        let oldest = channel_connections
            .first()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let newest = channel_connections
            .last()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let duration_minutes = (newest - oldest).num_minutes();

        // Select interval based on data range
        let interval_seconds = if duration_minutes < 10 {
            30 // Less than 10 minutes: 30-second intervals
        } else if duration_minutes < 60 {
            60 // 10-60 minutes: 1-minute intervals
        } else {
            300 // Over 1 hour: 5-minute intervals
        };

        // Group connections by time bucket
        let mut time_buckets: HashMap<String, (usize, usize, usize, usize, usize)> = HashMap::new();

        for conn in channel_connections.iter() {
            let seconds_since_epoch = conn.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_insert((0, 0, 0, 0, 0));
            entry.0 += 1; // connection count

            // Track failed and gateway faults separately
            if matches!(conn.status, ConnectionStatus::Failed) {
                entry.3 += 1; // failed count
            } else if matches!(conn.status, ConnectionStatus::GatewayFault) {
                entry.4 += 1; // gateway fault count
            }
        }

        // Add rule validation events to time buckets
        for event in channel_events.iter() {
            let seconds_since_epoch = event.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_insert((0, 0, 0, 0, 0));
            if event.accepted {
                entry.1 += 1; // accept count
            } else {
                entry.2 += 1; // deny count
            }
        }

        // Convert to sorted vector
        let mut time_series: Vec<TimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(timestamp, (count, accepts, denies, failed, gateway_faults))| TimeSeriesPoint {
                timestamp,
                count,
                rule_accepts: accepts,
                rule_denies: denies,
                failed,
                gateway_faults,
            })
            .collect();

        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        time_series
    }

    /// Get latency time series filtered by channel config ID
    pub async fn get_latency_time_series_by_channel(
        &self,
        channel_config_id: &str,
    ) -> Vec<LatencyTimeSeriesPoint> {
        let connections = self.connections.read().await;

        // Filter connections by channel
        let channel_connections: Vec<&ConnectionMetric> = connections
            .iter()
            .filter(|conn| conn.channel_config_id == channel_config_id)
            .collect();

        if channel_connections.is_empty() {
            return vec![];
        }

        // Calculate time range
        let oldest = channel_connections
            .first()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let newest = channel_connections
            .last()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let duration_minutes = (newest - oldest).num_minutes();

        // Select interval based on data range
        let interval_seconds = if duration_minutes < 10 {
            30 // Less than 10 minutes: 30-second intervals
        } else if duration_minutes < 60 {
            60 // 10-60 minutes: 1-minute intervals
        } else {
            300 // Over 1 hour: 5-minute intervals
        };

        // Group latencies by time bucket
        let mut time_buckets: HashMap<i64, Vec<u64>> = HashMap::new();

        for conn in channel_connections.iter() {
            if let Some(latency) = conn.latency_ms {
                let seconds_since_epoch = conn.timestamp.timestamp();
                let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
                time_buckets
                    .entry(bucket_seconds)
                    .or_default()
                    .push(latency);
            }
        }

        // Calculate statistics for each bucket
        let mut time_series: Vec<LatencyTimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(bucket_seconds, mut latencies)| {
                latencies.sort_unstable();

                let count = latencies.len();
                let sum: u64 = latencies.iter().sum();
                let avg = if count > 0 {
                    sum as f64 / count as f64
                } else {
                    0.0
                };

                let min = *latencies
                    .first()
                    .unwrap_or(&0);
                let max = *latencies.last().unwrap_or(&0);

                let p50 = percentile(&latencies, 50);
                let p95 = percentile(&latencies, 95);
                let p99 = percentile(&latencies, 99);

                let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);
                let timestamp = bucket_time.to_rfc3339();

                LatencyTimeSeriesPoint {
                    timestamp,
                    avg_latency_ms: avg,
                    p50_latency_ms: p50,
                    p95_latency_ms: p95,
                    p99_latency_ms: p99,
                    min_latency_ms: min,
                    max_latency_ms: max,
                    sample_count: count,
                }
            })
            .collect();

        // Sort by timestamp
        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        time_series
    }

    /// Start periodic background task to save metrics and cleanup old data
    fn start_periodic_save(
        &self,
        interval: std::time::Duration,
    ) {
        let connections = self.connections.clone();
        let rule_metrics = self.rule_metrics.clone();
        let rule_validation_events = self
            .rule_validation_events
            .clone();
        let backend = self.backend.clone();
        let handle_mutex = self.save_task_handle.clone();
        let dirty = self.dirty.clone();
        let retention_minutes = self.metrics_retention_minutes;
        let max_connections = self.max_connections;

        let handle = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;

                // Cleanup old connections and enforce count cap
                {
                    let retention_cutoff = Utc::now() - chrono::Duration::minutes(retention_minutes as i64);
                    let mut conns = connections.write().await;
                    let before_len = conns.len();
                    conns.retain(|conn| conn.timestamp >= retention_cutoff);
                    // Enforce count cap after time-based cleanup
                    if conns.len() > max_connections {
                        let to_remove = conns.len() - max_connections;
                        conns.drain(0..to_remove);
                    }
                    // Shrink the Vec if it has significant excess capacity
                    // to return memory to the allocator
                    if conns.capacity() > conns.len() * 2 + 100 {
                        let shrink_to = conns.len() + 100; // Keep some extra capacity to avoid frequent shrinking
                        conns.shrink_to(shrink_to);
                    }
                    let after_len = conns.len();
                    if before_len != after_len {
                        trace!("Cleaned up {} old connection metrics", before_len - after_len);
                    }
                }

                // Only persist if data has changed (dirty flag is set)
                let is_dirty = *dirty.read().await;
                if !is_dirty {
                    continue;
                }

                if let Some(ref backend) = backend {
                    let connections_snap = connections
                        .read()
                        .await
                        .clone();
                    let metrics_snap = rule_metrics
                        .read()
                        .await
                        .clone();
                    let events_snap = rule_validation_events
                        .read()
                        .await
                        .clone();

                    match backend
                        .persist(&connections_snap, &metrics_snap, &events_snap)
                        .await
                    {
                        Ok(_) => {
                            // Clear dirty flag after successful save (for file backends)
                            if is_dirty {
                                *dirty.write().await = false;
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to persist metrics to {}: {}", backend.name(), e);
                            // Keep dirty flag set so we retry on next interval
                        }
                    }
                }
            }
        });

        // Store the handle so we can cancel it later if needed
        tokio::spawn(async move {
            *handle_mutex.lock().await = Some(handle);
        });
    }

    /// Save metrics to file
    async fn save_to_file(
        path: &std::path::Path,
        connections: &[ConnectionMetric],
        _rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Convert flat data to hierarchical format organized by channel
        let mut connections_map: HashMap<String, SurfaceMetricsData> = HashMap::new();

        // Add connections organized by source -> identity -> destination -> trace_id
        // For both requests and responses, we want them grouped by the CLIENT source IP
        for conn in connections {
            // Determine the actual client source IP
            // Request: source = client, dest = target -> use source as-is
            // Response: source = target, dest = client -> swap to use client as "source"
            let (client_source, target_dest) = if conn.direction == ConnectionDirection::Response {
                // Response: source is target, dest is client - swap them
                (conn.destination.clone(), conn.source.clone())
            } else {
                // Request: source is client, dest is target - use as-is
                (conn.source.clone(), conn.destination.clone())
            };

            let channel_data = connections_map
                .entry(conn.channel_config_id.clone())
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            let source_map = channel_data
                .sources
                .entry(client_source)
                .or_default();
            let identity_key = conn
                .identity_hash
                .clone()
                .unwrap_or_else(|| "anonymous".to_string());
            let identity_map = source_map
                .entry(identity_key)
                .or_default();
            let dest_map = identity_map
                .entry(target_dest)
                .or_default();
            let trace_vec = dest_map
                .entry(conn.trace_id.clone())
                .or_default();
            trace_vec.push(ConnectionDataPoint {
                timestamp: conn.timestamp,
                status: conn.status,
                latency_ms: conn.latency_ms,
                identity_hash: conn.identity_hash.clone(),
                direction: conn.direction,
                ucp_operation: conn.ucp_operation.clone(),
                transit_point: conn.transit_point.clone(),
                variant_alias: conn.variant_alias.clone(),
                metric_type: conn.metric_type,
                correlation_id: conn.correlation_id.clone(),
                agent_identity: conn.agent_identity.clone(),
                channel_request_latency_ms: conn.channel_request_latency_ms,
                channel_response_latency_ms: conn.channel_response_latency_ms,
                request_bytes: conn.request_bytes,
                response_bytes: conn.response_bytes,
                retry_count: conn.retry_count,
                total_latency_ms: conn.total_latency_ms,
            });
        }

        // Add rule triggers to their respective channels
        for event in rule_validation_events {
            let channel_data = connections_map
                .entry(
                    event
                        .channel_config_id
                        .clone(),
                )
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            channel_data
                .rule_triggers
                .push(RuleValidationDataPoint {
                    timestamp: event.timestamp,
                    accepted: event.accepted,
                });
        }

        // Package all metrics data in hierarchical format
        let metrics_data = MetricsData { connections: connections_map };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&metrics_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Write to temporary file first, then atomically rename
        let temp_path = path.with_extension("json.tmp");
        let mut file = tokio::fs::File::create(&temp_path).await?;
        file.write_all(json.as_bytes())
            .await?;
        file.flush().await?;
        drop(file); // Close file before rename

        // Atomic rename
        tokio::fs::rename(&temp_path, path).await?;

        Ok(())
    }

    /// Load metrics from file (synchronous version for constructor)
    #[allow(dead_code)]
    fn load_from_file_sync(
        &mut self,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        use std::io::Read;

        if !path.exists() {
            return Ok(()); // No file yet, not an error
        }

        let mut file = std::fs::File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let cutoff_time = Utc::now() - chrono::Duration::minutes(self.metrics_retention_minutes as i64);

        let metrics_data = serde_json::from_str::<MetricsData>(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Load hierarchical format - convert to flat for in-memory storage
        if let Ok(mut connections) = self.connections.try_write() {
            for (channel_id, channel_data) in &metrics_data.connections {
                for (source, identities) in &channel_data.sources {
                    for (identity, destinations) in identities {
                        for (destination, traces) in destinations {
                            for (trace_id, data_points) in traces {
                                for point in data_points {
                                    if point.timestamp >= cutoff_time {
                                        connections.push(ConnectionMetric {
                                            timestamp: point.timestamp,
                                            channel_config_id: channel_id.clone(),
                                            source: source.clone(),
                                            destination: destination.clone(),
                                            status: point.status,
                                            latency_ms: point.latency_ms,
                                            identity_hash: if identity == "anonymous" {
                                                None
                                            } else {
                                                Some(identity.clone())
                                            },
                                            direction: point.direction,
                                            trace_id: trace_id.clone(),
                                            ucp_operation: point.ucp_operation.clone(),
                                            transit_point: point.transit_point.clone(),
                                            variant_alias: point.variant_alias.clone(),
                                            metric_type: point.metric_type,
                                            correlation_id: point.correlation_id.clone(),
                                            agent_identity: point.agent_identity.clone(),
                                            channel_request_latency_ms: point.channel_request_latency_ms,
                                            channel_response_latency_ms: point.channel_response_latency_ms,
                                            request_bytes: point.request_bytes,
                                            response_bytes: point.response_bytes,
                                            retry_count: point.retry_count,
                                            total_latency_ms: point.total_latency_ms,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Trim to max_connections if needed
            if connections.len() > self.max_connections {
                let excess = connections.len() - self.max_connections;
                connections.drain(0..excess);
            }
        }

        // Load rule triggers and rebuild rule_metrics
        if let Ok(mut events) = self
            .rule_validation_events
            .try_write()
        {
            for (channel_id, channel_data) in &metrics_data.connections {
                for validation in &channel_data.rule_triggers {
                    if validation.timestamp >= cutoff_time {
                        events.push(RuleValidationEvent {
                            timestamp: validation.timestamp,
                            channel_config_id: channel_id.clone(),
                            accepted: validation.accepted,
                        });
                    }
                }
            }

            // Trim to max_connections if needed
            if events.len() > self.max_connections {
                let excess = events.len() - self.max_connections;
                events.drain(0..excess);
            }
        }

        // Rebuild rule_metrics from rule_triggers
        if let Ok(mut rule_metrics) = self.rule_metrics.try_write() {
            rule_metrics.clear();
            for (channel_id, channel_data) in &metrics_data.connections {
                let mut accept_count = 0;
                let mut deny_count = 0;
                for validation in &channel_data.rule_triggers {
                    if validation.accepted {
                        accept_count += 1;
                    } else {
                        deny_count += 1;
                    }
                }
                if accept_count > 0 || deny_count > 0 {
                    rule_metrics.insert(
                        channel_id.clone(),
                        RuleMetric {
                            channel_config_id: channel_id.clone(),
                            accept_count,
                            deny_count,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    /// Record a rule validation result (accept or deny)
    pub async fn record_rule_validation(
        &self,
        channel_config_id: String,
        accepted: bool,
    ) {
        // Update aggregate counters
        let mut metrics = self
            .rule_metrics
            .write()
            .await;
        let metric = metrics
            .entry(channel_config_id.clone())
            .or_insert(RuleMetric {
                channel_config_id: channel_config_id.clone(),
                accept_count: 0,
                deny_count: 0,
            });

        if accepted {
            metric.accept_count += 1;
        } else {
            metric.deny_count += 1;
        }
        drop(metrics);

        // Track in Prometheus metrics
        crate::metrics::backends::prometheus::track_rule_validation(accepted);

        // Store timestamped event
        let event = RuleValidationEvent {
            timestamp: Utc::now(),
            channel_config_id,
            accepted,
        };

        let mut events = self
            .rule_validation_events
            .write()
            .await;
        events.push(event);

        // Keep only the most recent events
        if events.len() > self.max_connections {
            let excess = events.len() - self.max_connections;
            events.drain(0..excess);
        }
        drop(events);

        // Mark metrics as dirty
        *self.dirty.write().await = true;

        // Metrics are now saved periodically by the background task
    }

    /// Get rule validation metrics for a specifi (includes rule_triggers per channel)
    pub async fn get_hierarchical_connections(&self) -> HashMap<String, SurfaceMetricsData> {
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;
        let mut hierarchical: HashMap<String, SurfaceMetricsData> = HashMap::new();

        // Add connections organized by: channel -> source -> identity -> destination -> trace_id
        for conn in connections.iter() {
            let channel_data = hierarchical
                .entry(conn.channel_config_id.clone())
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            let source_map = channel_data
                .sources
                .entry(conn.source.clone())
                .or_default();
            let identity_key = conn
                .identity_hash
                .clone()
                .unwrap_or_else(|| "anonymous".to_string());
            let identity_map = source_map
                .entry(identity_key)
                .or_default();
            let dest_map = identity_map
                .entry(conn.destination.clone())
                .or_default();
            let trace_vec = dest_map
                .entry(conn.trace_id.clone())
                .or_default();
            trace_vec.push(ConnectionDataPoint {
                timestamp: conn.timestamp,
                status: conn.status,
                latency_ms: conn.latency_ms,
                identity_hash: conn.identity_hash.clone(),
                direction: conn.direction,
                ucp_operation: conn.ucp_operation.clone(),
                transit_point: conn.transit_point.clone(),
                variant_alias: conn.variant_alias.clone(),
                metric_type: conn.metric_type,
                correlation_id: conn.correlation_id.clone(),
                agent_identity: conn.agent_identity.clone(),
                channel_request_latency_ms: conn.channel_request_latency_ms,
                channel_response_latency_ms: conn.channel_response_latency_ms,
                request_bytes: conn.request_bytes,
                response_bytes: conn.response_bytes,
                retry_count: conn.retry_count,
                total_latency_ms: conn.total_latency_ms,
            });
        }

        // Add rule triggers to their channels
        for event in events.iter() {
            let channel_data = hierarchical
                .entry(
                    event
                        .channel_config_id
                        .clone(),
                )
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            channel_data
                .rule_triggers
                .push(RuleValidationDataPoint {
                    timestamp: event.timestamp,
                    accepted: event.accepted,
                });
        }

        hierarchical
    }

    /// Get rule validation metrics for a specific channel
    pub async fn get_rule_metrics(
        &self,
        channel_config_id: &str,
    ) -> Option<RuleMetric> {
        let metrics = self.rule_metrics.read().await;
        metrics
            .get(channel_config_id)
            .cloned()
    }

    /// Get all rule validation metrics
    #[allow(dead_code)]
    pub async fn get_all_rule_metrics(&self) -> Vec<RuleMetric> {
        let metrics = self.rule_metrics.read().await;
        metrics
            .values()
            .cloned()
            .collect()
    }

    /// Get the last connection status for a specific channel
    pub async fn get_last_status(
        &self,
        channel_config_id: &str,
    ) -> Option<ConnectionStatus> {
        let last_status = self
            .last_status_by_channel
            .read()
            .await;
        last_status
            .get(channel_config_id)
            .cloned()
    }

    /// Truncate metrics older than retention period and return stats
    pub async fn truncate_old_metrics(&self) -> Result<TruncateMetricsResult, String> {
        let cutoff_time = Utc::now() - chrono::Duration::minutes(self.metrics_retention_minutes as i64);

        let connections_removed;
        let connections_retained;
        let events_removed;
        let events_retained;

        // Filter connections
        {
            let mut connections = self.connections.write().await;
            let original_len = connections.len();
            connections.retain(|c| c.timestamp >= cutoff_time);
            connections_removed = original_len - connections.len();
            connections_retained = connections.len();
        }

        // Filter rule validation events
        {
            let mut events = self
                .rule_validation_events
                .write()
                .await;
            let original_len = events.len();
            events.retain(|e| e.timestamp >= cutoff_time);
            events_removed = original_len - events.len();
            events_retained = events.len();
        }

        // Save the filtered metrics to disk
        if let Some(path) = &self.storage_path {
            let connections = self
                .connections
                .read()
                .await
                .clone();
            let rule_metrics = self
                .rule_metrics
                .read()
                .await
                .clone();
            let events = self
                .rule_validation_events
                .read()
                .await
                .clone();
            let path_clone = path.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::save_to_file(&path_clone, &connections, &rule_metrics, &events).await {
                    eprintln!("Failed to save truncated metrics: {}", e);
                }
            });
        }

        Ok(TruncateMetricsResult {
            connections_removed,
            connections_retained,
            events_removed,
            events_retained,
        })
    }
}

/// Calculate percentile from sorted latencies
fn percentile(
    sorted_latencies: &[u64],
    p: u8,
) -> u64 {
    if sorted_latencies.is_empty() {
        return 0;
    }

    let index = ((p as f64 / 100.0) * (sorted_latencies.len() as f64 - 1.0)).round() as usize;
    sorted_latencies[index.min(sorted_latencies.len() - 1)]
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::MetricsStore;

    #[tokio::test]
    async fn record_user_login_increments_prometheus_counter() {
        let store = MetricsStore::new(10);
        let role = "store_test_login_role";

        let before = crate::metrics::backends::prometheus::USER_LOGINS
            .with_label_values(&[role])
            .get();

        store
            .record_user_login(role)
            .await;

        let after = crate::metrics::backends::prometheus::USER_LOGINS
            .with_label_values(&[role])
            .get();

        assert_eq!(after, before + 1);
    }
}
