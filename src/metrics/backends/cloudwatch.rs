//! CloudWatch metrics backend implementation

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use super::types::{MetricsAggregator, MetricsBackend, MetricsSnapshot};
use crate::config::metrics_config::CloudWatchMetricDimensionConfig;
use crate::identity::IdentityStore;
use crate::metrics::{ConnectionMetric, RuleMetric, RuleValidationEvent};
use crate::observability::TaskMonitor;

use aws_sdk_cloudwatch::types::Dimension;

use super::metric_names::cloudwatch as cw_names;

/// CloudWatch metrics backend (pushes aggregates to AWS CloudWatch)
pub struct CloudWatchMetricsBackend {
    namespace: String,
    enabled: bool,
    client: Option<aws_sdk_cloudwatch::Client>,
    region: Option<String>,
    profile: Option<String>,
    task_monitor: Option<Arc<TaskMonitor>>,
    identity_store: Option<Arc<dyn IdentityStore>>,
    last_sent: Arc<tokio::sync::RwLock<Option<MetricsAggregator>>>,
    dimensions: Option<Vec<Dimension>>,
}

impl CloudWatchMetricsBackend {
    pub fn new(
        namespace: String,
        dimensions: Option<Vec<CloudWatchMetricDimensionConfig>>,
    ) -> Self {
        let cw_dimensions = dimensions.map(|dimensions| {
            dimensions
                .into_iter()
                .map(|config| {
                    Dimension::builder()
                        .name(config.name)
                        .value(config.value)
                        .build()
                })
                .collect()
        });

        tracing::info!("CloudWatchMetricsBackend - initialized with dimensions: {:?}", cw_dimensions);
        Self {
            namespace,
            enabled: false,
            client: None,
            region: None,
            profile: None,
            task_monitor: None,
            identity_store: None,
            last_sent: Arc::new(tokio::sync::RwLock::new(None)),
            dimensions: cw_dimensions,
        }
    }

    pub fn with_enabled(
        mut self,
        enabled: bool,
    ) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_region(
        mut self,
        region: Option<String>,
    ) -> Self {
        self.region = region;
        self
    }

    pub fn with_profile(
        mut self,
        profile: Option<String>,
    ) -> Self {
        self.profile = profile;
        self
    }

    pub fn with_task_monitor(
        mut self,
        task_monitor: Arc<TaskMonitor>,
    ) -> Self {
        self.task_monitor = Some(task_monitor);
        self
    }

    pub fn with_identity_store(
        mut self,
        identity_store: Arc<dyn IdentityStore>,
    ) -> Self {
        self.identity_store = Some(identity_store);
        self
    }

    pub async fn with_aws_client(mut self) -> Self {
        if self.enabled {
            let mut config_loader = aws_config::from_env();

            // Set profile if specified
            if let Some(ref profile) = self.profile {
                config_loader = config_loader.profile_name(profile);
                tracing::info!("CloudWatch configured with AWS profile: {}", profile);
            }

            // Set region if specified
            if let Some(ref region) = self.region {
                config_loader = config_loader.region(aws_sdk_cloudwatch::config::Region::new(region.clone()));
                tracing::info!("CloudWatch configured with region: {}", region);
            }

            let config = config_loader.load().await;
            self.client = Some(aws_sdk_cloudwatch::Client::new(&config));

            tracing::info!("CloudWatch client initialized for namespace: {}", self.namespace);
        }
        self
    }
}

#[async_trait::async_trait]
impl MetricsBackend for CloudWatchMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        _rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        tracing::debug!("CloudWatch - starting metrics persist");
        if !self.enabled {
            return Ok(()); // Skip if not enabled
        }

        let client = match &self.client {
            Some(c) => c,
            None => {
                tracing::warn!("CloudWatch client not initialized");
                return Ok(());
            }
        };

        let now = chrono::Utc::now();
        let timestamp = aws_sdk_cloudwatch::primitives::DateTime::from_millis(now.timestamp_millis());

        // Use centralized aggregator for gauge metrics (active connections, throughput, latency)
        // But use Prometheus counters for cumulative totals to match Prometheus exactly
        let aggregator = MetricsAggregator::from_data(
            connections,
            rule_metrics,
            self.task_monitor.as_ref(),
            self.identity_store.as_ref(),
        )
        .await;

        // Get cumulative counter values from Prometheus (source of truth for totals)
        use crate::metrics::backends::prometheus::{
            FAILURE_COUNTER, GATEWAY_FAULT_COUNTER, REQUEST_COUNTER, RULE_ACCEPT_COUNTER, RULE_REJECT_COUNTER,
            SUCCESS_COUNTER,
        };

        let total_requests = REQUEST_COUNTER.get() as u64;
        let success_count = SUCCESS_COUNTER.get() as u64;
        let failure_count = FAILURE_COUNTER.get() as u64;
        let gateway_fault_count = GATEWAY_FAULT_COUNTER.get() as u64;
        let rule_accept_count = RULE_ACCEPT_COUNTER.get() as u64;
        let rule_reject_count = RULE_REJECT_COUNTER.get() as u64;

        // Check if data has changed since last send
        // We only check counters (cumulative totals) for change detection, not gauges
        // Gauges like throughput/active_connections decay to zero naturally, causing unnecessary pushes
        let last_sent = self.last_sent.read().await;
        let sent_metrics_changed = if let Some(ref last) = *last_sent {
            last.total_requests != total_requests
                || last.success_count != success_count
                || last.failure_count != failure_count
                || last.gateway_fault_count != gateway_fault_count
                || last.rule_accept_count != rule_accept_count
                || last.rule_reject_count != rule_reject_count
                || last.user_created_count != aggregator.user_created_count
                || last.user_login_count != aggregator.user_login_count
                || last.request_latency_sample_count != aggregator.request_latency_sample_count
                || last.response_latency_sample_count != aggregator.response_latency_sample_count
                || (last.avg_request_latency_ms - aggregator.avg_request_latency_ms).abs() >= 0.01
                || (last.avg_response_latency_ms - aggregator.avg_response_latency_ms).abs() >= 0.01
        } else {
            true // If we've never sent metrics before, consider it changed
        };

        if !sent_metrics_changed {
            tracing::debug!("CloudWatch metrics unchanged (counters + latency) - skipping to save costs");
            return Ok(());
        } else {
            if let Some(ref last) = *last_sent {
                tracing::debug!(
                    "CloudWatch metrics changed - requests: {} -> {}, success: {} -> {}, failure: {} -> {}, gateway_fault: {} -> {}, rule_accept: {} -> {}, rule_reject: {} -> {}, user_logins: {} -> {}, user_created: {} -> {}, avg_request_latency_ms: {:.2} -> {:.2}, avg_response_latency_ms: {:.2} -> {:.2}",
                    last.total_requests,
                    total_requests,
                    last.success_count,
                    success_count,
                    last.failure_count,
                    failure_count,
                    last.gateway_fault_count,
                    gateway_fault_count,
                    last.rule_accept_count,
                    rule_accept_count,
                    last.rule_reject_count,
                    rule_reject_count,
                    last.user_login_count,
                    aggregator.user_login_count,
                    last.user_created_count,
                    aggregator.user_created_count,
                    last.avg_request_latency_ms,
                    aggregator.avg_request_latency_ms,
                    last.avg_response_latency_ms,
                    aggregator.avg_response_latency_ms,
                );
            } else {
                tracing::debug!("CloudWatch metrics changed - no previous data to compare (first send)");
            }
        }
        drop(last_sent);

        // Create updated aggregator with Prometheus counter values for change tracking
        let updated_aggregator = MetricsAggregator {
            total_requests,
            success_count,
            failure_count,
            gateway_fault_count,
            avg_request_latency_ms: aggregator.avg_request_latency_ms,
            request_latency_sample_count: aggregator.request_latency_sample_count,
            avg_response_latency_ms: aggregator.avg_response_latency_ms,
            response_latency_sample_count: aggregator.response_latency_sample_count,
            unique_identity_count: aggregator.unique_identity_count,
            rule_accept_count,
            rule_reject_count,
            active_connections: aggregator.active_connections,
            throughput_bytes_per_sec: aggregator.throughput_bytes_per_sec,
            connections_per_minute: aggregator.connections_per_minute,
            user_created_count: aggregator.user_created_count,
            user_login_count: aggregator.user_login_count,
        };

        // Build metric data from updated aggregator (with Prometheus counter values)
        let mut metric_data = vec![];

        // Request count metrics (use Prometheus counter values)
        if total_requests > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::REQUEST_COUNT)
                    .value(total_requests as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        if success_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::SUCCESS_COUNT)
                    .value(success_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        if failure_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::FAILURE_COUNT)
                    .value(failure_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        if gateway_fault_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::GATEWAY_FAULT_COUNT)
                    .value(gateway_fault_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Success rate percentage (use Prometheus counter values)
        if total_requests > 0 {
            let success_rate = (success_count as f64 / total_requests as f64) * 100.0;
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::SUCCESS_RATE)
                    .value(success_rate)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Percent)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Request latency metrics
        if aggregator.request_latency_sample_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::AVG_REQUEST_LATENCY)
                    .value(aggregator.avg_request_latency_ms)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Milliseconds)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );

            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::REQUEST_LATENCY_SAMPLE_COUNT)
                    .value(aggregator.request_latency_sample_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Response latency metrics
        if aggregator.response_latency_sample_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::AVG_RESPONSE_LATENCY)
                    .value(aggregator.avg_response_latency_ms)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Milliseconds)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );

            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::RESPONSE_LATENCY_SAMPLE_COUNT)
                    .value(aggregator.response_latency_sample_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Active connections
        if aggregator.active_connections > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::ACTIVE_CONNECTIONS)
                    .value(aggregator.active_connections as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Throughput
        if aggregator.throughput_bytes_per_sec > 0.0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::THROUGHPUT_BYTES_PER_SEC)
                    .value(aggregator.throughput_bytes_per_sec)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::BytesSecond)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Connections per minute
        if aggregator.connections_per_minute > 0.0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::CONNECTIONS_PER_MINUTE)
                    .value(aggregator.connections_per_minute)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::CountSecond)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Unique identities (single source of truth from aggregator)
        if aggregator.unique_identity_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::UNIQUE_IDENTITIES)
                    .value(aggregator.unique_identity_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Rule validation metrics (use Prometheus counter values)
        if rule_accept_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::RULE_ACCEPT_COUNT)
                    .value(rule_accept_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        if rule_reject_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::RULE_REJECT_COUNT)
                    .value(rule_reject_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        if aggregator.user_login_count > 0 {
            tracing::info!("CloudWatch - user logins count from Prometheus: {}", aggregator.user_login_count);
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::USER_LOGINS)
                    .value(aggregator.user_login_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        if aggregator.user_created_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::USER_CREATED_COUNT)
                    .value(aggregator.user_created_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        let active_users = super::prometheus::USERS_ACTIVE.get();
        if active_users > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name(cw_names::ACTIVE_USERS)
                    .value(active_users as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .set_dimensions(self.dimensions.clone())
                    .build(),
            );
        }

        // Send metrics to CloudWatch (max 1000 per request, we're well under)
        if !metric_data.is_empty() {
            let _metric_count = metric_data.len();

            let _start = std::time::Instant::now();
            match client
                .put_metric_data()
                .namespace(&self.namespace)
                .set_metric_data(Some(metric_data))
                .send()
                .await
            {
                Ok(_response) => {
                    // Store updated values (with Prometheus counter values) as last sent
                    let mut last_sent = self.last_sent.write().await;
                    *last_sent = Some(updated_aggregator);
                }
                Err(e) => {
                    tracing::error!("CloudWatch metrics push failed: {}", e);
                    tracing::debug!(
                        error = ?e,
                        error_type = ?std::any::type_name_of_val(&e),
                        namespace = %self.namespace,
                        "CloudWatch error details: {:#?}",
                        e
                    );
                    // Store attempted values as last sent even on failure
                    // This prevents "first send" messages on every retry
                    let mut last_sent = self.last_sent.write().await;
                    *last_sent = Some(updated_aggregator);
                }
            }
        } else {
            tracing::debug!("No CloudWatch metrics to send (all values are zero)");
        }

        Ok(())
    }

    async fn load(&self) -> Result<MetricsSnapshot> {
        // CloudWatch doesn't support loading historical data this way
        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }

    fn name(&self) -> &str {
        "cloudwatch"
    }
}
