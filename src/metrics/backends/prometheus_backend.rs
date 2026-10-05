//! Prometheus metrics backend implementation

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use super::types::{MetricsBackend, MetricsSnapshot};
use crate::identity::IdentityStore;
use crate::metrics::{ConnectionMetric, RuleMetric, RuleValidationEvent};
use crate::observability::TaskMonitor;

/// Prometheus metrics backend (tracks real-time aggregates in Prometheus registry)
pub struct PrometheusMetricsBackend {
    task_monitor: Option<Arc<TaskMonitor>>,
    identity_store: Option<Arc<dyn IdentityStore>>,
}

impl PrometheusMetricsBackend {
    pub fn new() -> Self {
        Self {
            task_monitor: None,
            identity_store: None,
        }
    }

    pub fn with_task_monitor_and_identity_store(
        task_monitor: Arc<TaskMonitor>,
        identity_store: Arc<dyn IdentityStore>,
    ) -> Self {
        Self {
            task_monitor: Some(task_monitor),
            identity_store: Some(identity_store),
        }
    }
}

#[async_trait::async_trait]
impl MetricsBackend for PrometheusMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        _rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        // Calculate and update Prometheus metrics from current data
        let aggregator = super::types::MetricsAggregator::from_data(
            connections,
            rule_metrics,
            self.task_monitor.as_ref(),
            self.identity_store.as_ref(),
        )
        .await;

        // Update Prometheus metrics from aggregated values
        use super::prometheus::{
            ACTIVE_CONNECTIONS, AVG_REQUEST_LATENCY_MS, AVG_RESPONSE_LATENCY_MS, CONNECTIONS_PER_MINUTE,
            THROUGHPUT_BYTES_PER_SEC, UNIQUE_IDENTITIES,
        };

        ACTIVE_CONNECTIONS.set(aggregator.active_connections as f64);
        UNIQUE_IDENTITIES.set(aggregator.unique_identity_count as i64);
        THROUGHPUT_BYTES_PER_SEC.set(aggregator.throughput_bytes_per_sec);
        CONNECTIONS_PER_MINUTE.set(aggregator.connections_per_minute);
        AVG_REQUEST_LATENCY_MS.set(aggregator.avg_request_latency_ms);
        AVG_RESPONSE_LATENCY_MS.set(aggregator.avg_response_latency_ms);

        Ok(())
    }

    async fn load(&self) -> Result<MetricsSnapshot> {
        // Prometheus doesn't persist historical data, return empty snapshot
        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }

    fn name(&self) -> &str {
        "prometheus"
    }
}
