//! Metrics aggregator implementation

use crate::identity::IdentityStore;
use crate::metrics::{ConnectionDirection, ConnectionMetric, ConnectionStatus, RuleMetric};
use crate::observability::TaskMonitor;
use std::collections::HashMap;
use std::sync::Arc;

use super::types::MetricsAggregator;

impl MetricsAggregator {
    /// Aggregate metrics from raw connection data and rule metrics
    /// This is the single source of truth for all metric calculations
    pub async fn from_data(
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        task_monitor: Option<&Arc<TaskMonitor>>,
        identity_store: Option<&Arc<dyn IdentityStore>>,
    ) -> Self {
        // Calculate aggregates from connections (only count requests, not responses)
        let mut success_count = 0u64;
        let mut failure_count = 0u64;
        let mut gateway_fault_count = 0u64;
        let mut total_request_latency_ms = 0u64;
        let mut request_latency_count = 0usize;
        let mut total_response_latency_ms = 0u64;
        let mut response_latency_count = 0usize;
        let mut unique_identities = std::collections::HashSet::new();

        for conn in connections {
            // Count by direction
            if conn.direction == ConnectionDirection::Request {
                match conn.status {
                    ConnectionStatus::Success => success_count += 1,
                    ConnectionStatus::Failed => failure_count += 1,
                    ConnectionStatus::GatewayFault => gateway_fault_count += 1,
                }

                if let Some(latency) = conn.latency_ms {
                    total_request_latency_ms += latency;
                    request_latency_count += 1;
                }

                if let Some(ref identity) = conn.identity_hash {
                    unique_identities.insert(identity.clone());
                }
            } else if conn.direction == ConnectionDirection::Response {
                // Track response latency separately
                if let Some(latency) = conn.latency_ms {
                    total_response_latency_ms += latency;
                    response_latency_count += 1;
                }
            }
        }

        let total_requests = success_count + failure_count + gateway_fault_count;
        let avg_request_latency_ms = if request_latency_count > 0 {
            (total_request_latency_ms as f64) / (request_latency_count as f64)
        } else {
            0.0
        };
        let avg_response_latency_ms = if response_latency_count > 0 {
            (total_response_latency_ms as f64) / (response_latency_count as f64)
        } else {
            0.0
        };

        // Get unique identity count from identity_store (authoritative source)
        let unique_identity_count = if let Some(store) = identity_store {
            match store.list_all().await {
                Ok(identities) => identities.len(),
                Err(e) => {
                    tracing::warn!("Failed to get identity count: {}", e);
                    unique_identities.len() // Fallback to connection-based count
                }
            }
        } else {
            unique_identities.len()
        };

        // Calculate rule validation metrics
        let mut rule_accept_count = 0u64;
        let mut rule_reject_count = 0u64;
        for metric in rule_metrics.values() {
            rule_accept_count += metric.accept_count;
            rule_reject_count += metric.deny_count;
        }

        // Get real-time metrics from task monitor if available
        let (active_connections, throughput_bytes_per_sec, connections_per_minute) = if let Some(monitor) = task_monitor
        {
            let summary = monitor.get_summary().await;
            let all_metrics = monitor
                .get_all_metrics()
                .await;

            let mut total_throughput = 0.0;
            let mut total_connections_per_min = 0.0;
            for metric in &all_metrics {
                total_throughput += metric.throughput_bytes_per_sec;
                total_connections_per_min += metric.connections_per_minute;
            }

            tracing::debug!(
                "MetricsAggregator::from_data - {} tasks, total_throughput={:.2} B/s, metrics: {:?}",
                all_metrics.len(),
                total_throughput,
                all_metrics
                    .iter()
                    .map(|m| (m.task_id.as_str(), m.throughput_bytes_per_sec))
                    .collect::<Vec<_>>()
            );

            (summary.total_active_connections, total_throughput, total_connections_per_min)
        } else {
            (0, 0.0, 0.0)
        };

        // User lifecycle metrics (from Prometheus counters)
        use crate::auth::types::UserRole;
        use strum::IntoEnumIterator;
        let user_created_count = UserRole::iter()
            .map(|role| {
                super::prometheus::USER_EVENTS
                    .with_label_values(&["created", &role.to_string()])
                    .get()
            })
            .sum::<u64>();
        let user_login_count = UserRole::iter()
            .map(|role| {
                super::prometheus::USER_LOGINS
                    .with_label_values(&[&role.to_string()])
                    .get()
            })
            .sum::<u64>();

        Self {
            total_requests,
            success_count,
            failure_count,
            gateway_fault_count,
            avg_request_latency_ms,
            request_latency_sample_count: request_latency_count,
            avg_response_latency_ms,
            response_latency_sample_count: response_latency_count,
            unique_identity_count,
            rule_accept_count,
            rule_reject_count,
            active_connections: active_connections as usize,
            throughput_bytes_per_sec,
            connections_per_minute,
            user_created_count,
            user_login_count,
        }
    }
}
