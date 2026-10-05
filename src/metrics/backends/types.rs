//! Metrics backend types and traits

use crate::metrics::{ConnectionMetric, RuleMetric, RuleValidationEvent};
use anyhow::Result;
use std::collections::HashMap;

/// Trait for metrics persistence backends
#[async_trait::async_trait]
pub trait MetricsBackend: Send + Sync {
    /// Persist metrics to the backend
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()>;

    /// Load metrics from the backend
    async fn load(&self) -> Result<MetricsSnapshot>;

    /// Get the backend name for logging
    fn name(&self) -> &str;
}

/// Snapshot of metrics loaded from backend
pub struct MetricsSnapshot {
    pub connections: Vec<ConnectionMetric>,
    pub rule_validation_events: Vec<RuleValidationEvent>,
}

/// Centralized metrics aggregator to ensure consistent calculations across all backends
#[derive(Debug, Clone)]
pub struct MetricsAggregator {
    pub total_requests: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub gateway_fault_count: u64,
    pub avg_request_latency_ms: f64,
    pub request_latency_sample_count: usize,
    pub avg_response_latency_ms: f64,
    pub response_latency_sample_count: usize,
    pub unique_identity_count: usize,
    pub rule_accept_count: u64,
    pub rule_reject_count: u64,
    pub active_connections: usize,
    pub throughput_bytes_per_sec: f64,
    pub connections_per_minute: f64,
    pub user_created_count: u64,
    pub user_login_count: u64,
}

impl Default for MetricsAggregator {
    fn default() -> Self {
        MetricsAggregator {
            total_requests: 0,
            success_count: 0,
            failure_count: 0,
            gateway_fault_count: 0,
            avg_request_latency_ms: 0.0,
            request_latency_sample_count: 0,
            avg_response_latency_ms: 0.0,
            response_latency_sample_count: 0,
            unique_identity_count: 0,
            rule_accept_count: 0,
            rule_reject_count: 0,
            active_connections: 0,
            throughput_bytes_per_sec: 0.0,
            connections_per_minute: 0.0,
            user_created_count: 0,
            user_login_count: 0,
        }
    }
}
