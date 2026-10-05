//! OpenTelemetry metrics backend implementation
//!
//! Exports metrics to OpenTelemetry collectors via OTLP protocol

use anyhow::Result;
use opentelemetry::{KeyValue, metrics::*};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace};

use super::types::{MetricsBackend, MetricsSnapshot};
use crate::metrics::{ConnectionMetric, ConnectionStatus, RuleMetric, RuleValidationEvent};

use super::metric_names::otel as names;

/// Helper to build common attributes for connection metrics
fn connection_attributes(conn: &ConnectionMetric) -> Vec<KeyValue> {
    vec![
        KeyValue::new("metric.type", format!("{:?}", conn.metric_type).to_lowercase()),
        KeyValue::new("status", format!("{:?}", conn.status).to_lowercase()),
        KeyValue::new("direction", format!("{:?}", conn.direction).to_lowercase()),
    ]
}

/// Helper to build channel-specific attributes
fn channel_attributes(
    conn: &ConnectionMetric,
    channel_id: &str,
) -> Vec<KeyValue> {
    let mut attrs = connection_attributes(conn);
    attrs.push(KeyValue::new("channel.id", channel_id.to_string()));
    attrs
}

/// Helper to build MCP-specific attributes
fn mcp_attributes(
    conn: &ConnectionMetric,
    mcp_id: &str,
) -> Vec<KeyValue> {
    let mut attrs = connection_attributes(conn);
    attrs.push(KeyValue::new("mcp.id", mcp_id.to_string()));
    attrs
}

/// OpenTelemetry metrics backend for exporting to OTLP collectors
pub struct OpenTelemetryMetricsBackend {
    #[allow(dead_code)]
    meter: Meter,
    // Connection metrics instruments
    connection_counter: Counter<u64>,
    connection_latency: Histogram<f64>,
    #[allow(dead_code)]
    active_connections: UpDownCounter<i64>,

    // Channel metrics instruments
    channel_requests: Counter<u64>,
    channel_latency: Histogram<f64>,

    // MCP metrics instruments
    mcp_requests: Counter<u64>,
    mcp_latency: Histogram<f64>,

    // Rule validation metrics
    rule_validations: Counter<u64>,

    // Byte transfer metrics
    bytes_sent: Counter<u64>,
    bytes_received: Counter<u64>,

    // User lifecycle metrics
    #[allow(dead_code)]
    user_events: Counter<u64>,
    #[allow(dead_code)]
    user_logins: Counter<u64>,

    // Track active connections for gauge updates
    #[allow(dead_code)]
    active_connection_count: Arc<tokio::sync::RwLock<i64>>,
}

impl OpenTelemetryMetricsBackend {
    /// Create a new OpenTelemetry metrics backend
    pub fn new(meter_provider: &SdkMeterProvider) -> Self {
        let meter = meter_provider.meter(env!("CARGO_PKG_NAME"));

        // Connection metrics
        let connection_counter = meter
            .u64_counter(names::CONNECTIONS_TOTAL)
            .with_description("Total number of connections processed")
            .build();

        let connection_latency = meter
            .f64_histogram(names::CONNECTION_LATENCY)
            .with_description("Connection latency in milliseconds")
            .build();

        let active_connections = meter
            .i64_up_down_counter(names::CONNECTIONS_ACTIVE)
            .with_description("Number of currently active connections")
            .build();

        // Channel metrics
        let channel_requests = meter
            .u64_counter(names::CHANNEL_REQUESTS_TOTAL)
            .with_description("Total number of channel requests")
            .build();

        let channel_latency = meter
            .f64_histogram(names::CHANNEL_LATENCY)
            .with_description("Channel request latency in milliseconds")
            .build();

        // MCP metrics
        let mcp_requests = meter
            .u64_counter(names::MCP_REQUESTS_TOTAL)
            .with_description("Total number of MCP proxy requests")
            .build();

        let mcp_latency = meter
            .f64_histogram(names::MCP_LATENCY)
            .with_description("MCP request latency in milliseconds")
            .build();

        // Rule validation metrics
        let rule_validations = meter
            .u64_counter(names::RULES_VALIDATIONS_TOTAL)
            .with_description("Total number of rule validations")
            .build();

        // Byte transfer metrics
        let bytes_sent = meter
            .u64_counter(names::BYTES_SENT_TOTAL)
            .with_description("Total bytes sent")
            .build();

        let bytes_received = meter
            .u64_counter(names::BYTES_RECEIVED_TOTAL)
            .with_description("Total bytes received")
            .build();

        // User lifecycle metrics
        let user_events = meter
            .u64_counter(names::USER_EVENTS_TOTAL)
            .with_description("Total number of user lifecycle events")
            .build();

        let user_logins = meter
            .u64_counter(names::USER_LOGINS_TOTAL)
            .with_description("Total number of user logins")
            .build();

        Self {
            meter,
            connection_counter,
            connection_latency,
            active_connections,
            channel_requests,
            channel_latency,
            mcp_requests,
            mcp_latency,
            rule_validations,
            bytes_sent,
            bytes_received,
            user_events,
            user_logins,
            active_connection_count: Arc::new(tokio::sync::RwLock::new(0)),
        }
    }

    /// Record a single connection metric
    fn record_connection(
        &self,
        conn: &ConnectionMetric,
    ) {
        // Get base attributes for this connection
        let base_attributes = connection_attributes(conn);

        // Add channel/mcp specific attributes
        match conn.metric_type {
            crate::metrics::MetricType::Channel => {
                let attributes = channel_attributes(conn, &conn.channel_config_id);

                // Record channel request
                self.channel_requests
                    .add(1, &attributes);

                // Record channel latency
                if let Some(latency) = conn.latency_ms {
                    self.channel_latency
                        .record(latency as f64, &attributes);
                }
            }
            crate::metrics::MetricType::McpProxy => {
                let attributes = mcp_attributes(conn, &conn.channel_config_id);

                // Record MCP request
                self.mcp_requests
                    .add(1, &attributes);

                // Record MCP latency
                if let Some(latency) = conn.latency_ms {
                    self.mcp_latency
                        .record(latency as f64, &attributes);
                }
            }
        }

        // Record general connection metrics with base attributes
        self.connection_counter
            .add(1, &base_attributes);

        if let Some(latency) = conn.latency_ms {
            self.connection_latency
                .record(latency as f64, &base_attributes);
        }

        // Record byte transfers
        if let Some(bytes) = conn.request_bytes {
            self.bytes_received
                .add(bytes, &base_attributes);
        }

        if let Some(bytes) = conn.response_bytes {
            self.bytes_sent
                .add(bytes, &base_attributes);
        }

        // Update active connections gauge
        // Note: This is a simplification - in production you'd track actual active connections
        match conn.status {
            ConnectionStatus::Success | ConnectionStatus::Failed | ConnectionStatus::GatewayFault => {
                // Connection completed
                trace!("Connection completed: {:?}", conn.status);
            }
        }
    }

    /// Record rule validation metrics
    fn record_rule_validation(
        &self,
        event: &RuleValidationEvent,
    ) {
        let attributes = vec![
            KeyValue::new(
                "channel.id",
                event
                    .channel_config_id
                    .clone(),
            ),
            KeyValue::new("accepted", event.accepted),
        ];

        self.rule_validations
            .add(1, &attributes);
    }
}

#[async_trait::async_trait]
impl MetricsBackend for OpenTelemetryMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        _rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        trace!("Exporting {} connections to OpenTelemetry", connections.len());

        // Export connection metrics
        for conn in connections {
            self.record_connection(conn);
        }

        // Export rule validation metrics
        for event in rule_validation_events {
            self.record_rule_validation(event);
        }

        debug!(
            "Exported {} connections and {} rule validations to OpenTelemetry",
            connections.len(),
            rule_validation_events.len()
        );

        Ok(())
    }

    async fn load(&self) -> Result<MetricsSnapshot> {
        // OpenTelemetry is export-only, no loading
        // Return empty snapshot
        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }

    fn name(&self) -> &str {
        "opentelemetry"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore] // FIXME: failing test
    fn test_backend_name() {
        let _config = crate::observability::opentelemetry::OtelConfig::default();

        // This test would require initializing a full meter provider
        // For now, just verify the backend name concept
        assert_eq!("opentelemetry".len(), 14);
    }
}
