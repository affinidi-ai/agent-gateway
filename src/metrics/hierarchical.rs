//! Hierarchical metrics utilities

use std::collections::HashMap;

use crate::metrics::types::{
    ConnectionDataPoint, ConnectionDirection, ConnectionMetric, MetricsData, RuleMetric, RuleValidationDataPoint,
    RuleValidationEvent, SurfaceMetricsData,
};

/// Build hierarchical metrics format from flat metrics (public helper for backends)
pub fn build_hierarchical_metrics(
    connections: &[ConnectionMetric],
    _rule_metrics: &HashMap<String, RuleMetric>,
    rule_validation_events: &[RuleValidationEvent],
) -> MetricsData {
    let mut connections_map: HashMap<String, SurfaceMetricsData> = HashMap::new();

    // Add connections organized by source -> identity -> destination -> trace_id
    for conn in connections {
        let (client_source, target_dest) = if conn.direction == ConnectionDirection::Response {
            (conn.destination.clone(), conn.source.clone())
        } else {
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

    // Add rule triggers
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

    MetricsData { connections: connections_map }
}

/// Flatten hierarchical metrics back to flat format (public helper for backends)
pub fn flatten_hierarchical_metrics(data: &MetricsData) -> (Vec<ConnectionMetric>, Vec<RuleValidationEvent>) {
    let mut connections = Vec::new();
    let mut rule_validation_events = Vec::new();

    for (channel_config_id, channel_data) in &data.connections {
        // Flatten connections
        for (source, identity_map) in &channel_data.sources {
            for (identity, dest_map) in identity_map {
                for (dest, trace_map) in dest_map {
                    for (trace_id, datapoints) in trace_map {
                        for dp in datapoints {
                            let (actual_source, actual_dest) = if dp.direction == ConnectionDirection::Response {
                                (dest.clone(), source.clone())
                            } else {
                                (source.clone(), dest.clone())
                            };

                            connections.push(ConnectionMetric {
                                channel_config_id: channel_config_id.clone(),
                                source: actual_source,
                                destination: actual_dest,
                                timestamp: dp.timestamp,
                                status: dp.status,
                                latency_ms: dp.latency_ms,
                                identity_hash: if identity == "anonymous" {
                                    None
                                } else {
                                    Some(identity.clone())
                                },
                                direction: dp.direction,
                                trace_id: trace_id.clone(),
                                ucp_operation: dp.ucp_operation.clone(),
                                transit_point: dp.transit_point.clone(),
                                variant_alias: dp.variant_alias.clone(),
                                metric_type: dp.metric_type,
                                correlation_id: dp.correlation_id.clone(),
                                agent_identity: dp.agent_identity.clone(),
                                channel_request_latency_ms: dp.channel_request_latency_ms,
                                channel_response_latency_ms: dp.channel_response_latency_ms,
                                request_bytes: dp.request_bytes,
                                response_bytes: dp.response_bytes,
                                retry_count: dp.retry_count,
                                total_latency_ms: dp.total_latency_ms,
                            });
                        }
                    }
                }
            }
        }

        // Flatten rule triggers
        for trigger in &channel_data.rule_triggers {
            rule_validation_events.push(RuleValidationEvent {
                timestamp: trigger.timestamp,
                channel_config_id: channel_config_id.clone(),
                accepted: trigger.accepted,
            });
        }
    }

    (connections, rule_validation_events)
}
