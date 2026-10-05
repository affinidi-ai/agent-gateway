//! Periodic metrics updates via WebSocket

use chrono::Utc;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::debug;

/// Periodically send metrics updates via WebSocket to keep UI responsive even with no traffic
/// Only broadcasts when metrics have actually changed to reduce unnecessary network traffic
pub async fn periodic_metrics_update(
    ws_state: Arc<crate::server::WsState>,
    metrics_store: Arc<crate::metrics::MetricsStore>,
) {
    // Send updates every 5 seconds
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    debug!("Starting periodic metrics update task");

    // Track previous values to detect changes
    let mut last_connections_count: Option<usize> = None;
    let mut last_recent_count: Option<usize> = None;
    let mut last_channel_stats_hash: Option<u64> = None;

    loop {
        interval.tick().await;

        // Get current metrics
        let connections_count = metrics_store
            .get_total_connections()
            .await;
        let recent_connections = metrics_store
            .get_recent_connections(60)
            .await; // Last 60 connections
        let throughput = recent_connections.len() as f64 / 60.0; // Approximate requests per second

        // Get channel stats for active channels
        let channel_stats = metrics_store
            .get_channel_stats()
            .await;

        // Compute a simple hash of channel stats for change detection
        let channel_stats_hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            format!("{:?}", channel_stats).hash(&mut hasher);
            hasher.finish()
        };

        // Only broadcast if something changed
        let has_changes = last_connections_count != Some(connections_count)
            || last_recent_count != Some(recent_connections.len())
            || last_channel_stats_hash != Some(channel_stats_hash);

        if has_changes {
            // Update last known values
            last_connections_count = Some(connections_count);
            last_recent_count = Some(recent_connections.len());
            last_channel_stats_hash = Some(channel_stats_hash);

            // Broadcast metrics update
            ws_state.broadcast(crate::server::WsUpdate::MetricsUpdated {
                metrics: serde_json::json!({
                    "total_connections": connections_count,
                    "recent_connections_count": recent_connections.len(),
                    "throughput_rps": throughput,
                    "channel_stats": channel_stats,
                    "timestamp": Utc::now().to_rfc3339(),
                }),
            });

            debug!(
                "Sent periodic metrics update: {} total, {} recent, {:.2} rps (changes detected)",
                connections_count,
                recent_connections.len(),
                throughput
            );
        } else {
            debug!("Skipping metrics update - no changes detected");
        }
    }
}
