//! Payload capture and WebSocket broadcasting

use std::sync::Arc;
use tracing::{debug, warn};

/// Broadcast payload capture via WebSocket with validation status and store in metrics
/// Captures the full transformation pipeline with 4 stages
#[allow(clippy::too_many_arguments)]
pub async fn broadcast_payload_capture_async(
    ws_state: &Option<Arc<crate::server::WsState>>,
    metrics_store: &Option<Arc<crate::metrics::MetricsStore>>,
    channel_name: &str,
    config_id: &str,
    payload: &serde_json::Value,
    response_payload: Option<serde_json::Value>,
    validation_status: &str,
    validation_error: Option<String>,
    identity_hash: Option<String>,
    variant_alias: Option<&str>,
) {
    broadcast_payload_capture_extended(
        ws_state,
        metrics_store,
        channel_name,
        config_id,
        payload,
        None, // outbound_payload
        None, // inbound_response
        response_payload,
        validation_status,
        validation_error,
        identity_hash,
        variant_alias,
    )
    .await;
}

/// Extended payload capture with 4-stage transformation pipeline
#[allow(clippy::too_many_arguments)]
pub async fn broadcast_payload_capture_extended(
    ws_state: &Option<Arc<crate::server::WsState>>,
    metrics_store: &Option<Arc<crate::metrics::MetricsStore>>,
    channel_name: &str,
    config_id: &str,
    inbound_request: &serde_json::Value,
    outbound_request: Option<serde_json::Value>,
    inbound_response: Option<serde_json::Value>,
    outbound_response: Option<serde_json::Value>,
    validation_status: &str,
    validation_error: Option<String>,
    identity_hash: Option<String>,
    variant_alias: Option<&str>,
) {
    // Store payload in metrics if we have an identity hash
    if let (Some(metrics), Some(hash)) = (metrics_store, &identity_hash) {
        metrics
            .store_last_payload(hash.clone(), inbound_request.clone())
            .await;
    }

    // Always store the latest payload for this channel (regardless of identity)
    if let Some(metrics) = metrics_store {
        metrics
            .store_latest_channel_payload(channel_name.to_string(), inbound_request.clone())
            .await;
    }

    // Broadcast via websocket
    if let Some(ws) = ws_state {
        let timestamp = chrono::Utc::now().to_rfc3339();
        // Use default schema for non-onboarding channels
        let default_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "agentIdentity": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            "required": []
        });
        ws.broadcast(crate::server::WsUpdate::PayloadCaptured {
            channel: channel_name.to_string(),
            config_id: config_id.to_string(),
            payload: inbound_request.clone(),
            response_payload: outbound_response.clone(),
            outbound_request: Box::new(outbound_request.clone()),
            inbound_response: Box::new(inbound_response.clone()),
            timestamp,
            validation_status: validation_status.to_string(),
            validation_error,
            derived_schema: Box::new(default_schema),
            variant_alias: variant_alias.map(str::to_string),
        });
        debug!(
            channel = channel_name,
            config_id = config_id,
            validation_status = validation_status,
            "Broadcasted payload capture via WebSocket"
        );
    } else {
        warn!(channel = channel_name, "Cannot broadcast payload - ws_state is None");
    }
}
