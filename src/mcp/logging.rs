//! MCP logging support
//!
//! Deprecated: MCP `2026-07-28` deprecates protocol logging in favour of
//! stderr or OpenTelemetry. Kept for legacy (`2024-11-05`) peers; modern
//! request-scoped `notifications/message` are relayed only when the request
//! opts in with `io.modelcontextprotocol/logLevel` (`src/mcp/modern_sse.rs`).
//! Do not extend it.

use serde_json::Value as JsonValue;
use tracing::{debug, error, info, warn};

/// Handle logging notification from server
pub async fn handle_logging_message(
    body: &JsonValue,
    channel_name: &str,
) {
    if let Some(params) = body.get("params") {
        let level = params
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let logger = params
            .get("logger")
            .and_then(|v| v.as_str())
            .unwrap_or("mcp");
        let data = params.get("data");

        let log_message = if let Some(data_val) = data {
            format!("[{}] {}: {}", channel_name, logger, serde_json::to_string(data_val).unwrap_or_default())
        } else {
            format!("[{}] {}: (no data)", channel_name, logger)
        };

        match level {
            "debug" => debug!("{}", log_message),
            "info" => info!("{}", log_message),
            "warning" | "warn" => warn!("{}", log_message),
            "error" => error!("{}", log_message),
            _ => info!("{}", log_message),
        }
    }
}
