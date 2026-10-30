//! MCP logging support
//!
//! Deprecated: MCP `2026-07-28` deprecates protocol logging in favour of
//! stderr or OpenTelemetry. Kept for legacy (`2024-11-05`) peers; modern
//! request-scoped `notifications/message` are relayed only when the request
//! opts in with `io.modelcontextprotocol/logLevel` (`src/mcp/modern_sse.rs`).
//! Do not extend it.

use serde_json::Value as JsonValue;
use tracing::debug;

/// Record a `notifications/message` a client sent. Its level, logger and data are
/// chosen by the client, so only the size of its data is logged, at debug.
pub async fn handle_logging_message(
    body: &JsonValue,
    channel_name: &str,
) {
    let data_bytes = body
        .get("params")
        .and_then(|params| params.get("data"))
        .map_or(0, |data| data.to_string().len());
    debug!(channel = channel_name, data_bytes, "Received MCP logging notification");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::formatted_logs::FormattedLogs;

    #[tokio::test]
    async fn a_logging_notification_is_logged_at_debug_without_its_data() {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {"level": "error", "logger": "logger-marker", "data": {"text": "client-data-marker"}}
        });
        let data_bytes = notification["params"]["data"]
            .to_string()
            .len();
        let logs = FormattedLogs::capture();

        handle_logging_message(&notification, "test-channel").await;

        let text = logs.text();
        assert!(text.contains("DEBUG Received MCP logging notification"), "{text}");
        assert!(text.contains(&format!("data_bytes={data_bytes}")), "{text}");
        assert!(!text.contains("ERROR"), "the client chose the level: {text}");
        assert!(!text.contains("client-data-marker"), "a log holds the client's data: {text}");
        assert!(!text.contains("logger-marker"), "a log holds the client's logger name: {text}");
    }

    #[tokio::test]
    async fn a_logging_notification_without_data_logs_zero_bytes() {
        let logs = FormattedLogs::capture();

        handle_logging_message(&serde_json::json!({"method": "notifications/message"}), "test-channel").await;

        let text = logs.text();
        assert!(text.contains("Received MCP logging notification"), "{text}");
        assert!(text.contains("data_bytes=0"), "{text}");
    }
}
