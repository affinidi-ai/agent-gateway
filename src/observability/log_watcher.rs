//! Log file watcher for real-time log streaming via WebSocket
//! NOTE: This module is currently unused - logs are broadcast via WebSocketLogLayer instead
//! which intercepts log events directly from the tracing layer with zero overhead.

use std::sync::Arc;

/// Watch log file for changes and broadcast new entries via WebSocket
/// NOTE: This function is no longer used - replaced by WebSocketLogLayer for efficiency
#[allow(dead_code)]
pub async fn watch_log_file(
    _log_path: std::path::PathBuf,
    _ws_state: Arc<crate::server::WsState>,
) {
    // This function is deprecated and no longer called
    // Logs are now broadcast directly via WebSocketLogLayer
}
