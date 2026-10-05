//! Custom tracing layer that broadcasts log activity notifications via WebSocket

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Global WebSocket state for broadcasting log notifications
static WS_STATE: OnceLock<Arc<crate::server::WsState>> = OnceLock::new();
/// Flag to track if we need to send a notification
static NEEDS_NOTIFICATION: AtomicBool = AtomicBool::new(false);

/// Initialize the WebSocket state for log broadcasting
pub fn init_websocket_log_broadcast(ws_state: Arc<crate::server::WsState>) {
    let _ = WS_STATE.set(ws_state.clone());

    // Spawn background task to send batched notifications
    tokio::spawn(async move {
        // Check for log activity every second
        let notification_interval = tokio::time::Duration::from_secs(1);

        loop {
            tokio::time::sleep(notification_interval).await;

            // Check if any logs were written since last notification
            if NEEDS_NOTIFICATION.swap(false, Ordering::Relaxed) {
                // Send minimal ping - frontend only uses this as a trigger to call /delta
                ws_state.broadcast(crate::server::WsUpdate::LogEntry {
                    entry: String::new(), // Empty - frontend doesn't use this content
                });
            }
        }
    });
}

/// A tracing layer that notifies via WebSocket when logs are written
/// Note: We don't send log content, just a notification that logs changed
pub struct WebSocketLogLayer;

impl WebSocketLogLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for WebSocketLogLayer
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &Event<'_>,
        _ctx: Context<'_, S>,
    ) {
        let metadata = event.metadata();

        // Only trigger on INFO+ level (ignore DEBUG/TRACE)
        if metadata.level() > &tracing::Level::INFO {
            return;
        }

        // Filter out noisy background logs that don't need UI updates
        let target = metadata.target();

        // Skip these modules - they generate noise but don't need real-time UI updates
        if target.contains("dashboard") ||          // Dashboard endpoints
           target.contains("metrics") ||            // Metrics collection
           target.contains("observability") ||      // Internal observability
           target.contains("websocket") ||          // Websocket internal logs
           target.contains("hyper") ||              // HTTP server internals
           target.contains("tokio") ||              // Async runtime
           target.contains("tower")
        {
            // HTTP middleware
            return;
        }

        // Flag that a user-facing log was written
        NEEDS_NOTIFICATION.store(true, Ordering::Relaxed);
    }
}
