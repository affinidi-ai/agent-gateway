//! RAII guard for managing active connection counts
//!
//! Ensures active connection count is decremented even on abnormal disconnections

use std::sync::Arc;

/// RAII guard to ensure active connection count is decremented even on abnormal disconnections
pub struct ConnectionGuard {
    task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    task_id: Option<String>,
    decremented: bool,
}

impl ConnectionGuard {
    pub fn new(
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
        task_id: Option<String>,
    ) -> Self {
        Self {
            task_monitor,
            task_id,
            decremented: false,
        }
    }

    /// Manually decrement the connection (call this on successful completion)
    pub async fn decrement(&mut self) {
        if !self.decremented
            && let (Some(monitor), Some(id)) = (&self.task_monitor, &self.task_id)
        {
            monitor
                .decrement_active_connections(id)
                .await;
            self.decremented = true;
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if !self.decremented
            && let (Some(monitor), Some(id)) = (&self.task_monitor, &self.task_id)
        {
            let monitor = monitor.clone();
            let id = id.clone();
            // Use tokio::spawn to handle async cleanup in drop
            tokio::spawn(async move {
                tracing::warn!(
                    task_id = %id,
                    "Connection guard cleaning up - client likely disconnected abnormally"
                );
                monitor
                    .decrement_active_connections(&id)
                    .await;
            });
        }
    }
}
