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

    /// Release the connection from synchronous code, such as when a streamed
    /// response body ends or is dropped.
    pub fn release(mut self) {
        self.schedule_decrement(false);
    }

    fn schedule_decrement(
        &mut self,
        abnormal: bool,
    ) {
        if self.decremented {
            return;
        }
        self.decremented = true;
        let (Some(monitor), Some(id)) = (self.task_monitor.clone(), self.task_id.clone()) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(task_id = %id, "Connection released outside the async runtime; count not decremented");
            return;
        };
        runtime.spawn(async move {
            if abnormal {
                tracing::warn!(
                    task_id = %id,
                    "Connection guard cleaning up - client likely disconnected abnormally"
                );
            }
            monitor
                .decrement_active_connections(&id)
                .await;
        });
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.schedule_decrement(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{TaskInfo, TaskMonitor};

    const TASK: &str = "guarded";

    async fn monitor_with_one_connection() -> Arc<TaskMonitor> {
        let monitor = Arc::new(TaskMonitor::new(None));
        monitor
            .register_task(TaskInfo::running(TASK))
            .await;
        monitor
            .increment_connections(TASK)
            .await;
        monitor
    }

    async fn active(monitor: &TaskMonitor) -> u64 {
        for _ in 0..100 {
            let count = monitor
                .get_task(TASK)
                .await
                .unwrap()
                .active_connections;
            if count == 0 {
                return 0;
            }
            tokio::task::yield_now().await;
        }
        monitor
            .get_task(TASK)
            .await
            .unwrap()
            .active_connections
    }

    #[tokio::test]
    async fn release_and_drop_each_decrement_once() {
        let monitor = monitor_with_one_connection().await;
        ConnectionGuard::new(Some(monitor.clone()), Some(TASK.into())).release();
        assert_eq!(active(&monitor).await, 0);

        monitor
            .increment_connections(TASK)
            .await;
        drop(ConnectionGuard::new(Some(monitor.clone()), Some(TASK.into())));
        assert_eq!(active(&monitor).await, 0);

        monitor
            .increment_connections(TASK)
            .await;
        monitor
            .increment_connections(TASK)
            .await;
        let mut guard = ConnectionGuard::new(Some(monitor.clone()), Some(TASK.into()));
        guard.decrement().await;
        guard.release();
        tokio::task::yield_now().await;
        assert_eq!(
            monitor
                .get_task(TASK)
                .await
                .unwrap()
                .active_connections,
            1,
            "a decremented guard must not release again"
        );
    }

    #[test]
    fn dropping_outside_a_runtime_does_not_panic() {
        let monitor = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(monitor_with_one_connection());
        let guard = ConnectionGuard::new(Some(monitor.clone()), Some(TASK.into()));
        drop(guard);
        ConnectionGuard::new(Some(monitor), Some(TASK.into())).release();
    }
}
