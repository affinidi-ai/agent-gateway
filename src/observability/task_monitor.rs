//! Task monitoring for tracking spawned channel listeners and their metrics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Information about a running channel task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub task_id: String,
    pub config_id: Option<String>, // Immutable channel identifier
    pub channel_name: String,      // Display name only, can change
    /// When `Some(alias)`, this task represents a single transit-point
    /// (outbound virtual channel) of the parent surface, not the inbound
    /// access point. The dashboard renders TP rows nested under their
    /// surface group so per-TP throughput is visible separately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_point: Option<String>,
    pub listen_address: String,
    pub target_endpoint: String,
    pub started_at: DateTime<Utc>,
    pub status: TaskStatus,
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_activity: Option<DateTime<Utc>>,
    pub error_count: u64,
    // Recent activity tracking (last 60 seconds)
    #[serde(skip)]
    pub recent_bytes_sent: u64,
    #[serde(skip)]
    pub recent_bytes_received: u64,
    #[serde(skip)]
    pub recent_window_start: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Running,
    Starting,
    Stopping,
    Error,
}

/// Task metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMetrics {
    pub task_id: String,
    pub connections_per_minute: f64,
    pub throughput_bytes_per_sec: f64,
    pub avg_response_time_ms: f64,
    pub uptime_seconds: u64,
    pub cpu_usage_percent: Option<f64>,
    pub memory_usage_mb: Option<f64>,
}

/// Task statistics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatsSummary {
    pub total_tasks: usize,
    pub running_tasks: usize,
    pub total_connections: u64,
    pub total_active_connections: u64,
    pub total_bytes_transferred: u64,
    pub avg_uptime_seconds: u64,
}

/// Store for monitoring running tasks
pub struct TaskMonitor {
    tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    metrics_history: Arc<RwLock<HashMap<String, Vec<TaskMetrics>>>>,
    settings_store: Option<Arc<crate::storage::SettingsStore>>,
}

impl TaskMonitor {
    pub fn new(settings_store: Option<Arc<crate::storage::SettingsStore>>) -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            metrics_history: Arc::new(RwLock::new(HashMap::new())),
            settings_store,
        }
    }

    /// Register a new task
    pub async fn register_task(
        &self,
        mut task_info: TaskInfo,
    ) {
        let now = Utc::now();
        task_info.recent_bytes_sent = 0;
        task_info.recent_bytes_received = 0;
        task_info.recent_window_start = now;
        let mut tasks = self.tasks.write().await;
        tasks.insert(task_info.task_id.clone(), task_info);
    }

    /// Update task status
    pub async fn update_status(
        &self,
        task_id: &str,
        status: TaskStatus,
    ) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = status;
        }
    }

    /// Increment connection count for a task
    pub async fn increment_connections(
        &self,
        task_id: &str,
    ) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.total_connections += 1;
            task.active_connections += 1;
            task.last_activity = Some(Utc::now());
        }
    }

    /// Decrement active connection count for a task
    pub async fn decrement_active_connections(
        &self,
        task_id: &str,
    ) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id)
            && task.active_connections > 0
        {
            task.active_connections -= 1;
        }
    }

    /// Record bytes transferred for a task
    pub async fn record_bytes(
        &self,
        task_id: &str,
        sent: u64,
        received: u64,
    ) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            let prev_sent = task.bytes_sent;
            let prev_received = task.bytes_received;
            task.bytes_sent += sent;
            task.bytes_received += received;
            task.recent_bytes_sent += sent;
            task.recent_bytes_received += received;
            task.last_activity = Some(Utc::now());

            tracing::debug!(
                "TaskMonitor::record_bytes - task_id={}, surface={}, sent={} ({}→{}), received={} ({}→{}), total={}",
                task_id,
                task.channel_name,
                sent,
                prev_sent,
                task.bytes_sent,
                received,
                prev_received,
                task.bytes_received,
                task.bytes_sent + task.bytes_received
            );
        } else {
            tracing::warn!(
                "TaskMonitor::record_bytes - task_id={} not found, bytes not recorded (sent={}, received={})",
                task_id,
                sent,
                received
            );
        }
    }

    /// Record bytes for a transit-point task identified by its parent
    /// `config_id` and TP `alias`. Also bumps `total_connections` and
    /// `active_connections` to mirror what the inbound task accounting does.
    /// No-op if no matching TP task is registered.
    pub async fn record_tp_request(
        &self,
        config_id: &str,
        alias: &str,
        sent: u64,
        received: u64,
    ) {
        let mut tasks = self.tasks.write().await;
        let target_id = tasks
            .values()
            .find(|t| t.config_id.as_deref() == Some(config_id) && t.transit_point.as_deref() == Some(alias))
            .map(|t| t.task_id.clone());
        let Some(id) = target_id else {
            tracing::debug!("TaskMonitor::record_tp_request - no TP task for config_id={} alias={}", config_id, alias);
            return;
        };
        if let Some(task) = tasks.get_mut(&id) {
            task.bytes_sent += sent;
            task.bytes_received += received;
            task.recent_bytes_sent += sent;
            task.recent_bytes_received += received;
            task.total_connections += 1;
            task.last_activity = Some(Utc::now());
        }
    }

    /// Increment error count for a transit-point task.
    #[allow(dead_code)]
    pub async fn record_tp_error(
        &self,
        config_id: &str,
        alias: &str,
    ) {
        let mut tasks = self.tasks.write().await;
        let target_id = tasks
            .values()
            .find(|t| t.config_id.as_deref() == Some(config_id) && t.transit_point.as_deref() == Some(alias))
            .map(|t| t.task_id.clone());
        if let Some(id) = target_id
            && let Some(task) = tasks.get_mut(&id)
        {
            task.error_count += 1;
        }
    }

    /// Increment error count for a task
    pub async fn increment_errors(
        &self,
        task_id: &str,
    ) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.error_count += 1;
        }
    }

    /// Reset task activity windows when settings change
    #[allow(dead_code)]
    pub async fn reset_activity_windows(&self) {
        let mut tasks = self.tasks.write().await;
        let now = Utc::now();

        for task in tasks.values_mut() {
            task.recent_bytes_sent = 0;
            task.recent_bytes_received = 0;
            task.recent_window_start = now;
        }

        tracing::info!("Reset activity windows for {} tasks due to settings change", tasks.len());
    }

    /// Remove every registered task and its metrics history. Used by the
    /// full-reload path to guarantee no stale entries survive when port
    /// listeners are aborted (the post-`.await` cleanup in
    /// `run_port_server` is skipped when an `AbortHandle` cancels the
    /// serve future, so reload must clean up explicitly).
    pub async fn clear_all_tasks(&self) -> usize {
        let mut tasks = self.tasks.write().await;
        let mut metrics = self
            .metrics_history
            .write()
            .await;
        let n = tasks.len();
        tasks.clear();
        metrics.clear();
        if n > 0 {
            debug!("Cleared {} task(s) from monitor", n);
        }
        n
    }

    /// Unregister a task (when it stops)
    pub async fn unregister_task(
        &self,
        task_id: &str,
    ) {
        let mut tasks = self.tasks.write().await;
        tasks.remove(task_id);

        // Clean up metrics history
        let mut metrics = self
            .metrics_history
            .write()
            .await;
        metrics.remove(task_id);
    }

    /// Unregister all tasks for a given channel name (useful when disabling/deleting channels)
    /// DEPRECATED: Use unregister_all_tasks_for_config_id instead
    pub async fn unregister_all_tasks_for_channel(
        &self,
        channel_name: &str,
    ) -> usize {
        let mut tasks = self.tasks.write().await;
        let mut metrics = self
            .metrics_history
            .write()
            .await;

        // Find all task IDs that belong to this channel
        let task_ids_to_remove: Vec<String> = tasks
            .values()
            .filter(|task| task.channel_name == channel_name)
            .map(|task| task.task_id.clone())
            .collect();

        let count = task_ids_to_remove.len();

        // Remove all matching tasks
        for task_id in &task_ids_to_remove {
            tasks.remove(task_id);
            metrics.remove(task_id);
        }

        if count > 0 {
            debug!("Unregistered {} task(s) for channel '{}'", count, channel_name);
        }

        count
    }

    /// Unregister all tasks for a given config_id (proper way to handle channels)
    pub async fn unregister_all_tasks_for_config_id(
        &self,
        config_id: &str,
    ) -> usize {
        let mut tasks = self.tasks.write().await;
        let mut metrics = self
            .metrics_history
            .write()
            .await;

        // Find all task IDs that belong to this config_id
        let task_ids_to_remove: Vec<String> = tasks
            .values()
            .filter(|task| {
                task.config_id
                    .as_ref()
                    .map(|id| id == config_id)
                    .unwrap_or(false)
            })
            .map(|task| task.task_id.clone())
            .collect();

        let count = task_ids_to_remove.len();

        // Remove all matching tasks
        for task_id in &task_ids_to_remove {
            tasks.remove(task_id);
            metrics.remove(task_id);
        }

        if count > 0 {
            debug!("Unregistered {} task(s) for config_id '{}'", count, config_id);
        }

        count
    }

    /// Get all registered tasks
    pub async fn get_all_tasks(&self) -> Vec<TaskInfo> {
        let tasks = self.tasks.read().await;
        let task_list: Vec<TaskInfo> = tasks
            .values()
            .cloned()
            .collect();

        // Debug logging to track byte values
        for task in &task_list {
            if task.bytes_sent > 0 || task.bytes_received > 0 {
                tracing::debug!(
                    "TaskMonitor::get_all_tasks - task_id={}, surface={}, bytes_sent={}, bytes_received={}, total={}",
                    task.task_id,
                    task.channel_name,
                    task.bytes_sent,
                    task.bytes_received,
                    task.bytes_sent + task.bytes_received
                );
            }
        }

        task_list
    }

    /// Get task by ID
    pub async fn get_task(
        &self,
        task_id: &str,
    ) -> Option<TaskInfo> {
        let tasks = self.tasks.read().await;
        tasks.get(task_id).cloned()
    }

    /// Find the task_id of the Access Point (transit_point = None) task for
    /// a given surface `config_id`, if one is registered. Used to keep
    /// post-startup byte/connection accounting writing to the same TaskInfo
    /// that the port listener registered, instead of spawning a duplicate.
    pub async fn find_ap_task_id_by_config_id(
        &self,
        config_id: &str,
    ) -> Option<String> {
        let tasks = self.tasks.read().await;
        tasks
            .values()
            .find(|t| t.transit_point.is_none() && t.config_id.as_deref() == Some(config_id))
            .map(|t| t.task_id.clone())
    }

    /// Calculate and store current metrics for a task
    pub async fn calculate_metrics(
        &self,
        task_id: &str,
    ) -> Option<TaskMetrics> {
        let mut tasks = self.tasks.write().await;
        let task = tasks.get_mut(task_id)?;

        let now = Utc::now();
        let uptime_seconds = (now - task.started_at).num_seconds() as u64;
        let uptime_minutes = uptime_seconds as f64 / 60.0;

        let connections_per_minute = if uptime_minutes > 0.0 {
            task.total_connections as f64 / uptime_minutes
        } else {
            0.0
        };

        // Calculate throughput based on configurable activity window
        let activity_window_seconds = if let Some(ref store) = self.settings_store {
            store
                .get()
                .task_activity_window_seconds as i64
        } else {
            60 // Default to 60 seconds
        };

        let recent_window_duration = (now - task.recent_window_start).num_seconds();

        // Check if last activity is recent (within last 5 seconds for real-time throughput)
        // The activity window is for accumulating bytes, but throughput should drop quickly
        let seconds_since_last_activity = if let Some(last_activity) = task.last_activity {
            (now - last_activity).num_seconds()
        } else {
            activity_window_seconds // No activity, treat as expired
        };

        let throughput_bytes_per_sec = if seconds_since_last_activity >= 5 {
            // No activity in last 5 seconds, show 0 throughput immediately
            task.recent_bytes_sent = 0;
            task.recent_bytes_received = 0;
            task.recent_window_start = now;
            0.0
        } else if recent_window_duration >= activity_window_seconds {
            // Window fully expired, reset
            task.recent_bytes_sent = 0;
            task.recent_bytes_received = 0;
            task.recent_window_start = now;
            0.0
        } else if recent_window_duration > 0 {
            // Calculate throughput from recent activity
            let recent_total = task.recent_bytes_sent + task.recent_bytes_received;
            recent_total as f64 / recent_window_duration as f64
        } else {
            0.0
        };

        let metrics = TaskMetrics {
            task_id: task_id.to_string(),
            connections_per_minute,
            throughput_bytes_per_sec,
            avg_response_time_ms: 0.0, // Can be calculated from latency metrics
            uptime_seconds,
            cpu_usage_percent: None, // Would require system-level monitoring
            memory_usage_mb: None,   // Would require system-level monitoring
        };

        tracing::debug!(
            "TaskMonitor::calculate_metrics - task_id={}, throughput={:.2} B/s, recent_window_duration={} s, seconds_since_last_activity={} s",
            task_id,
            throughput_bytes_per_sec,
            recent_window_duration,
            seconds_since_last_activity
        );

        // Store in history (keep last 100 samples)
        drop(tasks);
        let mut history = self
            .metrics_history
            .write()
            .await;
        let task_history = history
            .entry(task_id.to_string())
            .or_insert_with(Vec::new);
        task_history.push(metrics.clone());
        if task_history.len() > 100 {
            task_history.remove(0);
        }

        Some(metrics)
    }

    /// Get metrics for all tasks
    pub async fn get_all_metrics(&self) -> Vec<TaskMetrics> {
        let task_ids: Vec<String> = {
            let tasks = self.tasks.read().await;
            tasks
                .keys()
                .cloned()
                .collect()
        };

        let mut all_metrics = Vec::new();
        for task_id in task_ids {
            if let Some(metrics) = self
                .calculate_metrics(&task_id)
                .await
            {
                all_metrics.push(metrics);
            }
        }

        all_metrics
    }

    /// Get summary statistics for all tasks
    pub async fn get_summary(&self) -> TaskStatsSummary {
        let tasks = self.tasks.read().await;

        // Note: total_tasks only counts channel tasks
        // Pipe tasks are counted separately in dashboard.rs and added to the total there
        let total_tasks = tasks.len();
        let running_tasks = tasks
            .values()
            .filter(|t| t.status == TaskStatus::Running)
            .count();

        let total_connections: u64 = tasks
            .values()
            .map(|t| t.total_connections)
            .sum();

        let total_active_connections: u64 = tasks
            .values()
            .map(|t| t.active_connections)
            .sum();

        let total_bytes_transferred: u64 = tasks
            .values()
            .map(|t| t.bytes_sent + t.bytes_received)
            .sum();

        let avg_uptime_seconds = if total_tasks > 0 {
            let total_uptime: i64 = tasks
                .values()
                .map(|t| (Utc::now() - t.started_at).num_seconds())
                .sum();
            (total_uptime / total_tasks as i64) as u64
        } else {
            0
        };

        TaskStatsSummary {
            total_tasks,
            running_tasks,
            total_connections,
            total_active_connections,
            total_bytes_transferred,
            avg_uptime_seconds,
        }
    }

    /// Get metrics history for a task
    #[allow(dead_code)]
    pub async fn get_metrics_history(
        &self,
        task_id: &str,
    ) -> Vec<TaskMetrics> {
        let history = self
            .metrics_history
            .read()
            .await;
        history
            .get(task_id)
            .cloned()
            .unwrap_or_default()
    }
}

impl Default for TaskMonitor {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
impl TaskInfo {
    /// A running task with no connections or traffic yet.
    pub(crate) fn running(task_id: &str) -> Self {
        let now = Utc::now();
        Self {
            task_id: task_id.into(),
            config_id: None,
            channel_name: task_id.into(),
            transit_point: None,
            listen_address: "127.0.0.1:0".into(),
            target_endpoint: String::new(),
            started_at: now,
            status: TaskStatus::Running,
            total_connections: 0,
            active_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: None,
            error_count: 0,
            recent_bytes_sent: 0,
            recent_bytes_received: 0,
            recent_window_start: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(
        task_id: &str,
        active_connections: u64,
        last_activity: Option<DateTime<Utc>>,
    ) -> TaskInfo {
        TaskInfo {
            total_connections: active_connections,
            active_connections,
            last_activity,
            ..TaskInfo::running(task_id)
        }
    }

    #[tokio::test]
    async fn summary_keeps_connections_that_have_been_idle_for_minutes() {
        let monitor = TaskMonitor::new(None);
        monitor
            .register_task(task("idle-stream", 2, Some(Utc::now() - chrono::Duration::minutes(10))))
            .await;
        monitor
            .register_task(task("no-activity", 1, None))
            .await;

        let summary = monitor.get_summary().await;

        assert_eq!(summary.total_active_connections, 3);
        assert_eq!(
            monitor
                .get_task("idle-stream")
                .await
                .unwrap()
                .active_connections,
            2
        );
        assert_eq!(
            monitor
                .get_task("no-activity")
                .await
                .unwrap()
                .active_connections,
            1
        );
    }

    #[tokio::test]
    async fn active_connections_drop_only_when_released_and_never_below_zero() {
        let monitor = TaskMonitor::new(None);
        monitor
            .register_task(task("stream", 0, None))
            .await;

        monitor
            .increment_connections("stream")
            .await;
        assert_eq!(
            monitor
                .get_summary()
                .await
                .total_active_connections,
            1
        );

        monitor
            .decrement_active_connections("stream")
            .await;
        monitor
            .decrement_active_connections("stream")
            .await;
        assert_eq!(
            monitor
                .get_summary()
                .await
                .total_active_connections,
            0
        );
    }
}
