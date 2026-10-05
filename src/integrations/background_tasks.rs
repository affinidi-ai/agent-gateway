//! Background task coordination with concurrency limits
//!
//! This module provides a semaphore-based system to limit the number of
//! concurrent background tasks (like integration triggers) to prevent
//! resource exhaustion under high load.

use once_cell::sync::Lazy;
use tokio::sync::Semaphore;
use tracing::warn;

/// Maximum number of concurrent background tasks (integration triggers, notifications, etc.)
const MAX_CONCURRENT_BACKGROUND_TASKS: usize = 100;

/// Global semaphore to limit concurrent background tasks
static BACKGROUND_TASK_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(MAX_CONCURRENT_BACKGROUND_TASKS));

/// Acquire a permit to run a background task
///
/// Returns None if the semaphore is at capacity (non-blocking check).
/// Use this for non-critical background operations that can be skipped under load.
pub fn try_acquire_background_task_permit() -> Option<tokio::sync::SemaphorePermit<'static>> {
    BACKGROUND_TASK_SEMAPHORE
        .try_acquire()
        .ok()
}

/// Acquire a permit to run a background task (async, waits if at capacity)
///
/// Use this for critical background operations that must eventually run.
#[allow(dead_code)]
pub async fn acquire_background_task_permit() -> tokio::sync::SemaphorePermit<'static> {
    BACKGROUND_TASK_SEMAPHORE
        .acquire()
        .await
        .expect("Semaphore should never be closed")
}

/// Execute a background task with concurrency control
///
/// Spawns the task only if a permit is available. If at capacity, logs a warning
/// and skips the task (non-blocking).
pub fn spawn_background_task<F>(
    name: &str,
    future: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Some(permit) = try_acquire_background_task_permit() {
        tokio::spawn(async move {
            let _permit = permit; // Hold permit until task completes
            future.await;
            drop(_permit);
        });
    } else {
        warn!("Background task queue at capacity ({}), skipping task: {}", MAX_CONCURRENT_BACKGROUND_TASKS, name);
    }
}

/// Execute a critical background task with concurrency control
///
/// Waits for a permit if at capacity (blocking). Use for important tasks
/// that must eventually run.
#[allow(dead_code)]
pub fn spawn_critical_background_task<F>(
    _name: &str,
    future: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let permit = acquire_background_task_permit().await;
        future.await;
        drop(permit);
    });
}
