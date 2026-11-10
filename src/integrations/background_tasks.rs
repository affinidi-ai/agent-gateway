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

/// A part of the background task limit that one kind of task cannot exceed, so a burst of it
/// leaves the rest of the limit to every other task.
pub struct TaskShare {
    name: &'static str,
    semaphore: Semaphore,
}

impl TaskShare {
    pub fn new(
        name: &'static str,
        max_tasks: usize,
    ) -> Self {
        Self {
            name,
            semaphore: Semaphore::new(max_tasks),
        }
    }
}

/// Like [`spawn_background_task`], but the task also needs a permit of `share`: when the share
/// or the whole limit is full, the task is skipped with a warning.
pub fn spawn_background_task_in<F>(
    share: &'static TaskShare,
    name: &str,
    future: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Ok(share_permit) = share
        .semaphore
        .try_acquire()
    else {
        warn!("Background task share '{}' at capacity, skipping task: {}", share.name, name);
        return;
    };
    spawn_background_task(name, async move {
        let _share_permit = share_permit;
        future.await;
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{Notify, mpsc};

    static SHARE: Lazy<TaskShare> = Lazy::new(|| TaskShare::new("test share", 1));

    #[tokio::test]
    async fn a_full_share_skips_a_task_until_its_running_task_ends() {
        let release = Arc::new(Notify::new());
        let (ran, mut runs) = mpsc::unbounded_channel::<&'static str>();
        spawn_background_task_in(&SHARE, "first", {
            let release = release.clone();
            let ran = ran.clone();
            async move {
                release.notified().await;
                ran.send("first").expect("receiver");
            }
        });
        spawn_background_task_in(&SHARE, "second", {
            let ran = ran.clone();
            async move {
                ran.send("second").expect("receiver");
            }
        });

        release.notify_one();
        let first = tokio::time::timeout(Duration::from_secs(5), runs.recv())
            .await
            .expect("a task runs");
        assert_eq!(first, Some("first"));
        tokio::time::timeout(Duration::from_secs(5), async {
            while SHARE
                .semaphore
                .available_permits()
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first task gives its permit back");
        spawn_background_task_in(&SHARE, "third", async move {
            ran.send("third").expect("receiver");
        });
        let next = tokio::time::timeout(Duration::from_secs(5), runs.recv())
            .await
            .expect("a task runs");
        assert_eq!(next, Some("third"));
    }
}
