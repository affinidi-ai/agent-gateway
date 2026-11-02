//! Per-record locks for stores whose writes must be atomic per record id.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// One async lock per record id. An entry exists only while a guard for that
/// id is held or awaited, so ids that are no longer written leave nothing behind.
#[derive(Default)]
pub struct IdLocks {
    locks: DashMap<String, Arc<Mutex<()>>>,
}

pub struct IdLockGuard<'a> {
    locks: &'a DashMap<String, Arc<Mutex<()>>>,
    id: &'a str,
    guard: Option<OwnedMutexGuard<()>>,
}

impl Drop for IdLockGuard<'_> {
    fn drop(&mut self) {
        self.guard.take();
        self.locks
            .remove_if(self.id, |_, lock| Arc::strong_count(lock) == 1);
    }
}

impl IdLocks {
    pub async fn lock<'a>(
        &'a self,
        id: &'a str,
    ) -> IdLockGuard<'a> {
        let mut guard = IdLockGuard {
            locks: &self.locks,
            id,
            guard: None,
        };
        let lock = self
            .locks
            .entry(id.to_string())
            .or_default()
            .clone();
        guard.guard = Some(lock.lock_owned().await);
        guard
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.locks.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_held_lock_on_one_id_does_not_block_another_and_is_released_afterwards() {
        let locks = IdLocks::default();
        let held = locks.lock("a").await;
        let other = tokio::time::timeout(Duration::from_secs(2), locks.lock("b"))
            .await
            .expect("an unrelated id is not blocked");
        assert_eq!(locks.len(), 2);
        drop(other);
        drop(held);
        assert!(locks.is_empty(), "idle locks are removed");
    }

    #[tokio::test]
    async fn a_lock_future_dropped_while_waiting_leaves_no_entry() {
        let locks = Arc::new(IdLocks::default());
        let held = locks.lock("a").await;

        let timed_out = tokio::time::timeout(Duration::from_millis(50), locks.lock("a")).await;
        assert!(timed_out.is_err());

        let waiter = {
            let locks = locks.clone();
            tokio::spawn(async move {
                let _guard = locks.lock("a").await;
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        waiter.abort();
        let _ = waiter.await;

        assert_eq!(locks.len(), 1, "the entry still held is kept");
        drop(held);
        assert!(locks.is_empty());
    }
}
