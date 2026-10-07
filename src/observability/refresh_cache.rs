//! Keyed cache whose values are refreshed in the background, at most once per key at a time
//! and with bounded concurrency, recording when each value last changed.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::{DashMap, DashSet};
use tokio::sync::Semaphore;

struct Entry<V> {
    value: V,
    checked_at: Instant,
    changed_at: Option<DateTime<Utc>>,
}

pub struct RefreshCache<V> {
    entries: DashMap<String, Entry<V>>,
    inflight: DashSet<String>,
    permits: Semaphore,
    ttl: Duration,
    changed: fn(Option<&V>, &V) -> bool,
}

struct InflightGuard<'a> {
    inflight: &'a DashSet<String>,
    key: String,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight
            .remove(&self.key);
    }
}

impl<V: Clone + Send + Sync + 'static> RefreshCache<V> {
    /// `changed` decides whether storing a value (after the previous one, if any) counts as a
    /// change for [`Self::changed_since`].
    pub fn new(
        ttl: Duration,
        max_concurrent_refreshes: usize,
        changed: fn(Option<&V>, &V) -> bool,
    ) -> Self {
        Self {
            entries: DashMap::new(),
            inflight: DashSet::new(),
            permits: Semaphore::new(max_concurrent_refreshes),
            ttl,
            changed,
        }
    }

    /// The cached value and whether it was checked within the TTL.
    pub fn get(
        &self,
        key: &str,
    ) -> Option<(V, bool)> {
        self.entries
            .get(key)
            .map(|e| (e.value.clone(), e.checked_at.elapsed() < self.ttl))
    }

    /// Stores the value produced by `refresh` on a background task, unless a refresh for `key`
    /// is already running or there is no Tokio runtime.
    pub fn spawn_refresh<F, Fut>(
        self: &Arc<Self>,
        key: &str,
        refresh: F,
    ) where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = V> + Send,
    {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if !self
            .inflight
            .insert(key.to_string())
        {
            return;
        }
        let cache = Arc::clone(self);
        let key = key.to_string();
        handle.spawn(async move {
            let _guard = InflightGuard {
                inflight: &cache.inflight,
                key: key.clone(),
            };
            let Ok(_permit) = cache.permits.acquire().await else {
                return;
            };
            let value = refresh().await;
            cache.store(&key, value);
        });
    }

    pub fn store(
        &self,
        key: &str,
        value: V,
    ) {
        let (changed, previous_changed_at) = match self.entries.get(key) {
            Some(previous) => ((self.changed)(Some(&previous.value), &value), previous.changed_at),
            None => ((self.changed)(None, &value), None),
        };
        let changed_at = if changed {
            Some(Utc::now())
        } else {
            previous_changed_at
        };
        self.entries.insert(
            key.to_string(),
            Entry {
                value,
                checked_at: Instant::now(),
                changed_at,
            },
        );
    }

    /// Keys whose value changed after `since`.
    pub fn changed_since(
        &self,
        since: DateTime<Utc>,
    ) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| {
                e.changed_at
                    .is_some_and(|t| t > since)
            })
            .map(|e| e.key().clone())
            .collect()
    }

    #[cfg(test)]
    pub fn is_idle(&self) -> bool {
        self.inflight.is_empty()
    }

    #[cfg(test)]
    pub fn expire(
        &self,
        key: &str,
    ) {
        if let Some(mut entry) = self.entries.get_mut(key) {
            entry.checked_at = Instant::now() - self.ttl;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    fn differs(
        previous: Option<&u32>,
        value: &u32,
    ) -> bool {
        previous != Some(value)
    }

    async fn wait_idle(cache: &RefreshCache<u32>) {
        for _ in 0..200 {
            if cache.is_idle() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("refresh did not finish");
    }

    #[test]
    fn test_get_reports_freshness() {
        let fresh = RefreshCache::new(Duration::from_secs(60), 1, differs);
        fresh.store("k", 7);
        assert_eq!(fresh.get("k"), Some((7, true)));
        assert_eq!(fresh.get("missing"), None);

        let stale = RefreshCache::new(Duration::ZERO, 1, differs);
        stale.store("k", 7);
        assert_eq!(stale.get("k"), Some((7, false)));
    }

    #[test]
    fn test_changed_since_uses_change_rule() {
        let cache = RefreshCache::new(Duration::from_secs(60), 1, differs);
        let before = Utc::now() - chrono::Duration::seconds(1);
        cache.store("k", 1);
        assert_eq!(cache.changed_since(before), vec!["k".to_string()]);

        let after = Utc::now() + chrono::Duration::milliseconds(1);
        std::thread::sleep(Duration::from_millis(2));
        cache.store("k", 1);
        assert!(
            cache
                .changed_since(after)
                .is_empty()
        );
        cache.store("k", 2);
        assert_eq!(cache.changed_since(after), vec!["k".to_string()]);
    }

    #[tokio::test]
    async fn test_spawn_refresh_runs_once_per_key_and_stores_value() {
        let cache = Arc::new(RefreshCache::new(Duration::from_secs(60), 1, differs));
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let gate = Arc::clone(&gate);
            let calls = Arc::clone(&calls);
            cache.spawn_refresh("k", move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                gate.notified().await;
                9
            });
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate.notify_one();
        wait_idle(&cache).await;

        assert_eq!(cache.get("k"), Some((9, true)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_spawn_refresh_without_runtime_does_nothing() {
        let cache = Arc::new(RefreshCache::new(Duration::from_secs(60), 1, differs));
        cache.spawn_refresh("k", || async { 1 });
        assert!(cache.is_idle());
        assert_eq!(cache.get("k"), None);
    }

    #[test]
    fn test_expire_marks_entry_stale() {
        let cache = RefreshCache::new(Duration::from_secs(60), 1, differs);
        cache.store("k", 1);
        cache.expire("k");
        assert_eq!(cache.get("k"), Some((1, false)));
    }
}
