//! IDs of outstanding SP-initiated AuthnRequests, so a response's `InResponseTo` can be matched
//! once against a request this service actually sent.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use chrono::{DateTime, Utc};

use super::service::AUTHN_REQUEST_TTL;

/// Caps memory held by AuthnRequests whose response never came back. An entry is an id and a
/// timestamp, so the cap is about 10 MB. It is set high enough that the per-source login throttle
/// (20 a minute, so about 100 entries per source over the 5-minute lifetime) stops one source long
/// before the cap, and filling it takes about 1000 sources.
pub(super) const MAX_PENDING_AUTHN_REQUESTS: usize = 100_000;

/// Lets a store sweep out expired entries at most once per second, so a burst of inserts does not
/// rescan a large map on every call.
#[derive(Default)]
pub(super) struct SweepGate {
    last_second: Option<i64>,
}

impl SweepGate {
    /// `true` for the first call in each second of `now`.
    pub(super) fn due(
        &mut self,
        now: DateTime<Utc>,
    ) -> bool {
        let second = now.timestamp();
        if self
            .last_second
            .is_some_and(|last| second <= last)
        {
            return false;
        }
        self.last_second = Some(second);
        true
    }
}

#[derive(Default)]
struct Entries {
    expiries: HashMap<String, DateTime<Utc>>,
    sweep: SweepGate,
}

#[derive(Default)]
pub(super) struct PendingRequests {
    entries: Mutex<Entries>,
}

impl PendingRequests {
    /// Records a request that expires after [`AUTHN_REQUEST_TTL`]. Expired requests are swept out
    /// at most once per second, and `false` is returned when the store is full.
    pub(super) fn register(
        &self,
        request_id: String,
        now: DateTime<Utc>,
    ) -> bool {
        let mut entries = self.lock();
        if entries.sweep.due(now) {
            entries
                .expiries
                .retain(|_, expiry| *expiry > now);
        }
        if entries.expiries.len() >= MAX_PENDING_AUTHN_REQUESTS {
            return false;
        }
        entries
            .expiries
            .insert(request_id, now + AUTHN_REQUEST_TTL);
        true
    }

    /// Removes the request, so it matches once, and returns its expiry.
    pub(super) fn consume(
        &self,
        request_id: &str,
    ) -> Option<DateTime<Utc>> {
        self.lock()
            .expiries
            .remove(request_id)
    }

    /// How many requests are held, expired ones included until the next sweep.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.lock().expiries.len()
    }

    fn lock(&self) -> MutexGuard<'_, Entries> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn fill(
        pending: &PendingRequests,
        now: DateTime<Utc>,
    ) {
        for index in 0..MAX_PENDING_AUTHN_REQUESTS {
            assert!(pending.register(format!("req-{index}"), now));
        }
    }

    #[test]
    fn a_request_is_consumed_once() {
        let pending = PendingRequests::default();
        let now = Utc::now();
        assert!(pending.register("req-1".to_string(), now));

        assert_eq!(pending.consume("req-1"), Some(now + AUTHN_REQUEST_TTL));
        assert_eq!(pending.consume("req-1"), None);
    }

    #[test]
    fn register_refuses_new_requests_at_the_cap() {
        let pending = PendingRequests::default();
        let now = Utc::now();
        fill(&pending, now);

        assert!(!pending.register("req-extra".to_string(), now));
        assert_eq!(pending.len(), MAX_PENDING_AUTHN_REQUESTS);
    }

    #[test]
    fn register_purges_expired_requests_before_checking_the_cap() {
        let pending = PendingRequests::default();
        let now = Utc::now();
        fill(&pending, now);

        assert!(pending.register("req-later".to_string(), now + AUTHN_REQUEST_TTL));
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn expired_requests_are_swept_at_most_once_per_second() {
        let pending = PendingRequests::default();
        let now = Utc::now();
        assert!(pending.register("first".to_string(), now));
        assert!(pending.register("already-expired".to_string(), now - AUTHN_REQUEST_TTL));

        assert!(pending.register("same-second".to_string(), now));
        assert_eq!(pending.len(), 3);
        assert!(pending.register("next-second".to_string(), now + Duration::seconds(1)));
        assert_eq!(pending.len(), 3);
        assert_eq!(pending.consume("already-expired"), None);
    }

    #[test]
    fn concurrent_registers_never_exceed_the_cap() {
        const CONCURRENT_REGISTERS: usize = 32;
        let pending = PendingRequests::default();
        let now = Utc::now();
        for index in 0..(MAX_PENDING_AUTHN_REQUESTS - 1) {
            assert!(pending.register(format!("req-{index}"), now));
        }

        let barrier = std::sync::Barrier::new(CONCURRENT_REGISTERS);
        let registered = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..CONCURRENT_REGISTERS)
                .map(|index| {
                    let (barrier, pending) = (&barrier, &pending);
                    scope.spawn(move || {
                        barrier.wait();
                        pending.register(format!("burst-{index}"), now)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|registered| *registered)
                .count()
        });

        assert_eq!(registered, 1);
        assert_eq!(pending.len(), MAX_PENDING_AUTHN_REQUESTS);
    }
}
