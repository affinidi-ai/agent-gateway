//! IDs of outstanding SP-initiated AuthnRequests, so a response's `InResponseTo` can be matched
//! once against a request this service actually sent.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use chrono::{DateTime, Utc};

use super::service::AUTHN_REQUEST_TTL;

/// Caps memory held by AuthnRequests whose response never came back.
pub(super) const MAX_PENDING_AUTHN_REQUESTS: usize = 1000;

#[derive(Default)]
pub(super) struct PendingRequests {
    expiries: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl PendingRequests {
    /// Records a request that expires after [`AUTHN_REQUEST_TTL`]. Expired requests are purged
    /// first, and `false` is returned when the store is still full.
    pub(super) fn register(
        &self,
        request_id: String,
        now: DateTime<Utc>,
    ) -> bool {
        let mut expiries = self.lock();
        expiries.retain(|_, expiry| *expiry > now);
        if expiries.len() >= MAX_PENDING_AUTHN_REQUESTS {
            return false;
        }
        expiries.insert(request_id, now + AUTHN_REQUEST_TTL);
        true
    }

    /// Removes the request, so it matches once, and returns its expiry.
    pub(super) fn consume(
        &self,
        request_id: &str,
    ) -> Option<DateTime<Utc>> {
        self.lock().remove(request_id)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, DateTime<Utc>>> {
        self.expiries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(pending.lock().len(), MAX_PENDING_AUTHN_REQUESTS);
    }

    #[test]
    fn register_purges_expired_requests_before_checking_the_cap() {
        let pending = PendingRequests::default();
        let now = Utc::now();
        fill(&pending, now);

        assert!(pending.register("req-later".to_string(), now + AUTHN_REQUEST_TTL));
        assert_eq!(pending.lock().len(), 1);
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
        assert_eq!(pending.lock().len(), MAX_PENDING_AUTHN_REQUESTS);
    }
}
