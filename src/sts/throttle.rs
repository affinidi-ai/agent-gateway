//! Throttle for the token endpoint: bounds repeated attempts per client id and
//! per source address so credential guessing is rate-limited. SAML and CLI login
//! reuse it per client IP only, with a bound on tracked addresses; their IP comes
//! from [`crate::source_auth::client_ip`], which trusts forwarded headers only from
//! `client_auth.trusted_proxies`.
//!
//! Process-local, like the other runtime caches. Counters roll over a
//! configurable window; a key that exceeds its limit is blocked for a
//! configurable lockout. Every bound comes from the gateway configuration.

use std::sync::atomic::{AtomicUsize, Ordering};

use std::net::IpAddr;

use dashmap::DashMap;

use super::handlers::now_secs;
use crate::config::types::{LoginThrottleConfig, RateLimitConfig, TokenEndpointThrottleConfig};

/// Soft cap on retained keys before a sweep of inactive entries.
const PRUNE_THRESHOLD: usize = 100_000;

/// Caps how many client IPs a sign-in throttle tracks at once.
const MAX_TRACKED_LOGIN_SOURCES: usize = 10_000;

#[derive(Clone, Copy)]
struct Limit {
    requests: u32,
    window_secs: u64,
}

impl From<&RateLimitConfig> for Limit {
    fn from(c: &RateLimitConfig) -> Self {
        Self {
            requests: c.requests.max(1),
            window_secs: c.window_secs.max(1),
        }
    }
}

#[derive(Default)]
struct KeyState {
    count: u32,
    window_start: u64,
    locked_until: u64,
}

/// Per-endpoint throttle keyed by client id and source address.
pub struct TokenEndpointThrottle {
    enabled: bool,
    failed_attempts_only: bool,
    per_client: Limit,
    per_ip: Limit,
    lockout_secs: u64,
    keep_secs: u64,
    /// New keys past this many are not tracked, so their attempts are not limited.
    max_keys: usize,
    state: DashMap<String, KeyState>,
    inserts: AtomicUsize,
}

impl TokenEndpointThrottle {
    pub fn from_config(cfg: &TokenEndpointThrottleConfig) -> Self {
        let per_client = Limit::from(&cfg.per_client);
        let per_ip = Limit::from(&cfg.per_ip);
        Self {
            enabled: cfg.enabled,
            failed_attempts_only: cfg.failed_attempts_only,
            per_client,
            per_ip,
            lockout_secs: cfg.lockout_secs,
            keep_secs: per_client
                .window_secs
                .max(per_ip.window_secs)
                .max(cfg.lockout_secs),
            max_keys: usize::MAX,
            state: DashMap::new(),
            inserts: AtomicUsize::new(0),
        }
    }

    /// A sign-in throttle that only limits client IPs, blocking an IP until its window rolls off.
    /// It tracks about 10,000 IPs at most; past that a new IP is not limited.
    pub fn per_client_ip(cfg: &LoginThrottleConfig) -> Self {
        Self::tracking_at_most(cfg, MAX_TRACKED_LOGIN_SOURCES)
    }

    /// Once `max_keys` sources are tracked and none can be pruned, a new source is let through
    /// untracked, so the map stays near `max_keys` (concurrent requests can overshoot it by at
    /// most their own number).
    fn tracking_at_most(
        cfg: &LoginThrottleConfig,
        max_keys: usize,
    ) -> Self {
        let per_ip = Limit::from(&cfg.per_ip);
        Self {
            enabled: cfg.enabled,
            failed_attempts_only: false,
            per_client: per_ip,
            per_ip,
            lockout_secs: 0,
            keep_secs: per_ip.window_secs,
            max_keys,
            state: DashMap::new(),
            inserts: AtomicUsize::new(0),
        }
    }

    /// Records one attempt for the caller's IP (see [`crate::source_auth::client_ip`]) and
    /// returns how long it must wait when it is over its limit. The IP is only missing when the
    /// server was not built with `ConnectInfo`, which every gateway listener is; such a request
    /// is not limited here.
    pub fn record_client_attempt(
        &self,
        client_ip: Option<IpAddr>,
    ) -> Option<u64> {
        let ip = client_ip?.to_string();
        let now = now_secs();
        self.record(None, Some(&ip), now);
        self.retry_after(None, Some(&ip), now)
    }

    /// Whether only failed client authentications should be recorded (vs every request).
    pub fn failed_attempts_only(&self) -> bool {
        self.failed_attempts_only
    }

    /// If any provided key is currently blocked, the maximum seconds to wait.
    pub fn retry_after(
        &self,
        client_id: Option<&str>,
        ip: Option<&str>,
        now: u64,
    ) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        let mut wait = 0u64;
        if let Some(c) = client_id {
            wait = wait.max(self.blocked_for(&client_key(c), now));
        }
        if let Some(i) = ip {
            wait = wait.max(self.blocked_for(&ip_key(i), now));
        }
        (wait > 0).then_some(wait)
    }

    /// Record one attempt against each provided key; a key that exceeds its
    /// window limit becomes blocked.
    pub fn record(
        &self,
        client_id: Option<&str>,
        ip: Option<&str>,
        now: u64,
    ) {
        if !self.enabled {
            return;
        }
        if let Some(c) = client_id {
            self.bump(client_key(c), self.per_client, now);
        }
        if let Some(i) = ip {
            self.bump(ip_key(i), self.per_ip, now);
        }
        if self
            .inserts
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(1024)
            && self.state.len() > PRUNE_THRESHOLD
        {
            self.prune(now);
        }
    }

    fn blocked_for(
        &self,
        key: &str,
        now: u64,
    ) -> u64 {
        self.state
            .get(key)
            .map(|st| {
                st.locked_until
                    .saturating_sub(now)
            })
            .unwrap_or(0)
    }

    fn bump(
        &self,
        key: String,
        limit: Limit,
        now: u64,
    ) {
        if self.state.len() >= self.max_keys && !self.state.contains_key(&key) {
            self.prune(now);
            if self.state.len() >= self.max_keys {
                return;
            }
        }
        let mut st = self
            .state
            .entry(key)
            .or_default();
        if now.saturating_sub(st.window_start) >= limit.window_secs {
            st.window_start = now;
            st.count = 0;
        }
        st.count = st.count.saturating_add(1);
        if st.count > limit.requests {
            st.locked_until = if self.lockout_secs > 0 {
                now.saturating_add(self.lockout_secs)
            } else {
                st.window_start
                    .saturating_add(limit.window_secs)
            };
        }
    }

    fn prune(
        &self,
        now: u64,
    ) {
        let keep = self.keep_secs;
        self.state
            .retain(|_, st| st.locked_until > now || now.saturating_sub(st.window_start) < keep);
    }
}

fn client_key(client_id: &str) -> String {
    format!("c:{client_id}")
}

fn ip_key(ip: &str) -> String {
    format!("i:{ip}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(
        reqs: u32,
        window: u64,
        lockout: u64,
    ) -> TokenEndpointThrottleConfig {
        TokenEndpointThrottleConfig {
            enabled: true,
            failed_attempts_only: true,
            per_client: RateLimitConfig {
                requests: reqs,
                window_secs: window,
                burst: None,
            },
            per_ip: RateLimitConfig {
                requests: 1000,
                window_secs: window,
                burst: None,
            },
            lockout_secs: lockout,
        }
    }

    #[test]
    fn under_limit_is_not_blocked() {
        let t = TokenEndpointThrottle::from_config(&cfg(3, 60, 300));
        t.record(Some("c1"), None, 10);
        t.record(Some("c1"), None, 11);
        assert_eq!(t.retry_after(Some("c1"), None, 12), None);
    }

    #[test]
    fn over_limit_locks_out() {
        let t = TokenEndpointThrottle::from_config(&cfg(3, 60, 300));
        for i in 0..4 {
            t.record(Some("c1"), None, 10 + i);
        }
        let wait = t
            .retry_after(Some("c1"), None, 15)
            .expect("client should be locked out");
        assert!(wait > 0 && wait <= 300);
    }

    #[test]
    fn keys_are_independent() {
        let t = TokenEndpointThrottle::from_config(&cfg(2, 60, 300));
        for _ in 0..3 {
            t.record(Some("c1"), None, 10);
        }
        assert!(
            t.retry_after(Some("c1"), None, 10)
                .is_some()
        );
        assert!(
            t.retry_after(Some("c2"), None, 10)
                .is_none(),
            "a different client must be unaffected"
        );
    }

    #[test]
    fn window_rolls_over_without_lockout() {
        let t = TokenEndpointThrottle::from_config(&cfg(2, 30, 0));
        for _ in 0..3 {
            t.record(Some("c1"), None, 10);
        }
        assert!(
            t.retry_after(Some("c1"), None, 15)
                .is_some()
        );
        assert!(
            t.retry_after(Some("c1"), None, 45)
                .is_none(),
            "once the window rolls off the key is free again"
        );
    }

    fn login_limit(requests: u32) -> LoginThrottleConfig {
        LoginThrottleConfig {
            enabled: true,
            per_ip: RateLimitConfig {
                requests,
                window_secs: 60,
                burst: None,
            },
        }
    }

    #[test]
    fn per_client_ip_blocks_until_the_window_rolls_off() {
        let t = TokenEndpointThrottle::per_client_ip(&login_limit(2));
        for _ in 0..3 {
            t.record(None, Some("203.0.113.7"), 1_000);
        }

        assert_eq!(t.retry_after(None, Some("203.0.113.7"), 1_000), Some(60));
        assert_eq!(t.retry_after(None, Some("203.0.113.8"), 1_000), None);
        assert_eq!(t.retry_after(None, Some("203.0.113.7"), 1_060), None);
    }

    #[test]
    fn per_client_ip_tracks_at_most_max_keys_sources() {
        let t = TokenEndpointThrottle::tracking_at_most(&login_limit(1), 2);
        for ip in ["a", "b", "c"] {
            t.record(None, Some(ip), 1_000);
            t.record(None, Some(ip), 1_000);
        }

        assert_eq!(t.state.len(), 2);
        assert!(
            t.retry_after(None, Some("c"), 1_000)
                .is_none()
        );
    }

    #[test]
    fn per_client_ip_tracks_a_new_source_once_inactive_ones_are_pruned() {
        let t = TokenEndpointThrottle::tracking_at_most(&login_limit(1), 2);
        for ip in ["a", "b"] {
            t.record(None, Some(ip), 1_000);
        }
        t.record(None, Some("c"), 1_060);
        t.record(None, Some("c"), 1_060);

        assert!(
            t.retry_after(None, Some("c"), 1_060)
                .is_some()
        );
    }

    #[test]
    fn disabled_never_blocks() {
        let mut c = cfg(1, 60, 300);
        c.enabled = false;
        let t = TokenEndpointThrottle::from_config(&c);
        for _ in 0..10 {
            t.record(Some("c1"), None, 10);
        }
        assert_eq!(t.retry_after(Some("c1"), None, 10), None);
    }
}
