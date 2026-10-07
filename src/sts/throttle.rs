//! Throttle for the token endpoint: bounds repeated attempts per client id and
//! per source address so credential guessing is rate-limited. SAML and CLI login
//! reuse it per client IP only, with a bound on tracked addresses; their IP comes
//! from [`crate::source_auth::client_ip`], which trusts forwarded headers only from
//! `client_auth.trusted_proxies`.
//!
//! Process-local, like the other runtime caches. Counters roll over a
//! configurable window; a key that exceeds its limit is blocked for a
//! configurable lockout. Every bound comes from the gateway configuration.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dashmap::DashMap;
use tracing::warn;

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
    /// New keys past this many are not tracked. The token endpoint never reaches it
    /// (`usize::MAX`); the login throttle refuses such sources, see [`Self::per_client_ip`].
    max_keys: usize,
    state: DashMap<String, KeyState>,
    inserts: AtomicUsize,
    /// The window (`now / window_secs`, plus one) in which the last saturation warning was
    /// logged, so a full table logs at most once per window.
    saturation_warned_window: AtomicU64,
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
            saturation_warned_window: AtomicU64::new(0),
        }
    }

    /// A sign-in throttle that only limits client IPs, blocking an IP until its window rolls off.
    /// An IPv6 client is counted by its /64 prefix, since one host usually holds the whole /64.
    /// It tracks about 10,000 sources; while that many are active, a new source is refused until
    /// a slot frees up, and sources already tracked keep their normal limit.
    pub fn per_client_ip(cfg: &LoginThrottleConfig) -> Self {
        Self::tracking_at_most(cfg, MAX_TRACKED_LOGIN_SOURCES)
    }

    /// Once `max_keys` sources are tracked and none can be pruned, a new source is not tracked
    /// and [`Self::record_client_attempt`] refuses it. Concurrent requests can push the map past
    /// `max_keys` by at most their own number.
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
            saturation_warned_window: AtomicU64::new(0),
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
        self.record_client_attempt_at(client_ip?, now_secs())
    }

    /// A new source arriving while the table is full waits one window, the longest it can take
    /// for a tracked source to expire.
    fn record_client_attempt_at(
        &self,
        client_ip: IpAddr,
        now: u64,
    ) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        let source = source_key(client_ip);
        if !self.bump(ip_key(&source), self.per_ip, now) {
            self.warn_saturated(now);
            return Some(self.per_ip.window_secs);
        }
        self.retry_after(None, Some(&source), now)
    }

    fn warn_saturated(
        &self,
        now: u64,
    ) {
        let window = now / self.per_ip.window_secs + 1;
        if self
            .saturation_warned_window
            .swap(window, Ordering::Relaxed)
            != window
        {
            warn!(
                tracked = self.state.len(),
                max = self.max_keys,
                "Sign-in throttle is full; refusing new client IPs until tracked ones expire"
            );
        }
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

    /// Counts one attempt for `key`. Returns `false`, counting nothing, when `key` is new and
    /// the table is still full after pruning.
    fn bump(
        &self,
        key: String,
        limit: Limit,
        now: u64,
    ) -> bool {
        if self.state.len() >= self.max_keys && !self.state.contains_key(&key) {
            self.prune(now);
            if self.state.len() >= self.max_keys {
                return false;
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
        true
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

/// The login throttle's source for an address: IPv4 (including IPv4-mapped IPv6) as is, other
/// IPv6 by its /64 prefix.
fn source_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let prefix = u128::from(v6) & !((1u128 << 64) - 1);
                format!("{}/64", std::net::Ipv6Addr::from(prefix))
            }
        },
    }
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

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn per_client_ip_blocks_until_the_window_rolls_off() {
        let t = TokenEndpointThrottle::per_client_ip(&login_limit(2));
        for _ in 0..2 {
            assert_eq!(t.record_client_attempt_at(ip("203.0.113.7"), 1_000), None);
        }

        assert_eq!(t.record_client_attempt_at(ip("203.0.113.7"), 1_000), Some(60));
        assert_eq!(t.record_client_attempt_at(ip("203.0.113.8"), 1_000), None);
        assert_eq!(t.record_client_attempt_at(ip("203.0.113.7"), 1_060), None);
    }

    #[test]
    fn ipv6_addresses_in_one_64_share_a_budget() {
        let t = TokenEndpointThrottle::per_client_ip(&login_limit(2));
        assert_eq!(t.record_client_attempt_at(ip("2001:db8:1:2::1"), 1_000), None);
        assert_eq!(t.record_client_attempt_at(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"), 1_000), None);

        assert_eq!(t.record_client_attempt_at(ip("2001:db8:1:2::abcd"), 1_000), Some(60));
        assert_eq!(t.record_client_attempt_at(ip("2001:db8:1:3::1"), 1_000), None);
    }

    #[test]
    fn ipv4_addresses_are_counted_one_by_one_and_mapped_ipv6_counts_as_ipv4() {
        let t = TokenEndpointThrottle::per_client_ip(&login_limit(1));
        assert_eq!(t.record_client_attempt_at(ip("203.0.113.7"), 1_000), None);

        assert_eq!(t.record_client_attempt_at(ip("203.0.113.8"), 1_000), None);
        assert_eq!(t.record_client_attempt_at(ip("::ffff:203.0.113.7"), 1_000), Some(60));
    }

    #[test]
    fn a_full_table_refuses_a_new_source_and_still_serves_tracked_ones() {
        let t = TokenEndpointThrottle::tracking_at_most(&login_limit(2), 2);
        for source in ["203.0.113.1", "203.0.113.2"] {
            assert_eq!(t.record_client_attempt_at(ip(source), 1_000), None);
        }

        assert_eq!(t.record_client_attempt_at(ip("203.0.113.3"), 1_010), Some(60));
        assert_eq!(t.record_client_attempt_at(ip("203.0.113.1"), 1_010), None);
        assert_eq!(t.state.len(), 2);
    }

    #[test]
    fn a_full_table_takes_new_sources_again_once_tracked_ones_expire() {
        let t = TokenEndpointThrottle::tracking_at_most(&login_limit(1), 2);
        for source in ["203.0.113.1", "203.0.113.2"] {
            t.record_client_attempt_at(ip(source), 1_000);
        }
        assert!(
            t.record_client_attempt_at(ip("203.0.113.3"), 1_030)
                .is_some()
        );

        assert_eq!(t.record_client_attempt_at(ip("203.0.113.3"), 1_060), None);
        assert!(
            t.record_client_attempt_at(ip("203.0.113.3"), 1_060)
                .is_some()
        );
    }

    #[test]
    fn a_disabled_login_throttle_refuses_nothing() {
        let mut cfg = login_limit(1);
        cfg.enabled = false;
        let t = TokenEndpointThrottle::tracking_at_most(&cfg, 1);
        for index in 0..5 {
            assert_eq!(t.record_client_attempt_at(ip(&format!("203.0.113.{index}")), 1_000), None);
        }
    }

    #[test]
    fn the_token_endpoint_throttle_still_keys_each_ipv6_address_on_its_own() {
        let mut config = cfg(1000, 60, 300);
        config.per_ip.requests = 1;
        let t = TokenEndpointThrottle::from_config(&config);
        for _ in 0..2 {
            t.record(None, Some("2001:db8:1:2::1"), 1_000);
        }

        assert!(
            t.retry_after(None, Some("2001:db8:1:2::1"), 1_000)
                .is_some()
        );
        assert!(
            t.retry_after(None, Some("2001:db8:1:2::2"), 1_000)
                .is_none()
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
