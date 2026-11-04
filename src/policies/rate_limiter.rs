use governor::{
    Quota, RateLimiter as GovernorRateLimiter,
    clock::{Clock, DefaultClock},
    nanos::Nanos,
    state::{
        InMemoryState, NotKeyed, StateStore,
        keyed::{DashMapStateStore, ShrinkableKeyedStateStore},
    },
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum RateLimitError {
    #[error("Rate limit exceeded. Retry after {retry_after:?}")]
    Exceeded { retry_after: Duration },

    #[error("Invalid rate limit configuration: {0}")]
    InvalidConfig(String),
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests
    pub requests: u32,

    /// Time window (in seconds)
    pub window_secs: u64,

    /// Optional burst size (defaults to requests if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

impl RateLimitConfig {
    /// Create a new rate limit config
    #[allow(dead_code)]
    pub fn new(
        requests_per_window: u32,
        window_secs: u64,
    ) -> Result<Self, RateLimitError> {
        if requests_per_window == 0 {
            return Err(RateLimitError::InvalidConfig("requests must be greater than 0".to_string()));
        }
        if window_secs == 0 {
            return Err(RateLimitError::InvalidConfig("window_secs must be greater than 0".to_string()));
        }

        Ok(Self {
            requests: requests_per_window,
            window_secs,
            burst: None,
        })
    }

    /// Set burst size
    #[allow(dead_code)]
    pub fn with_burst(
        mut self,
        burst: u32,
    ) -> Result<Self, RateLimitError> {
        if burst == 0 {
            return Err(RateLimitError::InvalidConfig("burst must be greater than 0".to_string()));
        }
        self.burst = Some(burst);
        Ok(self)
    }
}

impl From<&crate::config::RateLimitConfig> for RateLimitConfig {
    fn from(config: &crate::config::RateLimitConfig) -> Self {
        Self {
            requests: config.requests,
            window_secs: config.window_secs,
            burst: config.burst,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests: 100,
            window_secs: 60,
            burst: None,
        }
    }
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    limiter: Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    #[allow(dead_code)]
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter from config
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitError> {
        // Validate config
        if config.requests == 0 {
            return Err(RateLimitError::InvalidConfig("requests must be greater than 0".to_string()));
        }

        let limiter = Arc::new(GovernorRateLimiter::direct(quota_for(&config)?));

        debug!("Created rate limiter: {} requests per {} seconds", config.requests, config.window_secs);

        Ok(Self { limiter, config })
    }

    /// Check if a request is allowed
    /// Returns Ok(()) if allowed, Err with retry duration if rate limited
    pub fn check(&self) -> Result<(), RateLimitError> {
        match self.limiter.check() {
            Ok(_) => {
                debug!("Request allowed by rate limiter");
                Ok(())
            }
            Err(not_until) => {
                let clock = DefaultClock::default();
                let retry_after = not_until.wait_time_from(clock.now());
                warn!("Rate limit exceeded. Retry after {:?}", retry_after);
                Err(RateLimitError::Exceeded { retry_after })
            }
        }
    }

    /// Get the current configuration
    #[allow(dead_code)]
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

const MAX_TRACKED_CALLERS: usize = 10_000;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// How often, at most, the buckets are reclaimed while [`MAX_TRACKED_CALLERS`]
/// are tracked. It shares the cleanup timestamp, so a reclaim also defers the
/// periodic cleanup.
const AT_BOUND_RECLAIM_INTERVAL: Duration = Duration::from_secs(1);
const NO_CALLER_KEY: &str = "no-caller";
const OVERFLOW_KEY: &str = "overflow";
/// The longest a bucket may take to refill, in nanoseconds: half of what
/// governor counts in, so its time arithmetic cannot overflow.
const MAX_BUCKET_REFILL_NANOS: u128 = (u64::MAX / 2) as u128;

/// The callers' buckets, shared with the governor limiter so a caller can be
/// looked up without spending a request.
#[derive(Clone, Default)]
struct CallerBuckets(Arc<DashMapStateStore<String>>);

impl StateStore for CallerBuckets {
    type Key = String;

    fn measure_and_replace<T, F, E>(
        &self,
        key: &String,
        f: F,
    ) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        self.0
            .measure_and_replace(key, f)
    }
}

impl ShrinkableKeyedStateStore<String> for CallerBuckets {
    fn retain_recent(
        &self,
        drop_below: Nanos,
    ) {
        ShrinkableKeyedStateStore::retain_recent(&*self.0, drop_below);
    }

    fn shrink_to_fit(&self) {
        ShrinkableKeyedStateStore::shrink_to_fit(&*self.0);
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A rate limiter with one token bucket for each caller.
///
/// A request with no identified caller shares one bucket, so a request cannot
/// avoid the limit by having no caller. While [`MAX_TRACKED_CALLERS`] callers
/// have buckets that have not recovered, a caller without a bucket shares one
/// overflow bucket, so memory stays bounded; a caller who has a bucket keeps it.
pub struct CallerRateLimiter {
    buckets: CallerBuckets,
    limiter: GovernorRateLimiter<String, CallerBuckets, DefaultClock>,
    point: String,
    started: Instant,
    last_cleanup_secs: AtomicU64,
    last_full_warning_secs: AtomicU64,
}

/// A request a [`CallerRateLimiter`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerRefusal {
    /// The wait until the bucket that refused allows another request.
    pub retry_after: Duration,
    /// The shared overflow bucket refused it, not the caller's own.
    pub overflow: bool,
}

impl CallerRateLimiter {
    /// A limiter for the Transit Point `point`, named in its logs as
    /// `<surface id>/<alias>`. A bucket that would take longer than
    /// [`MAX_BUCKET_REFILL_NANOS`] to refill is refused.
    pub fn new(
        config: &RateLimitConfig,
        point: impl Into<String>,
    ) -> Result<Self, RateLimitError> {
        let quota = quota_for(config)?;
        if quota
            .replenish_interval()
            .as_nanos()
            * u128::from(quota.burst_size().get())
            > MAX_BUCKET_REFILL_NANOS
        {
            return Err(RateLimitError::InvalidConfig("window too long to count".to_string()));
        }
        let buckets = CallerBuckets::default();
        Ok(Self {
            limiter: GovernorRateLimiter::new(quota, buckets.clone(), DefaultClock::default()),
            buckets,
            point: point.into(),
            started: Instant::now(),
            last_cleanup_secs: AtomicU64::new(0),
            last_full_warning_secs: AtomicU64::new(0),
        })
    }

    /// Spend one request of `caller`'s bucket, or refuse it with the wait
    /// until that bucket allows another.
    pub fn check(
        &self,
        caller: Option<&str>,
    ) -> Result<(), CallerRefusal> {
        self.clean_up_when_due();
        let key = match caller {
            None => NO_CALLER_KEY,
            Some(caller) if self.has_bucket(caller) || !self.is_full() => caller,
            Some(_) => OVERFLOW_KEY,
        };
        self.limiter
            .check_key(&key.to_string())
            .map_err(|not_until| CallerRefusal {
                retry_after: not_until.wait_time_from(DefaultClock::default().now()),
                overflow: key == OVERFLOW_KEY,
            })
    }

    #[cfg(test)]
    pub fn tracked_callers(&self) -> usize {
        self.limiter.len()
    }

    fn has_bucket(
        &self,
        caller: &str,
    ) -> bool {
        self.buckets
            .0
            .contains_key(caller)
    }

    fn is_full(&self) -> bool {
        if self.limiter.len() < MAX_TRACKED_CALLERS {
            return false;
        }
        if self.claim(&self.last_cleanup_secs, AT_BOUND_RECLAIM_INTERVAL) {
            self.limiter.retain_recent();
        }
        let full = self.limiter.len() >= MAX_TRACKED_CALLERS;
        if full && self.claim(&self.last_full_warning_secs, AT_BOUND_RECLAIM_INTERVAL) {
            warn!(
                point = %self.point,
                tracked_callers = MAX_TRACKED_CALLERS,
                "Per-caller rate limit is at its bound: callers without a bucket share one until some recover"
            );
        }
        full
    }

    fn clean_up_when_due(&self) {
        if self.claim(&self.last_cleanup_secs, CLEANUP_INTERVAL) {
            self.clean_up();
        }
    }

    /// Whether `interval` has passed since `last`, claiming it when it has, so
    /// only one request acts on it.
    fn claim(
        &self,
        last: &AtomicU64,
        interval: Duration,
    ) -> bool {
        let now_secs = self
            .started
            .elapsed()
            .as_secs();
        let previous = last.load(Ordering::Relaxed);
        now_secs.saturating_sub(previous) >= interval.as_secs()
            && last
                .compare_exchange(previous, now_secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    fn clean_up(&self) {
        self.limiter.retain_recent();
        self.limiter.shrink_to_fit();
    }
}

fn quota_for(config: &RateLimitConfig) -> Result<Quota, RateLimitError> {
    let requests = NonZeroU32::new(config.requests)
        .ok_or_else(|| RateLimitError::InvalidConfig("requests must be > 0".to_string()))?;
    let replenishment_interval = Duration::from_secs(config.window_secs)
        .checked_div(config.requests)
        .ok_or_else(|| RateLimitError::InvalidConfig("invalid replenishment rate".to_string()))?;
    let burst_size = config
        .burst
        .and_then(NonZeroU32::new)
        .unwrap_or(requests);
    Ok(Quota::with_period(replenishment_interval)
        .ok_or_else(|| RateLimitError::InvalidConfig("more requests than the window can count".to_string()))?
        .allow_burst(burst_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn each_caller_has_a_bucket_of_their_own() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(2, 60).unwrap(), "partner").unwrap();
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok()
        );
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok()
        );
        assert!(
            limiter
                .check(Some("alice"))
                .is_err(),
            "alice spent her two"
        );
        assert!(
            limiter
                .check(Some("bob"))
                .is_ok(),
            "bob is not held up by alice"
        );
        assert!(
            limiter
                .check(Some("bob"))
                .is_ok()
        );
        assert!(
            limiter
                .check(Some("bob"))
                .is_err()
        );
        assert_eq!(limiter.tracked_callers(), 2);
    }

    #[test]
    fn requests_with_no_caller_share_one_bucket() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(2, 60).unwrap(), "partner").unwrap();
        assert!(limiter.check(None).is_ok());
        assert!(limiter.check(None).is_ok());
        assert!(limiter.check(None).is_err(), "a request cannot avoid the limit by naming no caller");
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok(),
            "an identified caller is not in that bucket"
        );
    }

    #[test]
    fn the_wait_is_the_time_until_that_callers_next_request() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(1, 10).unwrap(), "partner").unwrap();
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok()
        );
        let Err(CallerRefusal { retry_after, overflow: false }) = limiter.check(Some("alice")) else {
            panic!("the second request is refused");
        };
        assert!(retry_after > Duration::from_secs(8) && retry_after <= Duration::from_secs(10), "{retry_after:?}");
    }

    #[test]
    fn the_number_of_buckets_is_bounded_and_callers_past_the_bound_share_one() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(1, 3600).unwrap(), "partner").unwrap();
        for caller in 0..MAX_TRACKED_CALLERS {
            assert!(
                limiter
                    .check(Some(&format!("caller-{caller}")))
                    .is_ok()
            );
        }
        assert_eq!(limiter.tracked_callers(), MAX_TRACKED_CALLERS);
        assert!(
            limiter
                .check(Some("one-more"))
                .is_ok(),
            "the first past the bound takes the shared bucket"
        );
        assert!(
            limiter
                .check(Some("and-another"))
                .is_err(),
            "the next shares it"
        );
        assert!(limiter.tracked_callers() <= MAX_TRACKED_CALLERS + 1, "no bucket is added for them");
    }

    #[test]
    fn at_the_bound_a_caller_with_a_bucket_keeps_it() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(2, 3600).unwrap(), "partner").unwrap();
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok()
        );
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok()
        );
        assert!(
            limiter
                .check(Some("bob"))
                .is_ok()
        );
        for caller in 2..MAX_TRACKED_CALLERS {
            assert!(
                limiter
                    .check(Some(&format!("caller-{caller}")))
                    .is_ok()
            );
        }
        assert_eq!(limiter.tracked_callers(), MAX_TRACKED_CALLERS);

        assert!(
            limiter
                .check(Some("alice"))
                .is_err(),
            "alice spent her two and the unspent overflow bucket does not refill her"
        );
        assert!(
            limiter
                .check(Some("new-1"))
                .is_ok()
        );
        assert!(
            limiter
                .check(Some("new-2"))
                .is_ok()
        );
        assert!(
            matches!(limiter.check(Some("new-3")), Err(CallerRefusal { overflow: true, .. })),
            "new callers share the overflow bucket, and its refusal says so"
        );
        assert!(
            limiter
                .check(Some("bob"))
                .is_ok(),
            "bob keeps his own allowance while the overflow bucket is spent"
        );
        assert!(matches!(limiter.check(Some("bob")), Err(CallerRefusal { overflow: false, .. })), "and his own limit");
    }

    #[test]
    fn at_the_bound_recovered_buckets_are_reclaimed_for_new_callers() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(1000, 1).unwrap(), "partner").unwrap();
        for caller in 0..MAX_TRACKED_CALLERS {
            assert!(
                limiter
                    .check(Some(&format!("caller-{caller}")))
                    .is_ok()
            );
        }
        assert!(
            limiter
                .check(Some("too-soon"))
                .is_ok()
        );
        assert!(
            limiter.tracked_callers() > MAX_TRACKED_CALLERS,
            "within the interval nothing is reclaimed, so the caller shares the overflow bucket"
        );
        thread::sleep(AT_BOUND_RECLAIM_INTERVAL + Duration::from_millis(100));
        assert!(
            limiter
                .check(Some("later"))
                .is_ok()
        );
        assert!(
            limiter.tracked_callers() <= 2,
            "the recovered buckets are reclaimed and the new caller has one of their own: {}",
            limiter.tracked_callers()
        );
    }

    #[test]
    fn a_caller_with_a_recovered_bucket_is_forgotten() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(100, 1).unwrap(), "partner").unwrap();
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok()
        );
        thread::sleep(Duration::from_millis(50));
        limiter.clean_up();
        assert_eq!(limiter.tracked_callers(), 0);
    }

    #[test]
    fn an_invalid_caller_limit_is_refused() {
        let zero = RateLimitConfig {
            requests: 0,
            window_secs: 60,
            burst: None,
        };
        assert!(CallerRateLimiter::new(&zero, "partner").is_err());
    }

    #[test]
    fn a_limit_whose_bucket_takes_too_long_to_refill_is_refused() {
        for (requests, window_secs, burst) in [(1, 20_000_000_000, None), (1, 1_000_000_000, Some(100))] {
            let config = RateLimitConfig { requests, window_secs, burst };
            assert!(
                matches!(CallerRateLimiter::new(&config, "partner"), Err(RateLimitError::InvalidConfig(_))),
                "{config:?}"
            );
        }
        let a_year = RateLimitConfig {
            requests: 1,
            window_secs: 365 * 24 * 3600,
            burst: Some(100),
        };
        assert!(CallerRateLimiter::new(&a_year, "partner").is_ok());
        let shared = RateLimitConfig {
            requests: 1,
            window_secs: 10_000_000_000,
            burst: None,
        };
        assert!(RateLimiter::new(shared).is_ok(), "the shared limit keeps the range it had");
    }

    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimitConfig::new(2, 1).unwrap();
        let limiter = RateLimiter::new(config).unwrap();

        // First two requests should succeed
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());

        // Third request should fail
        assert!(limiter.check().is_err());
    }

    #[test]
    fn test_rate_limiter_recovery() {
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = RateLimiter::new(config).unwrap();

        // First request succeeds
        assert!(limiter.check().is_ok());

        // Second request fails
        assert!(limiter.check().is_err());

        // Wait for window to reset
        thread::sleep(Duration::from_secs(2));

        // Should work again
        assert!(limiter.check().is_ok());
    }

    #[test]
    fn test_rate_limiter_burst() {
        let config = RateLimitConfig::new(10, 60)
            .unwrap()
            .with_burst(20)
            .unwrap();

        let limiter = RateLimiter::new(config).unwrap();

        // Should allow burst of 20
        for _ in 0..20 {
            assert!(limiter.check().is_ok());
        }

        // 21st request should fail
        assert!(limiter.check().is_err());
    }

    #[test]
    fn test_invalid_config() {
        assert!(RateLimitConfig::new(0, 60).is_err());
        assert!(RateLimitConfig::new(100, 0).is_err());
    }
}
