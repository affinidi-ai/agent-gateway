use governor::{
    Quota, RateLimiter as GovernorRateLimiter,
    clock::{Clock, DefaultClock},
    state::{InMemoryState, NotKeyed, keyed::DashMapStateStore},
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
const NO_CALLER_KEY: &str = "no-caller";
const OVERFLOW_KEY: &str = "overflow";

/// A rate limiter with one token bucket for each caller.
///
/// A request with no identified caller, and every request while more than
/// [`MAX_TRACKED_CALLERS`] callers have buckets that have not recovered, share
/// one bucket each, so memory stays bounded and a request cannot avoid the
/// limit by having no caller.
pub struct CallerRateLimiter {
    limiter: GovernorRateLimiter<String, DashMapStateStore<String>, DefaultClock>,
    started: Instant,
    last_cleanup_secs: AtomicU64,
}

impl CallerRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Result<Self, RateLimitError> {
        let quota = quota_for(config)?;
        Ok(Self {
            limiter: GovernorRateLimiter::dashmap(quota),
            started: Instant::now(),
            last_cleanup_secs: AtomicU64::new(0),
        })
    }

    pub fn check(
        &self,
        caller: Option<&str>,
    ) -> Result<(), RateLimitError> {
        self.clean_up_when_due();
        let key = match caller {
            None => NO_CALLER_KEY,
            Some(_) if self.is_full() => OVERFLOW_KEY,
            Some(caller) => caller,
        };
        self.limiter
            .check_key(&key.to_string())
            .map_err(|not_until| RateLimitError::Exceeded {
                retry_after: not_until.wait_time_from(DefaultClock::default().now()),
            })
    }

    #[cfg(test)]
    pub fn tracked_callers(&self) -> usize {
        self.limiter.len()
    }

    fn is_full(&self) -> bool {
        if self.limiter.len() < MAX_TRACKED_CALLERS {
            return false;
        }
        self.clean_up();
        self.limiter.len() >= MAX_TRACKED_CALLERS
    }

    fn clean_up_when_due(&self) {
        let now_secs = self
            .started
            .elapsed()
            .as_secs();
        let last = self
            .last_cleanup_secs
            .load(Ordering::Relaxed);
        if now_secs.saturating_sub(last) >= CLEANUP_INTERVAL.as_secs()
            && self
                .last_cleanup_secs
                .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.clean_up();
        }
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
        .ok_or_else(|| RateLimitError::InvalidConfig("invalid window duration".to_string()))?
        .allow_burst(burst_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn each_caller_has_a_bucket_of_their_own() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(2, 60).unwrap()).unwrap();
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
        assert!(matches!(limiter.check(Some("alice")), Err(RateLimitError::Exceeded { .. })), "alice spent her two");
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
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(2, 60).unwrap()).unwrap();
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
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(1, 10).unwrap()).unwrap();
        assert!(
            limiter
                .check(Some("alice"))
                .is_ok()
        );
        let Err(RateLimitError::Exceeded { retry_after }) = limiter.check(Some("alice")) else {
            panic!("the second request is refused");
        };
        assert!(retry_after > Duration::from_secs(8) && retry_after <= Duration::from_secs(10), "{retry_after:?}");
    }

    #[test]
    fn the_number_of_buckets_is_bounded_and_callers_past_the_bound_share_one() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(1, 3600).unwrap()).unwrap();
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
    fn a_caller_with_a_recovered_bucket_is_forgotten() {
        let limiter = CallerRateLimiter::new(&RateLimitConfig::new(100, 1).unwrap()).unwrap();
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
        assert!(CallerRateLimiter::new(&zero).is_err());
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
