use governor::{
    Quota, RateLimiter as GovernorRateLimiter,
    clock::{Clock, DefaultClock},
    state::{InMemoryState, NotKeyed},
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
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

        let requests = NonZeroU32::new(config.requests)
            .ok_or_else(|| RateLimitError::InvalidConfig("requests must be > 0".to_string()))?;

        // Create quota: N requests per window
        // The replenishment period is window_secs / requests (time per single request)
        let replenishment_interval = Duration::from_secs(config.window_secs)
            .checked_div(config.requests)
            .ok_or_else(|| RateLimitError::InvalidConfig("invalid replenishment rate".to_string()))?;

        let burst_size = config
            .burst
            .and_then(NonZeroU32::new)
            .unwrap_or(requests);

        let quota = Quota::with_period(replenishment_interval)
            .ok_or_else(|| RateLimitError::InvalidConfig("invalid window duration".to_string()))?
            .allow_burst(burst_size);

        let limiter = Arc::new(GovernorRateLimiter::direct(quota));

        debug!(
            "Created rate limiter: {} requests per {} seconds (burst: {}, replenishment: {:?})",
            config.requests,
            config.window_secs,
            burst_size.get(),
            replenishment_interval
        );

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

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
