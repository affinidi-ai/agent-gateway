use crate::config::CircuitBreakerConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    /// Circuit is closed - requests are allowed through
    Closed,
    /// Circuit is open - requests are immediately rejected
    Open,
    /// Circuit is half-open - testing if backend has recovered
    HalfOpen,
}

/// Circuit breaker for failing fast when backends are down
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
}

#[derive(Debug)]
struct CircuitBreakerState {
    current_state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
    window_start: Instant,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration
    pub fn new(config: CircuitBreakerConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState {
                current_state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
                last_state_change: now,
                window_start: now,
            })),
        }
    }

    /// How much longer an open circuit refuses calls after `last_failure`, or
    /// `None` once it lets a test request through.
    fn open_for(
        &self,
        last_failure: Instant,
    ) -> Option<Duration> {
        let timeout = Duration::from_secs(self.config.timeout_secs);
        (last_failure.elapsed() <= timeout).then(|| timeout.saturating_sub(last_failure.elapsed()))
    }

    /// How much longer the circuit refuses calls, without making one: `None`
    /// when the next call would be let through.
    pub async fn refusing_for(&self) -> Option<Duration> {
        let state = self.state.read().await;
        match (&state.current_state, state.last_failure_time) {
            (CircuitState::Open, Some(last_failure)) => self.open_for(last_failure),
            _ => None,
        }
    }

    /// Check if a request is allowed through the circuit breaker
    /// Returns Ok(()) if allowed, Err if circuit is open
    pub async fn call<F, T, E>(
        &self,
        f: F,
    ) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        // Check if we should allow the request
        {
            let mut state = self.state.write().await;

            // Reset window if needed
            if state.window_start.elapsed() > Duration::from_secs(self.config.window_secs) {
                state.window_start = Instant::now();
                state.failure_count = 0;
                state.success_count = 0;
            }

            match state.current_state {
                CircuitState::Open => {
                    // Check if we should transition to half-open
                    if let Some(last_failure) = state.last_failure_time {
                        if let Some(retry_after) = self.open_for(last_failure) {
                            return Err(CircuitBreakerError::Open { retry_after });
                        }
                        info!("Circuit breaker transitioning from Open to HalfOpen");
                        state.current_state = CircuitState::HalfOpen;
                        state.success_count = 0;
                        state.last_state_change = Instant::now();
                    }
                }
                CircuitState::HalfOpen => {
                    debug!("Circuit breaker in HalfOpen state, allowing test request");
                }
                CircuitState::Closed => {
                    debug!("Circuit breaker in Closed state, allowing request");
                }
            }
        }

        // Execute the request
        let result = f.await;

        // Update state based on result
        {
            let mut state = self.state.write().await;

            match &result {
                Ok(_) => {
                    self.on_success(&mut state)
                        .await;
                }
                Err(_) => {
                    self.on_failure(&mut state)
                        .await;
                }
            }
        }

        result.map_err(CircuitBreakerError::Inner)
    }

    async fn on_success(
        &self,
        state: &mut CircuitBreakerState,
    ) {
        match state.current_state {
            CircuitState::HalfOpen => {
                state.success_count += 1;
                debug!(
                    "Circuit breaker success in HalfOpen state ({}/{})",
                    state.success_count, self.config.success_threshold
                );

                if state.success_count >= self.config.success_threshold {
                    info!("Circuit breaker transitioning from HalfOpen to Closed");
                    state.current_state = CircuitState::Closed;
                    state.failure_count = 0;
                    state.success_count = 0;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success
                state.failure_count = 0;
            }
            CircuitState::Open => {
                // Should not happen, but reset if it does
                warn!("Unexpected success while circuit is Open");
            }
        }
    }

    async fn on_failure(
        &self,
        state: &mut CircuitBreakerState,
    ) {
        state.last_failure_time = Some(Instant::now());

        match state.current_state {
            CircuitState::Closed => {
                state.failure_count += 1;
                warn!(
                    "Circuit breaker failure in Closed state ({}/{})",
                    state.failure_count, self.config.failure_threshold
                );

                if state.failure_count >= self.config.failure_threshold {
                    info!("Circuit breaker transitioning from Closed to Open");
                    state.current_state = CircuitState::Open;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                info!("Circuit breaker failure in HalfOpen state, reopening circuit");
                state.current_state = CircuitState::Open;
                state.success_count = 0;
                state.last_state_change = Instant::now();
            }
            CircuitState::Open => {
                // Already open, just update failure time
                debug!("Circuit breaker already Open");
            }
        }
    }

    /// Get the current state of the circuit breaker
    #[allow(dead_code)]
    pub async fn state(&self) -> CircuitState {
        self.state
            .read()
            .await
            .current_state
            .clone()
    }

    /// Get statistics about the circuit breaker
    #[allow(dead_code)]
    pub async fn stats(&self) -> CircuitBreakerStats {
        let state = self.state.read().await;
        CircuitBreakerStats {
            state: state.current_state.clone(),
            failure_count: state.failure_count,
            success_count: state.success_count,
            time_in_current_state: state
                .last_state_change
                .elapsed(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub time_in_current_state: Duration,
}

#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open - requests are being rejected
    Open { retry_after: Duration },
    /// Inner error from the executed function
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            CircuitBreakerError::Open { retry_after } => {
                write!(f, "Circuit breaker is open. Retry after {:?}", retry_after)
            }
            CircuitBreakerError::Inner(e) => write!(f, "{}", e),
        }
    }
}

impl<E: std::error::Error> std::error::Error for CircuitBreakerError<E> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker(timeout_secs: u64) -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            timeout_secs,
            window_secs: 60,
        })
    }

    async fn fail(breaker: &CircuitBreaker) {
        let _ = breaker
            .call(async { Err::<(), _>("down") })
            .await;
    }

    #[tokio::test]
    async fn a_breaker_that_is_not_open_refuses_nothing() {
        let breaker = breaker(30);
        assert_eq!(breaker.refusing_for().await, None);

        fail(&breaker).await;

        assert_eq!(breaker.refusing_for().await, None, "one failure is below the threshold");
    }

    #[tokio::test]
    async fn an_open_breaker_says_how_long_it_refuses_without_making_a_call() {
        let breaker = breaker(30);
        fail(&breaker).await;
        fail(&breaker).await;

        let remaining = breaker
            .refusing_for()
            .await
            .expect("the breaker is open");

        assert!(remaining > Duration::from_secs(29) && remaining <= Duration::from_secs(30), "{remaining:?}");
        assert_eq!(breaker.state().await, CircuitState::Open, "asking changes nothing");
        let refused = breaker
            .call(async { Ok::<_, &str>(()) })
            .await;
        assert!(matches!(refused, Err(CircuitBreakerError::Open { .. })));
    }

    #[test]
    fn an_open_circuit_lets_a_test_request_through_once_its_timeout_has_passed() {
        let breaker = breaker(30);
        let long_ago = Instant::now()
            .checked_sub(Duration::from_secs(31))
            .expect("the clock is far enough from its origin");

        assert_eq!(breaker.open_for(long_ago), None);
        assert!(
            breaker
                .open_for(Instant::now())
                .is_some()
        );
    }
}
