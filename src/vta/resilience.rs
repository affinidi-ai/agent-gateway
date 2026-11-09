//! Resilience for VTA calls (VTA-04): the gateway owns the deadline so a slow or
//! hung VTA cannot tie up surface request slots.
//!
//! A VTA call runs on the inbound hot path while a connection slot is held, so
//! this wraps each call with:
//! - **bounded concurrency** — a semaphore; excess calls *fail fast* rather than
//!   queue unboundedly,
//! - a **circuit breaker** — after N consecutive failures the circuit opens for
//!   a cooldown and calls fail fast (fail-closed, no fabricated output),
//! - **at most one** idempotent retry on a transient (transport) failure,
//! - **metrics** — latency, outcome class, and circuit-open count.
//!
//! The per-call timeout lives in the HTTP client ([`crate::http_client`]); this
//! layer adds the back-pressure around it.

use std::future::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Semaphore};

use super::error::VtaError;
use crate::metrics::backends::prometheus::{track_vta_call, track_vta_circuit_open};

/// Consecutive failures before the circuit opens.
const FAILURE_THRESHOLD: u32 = 5;
/// How long the circuit stays open before a trial (half-open) call is allowed.
const COOLDOWN: Duration = Duration::from_secs(30);

/// Back-pressure + circuit breaker shared by one VTA client.
pub struct Resilience {
    semaphore: Semaphore,
    failure_threshold: u32,
    cooldown: Duration,
    consecutive_failures: AtomicU32,
    /// `Some(instant)` while the circuit is open; the instant is when it may
    /// half-open.
    open_until: Mutex<Option<Instant>>,
}

impl Resilience {
    /// Bound concurrency to `max_concurrent` in-flight VTA calls (at least 1).
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Semaphore::new(max_concurrent.max(1)),
            failure_threshold: FAILURE_THRESHOLD,
            cooldown: COOLDOWN,
            consecutive_failures: AtomicU32::new(0),
            open_until: Mutex::new(None),
        }
    }

    /// Test-only constructor to exercise the breaker without waiting 30s.
    #[cfg(test)]
    fn with_params(
        max_concurrent: usize,
        failure_threshold: u32,
        cooldown: Duration,
    ) -> Self {
        Self {
            semaphore: Semaphore::new(max_concurrent.max(1)),
            failure_threshold,
            cooldown,
            consecutive_failures: AtomicU32::new(0),
            open_until: Mutex::new(None),
        }
    }

    /// Whether the circuit is currently open (half-opens once the cooldown has
    /// elapsed by clearing the gate).
    async fn circuit_open(&self) -> bool {
        let mut guard = self.open_until.lock().await;
        match *guard {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                *guard = None; // cooldown elapsed → allow a trial call
                false
            }
            None => false,
        }
    }

    async fn record_success(&self) {
        self.consecutive_failures
            .store(0, Ordering::SeqCst);
        *self.open_until.lock().await = None;
    }

    async fn record_failure(&self) {
        let failures = self
            .consecutive_failures
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        if failures >= self.failure_threshold {
            *self.open_until.lock().await = Some(Instant::now() + self.cooldown);
            track_vta_circuit_open();
        }
    }

    /// Run `op` under the breaker + concurrency bound, retrying once on a
    /// transient failure. `operation` labels the emitted metrics.
    pub async fn run<F, Fut, T>(
        &self,
        operation: &str,
        mut op: F,
    ) -> Result<T, VtaError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, VtaError>>,
    {
        if self.circuit_open().await {
            track_vta_call(operation, "circuit_open", 0.0);
            return Err(VtaError::Transport("VTA circuit breaker is open".to_string()));
        }
        let _permit = match self.semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                track_vta_call(operation, "busy", 0.0);
                return Err(VtaError::Transport("VTA connector is at capacity".to_string()));
            }
        };

        let start = Instant::now();
        let mut result = op().await;
        if let Err(ref e) = result
            && e.is_retryable()
        {
            // The agent tells us how long to wait on a 429; retrying instantly
            // would just burn the one retry we have against the same limit.
            if let Some(wait) = e.retry_after() {
                tokio::time::sleep(wait).await;
            }
            result = op().await;
        }
        let elapsed = start.elapsed().as_secs_f64();

        match &result {
            Ok(_) => {
                self.record_success().await;
                track_vta_call(operation, "ok", elapsed);
            }
            Err(_) => {
                self.record_failure().await;
                track_vta_call(operation, "error", elapsed);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn passes_through_a_successful_call() {
        let r = Resilience::new(4);
        let out: Result<u8, VtaError> = r
            .run("op", || async { Ok(42) })
            .await;
        assert_eq!(out.unwrap(), 42);
    }

    #[tokio::test]
    async fn retries_a_transient_failure_once_then_succeeds() {
        let r = Resilience::new(4);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let out: Result<u8, VtaError> = r
            .run("op", move || {
                let calls = Arc::clone(&calls2);
                async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(VtaError::Transport("flaky".to_string()))
                    } else {
                        Ok(7)
                    }
                }
            })
            .await;
        assert_eq!(out.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "one retry");
    }

    #[tokio::test]
    async fn does_not_retry_a_definite_http_error() {
        let r = Resilience::new(4);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let out: Result<u8, VtaError> = r
            .run("op", move || {
                let calls = Arc::clone(&calls2);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(VtaError::Http {
                        status: 403,
                        body: String::new(),
                    })
                }
            })
            .await;
        assert!(out.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry on a definite response");
    }

    #[tokio::test]
    async fn opens_the_circuit_after_the_failure_threshold_then_fails_fast() {
        let r = Resilience::with_params(4, 2, Duration::from_secs(60));
        for _ in 0..2 {
            let _: Result<u8, VtaError> = r
                .run("op", || async {
                    Err(VtaError::Http {
                        status: 500,
                        body: String::new(),
                    })
                })
                .await;
        }
        // Circuit now open: the next call fails fast without invoking `op`.
        let invoked = Arc::new(AtomicUsize::new(0));
        let invoked2 = Arc::clone(&invoked);
        let out: Result<u8, VtaError> = r
            .run("op", move || {
                let invoked = Arc::clone(&invoked2);
                async move {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    Ok(1)
                }
            })
            .await;
        assert!(out.is_err(), "fails fast while open");
        assert_eq!(invoked.load(Ordering::SeqCst), 0, "op not invoked while circuit open");
    }

    #[tokio::test]
    async fn half_opens_after_cooldown() {
        let r = Resilience::with_params(4, 1, Duration::from_millis(10));
        let _: Result<u8, VtaError> = r
            .run("op", || async {
                Err(VtaError::Http {
                    status: 500,
                    body: String::new(),
                })
            })
            .await;
        // Open now; wait out the short cooldown.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let out: Result<u8, VtaError> = r
            .run("op", || async { Ok(9) })
            .await;
        assert_eq!(out.unwrap(), 9, "a trial call succeeds after cooldown");
    }

    #[tokio::test]
    async fn bounds_concurrency_and_fails_excess_fast() {
        let r = Arc::new(Resilience::new(1));
        // Hold the single permit with a call that blocks until released.
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate2 = Arc::clone(&gate);
        let r2 = Arc::clone(&r);
        let holder = tokio::spawn(async move {
            let _: Result<u8, VtaError> = r2
                .run("op", || async {
                    gate2.notified().await;
                    Ok(1)
                })
                .await;
        });
        // Let the holder acquire the permit.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let out: Result<u8, VtaError> = r
            .run("op", || async { Ok(2) })
            .await;
        assert!(out.is_err(), "excess call fails fast rather than queueing");
        gate.notify_one();
        holder.await.unwrap();
    }
}
