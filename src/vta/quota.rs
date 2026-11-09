//! Signing-rate quota for the VTA connector (VTA-17 / SEC0-6115 condition 5).
//!
//! The circuit breaker and concurrency bound in [`super::resilience`] protect
//! the **gateway** from a slow VTA. This protects the **key** from the gateway:
//! it caps how many signatures can be minted in a window, so a compromised
//! caller, a runaway retry loop or a misbehaving surface cannot quietly produce
//! an unbounded number of tokens before anyone notices.
//!
//! Exceeding the quota **fails closed** — no token is minted — and is metered.
//! The limit is configuration (`[vta] sign_quota_max` /
//! `sign_quota_window_secs`); `0` disables it entirely.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::error::VtaError;

/// A fixed-window signing counter.
///
/// Fixed rather than sliding on purpose: the state is two numbers, so the hot
/// path is a lock, a compare and an increment. A sliding window would need a
/// per-call timestamp log — unbounded memory in exactly the runaway case this
/// exists to contain.
pub struct SignQuota {
    /// Max signatures per window. `0` = unlimited (quota disabled).
    max: u64,
    window: Duration,
    state: Mutex<Window>,
}

struct Window {
    started: Instant,
    used: u64,
}

impl SignQuota {
    /// Build a quota of `max` signatures per `window_secs`. `max == 0` disables
    /// it; a zero window is treated as disabled too (a window that never
    /// advances cannot express a rate).
    pub fn new(
        max: u64,
        window_secs: u64,
    ) -> Self {
        let disabled = max == 0 || window_secs == 0;
        Self {
            max: if disabled { 0 } else { max },
            window: Duration::from_secs(window_secs.max(1)),
            state: Mutex::new(Window {
                started: Instant::now(),
                used: 0,
            }),
        }
    }

    /// Whether the quota is switched off.
    pub fn is_disabled(&self) -> bool {
        self.max == 0
    }

    /// Claim one signature from the current window.
    ///
    /// Returns [`VtaError::QuotaExceeded`] when the window is exhausted — the
    /// caller must **not** sign. The window rolls over lazily on the first call
    /// after it elapses, so an idle connector holds no timer.
    pub fn claim(&self) -> Result<(), VtaError> {
        if self.is_disabled() {
            return Ok(());
        }
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a previous holder panicked mid-update. Fail
            // closed: a quota that cannot account is not a quota.
            Err(_) => {
                return Err(VtaError::QuotaExceeded("signing quota state is unavailable".to_string()));
            }
        };
        let now = Instant::now();
        if now.duration_since(state.started) >= self.window {
            state.started = now;
            state.used = 0;
        }
        if state.used >= self.max {
            let retry_after = self
                .window
                .saturating_sub(now.duration_since(state.started))
                .as_secs();
            drop(state);
            crate::metrics::backends::prometheus::track_vta_quota_exceeded();
            tracing::warn!(
                target: "vta_audit",
                quota_max = self.max,
                window_secs = self.window.as_secs(),
                "VTA signing quota exceeded — refusing to sign (fail closed)",
            );
            return Err(VtaError::QuotaExceeded(format!(
                "signing quota of {} per {}s is exhausted; retry in {retry_after}s",
                self.max,
                self.window.as_secs()
            )));
        }
        state.used += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_max_disables_the_quota() {
        let q = SignQuota::new(0, 60);
        assert!(q.is_disabled());
        for _ in 0..1000 {
            q.claim()
                .expect("a disabled quota never refuses");
        }
    }

    #[test]
    fn a_zero_window_disables_the_quota() {
        // A window that never advances cannot express a rate, so treat it as off
        // rather than as "one burst, then permanently closed".
        let q = SignQuota::new(5, 0);
        assert!(q.is_disabled());
        for _ in 0..50 {
            q.claim().expect("disabled");
        }
    }

    #[test]
    fn it_allows_up_to_the_limit_then_fails_closed() {
        let q = SignQuota::new(3, 60);
        for i in 0..3 {
            q.claim()
                .unwrap_or_else(|e| panic!("claim {i} should be allowed: {e}"));
        }
        let err = q
            .claim()
            .expect_err("the fourth claim is over the limit");
        assert!(matches!(err, VtaError::QuotaExceeded(_)), "got {err:?}");
    }

    #[test]
    fn the_error_names_the_limit_and_a_retry_hint() {
        let q = SignQuota::new(1, 60);
        q.claim().unwrap();
        let err = q
            .claim()
            .expect_err("over the limit");
        let text = err.to_string();
        assert!(text.contains('1'), "names the limit: {text}");
        assert!(text.contains("60"), "names the window: {text}");
    }

    #[test]
    fn the_window_rolls_over_and_restores_capacity() {
        // A 1-second window: exhaust it, wait for it to elapse, claim again.
        let q = SignQuota::new(2, 1);
        q.claim().unwrap();
        q.claim().unwrap();
        assert!(q.claim().is_err(), "window exhausted");

        std::thread::sleep(Duration::from_millis(1_100));
        q.claim()
            .expect("a new window restores capacity");
    }
}
