use std::future::Future;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use tracing::warn;

use crate::event_hook::Listing;

pub const ENV_ATTEMPTS: &str = "AG_MEDIATOR_DIRECTORY_FIRST_CALL_RETRY_ATTEMPTS";
pub const ENV_DELAY_MS: &str = "AG_MEDIATOR_DIRECTORY_FIRST_CALL_RETRY_DELAY_MS";

const DEFAULT_ATTEMPTS: u32 = 5;
const DEFAULT_DELAY_MS: u64 = 2_000;
const MAX_ATTEMPTS: u32 = 20;
const MAX_DELAY_MS: u64 = 60_000;
const MAX_TOTAL: Duration = Duration::from_secs(60);

const SOCKET_NOT_ACTIVE: &str = "WebSocket is not active";
const SOCKET_READINESS_TIMED_OUT: &str = "WebSocket isActive? command timed out";

/// How often a new Connection Point's first mediator call is repeated, with the
/// same DID, while the mediator still refuses a DID it has not admitted yet.
/// The whole sequence, calls and waits together, never runs past `max_total`.
/// It applies only to a mediator the directory lists; see [`applies_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstCallRetry {
    pub attempts: u32,
    pub delay: Duration,
    pub max_total: Duration,
}

impl Default for FirstCallRetry {
    fn default() -> Self {
        Self {
            attempts: DEFAULT_ATTEMPTS,
            delay: Duration::from_millis(DEFAULT_DELAY_MS),
            max_total: MAX_TOTAL,
        }
    }
}

impl FirstCallRetry {
    pub fn never() -> Self {
        Self { attempts: 0, ..Self::default() }
    }

    pub fn current() -> Self {
        static CURRENT: std::sync::OnceLock<FirstCallRetry> = std::sync::OnceLock::new();
        *CURRENT.get_or_init(|| Self::from_lookup(|name| std::env::var(name).ok()))
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let text = |name: &str| {
            lookup(name)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        let attempts = match text(ENV_ATTEMPTS) {
            None => DEFAULT_ATTEMPTS,
            Some(raw) => match raw.parse::<u32>() {
                Ok(value) if value <= MAX_ATTEMPTS => value,
                _ => {
                    warn!(
                        "{ENV_ATTEMPTS}={raw:?} is not an integer from 0 to {MAX_ATTEMPTS}; using {DEFAULT_ATTEMPTS} (it applies to mediators listed by the directory only)"
                    );
                    DEFAULT_ATTEMPTS
                }
            },
        };
        let delay_ms = match text(ENV_DELAY_MS) {
            None => DEFAULT_DELAY_MS,
            Some(raw) => match raw.parse::<u64>() {
                Ok(value) if (1..=MAX_DELAY_MS).contains(&value) => value,
                _ => {
                    warn!(
                        "{ENV_DELAY_MS}={raw:?} is not an integer from 1 to {MAX_DELAY_MS}; using {DEFAULT_DELAY_MS} (it applies to mediators listed by the directory only)"
                    );
                    DEFAULT_DELAY_MS
                }
            },
        };
        Self {
            attempts,
            delay: Duration::from_millis(delay_ms),
            max_total: MAX_TOTAL,
        }
    }

    /// Runs `call`, repeating it up to `attempts` more times while `refused`
    /// says the failure is the mediator not admitting the DID yet. Any other
    /// failure, the last refusal, and a refusal after which another wait would
    /// pass `max_total` are returned as they are. Each attempt is bounded by
    /// the time left, and an attempt that runs out of it ends the sequence with
    /// `timed_out()`. Without repeats (`attempts == 0`) the call runs as it
    /// would without this wrapper, with no time bound added.
    pub async fn run<T, E, Fut>(
        &self,
        mut call: impl FnMut() -> Fut,
        refused: impl Fn(&E) -> bool,
        timed_out: impl Fn() -> E,
    ) -> Result<T, E>
    where
        Fut: Future<Output = Result<T, E>>,
    {
        if self.attempts == 0 {
            return call().await;
        }
        let started = tokio::time::Instant::now();
        let mut retried = 0;
        loop {
            let remaining = self
                .max_total
                .saturating_sub(started.elapsed());
            let result = match tokio::time::timeout(remaining, call()).await {
                Ok(result) => result,
                Err(_) => return Err(timed_out()),
            };
            match result {
                Err(error)
                    if retried < self.attempts
                        && started.elapsed() + self.delay <= self.max_total
                        && refused(&error) =>
                {
                    retried += 1;
                    warn!(
                        retry = retried,
                        of = self.attempts,
                        delay_ms = self.delay.as_millis() as u64,
                        "Directory mediator has not admitted the connection point DID yet; retrying the first call"
                    );
                    tokio::time::sleep(self.delay).await;
                }
                other => return other,
            }
        }
    }
}

/// The retry is for a mediator the directory lists, whose directory may still
/// be admitting the DID. Any other mediator, an operator-added one included,
/// refuses for real, so its refusal fails at once.
/// A provided mediator whose directory has not answered yet is retried too:
/// nothing says it is gone.
pub(crate) fn applies_to(
    provided: bool,
    listing: Listing,
) -> bool {
    provided && listing != Listing::NotListed
}

pub(crate) fn no_longer_offered(
    provided: bool,
    listing: Listing,
) -> bool {
    provided && listing == Listing::NotListed
}

/// Whether `error` is the mediator refusing a DID it does not know yet. Opening
/// the live stream reports a refused authentication only as the socket not
/// becoming active, so those transport failures count too.
pub(crate) fn refused_until_admitted(error: &ATMError) -> bool {
    if let Some(status) = error.http_status() {
        return status.status == 403;
    }
    match error {
        ATMError::ACLDenied(_) => true,
        ATMError::TransportError(reason) => {
            reason.contains(SOCKET_NOT_ACTIVE) || reason.contains(SOCKET_READINESS_TIMED_OUT)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    fn policy(attempts: u32) -> FirstCallRetry {
        FirstCallRetry {
            attempts,
            delay: Duration::from_millis(1),
            max_total: MAX_TOTAL,
        }
    }

    async fn script(
        policy: FirstCallRetry,
        refusals: u32,
        failure: Option<&'static str>,
    ) -> (Result<u32, &'static str>, u32) {
        let calls = AtomicU32::new(0);
        let result = policy
            .run(
                || {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if let Some(reason) = failure {
                            Err(reason)
                        } else if n < refusals {
                            Err("refused")
                        } else {
                            Ok(n)
                        }
                    }
                },
                |error| *error == "refused",
                || "timed out",
            )
            .await;
        (result, calls.load(Ordering::SeqCst))
    }

    #[test]
    fn defaults_apply_without_env() {
        assert_eq!(FirstCallRetry::from_lookup(lookup(&[])), FirstCallRetry::default());
    }

    #[test]
    fn env_values_are_applied() {
        let parsed = FirstCallRetry::from_lookup(lookup(&[(ENV_ATTEMPTS, "3"), (ENV_DELAY_MS, " 250 ")]));
        assert_eq!(parsed.attempts, 3);
        assert_eq!(parsed.delay, Duration::from_millis(250));
    }

    #[test]
    fn zero_attempts_is_accepted() {
        assert_eq!(FirstCallRetry::from_lookup(lookup(&[(ENV_ATTEMPTS, "0")])).attempts, 0);
    }

    #[test]
    fn invalid_values_fall_back_to_defaults() {
        let parsed = FirstCallRetry::from_lookup(lookup(&[(ENV_ATTEMPTS, "many"), (ENV_DELAY_MS, "0")]));
        assert_eq!(parsed, FirstCallRetry::default());
        let parsed = FirstCallRetry::from_lookup(lookup(&[(ENV_ATTEMPTS, "21"), (ENV_DELAY_MS, "60001")]));
        assert_eq!(parsed, FirstCallRetry::default());
    }

    #[tokio::test]
    async fn refusal_then_success_returns_the_success() {
        assert_eq!(script(policy(5), 2, None).await, (Ok(2), 3));
    }

    #[tokio::test]
    async fn exhausted_retries_return_the_last_refusal() {
        assert_eq!(script(policy(3), 99, None).await, (Err("refused"), 4));
    }

    #[tokio::test]
    async fn other_failures_are_not_retried() {
        assert_eq!(script(policy(5), 0, Some("boom")).await, (Err("boom"), 1));
    }

    #[tokio::test]
    async fn the_total_time_bound_stops_retries_early() {
        let bounded = FirstCallRetry {
            attempts: 20,
            delay: Duration::from_millis(20),
            max_total: Duration::from_millis(70),
        };
        let (result, calls) = script(bounded, 99, None).await;
        assert_eq!(result, Err("refused"));
        assert!((2..=5).contains(&calls), "calls: {calls}");
    }

    #[tokio::test]
    async fn zero_attempts_calls_once() {
        assert_eq!(script(policy(0), 99, None).await, (Err("refused"), 1));
    }

    #[test]
    fn the_retry_applies_to_a_provided_mediator_unless_the_directory_dropped_it() {
        assert!(applies_to(true, Listing::Listed));
        assert!(applies_to(true, Listing::Unknown));
        assert!(!applies_to(true, Listing::NotListed));
        for listing in [Listing::Listed, Listing::NotListed, Listing::Unknown] {
            assert!(!applies_to(false, listing), "{listing:?}");
            assert!(!no_longer_offered(false, listing), "{listing:?}");
        }
        assert!(no_longer_offered(true, Listing::NotListed));
        assert!(!no_longer_offered(true, Listing::Listed));
        assert!(!no_longer_offered(true, Listing::Unknown), "an unknown directory is not a gone mediator");
    }

    #[tokio::test]
    async fn without_repeats_the_call_gets_no_time_bound() {
        let unbounded = FirstCallRetry {
            attempts: 0,
            delay: Duration::from_millis(10),
            max_total: Duration::from_millis(20),
        };
        let result: Result<u32, &str> = unbounded
            .run(
                || async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    Ok(7)
                },
                |_| true,
                || "timed out",
            )
            .await;
        assert_eq!(result, Ok(7));
        assert_eq!(FirstCallRetry::never().attempts, 0);
    }

    #[tokio::test]
    async fn an_attempt_is_bounded_by_the_time_left() {
        let bounded = FirstCallRetry {
            attempts: 5,
            delay: Duration::from_millis(10),
            max_total: Duration::from_millis(100),
        };
        let started = std::time::Instant::now();
        let result: Result<u32, &str> = bounded
            .run(
                || async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(1)
                },
                |_| true,
                || "timed out",
            )
            .await;
        assert_eq!(result, Err("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn exactly_these_transport_errors_count_as_a_refusal() {
        assert_eq!(SOCKET_NOT_ACTIVE, "WebSocket is not active");
        assert_eq!(SOCKET_READINESS_TIMED_OUT, "WebSocket isActive? command timed out");
        for reason in [SOCKET_NOT_ACTIVE, SOCKET_READINESS_TIMED_OUT] {
            assert!(refused_until_admitted(&ATMError::TransportError(reason.into())));
            assert!(refused_until_admitted(&ATMError::TransportError(format!("startup: {reason} (1)"))));
        }
        for reason in ["WebSocket closed", "websocket is not active", "connection reset", "timed out"] {
            assert!(!refused_until_admitted(&ATMError::TransportError(reason.into())), "{reason}");
        }
        assert!(!refused_until_admitted(&ATMError::ConfigError(SOCKET_NOT_ACTIVE.into())));
    }

    #[test]
    fn classifies_admission_refusals() {
        assert!(refused_until_admitted(&ATMError::ACLDenied("denied".into())));
        assert!(refused_until_admitted(&ATMError::TransportError("WebSocket is not active".into())));
        assert!(refused_until_admitted(&ATMError::TransportError("WebSocket isActive? command timed out".into())));
        assert!(!refused_until_admitted(&ATMError::AuthenticationError("403 Forbidden".into())));
        assert!(!refused_until_admitted(&ATMError::AuthenticationError("401 Unauthorized".into())));
        assert!(!refused_until_admitted(&ATMError::TransportError("blocked by 403 firewall".into())));
        assert!(!refused_until_admitted(&ATMError::TransportError("connection refused".into())));
        assert!(!refused_until_admitted(&ATMError::ConfigError("bad".into())));
    }
}
