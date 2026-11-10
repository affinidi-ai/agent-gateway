//! When the bundled control key is next due for rotation, and whether a given
//! moment is the one to do it.
//!
//! Everything here is a pure function of its inputs, so the timing rules can be
//! tested without a clock or a trust agent.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

/// The spread added to a due time so gateways installed together do not all
/// rotate in the same minute.
pub const JITTER_WINDOW: Duration = Duration::from_secs(6 * 3600);

const BACKOFF_BASE: Duration = Duration::from_secs(3600);
const BACKOFF_CAP: Duration = Duration::from_secs(24 * 3600);

/// Failures in a row after which the log line becomes an error.
pub const ESCALATE_AFTER_FAILURES: u32 = 3;

/// When rotation is next due: `days` after the last rotation, or after the
/// bootstrap when there has been none. `None` when `days` is zero.
pub fn next_due(
    rotated_at: Option<DateTime<Utc>>,
    bootstrapped_at: DateTime<Utc>,
    days: u32,
) -> Option<DateTime<Utc>> {
    if days == 0 {
        return None;
    }
    Some(rotated_at.unwrap_or(bootstrapped_at) + chrono::Duration::days(i64::from(days)))
}

/// A delay in `[0, JITTER_WINDOW)` that is the same every time for one DID.
pub fn jitter(control_did: &str) -> Duration {
    let digest = Sha256::digest(control_did.as_bytes());
    let value = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("eight bytes"),
    );
    Duration::from_secs(value % JITTER_WINDOW.as_secs())
}

/// How long to wait after the `failures`-th failure in a row: an hour, doubling,
/// at most a day.
pub fn backoff(failures: u32) -> Duration {
    let doublings = failures
        .saturating_sub(1)
        .min(16);
    BACKOFF_BASE
        .saturating_mul(1u32 << doublings)
        .min(BACKOFF_CAP)
}

/// What the schedule says to do at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Rotate,
    NotYet,
    Off,
    Standby,
    NotConnected,
}

/// Where the schedule stands between ticks.
#[derive(Debug, Default)]
pub struct Schedule {
    failures: u32,
    retry_at: Option<DateTime<Utc>>,
}

impl Schedule {
    pub fn decide(
        &self,
        now: DateTime<Utc>,
        due: Option<DateTime<Utc>>,
        jitter: Duration,
        standby: bool,
        connected: bool,
    ) -> Decision {
        let Some(due) = due else {
            return Decision::Off;
        };
        if standby {
            return Decision::Standby;
        }
        if !connected {
            return Decision::NotConnected;
        }
        let at = due + chrono::Duration::from_std(jitter).unwrap_or_else(|_| chrono::Duration::zero());
        if now < at
            || self
                .retry_at
                .is_some_and(|retry| now < retry)
        {
            return Decision::NotYet;
        }
        Decision::Rotate
    }

    /// Record a failed rotation; returns how many have failed in a row.
    pub fn failed(
        &mut self,
        now: DateTime<Utc>,
    ) -> u32 {
        self.failures += 1;
        self.retry_at = Some(now + chrono::Duration::from_std(backoff(self.failures)).unwrap_or_default());
        self.failures
    }

    pub fn succeeded(&mut self) {
        self.failures = 0;
        self.retry_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(day: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap() + chrono::Duration::days(day)
    }

    #[test]
    fn next_due_counts_from_the_last_rotation() {
        assert_eq!(next_due(Some(at(40)), at(0), 90), Some(at(130)));
    }

    #[test]
    fn next_due_counts_from_the_bootstrap_when_never_rotated() {
        assert_eq!(next_due(None, at(10), 90), Some(at(100)));
    }

    #[test]
    fn zero_days_turns_rotation_off() {
        assert_eq!(next_due(Some(at(1)), at(0), 0), None);
        assert_eq!(Schedule::default().decide(at(1000), None, Duration::ZERO, false, true), Decision::Off);
    }

    #[test]
    fn jitter_stays_under_six_hours_and_is_stable_for_one_did() {
        let a = jitter("did:key:z6MkA");
        assert!(a < JITTER_WINDOW);
        assert_eq!(a, jitter("did:key:z6MkA"));
        assert_ne!(a, jitter("did:key:z6MkB"), "another gateway rotates at another moment");
    }

    #[test]
    fn it_rotates_once_due_plus_jitter_has_passed() {
        let s = Schedule::default();
        let due = Some(at(90));
        let jitter = Duration::from_secs(3600);
        assert_eq!(s.decide(at(90), due, jitter, false, true), Decision::NotYet);
        assert_eq!(s.decide(at(90) + chrono::Duration::seconds(3599), due, jitter, false, true), Decision::NotYet);
        assert_eq!(s.decide(at(90) + chrono::Duration::seconds(3600), due, jitter, false, true), Decision::Rotate);
    }

    #[test]
    fn the_schedule_does_nothing_in_standby() {
        let s = Schedule::default();
        assert_eq!(s.decide(at(500), Some(at(90)), Duration::ZERO, true, true), Decision::Standby);
    }

    #[test]
    fn the_schedule_does_nothing_while_the_agent_is_not_connected() {
        let s = Schedule::default();
        assert_eq!(s.decide(at(500), Some(at(90)), Duration::ZERO, false, false), Decision::NotConnected);
    }

    #[test]
    fn backoff_doubles_and_caps_at_a_day() {
        assert_eq!(backoff(1), Duration::from_secs(3600));
        assert_eq!(backoff(2), Duration::from_secs(7200));
        assert_eq!(backoff(3), Duration::from_secs(14400));
        assert_eq!(backoff(5), Duration::from_secs(16 * 3600));
        assert_eq!(backoff(6), Duration::from_secs(24 * 3600));
        assert_eq!(backoff(40), Duration::from_secs(24 * 3600));
    }

    #[test]
    fn a_failure_holds_the_next_attempt_back_and_a_success_clears_it() {
        let mut s = Schedule::default();
        let due = Some(at(90));
        assert_eq!(s.failed(at(100)), 1);
        assert_eq!(s.decide(at(100), due, Duration::ZERO, false, true), Decision::NotYet);
        assert_eq!(s.decide(at(100) + chrono::Duration::hours(1), due, Duration::ZERO, false, true), Decision::Rotate);
        assert_eq!(s.failed(at(100)), 2);
        s.succeeded();
        assert_eq!(s.decide(at(100), due, Duration::ZERO, false, true), Decision::Rotate);
    }
}
