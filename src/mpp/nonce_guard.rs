//! In-memory single-use guard for verified MPP settlements.
//!
//! A verified MPP payment yields a settlement reference — a Stripe PaymentIntent
//! id, an on-chain transaction hash, or an EIP-3009 / Permit2 signature nonce.
//! Without an explicit consume step the same credential could be replayed to pay
//! for many requests (the challenge id alone is not enough because a client may
//! resubmit an identical, still-valid credential). This guard records each
//! settlement's replay key for the length of the challenge validity window and
//! rejects a second use within that window.
//!
//! Best-effort only — the state is per-process and non-durable, so it is not
//! shared across a restart or a second gateway. It reduces, but does not
//! eliminate, replay risk; durable multi-gateway protection comes from the
//! settlement layer itself (on-chain nonce consumption, Stripe idempotency).

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use super::types::MppCredential;

/// Shortest replay window kept regardless of the challenge's own expiry, so a
/// tiny remaining window still gets meaningful replay protection.
const MIN_REPLAY_TTL_SECS: u64 = 60;

/// Longest replay window kept, bounding how long a single key occupies memory.
/// Also the ceiling save-time posture validation enforces on
/// `challenge_ttl_seconds`, so a challenge can never outlive this guard's
/// memory of having already settled it.
pub(crate) const MAX_REPLAY_TTL_SECS: u64 = 3600;

/// Fallback window used when the challenge carries no parseable `expires`.
const DEFAULT_REPLAY_TTL_SECS: u64 = 300;

/// Sweep expired entries once the map grows past this many keys, bounding memory
/// under churn without paying an O(n) scan on every request.
const MAX_TRACKED_KEYS: usize = 100_000;

/// Result of checking (and recording) a replay key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// The key had not been seen within its window and is now recorded.
    Fresh,
    /// The key was already recorded within its window — a replay.
    Replay,
}

/// TTL-bounded single-use guard keyed by a verified settlement's replay key.
pub struct MppNonceGuard {
    seen: DashMap<String, Instant>,
}

impl Default for MppNonceGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl MppNonceGuard {
    /// Create an empty guard.
    pub fn new() -> Self {
        Self { seen: DashMap::new() }
    }

    /// Record `key` and report whether it was already present within its window.
    /// `ttl` is how long the key stays recorded (the challenge validity window).
    /// The check and insert are atomic per key, so two concurrent submissions of
    /// the same settlement cannot both be reported `Fresh`.
    pub fn check_and_record(
        &self,
        key: &str,
        ttl: Duration,
    ) -> ReplayCheck {
        self.check_and_record_at(key, Instant::now(), ttl)
    }

    fn check_and_record_at(
        &self,
        key: &str,
        now: Instant,
        ttl: Duration,
    ) -> ReplayCheck {
        let outcome = match self
            .seen
            .entry(key.to_string())
        {
            Entry::Occupied(mut e) => {
                if *e.get() > now {
                    ReplayCheck::Replay
                } else {
                    // Expired entry — the window lapsed, so treat as first use.
                    e.insert(now + ttl);
                    ReplayCheck::Fresh
                }
            }
            Entry::Vacant(e) => {
                e.insert(now + ttl);
                ReplayCheck::Fresh
            }
        };

        if outcome == ReplayCheck::Fresh && self.seen.len() > MAX_TRACKED_KEYS {
            self.seen
                .retain(|_, expiry| *expiry > now);
        }
        outcome
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
    }
}

/// Process-wide guard. Zero-config, so it is lazily built on first use rather
/// than wired through the orchestrator.
static GLOBAL_MPP_NONCE_GUARD: LazyLock<MppNonceGuard> = LazyLock::new(MppNonceGuard::new);

/// Access the process-wide MPP settlement single-use guard.
pub fn global_mpp_nonce_guard() -> &'static MppNonceGuard {
    &GLOBAL_MPP_NONCE_GUARD
}

/// The replay window to record a settlement key for: the time remaining until
/// the challenge's `expires`, clamped to a sane floor and ceiling. Falls back to
/// [`DEFAULT_REPLAY_TTL_SECS`] when the challenge carries no parseable expiry, so
/// a settlement is always protected for at least a bounded window.
pub fn replay_ttl(credential: &MppCredential) -> Duration {
    let secs = credential
        .challenge
        .expires
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|expiry| {
            let remaining = expiry.timestamp() - chrono::Utc::now().timestamp();
            remaining.max(0) as u64
        })
        .filter(|&remaining| remaining > 0)
        .unwrap_or(DEFAULT_REPLAY_TTL_SECS)
        .clamp(MIN_REPLAY_TTL_SECS, MAX_REPLAY_TTL_SECS);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::types::{MppChallengeEcho, MppCredential};

    fn credential_with_expires(expires: Option<String>) -> MppCredential {
        MppCredential {
            challenge: MppChallengeEcho {
                id: "test-id".to_string(),
                realm: "example.com".to_string(),
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                request: "eyJ0ZXN0IjoxfQ".to_string(),
                expires,
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload: serde_json::json!({"proof": "0x123"}),
        }
    }

    #[test]
    fn first_use_is_fresh_second_is_replay() {
        let guard = MppNonceGuard::new();
        let ttl = Duration::from_secs(60);
        assert_eq!(guard.check_and_record("key-1", ttl), ReplayCheck::Fresh);
        assert_eq!(guard.check_and_record("key-1", ttl), ReplayCheck::Replay);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let guard = MppNonceGuard::new();
        let ttl = Duration::from_secs(60);
        assert_eq!(guard.check_and_record("key-a", ttl), ReplayCheck::Fresh);
        assert_eq!(guard.check_and_record("key-b", ttl), ReplayCheck::Fresh);
    }

    #[test]
    fn expired_entry_is_treated_as_fresh() {
        let guard = MppNonceGuard::new();
        let now = Instant::now();
        assert_eq!(guard.check_and_record_at("key-1", now, Duration::from_secs(1)), ReplayCheck::Fresh);
        let later = now + Duration::from_secs(2);
        assert_eq!(guard.check_and_record_at("key-1", later, Duration::from_secs(60)), ReplayCheck::Fresh);
    }

    #[test]
    fn sweeps_expired_entries_past_the_tracked_cap() {
        let guard = MppNonceGuard::new();
        let now = Instant::now();
        for i in 0..10 {
            guard.check_and_record_at(&format!("key-{i}"), now, Duration::from_secs(0));
        }
        assert_eq!(guard.len(), 10);
        // A fresh insert past MAX_TRACKED_KEYS would sweep, but we're far under
        // the cap here — this asserts the sweep only runs when over cap, i.e.
        // stale-but-under-cap entries are left until a real sweep threshold.
        guard.check_and_record_at("key-new", now, Duration::from_secs(60));
        assert_eq!(guard.len(), 11);
    }

    #[test]
    fn replay_ttl_defaults_when_no_expiry() {
        let credential = credential_with_expires(None);
        assert_eq!(replay_ttl(&credential), Duration::from_secs(DEFAULT_REPLAY_TTL_SECS));
    }

    #[test]
    fn replay_ttl_clamps_to_floor_when_nearly_expired() {
        let expires = (chrono::Utc::now() + chrono::Duration::seconds(5)).to_rfc3339();
        let credential = credential_with_expires(Some(expires));
        assert_eq!(replay_ttl(&credential), Duration::from_secs(MIN_REPLAY_TTL_SECS));
    }

    #[test]
    fn replay_ttl_clamps_to_ceiling_when_far_in_future() {
        let expires = (chrono::Utc::now() + chrono::Duration::seconds(10_000)).to_rfc3339();
        let credential = credential_with_expires(Some(expires));
        assert_eq!(replay_ttl(&credential), Duration::from_secs(MAX_REPLAY_TTL_SECS));
    }
}
