//! Replay protection for received fabric envelopes.
//!
//! A DIDComm envelope is processed once: a digest of its `(sender DID,
//! message id)` pair is remembered in a process-local set until the envelope's
//! own `expires_time`, and a second delivery is refused. A `forward-request`
//! must carry `expires_time` (every sending gateway sets one) and is refused
//! once it has passed; a `created_time`, when present, may not lie in the
//! future beyond clock skew. Pairing messages are remembered until their
//! `expires_time`, at most [`MAX_ENVELOPE_LIFETIME_SECS`] from now, and for
//! that full horizon when they carry none.
//!
//! A sending gateway caps the lifetime it puts on a `forward-request` at
//! [`MAX_SENT_ENVELOPE_LIFETIME_SECS`] ([`sent_envelope_lifetime_secs`]),
//! whatever the request timeout, so a receiver whose clock runs up to
//! [`CREATED_TIME_SKEW_SECS`] behind still accepts it.
//!
//! The set lives in memory only.

use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use sha2::{Digest, Sha256};

use super::messages::ReceivedMessage;

/// Clock skew tolerated on `created_time`, in seconds, and the slack between
/// the lifetime a sender puts on an envelope and the lifetime a receiver
/// accepts.
pub const CREATED_TIME_SKEW_SECS: u64 = 120;

/// Longest accepted distance between now and `expires_time`, in seconds. It
/// bounds the seen set: no entry outlives this horizon.
pub const MAX_ENVELOPE_LIFETIME_SECS: u64 = 3600;

/// Longest lifetime a sending gateway puts on a `forward-request`, in
/// seconds. It stays [`CREATED_TIME_SKEW_SECS`] below the receiver's cap so
/// clock skew between the two gateways does not turn into a refusal.
pub const MAX_SENT_ENVELOPE_LIFETIME_SECS: u64 = MAX_ENVELOPE_LIFETIME_SECS - CREATED_TIME_SKEW_SECS;

/// Minimum interval between sweeps of expired entries, in seconds.
const PRUNE_INTERVAL_SECS: u64 = 60;

/// Why an envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeRejection {
    MissingSender,
    MissingExpiry,
    Expired { expires_time: u64, now: u64 },
    ExpiryTooFar { expires_time: u64, now: u64 },
    CreatedInFuture { created_time: u64, now: u64 },
    Duplicate { sender: String, message_id: String },
}

impl fmt::Display for EnvelopeRejection {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Self::MissingSender => write!(f, "envelope carries no authenticated sender"),
            Self::MissingExpiry => write!(f, "envelope carries no expires_time"),
            Self::Expired { expires_time, now } => {
                write!(f, "envelope expired at {expires_time} (now {now})")
            }
            Self::ExpiryTooFar { expires_time, now } => write!(
                f,
                "envelope expires_time {expires_time} is more than {MAX_ENVELOPE_LIFETIME_SECS}s ahead of now ({now})"
            ),
            Self::CreatedInFuture { created_time, now } => write!(
                f,
                "envelope created_time {created_time} is more than {CREATED_TIME_SKEW_SECS}s ahead of now ({now})"
            ),
            Self::Duplicate { sender, message_id } => {
                write!(f, "envelope {message_id} from {sender} was already processed")
            }
        }
    }
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lifetime, in seconds, a sending gateway puts on a `forward-request` whose
/// caller is prepared to wait `timeout_secs`. The caller deadline keeps the
/// full timeout; only the envelope's `expires_time` is capped, so a request
/// timeout above the cap still works as long as the envelope is delivered
/// within [`MAX_SENT_ENVELOPE_LIFETIME_SECS`].
pub fn sent_envelope_lifetime_secs(timeout_secs: u64) -> u64 {
    timeout_secs.clamp(1, MAX_SENT_ENVELOPE_LIFETIME_SECS)
}

/// Validates the envelope's temporal fields for a `forward-request` and
/// returns the instant until which the envelope must be remembered.
pub fn validate_envelope_times(
    created_time: Option<u64>,
    expires_time: Option<u64>,
    now: u64,
) -> Result<u64, EnvelopeRejection> {
    let expires_time = expires_time.ok_or(EnvelopeRejection::MissingExpiry)?;
    if expires_time <= now {
        return Err(EnvelopeRejection::Expired { expires_time, now });
    }
    if expires_time > now + MAX_ENVELOPE_LIFETIME_SECS {
        return Err(EnvelopeRejection::ExpiryTooFar { expires_time, now });
    }
    if let Some(created_time) = created_time
        && created_time > now + CREATED_TIME_SKEW_SECS
    {
        return Err(EnvelopeRejection::CreatedInFuture { created_time, now });
    }
    Ok(expires_time)
}

/// Digests of processed envelopes, each kept until its own retention
/// instant. Keys are SHA-256 digests of `(sender, message id)`, so an entry
/// costs the same however long the sender's DID or message id is.
pub struct SeenSet {
    entries: DashMap<[u8; 32], u64>,
    next_prune_at: AtomicU64,
}

impl Default for SeenSet {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenSet {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            next_prune_at: AtomicU64::new(0),
        }
    }

    /// Remembers `(sender, message_id)` until `retain_until`. A second call
    /// for the same pair before that instant is a duplicate.
    pub fn record_first_sight(
        &self,
        sender: &str,
        message_id: &str,
        retain_until: u64,
        now: u64,
    ) -> Result<(), EnvelopeRejection> {
        self.prune_expired(now);
        match self
            .entries
            .entry(digest(sender, message_id))
        {
            Entry::Occupied(mut slot) => {
                if *slot.get() > now {
                    return Err(EnvelopeRejection::Duplicate {
                        sender: sender.to_string(),
                        message_id: message_id.to_string(),
                    });
                }
                slot.insert(retain_until);
                Ok(())
            }
            Entry::Vacant(slot) => {
                slot.insert(retain_until);
                Ok(())
            }
        }
    }

    /// Whether `(sender, message_id)` is remembered at `now`, without
    /// recording it.
    pub fn is_remembered(
        &self,
        sender: &str,
        message_id: &str,
        now: u64,
    ) -> bool {
        self.entries
            .get(&digest(sender, message_id))
            .is_some_and(|retain_until| *retain_until > now)
    }

    /// Number of envelopes currently remembered, expired entries included
    /// until the next sweep.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn prune_expired(
        &self,
        now: u64,
    ) {
        let due = self
            .next_prune_at
            .load(Ordering::Acquire);
        if now < due {
            return;
        }
        if self
            .next_prune_at
            .compare_exchange(due, now + PRUNE_INTERVAL_SECS, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.entries
                .retain(|_, retain_until| *retain_until > now);
        }
    }
}

fn digest(
    sender: &str,
    message_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sender.as_bytes());
    hasher.update([0u8]);
    hasher.update(message_id.as_bytes());
    hasher.finalize().into()
}

static SEEN: OnceLock<SeenSet> = OnceLock::new();

fn seen() -> &'static SeenSet {
    SEEN.get_or_init(SeenSet::new)
}

fn remember(
    sender: &str,
    message_id: &str,
    retain_until: u64,
    now: u64,
) -> Result<(), EnvelopeRejection> {
    let outcome = seen().record_first_sight(sender, message_id, retain_until, now);
    crate::metrics::backends::prometheus::set_fabric_envelope_seen_entries(seen().len() as i64);
    outcome
}

/// The authenticated sender the envelope is keyed on. An envelope without one
/// is refused rather than pooled under an empty key.
fn sender_of(message: &ReceivedMessage) -> Result<&str, EnvelopeRejection> {
    message
        .from_did
        .as_deref()
        .filter(|sender| !sender.is_empty())
        .ok_or(EnvelopeRejection::MissingSender)
}

/// Checks a `forward-request` as `admit_forward_request` does, without
/// remembering it, so the admission that later records it still runs once.
pub fn check_forward_request(message: &ReceivedMessage) -> Result<(), EnvelopeRejection> {
    let sender = sender_of(message)?;
    let now = now_secs();
    validate_envelope_times(message.created_time, message.expires_time, now)?;
    if seen().is_remembered(sender, &message.didcomm_message_id, now) {
        return Err(EnvelopeRejection::Duplicate {
            sender: sender.to_string(),
            message_id: message
                .didcomm_message_id
                .clone(),
        });
    }
    Ok(())
}

/// Admits a `forward-request`: its `expires_time` is required and validated,
/// then the envelope is remembered until it expires.
pub fn admit_forward_request(message: &ReceivedMessage) -> Result<(), EnvelopeRejection> {
    let sender = sender_of(message)?;
    let now = now_secs();
    let retain_until = validate_envelope_times(message.created_time, message.expires_time, now)?;
    remember(sender, &message.didcomm_message_id, retain_until, now)
}

/// Checks a Fabric capability query as `admit_capability_query` does, without
/// remembering it, so a query refused for another reason is not used up.
pub fn check_capability_query(message: &ReceivedMessage) -> Result<(), EnvelopeRejection> {
    check_forward_request(message)
}

/// Admits a Fabric capability query like a `forward-request`: its
/// `expires_time` is required and validated, then the envelope is remembered
/// until it expires. A replayed query can then never recreate an offer that
/// has expired, so an `Open` bound to that offer stays refused.
pub fn admit_capability_query(message: &ReceivedMessage) -> Result<(), EnvelopeRejection> {
    admit_forward_request(message)
}

/// Admits a pairing message (`connection-setup`, `connection-accepted`): an
/// expired envelope is refused, and the envelope is remembered until its
/// `expires_time` or for [`MAX_ENVELOPE_LIFETIME_SECS`] when it has none.
pub fn admit_pairing_message(message: &ReceivedMessage) -> Result<(), EnvelopeRejection> {
    let sender = sender_of(message)?;
    let now = now_secs();
    if let Some(expires_time) = message.expires_time
        && expires_time <= now
    {
        return Err(EnvelopeRejection::Expired { expires_time, now });
    }
    let retain_until = message
        .expires_time
        .unwrap_or(now + MAX_ENVELOPE_LIFETIME_SECS)
        .min(now + MAX_ENVELOPE_LIFETIME_SECS);
    remember(sender, &message.didcomm_message_id, retain_until, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;
    use crate::messages::MessageType;

    const NOW: u64 = 1_800_000_000;

    fn unique(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4())
    }

    fn envelope(
        message_type: MessageType,
        created_time: Option<u64>,
        expires_time: Option<u64>,
    ) -> ReceivedMessage {
        envelope_from(Some(unique("did:web:sender")), message_type, created_time, expires_time)
    }

    fn envelope_from(
        from_did: Option<String>,
        message_type: MessageType,
        created_time: Option<u64>,
        expires_time: Option<u64>,
    ) -> ReceivedMessage {
        ReceivedMessage::new(
            "cp-1".to_string(),
            "gw-1".to_string(),
            message_type.to_string(),
            unique("msg"),
            None,
            from_did,
            vec!["did:web:receiver.example".to_string()],
            created_time,
            expires_time,
            serde_json::json!({}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        )
    }

    #[test]
    fn expires_time_is_required_and_must_be_in_the_future() {
        assert_eq!(validate_envelope_times(None, None, NOW), Err(EnvelopeRejection::MissingExpiry));
        assert_eq!(
            validate_envelope_times(None, Some(NOW), NOW),
            Err(EnvelopeRejection::Expired { expires_time: NOW, now: NOW })
        );
        assert_eq!(
            validate_envelope_times(None, Some(NOW - 1), NOW),
            Err(EnvelopeRejection::Expired {
                expires_time: NOW - 1,
                now: NOW
            })
        );
        assert_eq!(validate_envelope_times(None, Some(NOW + 90), NOW), Ok(NOW + 90));
    }

    #[test]
    fn expires_time_beyond_the_lifetime_cap_is_refused() {
        let too_far = NOW + MAX_ENVELOPE_LIFETIME_SECS + 1;
        assert_eq!(
            validate_envelope_times(None, Some(too_far), NOW),
            Err(EnvelopeRejection::ExpiryTooFar {
                expires_time: too_far,
                now: NOW
            })
        );
        assert_eq!(
            validate_envelope_times(None, Some(NOW + MAX_ENVELOPE_LIFETIME_SECS), NOW),
            Ok(NOW + MAX_ENVELOPE_LIFETIME_SECS)
        );
    }

    #[test]
    fn sent_lifetime_is_capped_below_the_receiver_horizon() {
        assert_eq!(sent_envelope_lifetime_secs(30), 30);
        assert_eq!(sent_envelope_lifetime_secs(0), 1);
        assert_eq!(sent_envelope_lifetime_secs(MAX_SENT_ENVELOPE_LIFETIME_SECS), MAX_SENT_ENVELOPE_LIFETIME_SECS);
        assert_eq!(sent_envelope_lifetime_secs(7200), MAX_SENT_ENVELOPE_LIFETIME_SECS);

        // A sender clock running the full tolerated skew ahead of the receiver
        // still lands within the receiver's cap.
        let sent_from_a_fast_clock = NOW + CREATED_TIME_SKEW_SECS + sent_envelope_lifetime_secs(7200);
        assert_eq!(validate_envelope_times(None, Some(sent_from_a_fast_clock), NOW), Ok(sent_from_a_fast_clock));
    }

    #[test]
    fn created_time_may_not_lie_beyond_clock_skew() {
        let future = NOW + CREATED_TIME_SKEW_SECS + 1;
        assert_eq!(
            validate_envelope_times(Some(future), Some(NOW + 90), NOW),
            Err(EnvelopeRejection::CreatedInFuture { created_time: future, now: NOW })
        );
        assert_eq!(validate_envelope_times(Some(NOW + CREATED_TIME_SKEW_SECS), Some(NOW + 90), NOW), Ok(NOW + 90));
        assert_eq!(validate_envelope_times(Some(NOW - 5), Some(NOW + 90), NOW), Ok(NOW + 90));
    }

    #[test]
    fn a_second_sight_within_the_retention_window_is_a_duplicate() {
        let set = SeenSet::new();
        let sender = unique("did:web:sender");
        let id = unique("msg");
        assert_eq!(set.record_first_sight(&sender, &id, NOW + 60, NOW), Ok(()));
        assert_eq!(
            set.record_first_sight(&sender, &id, NOW + 60, NOW + 1),
            Err(EnvelopeRejection::Duplicate {
                sender: sender.clone(),
                message_id: id.clone()
            })
        );
        assert_eq!(
            set.record_first_sight(&unique("did:web:other"), &id, NOW + 60, NOW),
            Ok(()),
            "message ids are unique per sender only"
        );
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn an_expired_entry_no_longer_counts_as_seen() {
        let set = SeenSet::new();
        let sender = unique("did:web:sender");
        let id = unique("msg");
        assert_eq!(set.record_first_sight(&sender, &id, NOW + 10, NOW), Ok(()));
        assert_eq!(set.record_first_sight(&sender, &id, NOW + 70, NOW + 10), Ok(()));
    }

    #[test]
    fn expired_entries_are_swept_once_the_prune_interval_elapses() {
        let set = SeenSet::new();
        let sender = unique("did:web:sender");
        assert_eq!(set.record_first_sight(&sender, "short", NOW + 10, NOW), Ok(()));
        assert_eq!(set.record_first_sight(&sender, "long", NOW + 3000, NOW + 1), Ok(()));
        assert_eq!(set.len(), 2, "no sweep before the interval");

        assert_eq!(set.record_first_sight(&sender, "later", NOW + 3000, NOW + PRUNE_INTERVAL_SECS), Ok(()));
        assert_eq!(set.len(), 2, "the expired entry was swept, the live ones kept");
    }

    #[test]
    fn keys_are_digests_that_separate_sender_and_message_id() {
        assert_ne!(digest("did:web:a", "b"), digest("did:web:ab", ""));
        assert_ne!(digest("did:web:a", "b"), digest("did:web:", "ab"));
        assert_eq!(digest("did:web:a", "b"), digest("did:web:a", "b"));
    }

    #[test]
    fn forward_request_is_admitted_once_and_needs_an_expiry() {
        let now = now_secs();
        let message = envelope(MessageType::ForwardRequest, Some(now), Some(now + 60));
        assert_eq!(admit_forward_request(&message), Ok(()));
        assert!(matches!(admit_forward_request(&message), Err(EnvelopeRejection::Duplicate { .. })));

        let without_expiry = envelope(MessageType::ForwardRequest, None, None);
        assert_eq!(admit_forward_request(&without_expiry), Err(EnvelopeRejection::MissingExpiry));
    }

    #[test]
    fn envelopes_without_an_authenticated_sender_are_refused() {
        let now = now_secs();
        let anonymous = envelope_from(None, MessageType::ForwardRequest, None, Some(now + 60));
        assert_eq!(admit_forward_request(&anonymous), Err(EnvelopeRejection::MissingSender));
        let blank = envelope_from(Some(String::new()), MessageType::ConnectionSetup, None, None);
        assert_eq!(admit_pairing_message(&blank), Err(EnvelopeRejection::MissingSender));
    }

    #[test]
    fn pairing_message_without_expiry_is_admitted_once() {
        let message = envelope(MessageType::ConnectionSetup, None, None);
        assert_eq!(admit_pairing_message(&message), Ok(()));
        assert!(matches!(admit_pairing_message(&message), Err(EnvelopeRejection::Duplicate { .. })));

        let now = now_secs();
        let expired = envelope(MessageType::ConnectionAccepted, None, Some(now - 1));
        assert!(matches!(admit_pairing_message(&expired), Err(EnvelopeRejection::Expired { .. })));
    }
}
