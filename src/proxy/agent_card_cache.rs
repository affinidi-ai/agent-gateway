//! Process-global TTL cache for outbound target agent-card lookups.
//!
//! `step_collect_trust_context` (`outbound_handler.rs`) fetches the target
//! agent card on every request when the widened gate is open (legacy
//! `trust_registry_verification` enabled, or the surface's target-leg
//! Trust Check list is non-empty). Without a cache that turns into a
//! per-request HTTP GET against the target's `.well-known/agent-card.json`.
//!
//! The cache is keyed on the tuple `(target_endpoint, agent_card_path)`
//! so two surfaces sharing an endpoint but overriding the card path do
//! **not** collide. Positive entries live for [`POSITIVE_TTL`]; negative
//! (fetch-failure) entries live for the shorter [`NEGATIVE_TTL`] so a
//! transient outage clears quickly.
//!
//! Follows the repo's DashMap-authoritative runtime idiom (see
//! `AGENTS.md` rule 11): the cache is a `DashMap` behind a `OnceLock`
//! accessor. Configuration reload (`POST /v1/config/reload` and the
//! in-process surface CRUD reload path) invalidates the whole cache via
//! [`invalidate_all`] so a redeploy never serves a stale card.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;

/// Positive-entry TTL. Matches typical outbound-proxy tolerance for
/// stale target metadata.
pub const POSITIVE_TTL: Duration = Duration::from_secs(60);

/// Negative-entry TTL. Shorter than [`POSITIVE_TTL`] so a transient
/// target outage self-heals quickly.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(10);

type CacheKey = (String, Option<String>);

struct CacheEntry {
    fetched_at: Instant,
    payload: Option<Value>,
}

impl CacheEntry {
    fn is_fresh(
        &self,
        now: Instant,
    ) -> bool {
        let ttl = if self.payload.is_some() {
            POSITIVE_TTL
        } else {
            NEGATIVE_TTL
        };
        now.saturating_duration_since(self.fetched_at) < ttl
    }
}

fn cache() -> &'static DashMap<CacheKey, CacheEntry> {
    static CACHE: OnceLock<DashMap<CacheKey, CacheEntry>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn make_key(
    target_endpoint: &str,
    agent_card_path: Option<&str>,
) -> CacheKey {
    (target_endpoint.to_string(), agent_card_path.map(str::to_string))
}

/// Memoized outcome of cryptographically verifying a target card's
/// `agent-identity-credential/v1` Verifiable Presentation. Only
/// successful verifications are memoized (keyed by the full VP string so
/// a hash collision can never surface the wrong subject DID); failures
/// are deliberately not cached so a transient DID-resolver outage does
/// not pin a "failed" verdict for the whole TTL.
struct VerifiedVpEntry {
    verified_at: Instant,
    subject_did: String,
}

fn verified_vp_cache() -> &'static DashMap<String, VerifiedVpEntry> {
    static CACHE: OnceLock<DashMap<String, VerifiedVpEntry>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

/// Lookup a memoized VP-verification result. Returns `Some(subject_did)`
/// when a fresh successful verification exists; `None` when the caller
/// must verify and, on success, memoize via [`insert_verified_vp`].
pub fn lookup_verified_vp(vp: &str) -> Option<String> {
    let entry = verified_vp_cache().get(vp)?;
    if Instant::now().saturating_duration_since(entry.verified_at) < POSITIVE_TTL {
        Some(entry.subject_did.clone())
    } else {
        None
    }
}

/// Memoize a successful VP verification, mapping the VP string to the
/// proof-verified `credentialSubject.id`.
pub fn insert_verified_vp(
    vp: &str,
    subject_did: &str,
) {
    verified_vp_cache().insert(
        vp.to_string(),
        VerifiedVpEntry {
            verified_at: Instant::now(),
            subject_did: subject_did.to_string(),
        },
    );
}

/// Lookup a cached agent card. Returns `Some(Option<Value>)` when a
/// fresh entry exists (inner `Option` distinguishes positive from
/// negative cache); returns `None` when the caller must fetch and
/// insert via [`insert`].
pub fn lookup(
    target_endpoint: &str,
    agent_card_path: Option<&str>,
) -> Option<Option<Value>> {
    let key = make_key(target_endpoint, agent_card_path);
    let now = Instant::now();
    let entry = cache().get(&key)?;
    if entry.is_fresh(now) {
        Some(entry.payload.clone())
    } else {
        None
    }
}

/// Insert a fresh fetch result. `payload = None` records a negative
/// entry with the shorter [`NEGATIVE_TTL`].
pub fn insert(
    target_endpoint: &str,
    agent_card_path: Option<&str>,
    payload: Option<Value>,
) {
    let key = make_key(target_endpoint, agent_card_path);
    cache().insert(
        key,
        CacheEntry {
            fetched_at: Instant::now(),
            payload,
        },
    );
}

/// Drop every cached entry (agent-card payloads **and** memoized
/// VP-verification outcomes). Wired into the two reload seams so a
/// config redeploy never serves a stale card or a stale identity verdict.
pub fn invalidate_all() {
    cache().clear();
    verified_vp_cache().clear();
}

#[cfg(test)]
pub(crate) fn entry_count() -> usize {
    cache().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    // Serialize every test in this module — they all share the same
    // process-global `CACHE`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        invalidate_all();
        guard
    }

    #[test]
    fn positive_hit_within_ttl() {
        let _guard = setup();
        insert("https://a.example.com", None, Some(json!({"kind": "card"})));
        let hit = lookup("https://a.example.com", None).expect("fresh entry");
        assert_eq!(hit, Some(json!({"kind": "card"})));
    }

    #[test]
    fn different_agent_card_path_isolates_key() {
        let _guard = setup();
        insert("https://a.example.com", None, Some(json!({"kind": "default"})));
        insert("https://a.example.com", Some("/custom/agent.json"), Some(json!({"kind": "custom"})));
        assert_eq!(lookup("https://a.example.com", None), Some(Some(json!({"kind": "default"}))));
        assert_eq!(lookup("https://a.example.com", Some("/custom/agent.json")), Some(Some(json!({"kind": "custom"}))));
    }

    #[test]
    fn negative_entry_returns_some_none() {
        let _guard = setup();
        insert("https://down.example.com", None, None);
        let hit = lookup("https://down.example.com", None).expect("fresh negative entry");
        assert!(hit.is_none(), "negative cache entry surfaces as Some(None)");
    }

    #[test]
    fn invalidate_all_clears_cache() {
        let _guard = setup();
        insert("https://a.example.com", None, Some(json!({"a": 1})));
        insert("https://b.example.com", None, None);
        assert_eq!(entry_count(), 2);
        invalidate_all();
        assert_eq!(entry_count(), 0);
        assert!(lookup("https://a.example.com", None).is_none());
    }

    #[test]
    fn verified_vp_roundtrip_and_invalidation() {
        let _guard = setup();
        let vp = "{\"vp\":\"target\"}";
        assert!(lookup_verified_vp(vp).is_none(), "miss before insert");
        insert_verified_vp(vp, "did:web:subject");
        assert_eq!(lookup_verified_vp(vp).as_deref(), Some("did:web:subject"));
        // A different VP string must not collide.
        assert!(lookup_verified_vp("{\"vp\":\"other\"}").is_none());
        invalidate_all();
        assert!(lookup_verified_vp(vp).is_none(), "cleared on invalidate_all");
    }
}
