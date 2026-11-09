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
//!
//! The card a Fabric receiving surface reads for its policy input may be read
//! with the surface's Target credential, so it is kept in its own map keyed on
//! the surface, the card URL and the Target authentication it was read with
//! ([`lookup_surface_card`]), so variants of one surface never share a card.

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
    fn now(payload: Option<Value>) -> Self {
        Self {
            fetched_at: Instant::now(),
            payload,
        }
    }

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

type SurfaceCardKey = (String, String, String);

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

#[derive(Default)]
struct AgentCardCache {
    cards: DashMap<CacheKey, CacheEntry>,
    surface_cards: DashMap<SurfaceCardKey, CacheEntry>,
    verified_vps: DashMap<String, VerifiedVpEntry>,
}

impl AgentCardCache {
    fn lookup_verified_vp(
        &self,
        vp: &str,
    ) -> Option<String> {
        let entry = self.verified_vps.get(vp)?;
        (Instant::now().saturating_duration_since(entry.verified_at) < POSITIVE_TTL).then(|| entry.subject_did.clone())
    }

    fn insert_verified_vp(
        &self,
        vp: &str,
        subject_did: &str,
    ) {
        self.verified_vps.insert(
            vp.to_string(),
            VerifiedVpEntry {
                verified_at: Instant::now(),
                subject_did: subject_did.to_string(),
            },
        );
    }

    fn lookup(
        &self,
        target_endpoint: &str,
        agent_card_path: Option<&str>,
    ) -> Option<Option<Value>> {
        let entry = self
            .cards
            .get(&make_key(target_endpoint, agent_card_path))?;
        entry
            .is_fresh(Instant::now())
            .then(|| entry.payload.clone())
    }

    fn insert(
        &self,
        target_endpoint: &str,
        agent_card_path: Option<&str>,
        payload: Option<Value>,
    ) {
        self.cards
            .insert(make_key(target_endpoint, agent_card_path), CacheEntry::now(payload));
    }

    fn lookup_surface_card(
        &self,
        surface_id: &str,
        card_url: &str,
        target_auth: &str,
    ) -> Option<Option<Value>> {
        let entry = self
            .surface_cards
            .get(&(surface_id.to_string(), card_url.to_string(), target_auth.to_string()))?;
        entry
            .is_fresh(Instant::now())
            .then(|| entry.payload.clone())
    }

    fn insert_surface_card(
        &self,
        surface_id: &str,
        card_url: &str,
        target_auth: &str,
        payload: Option<Value>,
    ) {
        self.surface_cards
            .insert((surface_id.to_string(), card_url.to_string(), target_auth.to_string()), CacheEntry::now(payload));
    }

    fn invalidate_all(&self) {
        self.cards.clear();
        self.surface_cards.clear();
        self.verified_vps.clear();
    }
}

fn global() -> &'static AgentCardCache {
    static CACHE: OnceLock<AgentCardCache> = OnceLock::new();
    CACHE.get_or_init(AgentCardCache::default)
}

fn make_key(
    target_endpoint: &str,
    agent_card_path: Option<&str>,
) -> CacheKey {
    (target_endpoint.to_string(), agent_card_path.map(str::to_string))
}

/// Lookup a memoized VP-verification result. Returns `Some(subject_did)`
/// when a fresh successful verification exists; `None` when the caller
/// must verify and, on success, memoize via [`insert_verified_vp`].
pub fn lookup_verified_vp(vp: &str) -> Option<String> {
    global().lookup_verified_vp(vp)
}

/// Memoize a successful VP verification, mapping the VP string to the
/// proof-verified `credentialSubject.id`.
pub fn insert_verified_vp(
    vp: &str,
    subject_did: &str,
) {
    global().insert_verified_vp(vp, subject_did);
}

/// Lookup a cached agent card. Returns `Some(Option<Value>)` when a
/// fresh entry exists (inner `Option` distinguishes positive from
/// negative cache); returns `None` when the caller must fetch and
/// insert via [`insert`].
pub fn lookup(
    target_endpoint: &str,
    agent_card_path: Option<&str>,
) -> Option<Option<Value>> {
    global().lookup(target_endpoint, agent_card_path)
}

/// Insert a fresh fetch result. `payload = None` records a negative
/// entry with the shorter [`NEGATIVE_TTL`].
pub fn insert(
    target_endpoint: &str,
    agent_card_path: Option<&str>,
    payload: Option<Value>,
) {
    global().insert(target_endpoint, agent_card_path, payload);
}

/// [`lookup`] for the card `surface_id` read from `card_url` with the Target
/// authentication `target_auth` (its configuration, serialised) for its policy
/// input. No other surface or Target authentication, and no outbound lookup,
/// sees it.
pub fn lookup_surface_card(
    surface_id: &str,
    card_url: &str,
    target_auth: &str,
) -> Option<Option<Value>> {
    global().lookup_surface_card(surface_id, card_url, target_auth)
}

/// [`insert`] for the card `surface_id` read from `card_url` with `target_auth`.
pub fn insert_surface_card(
    surface_id: &str,
    card_url: &str,
    target_auth: &str,
    payload: Option<Value>,
) {
    global().insert_surface_card(surface_id, card_url, target_auth, payload);
}

/// Drop every cached entry (agent-card payloads, surface policy cards **and**
/// memoized VP-verification outcomes). Wired into the reload seams so a
/// config redeploy never serves a stale card or a stale identity verdict.
pub fn invalidate_all() {
    global().invalidate_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn positive_hit_within_ttl() {
        let cache = AgentCardCache::default();
        cache.insert("https://a.example.com", None, Some(json!({"kind": "card"})));
        let hit = cache
            .lookup("https://a.example.com", None)
            .expect("fresh entry");
        assert_eq!(hit, Some(json!({"kind": "card"})));
    }

    #[test]
    fn different_agent_card_path_isolates_key() {
        let cache = AgentCardCache::default();
        cache.insert("https://a.example.com", None, Some(json!({"kind": "default"})));
        cache.insert("https://a.example.com", Some("/custom/agent.json"), Some(json!({"kind": "custom"})));
        assert_eq!(cache.lookup("https://a.example.com", None), Some(Some(json!({"kind": "default"}))));
        assert_eq!(
            cache.lookup("https://a.example.com", Some("/custom/agent.json")),
            Some(Some(json!({"kind": "custom"})))
        );
    }

    #[test]
    fn negative_entry_returns_some_none() {
        let cache = AgentCardCache::default();
        cache.insert("https://down.example.com", None, None);
        let hit = cache
            .lookup("https://down.example.com", None)
            .expect("fresh negative entry");
        assert!(hit.is_none(), "negative cache entry surfaces as Some(None)");
    }

    #[test]
    fn a_stale_entry_is_a_miss() {
        let cache = AgentCardCache::default();
        cache.insert("https://a.example.com", None, Some(json!({"a": 1})));
        cache.insert("https://down.example.com", None, None);
        let backdate = |key: CacheKey, age: Duration| {
            if let Some(mut entry) = cache.cards.get_mut(&key) {
                entry.fetched_at = Instant::now()
                    .checked_sub(age)
                    .expect("monotonic clock far enough from its origin");
            }
        };
        backdate(make_key("https://a.example.com", None), POSITIVE_TTL);
        backdate(make_key("https://down.example.com", None), NEGATIVE_TTL);
        assert!(
            cache
                .lookup("https://a.example.com", None)
                .is_none()
        );
        assert!(
            cache
                .lookup("https://down.example.com", None)
                .is_none()
        );
    }

    #[test]
    fn invalidate_all_clears_cache() {
        let cache = AgentCardCache::default();
        cache.insert("https://a.example.com", None, Some(json!({"a": 1})));
        cache.insert("https://b.example.com", None, None);
        assert_eq!(cache.cards.len(), 2);
        cache.invalidate_all();
        assert_eq!(cache.cards.len(), 0);
        assert!(
            cache
                .lookup("https://a.example.com", None)
                .is_none()
        );
    }

    #[test]
    fn a_surface_card_is_seen_only_by_its_surface_and_target_auth_and_cleared_on_invalidate_all() {
        let cache = AgentCardCache::default();
        let url = "https://a.example.com/.well-known/agent.json";
        let key_a = r#"{"method":"a"}"#;
        assert!(
            cache
                .lookup_surface_card("orders", url, key_a)
                .is_none(),
            "miss before insert"
        );
        cache.insert_surface_card("orders", url, key_a, Some(json!({"kind": "protected"})));
        cache.insert_surface_card("billing", url, key_a, None);
        assert_eq!(cache.lookup_surface_card("orders", url, key_a), Some(Some(json!({"kind": "protected"}))));
        assert_eq!(cache.lookup_surface_card("billing", url, key_a), Some(None));
        assert!(
            cache
                .lookup_surface_card("orders", url, r#"{"method":"b"}"#)
                .is_none(),
            "another Target authentication"
        );
        assert!(
            cache
                .lookup_surface_card("orders", "https://b.example.com/.well-known/agent.json", key_a)
                .is_none()
        );
        assert!(
            cache
                .lookup("https://a.example.com", None)
                .is_none(),
            "an outbound lookup never sees it"
        );
        cache.invalidate_all();
        assert!(
            cache
                .lookup_surface_card("orders", url, key_a)
                .is_none(),
            "cleared on invalidate_all"
        );
    }

    #[test]
    fn verified_vp_roundtrip_and_invalidation() {
        let cache = AgentCardCache::default();
        let vp = "{\"vp\":\"target\"}";
        assert!(
            cache
                .lookup_verified_vp(vp)
                .is_none(),
            "miss before insert"
        );
        cache.insert_verified_vp(vp, "did:web:subject");
        assert_eq!(
            cache
                .lookup_verified_vp(vp)
                .as_deref(),
            Some("did:web:subject")
        );
        assert!(
            cache
                .lookup_verified_vp("{\"vp\":\"other\"}")
                .is_none()
        );
        cache.invalidate_all();
        assert!(
            cache
                .lookup_verified_vp(vp)
                .is_none(),
            "cleared on invalidate_all"
        );
    }
}
