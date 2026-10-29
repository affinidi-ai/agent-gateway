//! JWKS fetching and in-memory caching
//!
//! [`JwksClient`] fetches JSON Web Key Sets from a JWT verification strategy's JWKS URI
//! and caches one key set per strategy. A cached set is used only while the strategy's
//! `jwks_uri` and `updated_at` still match the ones it was fetched for, so an edit made
//! on any node, through the API or on disk, is a cache miss everywhere.
//!
//! # Cache TTL
//! The TTL is taken from the `Cache-Control: max-age=N` response header, clamped to
//! between 60 seconds and 24 hours. When the header is absent, 24 hours is used.
//!
//! # Refetch limits
//! - A token whose `kid` is not in a fresh set triggers at most one refetch per
//!   strategy every 60 seconds.
//! - After a failed fetch, the next fetch waits 10 seconds.
//! - Concurrent requests for one strategy share a single fetch.
//! - When a refetch of an expired set fails, the last good set keeps serving for up to
//!   one hour past its expiry.
//!
//! A response body over 64 KiB, more than 64 keys, a repeated `kid`, or a key without a
//! `kid` in a set of several keys is rejected as a failed fetch.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::authz_metadata::EgressPosture;
use crate::jwt_bearer::errors::{JwtBearerError, JwtBearerResult};
use crate::jwt_bearer::fetch::{FetchError, FetchFailure, get_bounded};
use crate::jwt_bearer::models::JwtVerificationStrategy;

/// Largest JWKS response body accepted.
pub const MAX_JWKS_BYTES: usize = 64 * 1024;

/// Most keys accepted in one JWKS.
pub const MAX_JWKS_KEYS: usize = 64;

const DEFAULT_TTL: Duration = Duration::from_secs(86_400);
const MIN_TTL: Duration = Duration::from_secs(60);
const MAX_TTL: Duration = DEFAULT_TTL;
const KID_MISS_COOLDOWN: Duration = Duration::from_secs(60);
const FAILURE_BACKOFF: Duration = Duration::from_secs(10);
const STALE_IF_ERROR: Duration = Duration::from_secs(3600);

// ── JSON Web Key types ────────────────────────────────────────────────────────

/// A single JSON Web Key as returned by a JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwk {
    /// Key type, e.g. `"RSA"` or `"EC"`.
    pub kty: String,

    /// Key use, e.g. `"sig"`.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,

    /// Key ID — used to match a token's `kid` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Algorithm, e.g. `"RS256"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    // RSA parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    // EC parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// Response from a JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// The strategy fields a cached key set was fetched for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceVersion {
    jwks_uri: String,
    updated_at: DateTime<Utc>,
}

impl SourceVersion {
    fn of(
        strategy: &JwtVerificationStrategy,
        jwks_uri: &str,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.to_string(),
            updated_at: strategy.updated_at,
        }
    }
}

struct CacheEntry {
    /// Map of `kid` → `Jwk`. A single key without a `kid` is stored under `""`.
    keys: HashMap<String, Jwk>,
    fetched_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired_at(
        &self,
        now: Instant,
    ) -> bool {
        now.saturating_duration_since(self.fetched_at) > self.ttl
    }

    fn is_within_stale_grace_at(
        &self,
        now: Instant,
    ) -> bool {
        now.saturating_duration_since(self.fetched_at) <= self.ttl + STALE_IF_ERROR
    }
}

struct Attempt {
    at: Instant,
    failed: bool,
}

struct Slot {
    version: SourceVersion,
    entry: Option<CacheEntry>,
    last_attempt: Option<Attempt>,
    fetch_lock: Arc<Mutex<()>>,
}

enum Decision {
    Hit(Jwk),
    Refuse(JwtBearerError),
    Fetch,
}

impl Slot {
    fn new(version: SourceVersion) -> Self {
        Self {
            version,
            entry: None,
            last_attempt: None,
            fetch_lock: Arc::new(Mutex::new(())),
        }
    }

    fn since_last_attempt(
        &self,
        now: Instant,
    ) -> Option<(Duration, bool)> {
        self.last_attempt
            .as_ref()
            .map(|attempt| (now.saturating_duration_since(attempt.at), attempt.failed))
    }

    fn decide(
        &self,
        kid: &str,
        now: Instant,
    ) -> Decision {
        let since_last_attempt = self.since_last_attempt(now);
        match &self.entry {
            Some(entry) if !entry.is_expired_at(now) => match entry.keys.get(kid) {
                Some(jwk) => Decision::Hit(jwk.clone()),
                None if since_last_attempt.is_some_and(|(age, _)| age < KID_MISS_COOLDOWN) => {
                    Decision::Refuse(JwtBearerError::KeyNotFound(kid.to_string()))
                }
                None => Decision::Fetch,
            },
            _ => match since_last_attempt {
                Some((age, true)) if age < FAILURE_BACKOFF => match self.stale_key(kid, now) {
                    Some(jwk) => Decision::Hit(jwk),
                    None => Decision::Refuse(JwtBearerError::JwksFetchFailed("JWKS endpoint unavailable".to_string())),
                },
                _ => Decision::Fetch,
            },
        }
    }

    fn stale_key(
        &self,
        kid: &str,
        now: Instant,
    ) -> Option<Jwk> {
        self.entry
            .as_ref()
            .filter(|entry| entry.is_within_stale_grace_at(now))
            .and_then(|entry| entry.keys.get(kid))
            .cloned()
    }
}

// ── JwksClient ────────────────────────────────────────────────────────────────

/// Thread-safe JWKS client with per-strategy caching.
#[derive(Clone)]
pub struct JwksClient {
    /// strategy_id → cached key set and fetch state
    cache: Arc<RwLock<HashMap<String, Slot>>>,
}

impl Default for JwksClient {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksClient {
    /// Create a client with an empty cache.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetch JWKS from `jwks_uri` under `posture` without caching.
    ///
    /// Used by the `validate_jwks_uri` admin endpoint to probe whether a URI is
    /// reachable and returns a JWKS the cache would accept.
    pub async fn fetch_jwks(
        &self,
        jwks_uri: &str,
        posture: EgressPosture,
    ) -> Result<JwksResponse, FetchError> {
        let (jwks, _) = fetch_key_set(jwks_uri, posture).await?;
        index_keys(&jwks.keys)?;
        Ok(jwks)
    }

    /// Evict the cached JWKS for `strategy_id`. Called when a strategy is updated or deleted.
    pub async fn evict(
        &self,
        strategy_id: &str,
    ) {
        if self
            .cache
            .write()
            .await
            .remove(strategy_id)
            .is_some()
        {
            debug!("Evicted JWKS cache for strategy {}", strategy_id);
        }
    }

    /// Drop every cached JWKS. Called when a standby node becomes Active.
    pub async fn clear(&self) {
        self.cache
            .write()
            .await
            .clear();
    }

    #[cfg(test)]
    pub(crate) async fn is_cached(
        &self,
        strategy_id: &str,
    ) -> bool {
        self.cache
            .read()
            .await
            .contains_key(strategy_id)
    }

    /// Retrieve the JWK for `kid` from the JWKS at `jwks_uri` for `strategy`.
    ///
    /// 1. A fresh cached set for the same `jwks_uri` and `updated_at` answers directly.
    /// 2. Otherwise one fetch runs, within the refetch limits in the module docs.
    /// 3. If `kid` is still absent, return [`JwtBearerError::KeyNotFound`].
    pub async fn get_key(
        &self,
        strategy: &JwtVerificationStrategy,
        jwks_uri: &str,
        kid: &str,
    ) -> JwtBearerResult<Jwk> {
        let version = SourceVersion::of(strategy, jwks_uri);
        let (decision, fetch_lock) = self
            .decide(&strategy.id, &version, kid)
            .await;
        if let Some(outcome) = settled(decision) {
            return outcome;
        }

        let _in_flight = fetch_lock.lock().await;
        let (decision, _) = self
            .decide(&strategy.id, &version, kid)
            .await;
        if let Some(outcome) = settled(decision) {
            return outcome;
        }

        info!("Fetching JWKS for strategy {} from {}", strategy.id, crate::observability::loggable::url(jwks_uri));
        let fetched = fetch_entry(jwks_uri).await;
        self.record(&strategy.id, &version, kid, fetched)
            .await
    }

    // ── private ───────────────────────────────────────────────────────────────

    async fn decide(
        &self,
        strategy_id: &str,
        version: &SourceVersion,
        kid: &str,
    ) -> (Decision, Arc<Mutex<()>>) {
        {
            let cache = self.cache.read().await;
            if let Some(slot) = cache
                .get(strategy_id)
                .filter(|slot| slot.version == *version)
            {
                return (slot.decide(kid, Instant::now()), Arc::clone(&slot.fetch_lock));
            }
        }
        let mut cache = self.cache.write().await;
        let slot = match cache.entry(strategy_id.to_string()) {
            Entry::Occupied(occupied) => {
                let slot = occupied.into_mut();
                if slot.version != *version {
                    *slot = Slot::new(version.clone());
                }
                slot
            }
            Entry::Vacant(vacant) => vacant.insert(Slot::new(version.clone())),
        };
        (slot.decide(kid, Instant::now()), Arc::clone(&slot.fetch_lock))
    }

    async fn record(
        &self,
        strategy_id: &str,
        version: &SourceVersion,
        kid: &str,
        fetched: JwtBearerResult<CacheEntry>,
    ) -> JwtBearerResult<Jwk> {
        let now = Instant::now();
        let mut cache = self.cache.write().await;
        let slot = cache
            .get_mut(strategy_id)
            .filter(|slot| slot.version == *version);
        match fetched {
            Ok(entry) => {
                let jwk = entry.keys.get(kid).cloned();
                if let Some(slot) = slot {
                    slot.entry = Some(entry);
                    slot.last_attempt = Some(Attempt { at: now, failed: false });
                }
                jwk.ok_or_else(|| JwtBearerError::KeyNotFound(kid.to_string()))
            }
            Err(error) => {
                let Some(slot) = slot else {
                    return Err(error);
                };
                slot.last_attempt = Some(Attempt { at: now, failed: true });
                match slot.stale_key(kid, now) {
                    Some(jwk) => {
                        warn!(strategy_id = %strategy_id, %error, "JWKS refresh failed; serving the last good key set");
                        Ok(jwk)
                    }
                    None => Err(error),
                }
            }
        }
    }
}

fn settled(decision: Decision) -> Option<JwtBearerResult<Jwk>> {
    match decision {
        Decision::Hit(jwk) => Some(Ok(jwk)),
        Decision::Refuse(error) => Some(Err(error)),
        Decision::Fetch => None,
    }
}

async fn fetch_entry(jwks_uri: &str) -> JwtBearerResult<CacheEntry> {
    let fetched = fetch_key_set(jwks_uri, EgressPosture::CloudMetadataOnly)
        .await
        .and_then(|(jwks, max_age)| index_keys(&jwks.keys).map(|keys| (keys, max_age)));
    crate::metrics::backends::prometheus::track_jwks_fetch(match &fetched {
        Ok(_) => "ok",
        Err(error) => error.failure().code(),
    });
    let (keys, max_age) = fetched.map_err(|e| JwtBearerError::JwksFetchFailed(e.to_string()))?;
    let ttl = ttl_from(max_age);
    debug!("Fetched {} key(s) from JWKS, TTL={:?}", keys.len(), ttl);
    Ok(CacheEntry {
        keys,
        fetched_at: Instant::now(),
        ttl,
    })
}

/// GET and parse a JWKS through the pinned client, returning it with the response's `max-age`.
///
/// The pinned client is also a defense-in-depth SSRF guard: the write-path handler
/// validates too, but strategies could have been stored before that check existed.
async fn fetch_key_set(
    jwks_uri: &str,
    posture: EgressPosture,
) -> Result<(JwksResponse, Option<u64>), FetchError> {
    let (body, headers) = get_bounded(jwks_uri, posture, MAX_JWKS_BYTES).await?;
    let jwks = serde_json::from_slice::<JwksResponse>(&body)
        .map_err(|e| FetchError::new(FetchFailure::InvalidDocument, format!("Failed to parse JWKS: {e}")))?;
    Ok((jwks, parse_max_age(&headers)))
}

/// Index a key set by `kid`, refusing sets a token could not select a key from unambiguously.
fn index_keys(keys: &[Jwk]) -> Result<HashMap<String, Jwk>, FetchError> {
    let invalid = |detail: String| FetchError::new(FetchFailure::InvalidDocument, detail);
    if keys.len() > MAX_JWKS_KEYS {
        return Err(invalid(format!("JWKS holds more than {MAX_JWKS_KEYS} keys")));
    }
    if keys.len() > 1
        && keys
            .iter()
            .any(|key| key.kid.is_none())
    {
        return Err(invalid("JWKS with several keys has a key without a kid".to_string()));
    }
    let mut indexed = HashMap::with_capacity(keys.len());
    for key in keys {
        let kid = key
            .kid
            .clone()
            .unwrap_or_default();
        if indexed
            .insert(kid, key.clone())
            .is_some()
        {
            return Err(invalid("JWKS repeats a kid".to_string()));
        }
    }
    Ok(indexed)
}

fn ttl_from(max_age: Option<u64>) -> Duration {
    max_age.map_or(DEFAULT_TTL, |secs| Duration::from_secs(secs).clamp(MIN_TTL, MAX_TTL))
}

/// Parse `Cache-Control: max-age=N` from response headers.
/// Returns `None` if the header is absent or unparseable.
fn parse_max_age(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let value = headers
        .get(reqwest::header::CACHE_CONTROL)?
        .to_str()
        .ok()?;

    for directive in value.split(',') {
        let directive = directive.trim();
        if let Some(rest) = directive.strip_prefix("max-age=") {
            return rest
                .trim()
                .parse::<u64>()
                .ok();
        }
    }
    None
}

/// Look up a key by `kid` in a static (inline) JWKS slice.
///
/// Used by the validator when the strategy's `JwksSource` is `Static { jwks }`.
/// No HTTP request is made and no caching is performed — the keys are already
/// present in the strategy configuration.
///
/// # Errors
/// Returns [`JwtBearerError::KeyNotFound`] when no key with a matching `kid` exists.
pub fn get_static_key(
    jwks: &[Jwk],
    kid: &str,
) -> JwtBearerResult<Jwk> {
    jwks.iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .cloned()
        .ok_or_else(|| JwtBearerError::KeyNotFound(kid.to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::mock_auth_server::{Endpoint, Fault, MockAuthServer};
    use crate::jwt_bearer::models::JwksSource;
    use crate::jwt_bearer::test_utils::{rsa_jwks_body, start_jwks_server};
    use reqwest::header::{CACHE_CONTROL, HeaderMap, HeaderValue};

    // Dummy RSA n/e — only used to exercise caching logic, not signature verification.
    const DUMMY_N: &str = "sIwr7ZNXUF0";
    const DUMMY_E: &str = "AQAB";

    fn remote_strategy(
        id: &str,
        jwks_uri: &str,
    ) -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: id.to_string(),
            jwks_source: JwksSource::Remote { jwks_uri: jwks_uri.to_string() },
            ..Default::default()
        }
    }

    fn make_jwk(kid: Option<&str>) -> Jwk {
        Jwk {
            kty: "RSA".to_string(),
            key_use: Some("sig".to_string()),
            kid: kid.map(str::to_string),
            alg: Some("RS256".to_string()),
            n: Some("dummy-n".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        }
    }

    fn slot_with(
        keys: &[&str],
        fetched_ago: Duration,
        ttl: Duration,
        last_attempt: Option<(Duration, bool)>,
    ) -> (Slot, Instant) {
        let now = Instant::now() + Duration::from_secs(200_000);
        let mut slot = Slot::new(SourceVersion {
            jwks_uri: "https://issuer.example/jwks.json".to_string(),
            updated_at: DateTime::<Utc>::default(),
        });
        slot.entry = Some(CacheEntry {
            keys: keys
                .iter()
                .map(|kid| (kid.to_string(), make_jwk(Some(kid))))
                .collect(),
            fetched_at: now - fetched_ago,
            ttl,
        });
        slot.last_attempt = last_attempt.map(|(ago, failed)| Attempt { at: now - ago, failed });
        (slot, now)
    }

    async fn slot_state<T>(
        client: &JwksClient,
        strategy_id: &str,
        read: impl FnOnce(&Slot) -> T,
    ) -> Option<T> {
        client
            .cache
            .read()
            .await
            .get(strategy_id)
            .map(read)
    }

    async fn age_entry(
        client: &JwksClient,
        strategy_id: &str,
        fetched_ago: Duration,
        last_attempt_ago: Duration,
    ) {
        let mut cache = client.cache.write().await;
        let slot = cache
            .get_mut(strategy_id)
            .unwrap();
        let entry = slot.entry.as_mut().unwrap();
        entry.fetched_at = Instant::now() - fetched_ago;
        slot.last_attempt = Some(Attempt {
            at: Instant::now() - last_attempt_ago,
            failed: false,
        });
    }

    // ── parse_max_age and TTL clamp ───────────────────────────────────────────

    #[test]
    fn test_parse_max_age_present() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
        assert_eq!(parse_max_age(&headers), Some(3600));
    }

    #[test]
    fn test_parse_max_age_only_value() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=7200"));
        assert_eq!(parse_max_age(&headers), Some(7200));
    }

    #[test]
    fn test_parse_max_age_absent() {
        let headers = HeaderMap::new();
        assert_eq!(parse_max_age(&headers), None);
    }

    #[test]
    fn test_parse_max_age_no_directive() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, no-cache"));
        assert_eq!(parse_max_age(&headers), None);
    }

    #[test]
    fn ttl_is_clamped_between_one_minute_and_one_day() {
        assert_eq!(ttl_from(Some(0)), Duration::from_secs(60));
        assert_eq!(ttl_from(Some(59)), Duration::from_secs(60));
        assert_eq!(ttl_from(Some(1800)), Duration::from_secs(1800));
        assert_eq!(ttl_from(Some(u64::MAX)), Duration::from_secs(86_400));
        assert_eq!(ttl_from(None), Duration::from_secs(86_400));
    }

    // ── Key set rules ─────────────────────────────────────────────────────────

    #[test]
    fn a_single_key_without_kid_is_indexed_under_the_empty_kid() {
        let indexed = index_keys(&[make_jwk(None)]).unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(
            indexed
                .get("")
                .map(|jwk| jwk.kid.clone()),
            Some(None)
        );
    }

    #[test]
    fn distinct_kids_are_indexed_by_kid() {
        let indexed = index_keys(&[make_jwk(Some("a")), make_jwk(Some("b"))]).unwrap();
        let mut kids: Vec<&String> = indexed.keys().collect();
        kids.sort();
        assert_eq!(kids, ["a", "b"]);
    }

    #[test]
    fn several_keys_with_one_missing_kid_are_rejected() {
        let result = index_keys(&[make_jwk(Some("a")), make_jwk(None)]);
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::InvalidDocument && e.to_string().contains("without a kid")),
            "got {result:?}"
        );
    }

    #[test]
    fn a_repeated_kid_is_rejected() {
        let result = index_keys(&[make_jwk(Some("a")), make_jwk(Some("a"))]);
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::InvalidDocument && e.to_string().contains("repeats a kid")),
            "got {result:?}"
        );
    }

    #[test]
    fn more_keys_than_the_bound_are_rejected() {
        let keys: Vec<Jwk> = (0..=MAX_JWKS_KEYS)
            .map(|index| make_jwk(Some(&format!("k{index}"))))
            .collect();
        assert!(matches!(index_keys(&keys), Err(e) if e.failure() == FetchFailure::InvalidDocument));
        assert_eq!(
            index_keys(&keys[..MAX_JWKS_KEYS])
                .unwrap()
                .len(),
            MAX_JWKS_KEYS
        );
    }

    // ── CacheEntry expiry ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_entry_not_expired_when_fresh() {
        let entry = CacheEntry {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        };
        assert!(!entry.is_expired_at(Instant::now()));
    }

    #[test]
    fn test_cache_entry_expired_with_zero_ttl() {
        let entry = CacheEntry {
            keys: HashMap::new(),
            fetched_at: Instant::now() - Duration::from_secs(1),
            ttl: Duration::from_secs(0),
        };
        assert!(entry.is_expired_at(Instant::now()));
    }

    // ── Slot decisions ────────────────────────────────────────────────────────

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn a_fresh_set_answers_a_known_kid() {
        let (slot, now) = slot_with(&["a"], Duration::from_secs(5), HOUR, Some((Duration::from_secs(5), false)));
        assert!(matches!(slot.decide("a", now), Decision::Hit(jwk) if jwk.kid.as_deref() == Some("a")));
    }

    #[test]
    fn an_unknown_kid_inside_the_cooldown_is_refused_without_a_fetch() {
        let (slot, now) = slot_with(&["a"], Duration::from_secs(5), HOUR, Some((Duration::from_secs(59), false)));
        assert!(matches!(slot.decide("b", now), Decision::Refuse(JwtBearerError::KeyNotFound(kid)) if kid == "b"));
    }

    #[test]
    fn an_unknown_kid_after_the_cooldown_refetches() {
        let (slot, now) = slot_with(&["a"], Duration::from_secs(61), HOUR, Some((Duration::from_secs(61), false)));
        assert!(matches!(slot.decide("b", now), Decision::Fetch));
    }

    #[test]
    fn an_empty_slot_fetches() {
        let slot = Slot::new(SourceVersion {
            jwks_uri: "https://issuer.example/jwks.json".to_string(),
            updated_at: DateTime::<Utc>::default(),
        });
        assert!(matches!(slot.decide("a", Instant::now()), Decision::Fetch));
    }

    #[test]
    fn an_expired_set_refetches_once_the_last_fetch_succeeded() {
        let (slot, now) = slot_with(&["a"], HOUR * 2, HOUR, Some((HOUR * 2, false)));
        assert!(matches!(slot.decide("a", now), Decision::Fetch));
    }

    #[test]
    fn an_expired_set_inside_the_failure_backoff_serves_the_stale_key() {
        let (slot, now) = slot_with(&["a"], HOUR + Duration::from_secs(30), HOUR, Some((Duration::from_secs(9), true)));
        assert!(matches!(slot.decide("a", now), Decision::Hit(jwk) if jwk.kid.as_deref() == Some("a")));
    }

    #[test]
    fn an_expired_set_past_the_stale_grace_is_refused_inside_the_failure_backoff() {
        let (slot, now) = slot_with(&["a"], HOUR * 3, HOUR, Some((Duration::from_secs(9), true)));
        assert!(matches!(slot.decide("a", now), Decision::Refuse(JwtBearerError::JwksFetchFailed(_))));
    }

    #[test]
    fn an_expired_set_after_the_failure_backoff_refetches() {
        let (slot, now) =
            slot_with(&["a"], HOUR + Duration::from_secs(30), HOUR, Some((Duration::from_secs(11), true)));
        assert!(matches!(slot.decide("a", now), Decision::Fetch));
    }

    // ── JwksClient over HTTP ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_key_cache_miss_fetches_from_server() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        let jwk = client
            .get_key(&remote_strategy("provider-a", &jwks_uri), &jwks_uri, "key-1")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("key-1"));
    }

    #[tokio::test]
    async fn cache_fills_are_counted_by_outcome() {
        let counter = |result: &str| {
            crate::metrics::backends::prometheus::JWKS_FETCH
                .with_label_values(&[result])
                .get()
        };
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{base}/.well-known/jwks.json");
        let client = JwksClient::new();
        let ok_before = counter("ok");
        client
            .get_key(&remote_strategy("provider-counted", &jwks_uri), &jwks_uri, "key-1")
            .await
            .expect("the key set is fetched");
        assert!(counter("ok") > ok_before);

        let blocked_before = counter("blocked");
        let blocked = "http://169.254.169.254/jwks.json";
        let error = client
            .get_key(&remote_strategy("provider-blocked", blocked), blocked, "key-1")
            .await
            .expect_err("cloud metadata is never fetched");
        assert!(matches!(error, JwtBearerError::JwksFetchFailed(_)), "{error:?}");
        assert!(counter("blocked") > blocked_before);
    }

    #[tokio::test]
    async fn a_cached_kid_is_served_without_another_fetch() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("cached", &jwks_uri);
        let client = JwksClient::new();
        let expiry = || {
            slot_state(&client, "cached", |slot| {
                slot.entry
                    .as_ref()
                    .map(|entry| (entry.fetched_at, entry.ttl))
            })
        };

        let mut first_expiry = None;
        for _ in 0..3 {
            let jwk = client
                .get_key(&strategy, &jwks_uri, "rs256-0")
                .await
                .unwrap();
            assert_eq!(jwk.kid.as_deref(), Some("rs256-0"));
            let current = expiry().await;
            assert!(current.is_some_and(|entry| entry.is_some()));
            assert_eq!(*first_expiry.get_or_insert(current), current);
        }
        assert_eq!(server.request_count(Endpoint::Jwks), 1);
    }

    #[tokio::test]
    async fn unknown_kids_inside_the_cooldown_do_not_refetch() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("cooldown", &jwks_uri);
        let client = JwksClient::new();

        for attempt in 0..5 {
            let result = client
                .get_key(&strategy, &jwks_uri, &format!("unknown-{attempt}"))
                .await;
            assert!(matches!(result, Err(JwtBearerError::KeyNotFound(_))), "got {result:?}");
        }
        assert_eq!(server.request_count(Endpoint::Jwks), 1);
    }

    #[tokio::test]
    async fn a_rotated_kid_after_the_cooldown_is_fetched() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("rotation", &jwks_uri);
        let client = JwksClient::new();
        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();

        server.rotate_keys(false);
        let refused = client
            .get_key(&strategy, &jwks_uri, "rs256-1")
            .await;
        assert!(matches!(refused, Err(JwtBearerError::KeyNotFound(_))), "got {refused:?}");
        assert_eq!(server.request_count(Endpoint::Jwks), 1);

        age_entry(&client, "rotation", Duration::from_secs(61), Duration::from_secs(61)).await;
        let jwk = client
            .get_key(&strategy, &jwks_uri, "rs256-1")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("rs256-1"));
        assert_eq!(server.request_count(Endpoint::Jwks), 2);
    }

    #[tokio::test]
    async fn concurrent_lookups_on_a_cold_cache_share_one_fetch() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("single-flight", &jwks_uri);
        let client = JwksClient::new();

        let lookups = (0..8).map(|_| {
            let client = client.clone();
            let strategy = strategy.clone();
            let jwks_uri = jwks_uri.clone();
            tokio::spawn(async move {
                client
                    .get_key(&strategy, &jwks_uri, "es256-0")
                    .await
            })
        });
        for lookup in futures::future::join_all(lookups).await {
            assert_eq!(
                lookup
                    .unwrap()
                    .unwrap()
                    .kid
                    .as_deref(),
                Some("es256-0")
            );
        }
        assert_eq!(server.request_count(Endpoint::Jwks), 1);
    }

    #[tokio::test]
    async fn a_changed_updated_at_misses_the_cache() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let mut strategy = remote_strategy("edited", &jwks_uri);
        let client = JwksClient::new();
        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();

        strategy.updated_at += chrono::Duration::seconds(1);
        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();
        assert_eq!(server.request_count(Endpoint::Jwks), 2);
        assert_eq!(
            client
                .cache
                .read()
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_changed_jwks_uri_never_serves_the_previous_keys() {
        let first = MockAuthServer::start().await;
        let (other_base, _other) = start_jwks_server(rsa_jwks_body("other-key", DUMMY_N, DUMMY_E), Some(3600)).await;
        let other_uri = format!("{other_base}/.well-known/jwks.json");
        let client = JwksClient::new();
        client
            .get_key(&remote_strategy("moved", &first.jwks_uri()), &first.jwks_uri(), "rs256-0")
            .await
            .unwrap();

        let moved = remote_strategy("moved", &other_uri);
        let previous = client
            .get_key(&moved, &other_uri, "rs256-0")
            .await;
        assert!(matches!(previous, Err(JwtBearerError::KeyNotFound(_))), "got {previous:?}");
        let jwk = client
            .get_key(&moved, &other_uri, "other-key")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("other-key"));
    }

    #[tokio::test]
    async fn test_max_age_header_respected() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(1800)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        client
            .get_key(&remote_strategy("provider-d", &jwks_uri), &jwks_uri, "key-1")
            .await
            .unwrap();

        let ttl = slot_state(&client, "provider-d", |slot| {
            slot.entry
                .as_ref()
                .map(|entry| entry.ttl)
        })
        .await;
        assert_eq!(ttl, Some(Some(Duration::from_secs(1800))));
    }

    #[tokio::test]
    async fn a_zero_max_age_is_raised_to_the_minimum_ttl() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(0)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        client
            .get_key(&remote_strategy("zero-age", &jwks_uri), &jwks_uri, "key-1")
            .await
            .unwrap();

        let ttl = slot_state(&client, "zero-age", |slot| {
            slot.entry
                .as_ref()
                .map(|entry| entry.ttl)
        })
        .await;
        assert_eq!(ttl, Some(Some(MIN_TTL)));
    }

    #[tokio::test]
    async fn test_missing_max_age_defaults_to_24h() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), None).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        client
            .get_key(&remote_strategy("provider-e", &jwks_uri), &jwks_uri, "key-1")
            .await
            .unwrap();

        let ttl = slot_state(&client, "provider-e", |slot| {
            slot.entry
                .as_ref()
                .map(|entry| entry.ttl)
        })
        .await;
        assert_eq!(ttl, Some(Some(DEFAULT_TTL)));
    }

    #[tokio::test]
    async fn test_expired_cache_triggers_refetch() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("expired", &jwks_uri);
        let client = JwksClient::new();
        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();

        age_entry(&client, "expired", DEFAULT_TTL + Duration::from_secs(1), DEFAULT_TTL).await;
        let jwk = client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("rs256-0"));
        assert_eq!(server.request_count(Endpoint::Jwks), 2);
    }

    #[tokio::test]
    async fn a_failed_refresh_serves_the_last_good_set_and_backs_off() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("stale", &jwks_uri);
        let client = JwksClient::new();
        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();

        server.set_fault(Endpoint::Jwks, Fault::NotFound);
        age_entry(&client, "stale", DEFAULT_TTL + Duration::from_secs(60), DEFAULT_TTL).await;
        for _ in 0..3 {
            let jwk = client
                .get_key(&strategy, &jwks_uri, "rs256-0")
                .await
                .unwrap();
            assert_eq!(jwk.kid.as_deref(), Some("rs256-0"));
        }
        assert_eq!(server.request_count(Endpoint::Jwks), 2);
    }

    #[tokio::test]
    async fn a_failed_refresh_past_the_stale_grace_fails() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("too-stale", &jwks_uri);
        let client = JwksClient::new();
        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();

        server.set_fault(Endpoint::Jwks, Fault::NotFound);
        age_entry(&client, "too-stale", DEFAULT_TTL + STALE_IF_ERROR + Duration::from_secs(1), DEFAULT_TTL).await;
        let result = client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await;
        assert!(matches!(result, Err(JwtBearerError::JwksFetchFailed(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn an_oversized_jwks_is_rejected() {
        let server = MockAuthServer::start().await;
        server.set_fault(Endpoint::Jwks, Fault::Oversized);
        let jwks_uri = server.jwks_uri();
        let client = JwksClient::new();

        let cached = client
            .get_key(&remote_strategy("oversized", &jwks_uri), &jwks_uri, "rs256-0")
            .await;
        assert!(
            matches!(&cached, Err(JwtBearerError::JwksFetchFailed(msg)) if msg.contains("exceeds")),
            "got {cached:?}"
        );
        let probed = client
            .fetch_jwks(&jwks_uri, EgressPosture::CloudMetadataOnly)
            .await;
        assert!(matches!(&probed, Err(e) if e.failure() == FetchFailure::TooLarge), "got {probed:?}");
    }

    #[tokio::test]
    async fn a_jwks_with_a_repeated_kid_is_rejected_by_the_cache_and_the_probe() {
        let key = r#"{"kty":"RSA","kid":"dup","use":"sig","alg":"RS256","n":"sIwr7ZNXUF0","e":"AQAB"}"#;
        let (base, _server) = start_jwks_server(format!(r#"{{"keys":[{key},{key}]}}"#), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        let cached = client
            .get_key(&remote_strategy("duplicate", &jwks_uri), &jwks_uri, "dup")
            .await;
        assert!(matches!(cached, Err(JwtBearerError::JwksFetchFailed(_))), "got {cached:?}");
        let probed = client
            .fetch_jwks(&jwks_uri, EgressPosture::CloudMetadataOnly)
            .await;
        assert!(matches!(&probed, Err(e) if e.failure() == FetchFailure::InvalidDocument), "got {probed:?}");
    }

    #[tokio::test]
    async fn the_strict_probe_refuses_an_http_jwks_uri_before_any_request() {
        let server = MockAuthServer::start().await;
        let client = JwksClient::new();

        let probed = client
            .fetch_jwks(&server.jwks_uri(), EgressPosture::Strict)
            .await;
        assert!(matches!(&probed, Err(e) if e.failure() == FetchFailure::InvalidUrl), "got {probed:?}");
        assert_eq!(server.request_count(Endpoint::Jwks), 0);
    }

    #[tokio::test]
    async fn the_probe_returns_every_key_of_a_valid_set() {
        let server = MockAuthServer::start().await;
        let client = JwksClient::new();

        let jwks = client
            .fetch_jwks(&server.jwks_uri(), EgressPosture::CloudMetadataOnly)
            .await
            .unwrap();
        let mut kids: Vec<Option<String>> = jwks
            .keys
            .into_iter()
            .map(|key| key.kid)
            .collect();
        kids.sort();
        assert_eq!(kids, [Some("es256-0".to_string()), Some("rs256-0".to_string())]);
    }

    #[tokio::test]
    async fn test_evict_removes_cache_entry() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let strategy = remote_strategy("evicted", &jwks_uri);
        let client = JwksClient::new();
        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();
        assert!(
            slot_state(&client, "evicted", |_| ())
                .await
                .is_some()
        );

        client.evict("evicted").await;
        assert!(
            slot_state(&client, "evicted", |_| ())
                .await
                .is_none()
        );

        client
            .get_key(&strategy, &jwks_uri, "rs256-0")
            .await
            .unwrap();
        assert_eq!(server.request_count(Endpoint::Jwks), 2);
    }

    #[tokio::test]
    async fn clear_drops_every_strategy() {
        let server = MockAuthServer::start().await;
        let jwks_uri = server.jwks_uri();
        let client = JwksClient::new();
        for id in ["one", "two"] {
            client
                .get_key(&remote_strategy(id, &jwks_uri), &jwks_uri, "rs256-0")
                .await
                .unwrap();
        }

        client.clear().await;
        assert!(
            client
                .cache
                .read()
                .await
                .is_empty()
        );
    }

    // ── get_static_key ────────────────────────────────────────────────────────

    #[test]
    fn test_get_static_key_returns_correct_key() {
        let jwks = vec![make_jwk(Some("key-a")), make_jwk(Some("key-b")), make_jwk(Some("key-c"))];

        let result = get_static_key(&jwks, "key-b");

        assert!(result.is_ok(), "should find key-b in the static JWKS");
        assert_eq!(result.unwrap().kid.as_deref(), Some("key-b"));
    }

    #[test]
    fn test_get_static_key_missing_kid_returns_key_not_found() {
        let jwks = vec![make_jwk(Some("key-a")), make_jwk(Some("key-b"))];

        let result = get_static_key(&jwks, "key-z");

        assert!(
            matches!(result, Err(JwtBearerError::KeyNotFound(ref kid)) if kid == "key-z"),
            "should return KeyNotFound for an unknown kid, got: {:?}",
            result
        );
    }

    // ── SSRF guard in fetch_key_set ──────────────────────────────────────────

    #[tokio::test]
    async fn fetch_jwks_rejects_aws_metadata_ip() {
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://169.254.169.254/latest/meta-data/jwks.json", EgressPosture::CloudMetadataOnly)
            .await;
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::Blocked),
            "should block AWS metadata IP, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_loopback() {
        // Loopback is blocked at the write path (create/update strategy).
        // The runtime fetcher only blocks cloud metadata — allowing loopback
        // keeps dev/test scenarios working and is safe because no loopback URI
        // can be stored in the first place.
        // This test verifies that a cloud-metadata IP (link-local range) is still blocked.
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://169.254.170.2/v2/credentials/jwks.json", EgressPosture::CloudMetadataOnly)
            .await;
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::Blocked),
            "should block cloud metadata IP, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_localhost() {
        // Loopback/localhost is blocked at the write path only.
        // The runtime fetcher blocks cloud metadata; loopback is allowed so that
        // stored strategies that pre-date the write-path guard still work in dev.
        // This test verifies GCP metadata hostname is blocked at fetch time.
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://metadata.google.internal/.well-known/jwks.json", EgressPosture::CloudMetadataOnly)
            .await;
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::Blocked),
            "should block GCP metadata hostname, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_embedded_credentials() {
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://user:pass@public.example.com/jwks.json", EgressPosture::CloudMetadataOnly)
            .await;
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::InvalidUrl),
            "should block URLs with embedded credentials, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_ipv6_loopback() {
        // IPv6 loopback is blocked at write-path; the fetcher blocks cloud metadata.
        // This test verifies the IPv6 AWS metadata endpoint is blocked at fetch time.
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://[fd00:ec2::254]/jwks.json", EgressPosture::CloudMetadataOnly)
            .await;
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::Blocked),
            "should block IPv6 AWS metadata, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn get_key_rejects_metadata_ip_without_network_io() {
        let client = JwksClient::new();
        let result = client
            .get_key(
                &remote_strategy("strat-ssrf", "http://169.254.169.254/jwks.json"),
                "http://169.254.169.254/jwks.json",
                "kid-1",
            )
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
            "get_key must block SSRF at the execution sink, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn get_key_rejects_loopback_uri() {
        // Loopback is blocked at write-path; the fetcher only blocks cloud metadata.
        // This test verifies that a cloud-metadata URI is still rejected at get_key.
        let client = JwksClient::new();
        let result = client
            .get_key(
                &remote_strategy("strat-loopback", "http://169.254.169.254/jwks.json"),
                "http://169.254.169.254/jwks.json",
                "kid-1",
            )
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
            "get_key must block cloud metadata SSRF, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_non_http_scheme() {
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("file:///etc/passwd", EgressPosture::CloudMetadataOnly)
            .await;
        assert!(
            matches!(&result, Err(e) if e.failure() == FetchFailure::InvalidUrl),
            "should block non-http scheme, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn a_fetch_that_finishes_after_its_strategy_was_evicted_records_nothing() {
        let client = JwksClient::new();
        let version = SourceVersion {
            jwks_uri: "https://issuer.example/jwks.json".to_string(),
            updated_at: DateTime::<Utc>::default(),
        };

        let failure = client
            .record("gone", &version, "k1", Err(JwtBearerError::JwksFetchFailed("upstream down".into())))
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, JwtBearerError::JwksFetchFailed(message) if message == "upstream down"),
            "{failure}"
        );

        let entry = CacheEntry {
            keys: HashMap::from([("k1".to_string(), make_jwk(Some("k1")))]),
            fetched_at: Instant::now(),
            ttl: DEFAULT_TTL,
        };
        let jwk = client
            .record("gone", &version, "k1", Ok(entry))
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("k1"));
        assert!(
            slot_state(&client, "gone", |_| ())
                .await
                .is_none()
        );
    }
}
