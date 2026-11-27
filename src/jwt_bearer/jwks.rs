//! JWKS fetching and in-memory caching
//!
//! [`JwksClient`] fetches JSON Web Key Sets from a JWT verification strategy's JWKS URI,
//! caches them per strategy, and re-fetches when a token references a `kid` that
//! is not in the current cache.
//!
//! # Cache TTL
//! The TTL is taken from the `Cache-Control: max-age=N` response header, and is never shorter
//! than [`REFETCH_COOLDOWN`]. When the header is absent, a default of **86 400 seconds (24 h)**
//! is used.
//!
//! A `kid` missing from fresh keys causes at most one re-fetch per [`REFETCH_COOLDOWN`] for
//! each cache entry, and a failed fetch is not tried again within it, so neither tokens naming
//! made-up `kid` values nor a key server that fails can make every request fetch from it. When
//! the fetch replacing expired keys fails, those keys are still used for one cooldown.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::jwt_bearer::errors::{JwtBearerError, JwtBearerResult};
use crate::observability::loggable;

/// The largest JWKS response the gateway reads.
const MAX_JWKS_BYTES: usize = 256 * 1024;

/// The exact URLs a JWKS fetch may reach although the Configured policy refuses them:
/// the BDD egress allow-list under `AG_TEST_MODE`, plus, in unit tests, the
/// loopback servers [`super::test_utils::start_jwks_server`] started. `None` in
/// production.
fn jwks_egress_allowlist() -> Option<String> {
    let allowlist = crate::egress::bdd_egress_allowlist();
    #[cfg(test)]
    {
        let fixtures = super::test_utils::jwks_fixture_origins();
        if !fixtures.is_empty() {
            return Some(
                allowlist
                    .into_iter()
                    .chain(fixtures)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }
    allowlist
}

/// Vet `jwks_uri` with the Configured egress policy when a strategy is saved
/// ([`crate::egress::configured_refuses`]): it must be an http(s) URL resolving
/// to neither cloud metadata, loopback nor an unspecified address; private
/// networks are allowed. A refusal is [`JwtBearerError::JwksUriBlocked`]. A host
/// that does not resolve, or not in time, passes, since every fetch vets it again.
pub(crate) async fn vet_jwks_uri(jwks_uri: &str) -> JwtBearerResult<()> {
    if crate::egress::configured_refuses(jwks_uri, jwks_egress_allowlist().as_deref()).await {
        return Err(JwtBearerError::JwksUriBlocked);
    }
    Ok(())
}

/// Build a per-fetch client for a JWKS URI, vetted with the Configured policy
/// ([`crate::egress::vet_configured`]), pinned to the addresses the host resolved to so it
/// cannot rebind between validation and connect, with redirects refused and
/// proxies ignored, since a proxy would resolve the host again. Built per
/// fetch because JWKS fetches are transient and cached.
async fn pinned_jwks_client(jwks_uri: &str) -> JwtBearerResult<reqwest::Client> {
    let raw = jwks_uri.to_string();
    let allowlist = jwks_egress_allowlist();
    let pinned = tokio::task::spawn_blocking(move || {
        crate::egress::pinned_configured_direct_client(
            &raw,
            Duration::from_secs(crate::http_client::SHORT_TIMEOUT_SECS),
            allowlist.as_deref(),
        )
    })
    .await
    .map_err(|e| JwtBearerError::JwksFetchFailed(format!("jwks_uri resolve task failed: {e}")))?;
    pinned
        .map(|(client, _target)| client)
        .map_err(egress_refusal)
}

fn egress_refusal(error: crate::egress::EgressError) -> JwtBearerError {
    warn!(error = %error, "JWKS URI refused by egress policy or not resolvable");
    match error {
        crate::egress::EgressError::Blocked(_) | crate::egress::EgressError::Parse(_) => JwtBearerError::JwksUriBlocked,
        other => JwtBearerError::JwksFetchFailed(other.to_string()),
    }
}

/// Read a JWKS answer of at most [`MAX_JWKS_BYTES`] and parse it.
async fn read_jwks(response: reqwest::Response) -> JwtBearerResult<JwksResponse> {
    let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
        MAX_JWKS_BYTES,
        None,
        crate::http_client::SHORT_TIMEOUT_SECS,
    );
    let body = crate::proxy::upstream_body::read_bounded(response, limits)
        .await
        .map_err(|e| JwtBearerError::JwksFetchFailed(e.to_string()))?;
    serde_json::from_slice(&body).map_err(|e| JwtBearerError::JwksFetchFailed(format!("Failed to parse JWKS: {}", e)))
}

/// Default JWKS cache TTL when no `Cache-Control: max-age` header is present.
const DEFAULT_TTL_SECS: u64 = 86_400;

/// The shortest time between two fetches for one cache entry: keys are cached at least this
/// long, a failed fetch is answered again without a fetch until it has passed (expired keys it
/// failed to replace are still used meanwhile, once per entry), and a `kid` that fresh keys lack
/// re-fetches at most once within it, so a rotated key is picked up within this long of its first
/// use.
pub const REFETCH_COOLDOWN: Duration = Duration::from_secs(60);

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

// ── Cache entry ───────────────────────────────────────────────────────────────

struct CacheEntry {
    /// Map of `kid` → `Jwk`.  Keys without a `kid` are stored under `""`.
    keys: HashMap<String, Jwk>,
    fetched_at: Instant,
    ttl: Duration,
    /// When this entry was fetched because fresh keys lacked a `kid`.
    unknown_kid_refetch_at: Option<Instant>,
    /// Until when these keys are still used once expired, because the fetch to replace them
    /// failed. Set once, so expired keys are used for at most one [`REFETCH_COOLDOWN`].
    stale_until: Option<Instant>,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > self.ttl
    }

    fn is_usable(&self) -> bool {
        !self.is_expired()
            || self
                .stale_until
                .is_some_and(|until| Instant::now() < until)
    }

    fn refetched_for_unknown_kid_recently(&self) -> bool {
        self.unknown_kid_refetch_at
            .is_some_and(|at| at.elapsed() < REFETCH_COOLDOWN)
    }
}

/// A fetch that failed, answered again without a fetch until [`REFETCH_COOLDOWN`] has passed.
struct FailedFetch {
    at: Instant,
    error: JwtBearerError,
}

// ── JwksClient ────────────────────────────────────────────────────────────────

/// Thread-safe JWKS client with per-strategy caching.
#[derive(Clone)]
pub struct JwksClient {
    /// strategy_id → cache entry
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// strategy_id → its last fetch, when that failed
    failed_fetches: Arc<RwLock<HashMap<String, FailedFetch>>>,
}

impl Default for JwksClient {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksClient {
    /// Create a new client.
    ///
    /// No shared HTTP client is stored: JWKS network GETs build a per-fetch
    /// pinned client ([`pinned_jwks_client`]) so DNS is resolved and pinned
    /// once per fetch.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            failed_fetches: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetch JWKS from `jwks_uri` without caching.
    ///
    /// Used by the `validate_jwks_uri` admin endpoint to probe whether a URI is
    /// reachable and returns a parseable JWKS.
    ///
    /// Returns the parsed [`JwksResponse`] on success, or a [`JwtBearerError::JwksFetchFailed`]
    /// on any HTTP or parse error.
    pub async fn fetch_jwks(
        &self,
        jwks_uri: &str,
    ) -> JwtBearerResult<JwksResponse> {
        let client = pinned_jwks_client(jwks_uri).await?;

        let response = client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(JwtBearerError::JwksFetchFailed(format!("JWKS endpoint returned HTTP {}", response.status())));
        }

        read_jwks(response).await
    }

    /// Evict the cached JWKS for `strategy_id`.
    /// Should be called when a strategy is updated or deleted.
    /// FIXME: should be used in production code
    #[allow(dead_code)]
    pub async fn evict(
        &self,
        strategy_id: &str,
    ) {
        let mut cache = self.cache.write().await;
        if cache
            .remove(strategy_id)
            .is_some()
        {
            debug!("Evicted JWKS cache for strategy {}", strategy_id);
        }
    }

    /// Retrieve the JWK for the given `kid` from `strategy_id`'s JWKS.
    ///
    /// 1. If the cache is present and fresh, look up `kid` there.
    /// 2. If missing or expired, or if `kid` is not found, re-fetch once. A `kid` that fresh
    ///    keys lack re-fetches only when the entry was not itself re-fetched for an unknown
    ///    `kid` within [`REFETCH_COOLDOWN`]. A fetch that failed within it is not tried again:
    ///    its error is returned at once.
    /// 3. If `kid` is still absent after a re-fetch, return [`JwtBearerError::KeyNotFound`];
    ///    when the cooldown prevents the re-fetch, return
    ///    [`JwtBearerError::KeyNotFoundDuringCooldown`].
    pub async fn get_key(
        &self,
        strategy_id: &str,
        jwks_uri: &str,
        kid: &str,
    ) -> JwtBearerResult<Jwk> {
        // Fast path — read lock only
        let mut unknown_kid = false;
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(strategy_id) {
                if entry.is_usable() {
                    if let Some(jwk) = entry.keys.get(kid) {
                        debug!("JWKS cache hit for strategy {} kid {}", strategy_id, kid);
                        return Ok(jwk.clone());
                    }
                    if entry.refetched_for_unknown_kid_recently() {
                        debug!(
                            "kid {} not found for strategy {}; re-fetched recently, not again",
                            loggable::untrusted(kid),
                            strategy_id
                        );
                        return Err(JwtBearerError::KeyNotFoundDuringCooldown(kid.to_string()));
                    }
                    unknown_kid = true;
                } else {
                    debug!("JWKS cache expired for strategy {}, re-fetching", strategy_id);
                }
            }
        }

        if let Some(failed) = self
            .failed_fetches
            .read()
            .await
            .get(strategy_id)
            .filter(|failed| failed.at.elapsed() < REFETCH_COOLDOWN)
        {
            debug!("JWKS fetch for strategy {} failed recently, not tried again yet", strategy_id);
            return Err(failed.error.clone());
        }

        // Claim the unknown-kid re-fetch under the write lock before fetching, so concurrent
        // requests make one fetch between them and a failed fetch still starts the cooldown.
        let mut unknown_kid_refetch_at = None;
        if unknown_kid {
            let mut cache = self.cache.write().await;
            if let Some(entry) = cache
                .get_mut(strategy_id)
                .filter(|entry| !entry.is_expired())
            {
                if let Some(jwk) = entry.keys.get(kid) {
                    return Ok(jwk.clone());
                }
                if entry.refetched_for_unknown_kid_recently() {
                    return Err(JwtBearerError::KeyNotFoundDuringCooldown(kid.to_string()));
                }
                debug!(
                    "kid {} not found in fresh cache for strategy {}, re-fetching",
                    loggable::untrusted(kid),
                    strategy_id
                );
                let now = Instant::now();
                entry.unknown_kid_refetch_at = Some(now);
                unknown_kid_refetch_at = Some(now);
            }
        }

        // Slow path — re-fetch and write
        info!("Fetching JWKS for strategy {} from {}", strategy_id, jwks_uri);
        let mut entry = match self
            .fetch_and_build_entry(jwks_uri)
            .await
        {
            Ok(entry) => entry,
            Err(error) => {
                let now = Instant::now();
                self.failed_fetches
                    .write()
                    .await
                    .insert(strategy_id.to_string(), FailedFetch { at: now, error: error.clone() });
                let mut cache = self.cache.write().await;
                if let Some(entry) = cache
                    .get_mut(strategy_id)
                    .filter(|entry| entry.is_expired())
                {
                    let stale_until = *entry
                        .stale_until
                        .get_or_insert_with(|| {
                            warn!(
                                "JWKS fetch for strategy {} failed; its expired keys are used for {:?} more",
                                strategy_id, REFETCH_COOLDOWN
                            );
                            now + REFETCH_COOLDOWN
                        });
                    if now < stale_until
                        && let Some(jwk) = entry.keys.get(kid)
                    {
                        return Ok(jwk.clone());
                    }
                }
                return Err(error);
            }
        };
        self.failed_fetches
            .write()
            .await
            .remove(strategy_id);
        entry.unknown_kid_refetch_at = unknown_kid_refetch_at;

        let jwk = entry.keys.get(kid).cloned();

        {
            let mut cache = self.cache.write().await;
            cache.insert(strategy_id.to_string(), entry);
        }

        jwk.ok_or_else(|| JwtBearerError::KeyNotFound(kid.to_string()))
    }

    // ── private ───────────────────────────────────────────────────────────────

    async fn fetch_and_build_entry(
        &self,
        jwks_uri: &str,
    ) -> JwtBearerResult<CacheEntry> {
        // Vetted on every fetch: a stored strategy may predate the save check, and DNS answers change.
        let client = pinned_jwks_client(jwks_uri).await?;

        let response = client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(e.to_string()))?;

        // Parse Cache-Control: max-age=N
        let ttl = parse_max_age(response.headers()).unwrap_or(DEFAULT_TTL_SECS);
        let ttl = Duration::from_secs(ttl).max(REFETCH_COOLDOWN);

        if !response.status().is_success() {
            return Err(JwtBearerError::JwksFetchFailed(format!("JWKS endpoint returned HTTP {}", response.status())));
        }

        let jwks = read_jwks(response).await?;

        let mut keys: HashMap<String, Jwk> = HashMap::new();
        for key in jwks.keys {
            let id = key
                .kid
                .clone()
                .unwrap_or_default();
            keys.insert(id, key);
        }

        debug!("Fetched {} key(s) from JWKS, TTL={:?}", keys.len(), ttl);

        Ok(CacheEntry {
            keys,
            fetched_at: Instant::now(),
            ttl,
            unknown_kid_refetch_at: None,
            stale_until: None,
        })
    }
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
    use reqwest::header::{CACHE_CONTROL, HeaderMap, HeaderValue};

    // ── parse_max_age ─────────────────────────────────────────────────────────

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

    // ── CacheEntry expiry ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_entry_not_expired_when_fresh() {
        let entry = CacheEntry {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(3600),
            unknown_kid_refetch_at: None,
            stale_until: None,
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_expired_with_zero_ttl() {
        let entry = CacheEntry {
            keys: HashMap::new(),
            fetched_at: Instant::now() - Duration::from_secs(1),
            ttl: Duration::from_secs(0),
            unknown_kid_refetch_at: None,
            stale_until: None,
        };
        assert!(entry.is_expired());
    }

    // ── JwksClient with mock HTTP ─────────────────────────────────────────────
    // These tests use axum to spin up an in-process HTTP server.

    use crate::jwt_bearer::test_utils::{rsa_jwks_body, start_jwks_server};

    // Dummy RSA n/e — only used to exercise caching logic, not signature verification.
    const DUMMY_N: &str = "sIwr7ZNXUF0";
    const DUMMY_E: &str = "AQAB";

    #[tokio::test]
    async fn test_get_key_cache_miss_fetches_from_server() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        let jwk = client
            .get_key("provider-a", &jwks_uri, "key-1")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("key-1"));
    }

    #[tokio::test]
    async fn test_get_key_cache_hit_does_not_change_ttl() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        client
            .get_key("provider-b", &jwks_uri, "key-1")
            .await
            .unwrap();
        let ttl_after_first = {
            let cache = client.cache.read().await;
            cache
                .get("provider-b")
                .map(|e| e.ttl)
        };

        client
            .get_key("provider-b", &jwks_uri, "key-1")
            .await
            .unwrap();
        let ttl_after_second = {
            let cache = client.cache.read().await;
            cache
                .get("provider-b")
                .map(|e| e.ttl)
        };

        assert_eq!(ttl_after_first, ttl_after_second);
    }

    #[tokio::test]
    async fn test_get_key_unknown_kid_returns_error() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        let result = client
            .get_key("provider-c", &jwks_uri, "missing-kid")
            .await;
        assert!(matches!(result, Err(JwtBearerError::KeyNotFound(_))));
    }

    /// A JWKS server whose answer can change, counting its fetches. Returns the JWKS URI, the
    /// body it serves, the fetch count and the server guard.
    async fn counting_jwks_server(
        body: &str
    ) -> (
        String,
        Arc<std::sync::Mutex<String>>,
        Arc<std::sync::atomic::AtomicUsize>,
        crate::jwt_bearer::test_utils::TestServer,
    ) {
        let served = Arc::new(std::sync::Mutex::new(body.to_string()));
        let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (answer, counter) = (served.clone(), fetches.clone());
        let app = axum::Router::new().route(
            "/.well-known/jwks.json",
            axum::routing::get(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = answer.lock().unwrap().clone();
                async move { ([(axum::http::header::CONTENT_TYPE, "application/json")], body) }
            }),
        );
        let (base, server) = crate::jwt_bearer::test_utils::TestServer::serve(app).await;
        (format!("{base}/.well-known/jwks.json"), served, fetches, server)
    }

    fn fetched(fetches: &std::sync::atomic::AtomicUsize) -> usize {
        fetches.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn made_up_kids_refetch_at_most_once_per_cooldown_and_a_rotated_key_is_found() {
        let (jwks_uri, served, fetches, _server) =
            counting_jwks_server(&rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)).await;
        let client = JwksClient::new();
        client
            .get_key("provider-k", &jwks_uri, "key-1")
            .await
            .unwrap();

        *served.lock().unwrap() = rsa_jwks_body("key-2", DUMMY_N, DUMMY_E);
        let rotated = client
            .get_key("provider-k", &jwks_uri, "key-2")
            .await
            .unwrap();
        assert_eq!(rotated.kid.as_deref(), Some("key-2"));
        assert_eq!(fetched(&fetches), 2, "the first new kid re-fetches");

        for made_up in ["made-up-1", "made-up-2", "made-up-3"] {
            let result = client
                .get_key("provider-k", &jwks_uri, made_up)
                .await;
            assert!(matches!(result, Err(JwtBearerError::KeyNotFoundDuringCooldown(_))), "{made_up}: {result:?}");
        }
        assert_eq!(fetched(&fetches), 2, "no re-fetch within the cooldown");
        assert!(
            client
                .get_key("provider-k", &jwks_uri, "key-2")
                .await
                .is_ok(),
            "a cached key is still found during the cooldown"
        );

        client
            .cache
            .write()
            .await
            .get_mut("provider-k")
            .unwrap()
            .unknown_kid_refetch_at = Some(Instant::now() - REFETCH_COOLDOWN);
        let after = client
            .get_key("provider-k", &jwks_uri, "made-up-4")
            .await;
        assert!(matches!(after, Err(JwtBearerError::KeyNotFound(_))), "{after:?}");
        assert_eq!(fetched(&fetches), 3, "after the cooldown one more re-fetch");
    }

    #[tokio::test]
    async fn the_cooldown_counts_from_the_last_unknown_kid_refetch_not_the_first_fetch() {
        let (jwks_uri, served, fetches, _server) =
            counting_jwks_server(&rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)).await;
        let client = JwksClient::new();
        client
            .get_key("provider-r", &jwks_uri, "key-1")
            .await
            .unwrap();
        *served.lock().unwrap() = rsa_jwks_body("key-2", DUMMY_N, DUMMY_E);

        let rotated = client
            .get_key("provider-r", &jwks_uri, "key-2")
            .await;

        assert!(rotated.is_ok(), "a key rotated right after the first fetch is found at once: {rotated:?}");
        assert_eq!(fetched(&fetches), 2);
    }

    #[tokio::test]
    async fn concurrent_made_up_kids_make_one_refetch_between_them() {
        let (jwks_uri, _served, fetches, _server) =
            counting_jwks_server(&rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)).await;
        let client = JwksClient::new();
        client
            .get_key("provider-c2", &jwks_uri, "key-1")
            .await
            .unwrap();

        let lookups = (0..20).map(|index| {
            let client = client.clone();
            let jwks_uri = jwks_uri.clone();
            tokio::spawn(async move {
                client
                    .get_key("provider-c2", &jwks_uri, &format!("made-up-{index}"))
                    .await
            })
        });
        for lookup in futures::future::join_all(lookups).await {
            assert!(matches!(
                lookup.unwrap(),
                Err(JwtBearerError::KeyNotFound(_) | JwtBearerError::KeyNotFoundDuringCooldown(_))
            ));
        }
        assert_eq!(fetched(&fetches), 2);
    }

    #[tokio::test]
    async fn a_failed_unknown_kid_refetch_still_starts_the_cooldown() {
        let (jwks_uri, served, fetches, _server) =
            counting_jwks_server(&rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)).await;
        let client = JwksClient::new();
        client
            .get_key("provider-x", &jwks_uri, "key-1")
            .await
            .unwrap();

        *served.lock().unwrap() = "not a key set".to_string();
        let failed = client
            .get_key("provider-x", &jwks_uri, "made-up-1")
            .await;
        assert!(matches!(failed, Err(JwtBearerError::JwksFetchFailed(_))), "{failed:?}");
        let cooled = client
            .get_key("provider-x", &jwks_uri, "made-up-2")
            .await;
        assert!(matches!(cooled, Err(JwtBearerError::KeyNotFoundDuringCooldown(_))), "{cooled:?}");
        assert_eq!(fetched(&fetches), 2);
        assert!(
            client
                .get_key("provider-x", &jwks_uri, "key-1")
                .await
                .is_ok(),
            "the keys fetched before stay usable"
        );
    }

    #[tokio::test]
    async fn a_failed_fetch_is_answered_again_without_a_fetch_until_the_cooldown_ends() {
        let (jwks_uri, served, fetches, _server) = counting_jwks_server("not a key set").await;
        let client = JwksClient::new();

        for attempt in 0..3 {
            let failed = client
                .get_key("provider-down", &jwks_uri, "key-1")
                .await;
            assert!(matches!(failed, Err(JwtBearerError::JwksFetchFailed(_))), "{attempt}: {failed:?}");
        }
        assert_eq!(fetched(&fetches), 1, "the failure is answered again without a fetch");

        *served.lock().unwrap() = rsa_jwks_body("key-1", DUMMY_N, DUMMY_E);
        assert!(
            client
                .get_key("provider-other", &jwks_uri, "key-1")
                .await
                .is_ok(),
            "another cache entry fetches for itself"
        );
        client
            .failed_fetches
            .write()
            .await
            .get_mut("provider-down")
            .unwrap()
            .at = Instant::now() - REFETCH_COOLDOWN;
        let recovered = client
            .get_key("provider-down", &jwks_uri, "key-1")
            .await;
        assert!(recovered.is_ok(), "after the cooldown one more fetch: {recovered:?}");
        assert_eq!(fetched(&fetches), 3);
        assert!(
            !client
                .failed_fetches
                .read()
                .await
                .contains_key("provider-down"),
            "a fetch that succeeds clears the failure"
        );
    }

    #[tokio::test]
    async fn expired_keys_whose_refetch_failed_are_used_for_one_cooldown_without_another_fetch() {
        let (jwks_uri, served, fetches, _server) =
            counting_jwks_server(&rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)).await;
        let client = JwksClient::new();
        client
            .get_key("provider-ex", &jwks_uri, "key-1")
            .await
            .unwrap();
        let expire = |entry: &mut CacheEntry| entry.fetched_at = Instant::now() - Duration::from_secs(90_000);
        expire(
            client
                .cache
                .write()
                .await
                .get_mut("provider-ex")
                .unwrap(),
        );
        *served.lock().unwrap() = "not a key set".to_string();

        for attempt in 0..3 {
            let stale = client
                .get_key("provider-ex", &jwks_uri, "key-1")
                .await;
            assert_eq!(stale.unwrap().kid.as_deref(), Some("key-1"), "{attempt}");
        }
        let unknown = client
            .get_key("provider-ex", &jwks_uri, "key-2")
            .await;
        assert!(matches!(unknown, Err(JwtBearerError::JwksFetchFailed(_))), "{unknown:?}");
        assert_eq!(fetched(&fetches), 2, "one failed fetch, then the cooldown");

        let long_ago = Instant::now() - REFETCH_COOLDOWN;
        client
            .failed_fetches
            .write()
            .await
            .get_mut("provider-ex")
            .unwrap()
            .at = long_ago;
        client
            .cache
            .write()
            .await
            .get_mut("provider-ex")
            .unwrap()
            .stale_until = Some(long_ago);
        let refused = client
            .get_key("provider-ex", &jwks_uri, "key-1")
            .await;
        assert!(matches!(refused, Err(JwtBearerError::JwksFetchFailed(_))), "expired keys are used once: {refused:?}");
        assert_eq!(fetched(&fetches), 3);

        *served.lock().unwrap() = rsa_jwks_body("key-2", DUMMY_N, DUMMY_E);
        client
            .failed_fetches
            .write()
            .await
            .get_mut("provider-ex")
            .unwrap()
            .at = long_ago;
        assert!(
            client
                .get_key("provider-ex", &jwks_uri, "key-2")
                .await
                .is_ok()
        );
        expire(
            client
                .cache
                .write()
                .await
                .get_mut("provider-ex")
                .unwrap(),
        );
        *served.lock().unwrap() = "not a key set".to_string();
        assert!(
            client
                .get_key("provider-ex", &jwks_uri, "key-2")
                .await
                .is_ok(),
            "keys fetched anew get their own cooldown of use once expired"
        );
    }

    #[tokio::test]
    async fn keys_served_with_a_shorter_max_age_are_kept_for_the_cooldown() {
        for (max_age, kept) in [(0, REFETCH_COOLDOWN), (59, REFETCH_COOLDOWN), (61, Duration::from_secs(61))] {
            let (base, server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(max_age)).await;
            let jwks_uri = format!("{base}/.well-known/jwks.json");
            let client = JwksClient::new();
            client
                .get_key("provider-t", &jwks_uri, "key-1")
                .await
                .unwrap();
            assert_eq!(
                client
                    .cache
                    .read()
                    .await
                    .get("provider-t")
                    .unwrap()
                    .ttl,
                kept,
                "max-age={max_age}"
            );

            drop(server);
            let cached = client
                .get_key("provider-t", &jwks_uri, "key-1")
                .await;
            assert!(cached.is_ok(), "max-age={max_age}: answered from the cache, not fetched again: {cached:?}");
        }
    }

    #[tokio::test]
    async fn a_made_up_kid_is_logged_as_one_escaped_value() {
        let (jwks_uri, _served, _fetches, _server) =
            counting_jwks_server(&rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)).await;
        let client = JwksClient::new();
        client
            .get_key("provider-l", &jwks_uri, "key-1")
            .await
            .unwrap();
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

        for _ in 0..2 {
            let _ = client
                .get_key("provider-l", &jwks_uri, "made-up\nERROR forged line")
                .await;
        }

        let text = logs.text();
        assert_eq!(
            text.matches(r#""made-up\nERROR forged line""#)
                .count(),
            2,
            "{text}"
        );
        assert!(!text.contains("made-up\nERROR"), "{text}");
    }

    #[tokio::test]
    async fn test_max_age_header_respected() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(1800)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        client
            .get_key("provider-d", &jwks_uri, "key-1")
            .await
            .unwrap();

        let cache = client.cache.read().await;
        let entry = cache
            .get("provider-d")
            .unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(1800));
    }

    #[tokio::test]
    async fn test_missing_max_age_defaults_to_24h() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), None).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        client
            .get_key("provider-e", &jwks_uri, "key-1")
            .await
            .unwrap();

        let cache = client.cache.read().await;
        let entry = cache
            .get("provider-e")
            .unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(DEFAULT_TTL_SECS));
    }

    #[tokio::test]
    async fn test_expired_cache_triggers_refetch() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        {
            let mut cache = client.cache.write().await;
            cache.insert(
                "provider-f".to_string(),
                CacheEntry {
                    keys: HashMap::new(),
                    fetched_at: Instant::now() - Duration::from_secs(90_000),
                    ttl: Duration::from_secs(3600),
                    unknown_kid_refetch_at: None,
                    stale_until: None,
                },
            );
        }

        let jwk = client
            .get_key("provider-f", &jwks_uri, "key-1")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("key-1"));
    }

    #[tokio::test]
    async fn test_evict_removes_cache_entry() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new();

        client
            .get_key("provider-g", &jwks_uri, "key-1")
            .await
            .unwrap();
        assert!(
            client
                .cache
                .read()
                .await
                .contains_key("provider-g")
        );

        client
            .evict("provider-g")
            .await;
        assert!(
            !client
                .cache
                .read()
                .await
                .contains_key("provider-g")
        );
    }

    // ── get_static_key ────────────────────────────────────────────────────────

    fn make_jwk(kid: &str) -> Jwk {
        Jwk {
            kty: "RSA".to_string(),
            key_use: Some("sig".to_string()),
            kid: Some(kid.to_string()),
            alg: Some("RS256".to_string()),
            n: Some("dummy-n".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        }
    }

    #[test]
    fn test_get_static_key_returns_correct_key() {
        let jwks = vec![make_jwk("key-a"), make_jwk("key-b"), make_jwk("key-c")];

        let result = get_static_key(&jwks, "key-b");

        assert!(result.is_ok(), "should find key-b in the static JWKS");
        assert_eq!(result.unwrap().kid.as_deref(), Some("key-b"));
    }

    #[test]
    fn test_get_static_key_missing_kid_returns_key_not_found() {
        let jwks = vec![make_jwk("key-a"), make_jwk("key-b")];

        let result = get_static_key(&jwks, "key-z");

        assert!(
            matches!(result, Err(JwtBearerError::KeyNotFound(ref kid)) if kid == "key-z"),
            "should return KeyNotFound for an unknown kid, got: {:?}",
            result
        );
    }

    // ── SSRF guard in fetch_and_build_entry / fetch_jwks ─────────────────────

    #[tokio::test]
    async fn fetch_jwks_rejects_aws_metadata_ip() {
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://169.254.169.254/latest/meta-data/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "should block AWS metadata IP, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_ecs_metadata() {
        // The ECS task metadata address is refused as cloud metadata.
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://169.254.170.2/v2/credentials/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "should block cloud metadata IP, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_gcp_metadata_host() {
        // The GCP metadata host name is refused before it is resolved.
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://metadata.google.internal/.well-known/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "should block GCP metadata hostname, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_embedded_credentials() {
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://user:pass@public.example.com/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "should block URLs with embedded credentials, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_ipv6_metadata() {
        // The IPv6 AWS metadata address is refused as cloud metadata.
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("http://[fd00:ec2::254]/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "should block IPv6 AWS metadata, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn get_key_rejects_metadata_ip_without_network_io() {
        let client = JwksClient::new();
        let result = client
            .get_key("strat-ssrf", "http://169.254.169.254/jwks.json", "kid-1")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "get_key must block SSRF at the execution sink, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn get_key_rejects_metadata_uri() {
        // A token check refuses a cloud metadata URI before any request.
        let client = JwksClient::new();
        let result = client
            .get_key("strat-loopback", "http://169.254.169.254/jwks.json", "kid-1")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "get_key must block cloud metadata SSRF, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_non_http_scheme() {
        let client = JwksClient::new();
        let result = client
            .fetch_jwks("file:///etc/passwd")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksUriBlocked)),
            "should block non-http scheme, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn a_loopback_or_metadata_jwks_uri_is_refused_without_a_request() {
        let client = JwksClient::new();
        for uri in [
            "https://127.0.0.1:1/jwks.json",
            "https://localhost:1/jwks.json",
            "https://[::1]:1/jwks.json",
            "https://0.0.0.0/jwks.json",
            "https://0x7f000001/jwks.json",
            "https://[::ffff:127.0.0.1]/jwks.json",
            "https://169.254.169.254/jwks.json",
            "https://[fd00:ec2::254]/jwks.json",
            "https://metadata.google.internal/jwks.json",
        ] {
            assert!(
                matches!(client.fetch_jwks(uri).await, Err(JwtBearerError::JwksUriBlocked)),
                "fetch must refuse {uri}"
            );
            assert!(
                matches!(
                    client
                        .get_key("strategy", uri, "kid")
                        .await,
                    Err(JwtBearerError::JwksUriBlocked)
                ),
                "a token check must refuse {uri}"
            );
            assert!(matches!(vet_jwks_uri(uri).await, Err(JwtBearerError::JwksUriBlocked)), "save must refuse {uri}");
        }
    }

    #[tokio::test]
    async fn a_private_network_jwks_uri_passes_the_vetting() {
        for uri in [
            "https://10.0.0.1/jwks.json",
            "https://172.16.0.1/jwks.json",
            "https://192.168.100.100:11443/jwks.json",
            "https://169.254.1.1/jwks.json",
        ] {
            assert!(
                vet_jwks_uri(uri)
                    .await
                    .is_ok(),
                "save must accept {uri}"
            );
        }
    }

    #[tokio::test]
    async fn a_stopped_jwks_fixture_is_no_longer_admitted() {
        let (base, server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), None).await;
        let uri = format!("{base}/.well-known/jwks.json");
        assert!(
            vet_jwks_uri(&uri)
                .await
                .is_ok(),
            "a running fixture is admitted"
        );
        drop(server);
        assert!(
            matches!(vet_jwks_uri(&uri).await, Err(JwtBearerError::JwksUriBlocked)),
            "a stopped fixture's loopback origin is refused like any other"
        );
    }

    #[tokio::test]
    async fn a_public_jwks_uri_passes_the_vetting() {
        assert!(
            vet_jwks_uri("https://1.2.3.4/.well-known/jwks.json")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_jwks_answer_over_the_size_cap_is_refused() {
        let keys = (0..MAX_JWKS_BYTES / 32)
            .map(|index| format!(r#"{{"kty":"RSA","kid":"key-{index}","n":"{DUMMY_N}","e":"{DUMMY_E}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let body = format!(r#"{{"keys":[{keys}]}}"#);
        assert!(body.len() > MAX_JWKS_BYTES);
        let (base, _server) = start_jwks_server(body, None).await;
        let result = JwksClient::new()
            .fetch_jwks(&format!("{base}/.well-known/jwks.json"))
            .await;
        assert!(matches!(result, Err(JwtBearerError::JwksFetchFailed(_))), "got: {result:?}");
    }
}
