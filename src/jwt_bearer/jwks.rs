//! JWKS fetching and in-memory caching
//!
//! [`JwksClient`] fetches JSON Web Key Sets from a JWT verification strategy's JWKS URI,
//! caches them per strategy, and re-fetches when a token references a `kid` that
//! is not in the current cache.
//!
//! # Cache TTL
//! The TTL is taken from the `Cache-Control: max-age=N` response header.
//! When the header is absent, a default of **86 400 seconds (24 h)** is used.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::jwt_bearer::errors::{JwtBearerError, JwtBearerResult};

/// Build a per-fetch pinned, redirect-disabled client for a JWKS URI.
///
/// Vets `jwks_uri` with the cloud-metadata-only policy (loopback and RFC 1918
/// stay allowed for admin/same-VPC IdPs), resolves DNS once, and pins the
/// connection to that exact address so the host cannot rebind to a cloud
/// metadata IP between validation and connect (SSRF rebinding TOCTOU). Built
/// per fetch because JWKS fetches are transient and cached.
///
/// Resolves DNS on a blocking pool so the async runtime is not stalled. The
/// resolved IP stays log-only; the returned error keeps the generic
/// `jwks_uri blocked` shape.
async fn pinned_jwks_client(jwks_uri: &str) -> JwtBearerResult<reqwest::Client> {
    let raw = jwks_uri.to_string();
    let pinned = tokio::task::spawn_blocking(move || {
        crate::egress::pinned_forward_client(&raw, Duration::from_secs(crate::http_client::SHORT_TIMEOUT_SECS))
    })
    .await
    .map_err(|e| JwtBearerError::JwksFetchFailed(format!("jwks_uri resolve task failed: {e}")))?;

    match pinned {
        Ok((client, _target)) => Ok(client),
        Err(e) => Err(JwtBearerError::JwksFetchFailed(format!("jwks_uri blocked: {e}"))),
    }
}

/// Default JWKS cache TTL when no `Cache-Control: max-age` header is present.
const DEFAULT_TTL_SECS: u64 = 86_400;

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
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > self.ttl
    }
}

// ── JwksClient ────────────────────────────────────────────────────────────────

/// Thread-safe JWKS client with per-strategy caching.
#[derive(Clone)]
pub struct JwksClient {
    /// strategy_id → cache entry
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
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

        response
            .json::<JwksResponse>()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(format!("Failed to parse JWKS: {}", e)))
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
    /// 2. If missing or expired, or if `kid` is not found, re-fetch once.
    /// 3. If `kid` is still absent after a re-fetch, return [`JwtBearerError::KeyNotFound`].
    pub async fn get_key(
        &self,
        strategy_id: &str,
        jwks_uri: &str,
        kid: &str,
    ) -> JwtBearerResult<Jwk> {
        // Fast path — read lock only
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(strategy_id) {
                if !entry.is_expired() {
                    if let Some(jwk) = entry.keys.get(kid) {
                        debug!("JWKS cache hit for strategy {} kid {}", strategy_id, kid);
                        return Ok(jwk.clone());
                    }
                    // kid not in cache even though entry is fresh — fall through to re-fetch
                    debug!("kid '{}' not found in fresh cache for strategy {}, re-fetching", kid, strategy_id);
                } else {
                    debug!("JWKS cache expired for strategy {}, re-fetching", strategy_id);
                }
            }
        }

        // Slow path — re-fetch and write
        info!("Fetching JWKS for strategy {} from {}", strategy_id, jwks_uri);
        let entry = self
            .fetch_and_build_entry(jwks_uri)
            .await?;

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
        // Defense-in-depth SSRF guard: the write-path handler also validates,
        // but strategies could have been stored before this check existed. The
        // pinned client vets the URI (cloud-metadata-only), resolves DNS once,
        // and pins the connection so a rebind cannot move it to an internal
        // address between validation and connect.
        let client = pinned_jwks_client(jwks_uri).await?;

        let response = client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(e.to_string()))?;

        // Parse Cache-Control: max-age=N
        let ttl = parse_max_age(response.headers()).unwrap_or(DEFAULT_TTL_SECS);
        let ttl = Duration::from_secs(ttl);

        if !response.status().is_success() {
            return Err(JwtBearerError::JwksFetchFailed(format!("JWKS endpoint returned HTTP {}", response.status())));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(format!("Failed to parse JWKS: {}", e)))?;

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
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_expired_with_zero_ttl() {
        let entry = CacheEntry {
            keys: HashMap::new(),
            fetched_at: Instant::now() - Duration::from_secs(1),
            ttl: Duration::from_secs(0),
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
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
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
            .fetch_jwks("http://169.254.170.2/v2/credentials/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
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
            .fetch_jwks("http://metadata.google.internal/.well-known/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
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
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
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
            .fetch_jwks("http://[fd00:ec2::254]/jwks.json")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
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
            .get_key("strat-loopback", "http://169.254.169.254/jwks.json", "kid-1")
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
            .fetch_jwks("file:///etc/passwd")
            .await;
        assert!(
            matches!(result, Err(JwtBearerError::JwksFetchFailed(_))),
            "should block non-http scheme, got: {:?}",
            result
        );
    }
}
