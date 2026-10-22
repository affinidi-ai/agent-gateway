use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::warn;

use super::config::{EventHookSettings, HookSecret};
use super::transport;

pub const DIRECTORY_ID_PREFIX: &str = "directory:";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const STARTUP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const FRESH_TTL: Duration = Duration::from_secs(300);
const RETRY_TTL: Duration = Duration::from_secs(30);
const RESPONSE_LIMIT: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 50;
const MAX_DID_BYTES: usize = 1024;
const MAX_NAME_CHARS: usize = 200;
const WAIT_GRACE: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const WARMUP_WINDOW: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const WARMUP_RETRY_EVERY: Duration = Duration::from_secs(2);

/// A mediator offered by the directory next to the ones stored on the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub did: String,
    pub name: String,
}

impl DirectoryEntry {
    pub fn id(&self) -> String {
        directory_mediator_id(&self.did)
    }
}

pub fn directory_mediator_id(did: &str) -> String {
    let digest = hex::encode(Sha256::digest(did.as_bytes()));
    format!("{DIRECTORY_ID_PREFIX}{}", &digest[..16])
}

pub fn is_directory_mediator_id(id: &str) -> bool {
    id.starts_with(DIRECTORY_ID_PREFIX)
}

#[derive(Deserialize)]
struct DirectoryResponse {
    items: Vec<serde_json::Value>,
}

struct CachedEntries {
    entries: Vec<DirectoryEntry>,
    fetched_at: Instant,
    ttl: Duration,
}

/// Cached client for the operator-configured mediator directory.
///
/// A failing or slow directory never fails the caller: it keeps serving the
/// last list it answered, retrying every 30 s, or an empty list if it has never
/// answered. A successful answer, even an empty one, replaces the list.
///
/// At startup the directory may need time to answer its first request, or
/// answer that it is unavailable. A background task asks again every 2 s for up
/// to 30 s, allowing each request up to 10 s. No request waits for it: until it
/// has an answer, callers get an empty list.
pub struct MediatorDirectory {
    url: String,
    timeout: Duration,
    startup_timeout: Duration,
    secret: Option<HookSecret>,
    cache: Mutex<Option<CachedEntries>>,
    refresh: Mutex<()>,
    warming_up: AtomicBool,
    loaded: AtomicBool,
}

/// What the gateway knows about whether the directory lists a mediator: it has
/// a successful answer that does, a successful answer that does not, or no
/// successful answer yet (never fetched, or every fetch failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    Listed,
    NotListed,
    Unknown,
}

impl MediatorDirectory {
    pub fn new(settings: &EventHookSettings) -> Option<Arc<Self>> {
        let url = settings
            .directory_url
            .clone()?;
        let directory = Arc::new(Self::with_timeout(url, settings.hook_secret.clone(), REQUEST_TIMEOUT));
        #[cfg(not(test))]
        directory.start_warmup(WARMUP_RETRY_EVERY, WARMUP_WINDOW);
        Some(directory)
    }

    fn with_timeout(
        url: String,
        secret: Option<HookSecret>,
        timeout: Duration,
    ) -> Self {
        Self {
            url,
            timeout,
            startup_timeout: timeout.max(STARTUP_REQUEST_TIMEOUT),
            secret,
            cache: Mutex::new(None),
            refresh: Mutex::new(()),
            warming_up: AtomicBool::new(false),
            loaded: AtomicBool::new(false),
        }
    }

    fn start_warmup(
        self: &Arc<Self>,
        retry_every: Duration,
        window: Duration,
    ) {
        self.warming_up
            .store(true, Ordering::SeqCst);
        let directory = Arc::clone(self);
        tokio::spawn(async move {
            let started = Instant::now();
            loop {
                let answered = {
                    let _refresh = directory.refresh.lock().await;
                    directory
                        .fetch_into_cache()
                        .await
                };
                if answered || started.elapsed() + retry_every > window {
                    break;
                }
                tokio::time::sleep(retry_every).await;
            }
            directory
                .warming_up
                .store(false, Ordering::SeqCst);
        });
    }

    async fn fetch_into_cache(&self) -> bool {
        match tokio::time::timeout(self.startup_timeout, self.fetch(self.startup_timeout)).await {
            Ok(Ok(entries)) => {
                self.apply_success(entries)
                    .await;
                true
            }
            Ok(Err(reason)) => {
                warn!("Mediator directory unavailable: {reason}");
                false
            }
            Err(_) => {
                warn!("Mediator directory did not answer within {:?}", self.startup_timeout);
                false
            }
        }
    }

    /// Stores a successful answer. The cache is written before `loaded` is set,
    /// so a reader that sees `loaded` also sees the answer.
    async fn apply_success(
        &self,
        entries: Vec<DirectoryEntry>,
    ) {
        let ttl = if entries.is_empty() {
            RETRY_TTL
        } else {
            FRESH_TTL
        };
        self.store(entries, ttl).await;
        self.loaded
            .store(true, Ordering::SeqCst);
    }

    async fn store(
        &self,
        entries: Vec<DirectoryEntry>,
        ttl: Duration,
    ) {
        *self.cache.lock().await = Some(CachedEntries {
            entries,
            fetched_at: Instant::now(),
            ttl,
        });
    }

    /// One fetch runs at a time and never under the cache lock. While it runs,
    /// other callers get the previous list, or wait for the fetch when there is
    /// none yet, and then use its result. During the startup warm-up nobody
    /// waits: callers get the list the warm-up has so far.
    pub async fn entries(&self) -> Vec<DirectoryEntry> {
        let stale = {
            let cache = self.cache.lock().await;
            match cache.as_ref() {
                Some(cached) if cached.fetched_at.elapsed() < cached.ttl => return cached.entries.clone(),
                Some(cached) => Some(cached.entries.clone()),
                None => None,
            }
        };
        if self
            .warming_up
            .load(Ordering::SeqCst)
        {
            return stale.unwrap_or_default();
        }
        let _refresh = match self.refresh.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(entries) = stale {
                    return entries;
                }
                match tokio::time::timeout(self.timeout + WAIT_GRACE, self.refresh.lock()).await {
                    Ok(guard) => guard,
                    Err(_) => return self.cached_or_empty().await,
                }
            }
        };
        if let Some(cached) = self
            .cache
            .lock()
            .await
            .as_ref()
            && cached.fetched_at.elapsed() < cached.ttl
        {
            return cached.entries.clone();
        }
        match tokio::time::timeout(self.timeout, self.fetch(self.timeout)).await {
            Ok(Ok(entries)) => {
                self.apply_success(entries.clone())
                    .await;
                entries
            }
            Ok(Err(reason)) => {
                warn!("Mediator directory unavailable: {reason}");
                self.keep(stale).await
            }
            Err(_) => {
                warn!("Mediator directory did not answer within {:?}", self.timeout);
                self.keep(stale).await
            }
        }
    }

    async fn keep(
        &self,
        stale: Option<Vec<DirectoryEntry>>,
    ) -> Vec<DirectoryEntry> {
        let entries = stale.unwrap_or_default();
        self.store(entries.clone(), RETRY_TTL)
            .await;
        entries
    }

    /// Whether the directory has ever answered successfully.
    pub fn has_loaded(&self) -> bool {
        self.loaded
            .load(Ordering::SeqCst)
    }

    /// Whether the last successful answer, however old, lists this DID. A
    /// directory that has not answered successfully yet is `Unknown`, whatever a
    /// failed fetch left in the cache. It never fetches, so it never waits.
    pub async fn listing(
        &self,
        did: &str,
    ) -> Listing {
        if !self
            .loaded
            .load(Ordering::SeqCst)
        {
            return Listing::Unknown;
        }
        let listed = self
            .cache
            .lock()
            .await
            .as_ref()
            .is_some_and(|cached| {
                cached
                    .entries
                    .iter()
                    .any(|entry| entry.did == did)
            });
        if listed {
            Listing::Listed
        } else {
            Listing::NotListed
        }
    }

    async fn cached_or_empty(&self) -> Vec<DirectoryEntry> {
        self.cache
            .lock()
            .await
            .as_ref()
            .map(|cached| cached.entries.clone())
            .unwrap_or_default()
    }

    pub async fn find(
        &self,
        id: &str,
    ) -> Option<DirectoryEntry> {
        self.entries()
            .await
            .into_iter()
            .find(|entry| entry.id() == id)
    }

    async fn fetch(
        &self,
        timeout: Duration,
    ) -> Result<Vec<DirectoryEntry>, String> {
        let (status, body) = transport::get_limited(&self.url, timeout, self.secret.as_ref(), RESPONSE_LIMIT).await?;
        if !status.is_success() {
            return Err(format!("directory answered {status}"));
        }
        let response: DirectoryResponse =
            serde_json::from_slice(&body).map_err(|e| format!("invalid directory response: {e}"))?;
        Ok(sanitize_entries(response.items))
    }

    #[cfg(test)]
    async fn expire_cache(&self) {
        if let Some(cached) = self
            .cache
            .lock()
            .await
            .as_mut()
        {
            cached.ttl = Duration::ZERO;
        }
    }
}

fn sanitize_entries(items: Vec<serde_json::Value>) -> Vec<DirectoryEntry> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter_map(|item| serde_json::from_value::<DirectoryEntry>(item).ok())
        .filter_map(sanitize_entry)
        .filter(|entry| seen.insert(entry.did.clone()))
        .take(MAX_ENTRIES)
        .collect()
}

fn sanitize_entry(entry: DirectoryEntry) -> Option<DirectoryEntry> {
    let did = entry.did.trim().to_string();
    let well_formed = did.starts_with("did:")
        && did.len() <= MAX_DID_BYTES
        && did.split(':').count() >= 3
        && !did
            .chars()
            .any(|c| c.is_whitespace() || c.is_control());
    if !well_formed {
        return None;
    }
    let name = clip(&entry.name, MAX_NAME_CHARS)?;
    Some(DirectoryEntry { did, name })
}

fn clip(
    raw: &str,
    max_chars: usize,
) -> Option<String> {
    let spaced: String = raw
        .chars()
        .map(|c| {
            if c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    let cleaned: String = spaced
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max_chars)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_hook::tests_support::serve;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn directory(url: String) -> MediatorDirectory {
        MediatorDirectory::with_timeout(url, None, Duration::from_secs(3))
    }

    async fn serve_with(handler: axum::routing::MethodRouter) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, axum::Router::new().route("/dir", handler))
                .await
                .unwrap();
        });
        format!("http://{addr}/dir")
    }

    #[test]
    fn ids_are_stable_and_prefixed() {
        let id = directory_mediator_id("did:web:mediator.example");
        assert!(is_directory_mediator_id(&id));
        assert_eq!(id.len(), DIRECTORY_ID_PREFIX.len() + 16);
        assert_eq!(id, directory_mediator_id("did:web:mediator.example"));
        assert_ne!(id, directory_mediator_id("did:web:other.example"));
        assert!(!is_directory_mediator_id("3f6c1f1e-1111-2222-3333-444444444444"));
    }

    #[test]
    fn sanitizes_and_deduplicates_entries() {
        let entries = sanitize_entries(vec![
            json!({"did": " did:web:a.example ", "name": "A", "badge": "ignored", "extra": 1}),
            json!({"did": "did:web:a.example", "name": "duplicate"}),
            json!({"did": "not-a-did", "name": "bad"}),
            json!({"did": "did:web:b.example", "name": "  "}),
            json!({"name": "missing did"}),
            json!({"did": "did:web:c.example", "name": "C".repeat(500)}),
        ]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].did, "did:web:a.example");
        assert_eq!(entries[0].name, "A");
        assert_eq!(entries[1].did, "did:web:c.example");
        assert_eq!(
            entries[1]
                .name
                .chars()
                .count(),
            MAX_NAME_CHARS
        );
    }

    #[test]
    fn no_directory_url_means_no_directory() {
        assert!(MediatorDirectory::new(&EventHookSettings::default()).is_none());
    }

    #[tokio::test]
    async fn fetches_with_a_signed_empty_get_and_caches_entries() {
        let (url, captured) = serve(
            200,
            r#"{"items":[{"did":"did:web:m.example","name":"Shared","description":"ignored","badge":"ignored"}]}"#,
        )
        .await;
        let secret = uuid::Uuid::new_v4()
            .simple()
            .to_string();
        let directory = MediatorDirectory::with_timeout(url, HookSecret::new(&secret), Duration::from_secs(3));
        let first = directory.entries().await;
        let second = directory.entries().await;
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].name, "Shared");
        let calls = captured
            .lock()
            .unwrap()
            .clone();
        assert_eq!(calls.len(), 1, "second call served from cache");
        assert_eq!(calls[0].method, "GET");
        assert!(calls[0].body.is_empty());
        let timestamp = calls[0].headers["x-webhook-timestamp"]
            .to_str()
            .unwrap();
        let expected = crate::integrations::webhook_signing::sign_timestamped_payload(&secret, timestamp, b"").unwrap();
        assert_eq!(calls[0].headers["x-webhook-signature-256"], format!("sha256={expected}").as_str());
        assert_eq!(
            directory
                .find(&directory_mediator_id("did:web:m.example"))
                .await
                .map(|entry| entry.did),
            Some("did:web:m.example".to_string())
        );
        assert_eq!(
            directory
                .find("directory:0000000000000000")
                .await,
            None
        );
    }

    #[tokio::test]
    async fn without_a_secret_the_request_is_unsigned() {
        let (url, captured) = serve(200, r#"{"items":[]}"#).await;
        directory(url).entries().await;
        let calls = captured
            .lock()
            .unwrap()
            .clone();
        assert!(
            calls[0]
                .headers
                .get("x-webhook-signature-256")
                .is_none()
        );
    }

    #[tokio::test]
    async fn failures_yield_an_empty_list() {
        for (status, body) in [(503u16, ""), (401, ""), (302, ""), (200, "not json"), (200, r#"{"items":"x"}"#)] {
            let (url, _) = serve(status, body).await;
            assert!(
                directory(url)
                    .entries()
                    .await
                    .is_empty(),
                "{status} {body}"
            );
        }
    }

    #[tokio::test]
    async fn an_oversized_answer_is_treated_as_unavailable() {
        let big = Box::leak(
            format!(r#"{{"items":[{{"did":"did:web:m.example","name":"{}"}}]}}"#, "x".repeat(RESPONSE_LIMIT))
                .into_boxed_str(),
        );
        let (url, _) = serve(200, big).await;
        assert!(
            directory(url)
                .entries()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn slow_directory_is_cut_off_by_the_timeout() {
        let url = serve_with(axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            "{}"
        }))
        .await;
        let directory = MediatorDirectory::with_timeout(url, None, Duration::from_millis(300));
        let started = Instant::now();
        assert!(
            directory
                .entries()
                .await
                .is_empty()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_fetch() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let url = serve_with(axum::routing::get(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(200)).await;
                r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#
            }
        }))
        .await;
        let directory = Arc::new(directory(url));
        let callers: Vec<_> = (0..5)
            .map(|_| {
                let directory = directory.clone();
                tokio::spawn(async move { directory.entries().await })
            })
            .collect();
        for caller in callers {
            assert_eq!(caller.await.unwrap().len(), 1);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_serving_the_last_answer() {
        let healthy = Arc::new(AtomicBool::new(true));
        let state = healthy.clone();
        let url = serve_with(axum::routing::get(move || {
            let state = state.clone();
            async move {
                if state.load(Ordering::SeqCst) {
                    (
                        axum::http::StatusCode::OK,
                        r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#.to_string(),
                    )
                } else {
                    (axum::http::StatusCode::SERVICE_UNAVAILABLE, String::new())
                }
            }
        }))
        .await;
        let directory = directory(url);
        assert_eq!(
            directory
                .entries()
                .await
                .len(),
            1
        );

        healthy.store(false, Ordering::SeqCst);
        directory.expire_cache().await;
        assert_eq!(
            directory
                .entries()
                .await
                .len(),
            1,
            "an outage keeps the last answered list"
        );
        assert!(
            directory
                .find(&directory_mediator_id("did:web:m.example"))
                .await
                .is_some(),
            "an id shown before the outage still resolves"
        );
    }

    #[tokio::test]
    async fn a_successful_empty_answer_replaces_the_list() {
        let healthy = Arc::new(AtomicBool::new(true));
        let state = healthy.clone();
        let url = serve_with(axum::routing::get(move || {
            let state = state.clone();
            async move {
                if state.load(Ordering::SeqCst) {
                    r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#
                } else {
                    r#"{"items":[]}"#
                }
            }
        }))
        .await;
        let directory = directory(url);
        assert_eq!(
            directory
                .entries()
                .await
                .len(),
            1
        );
        healthy.store(false, Ordering::SeqCst);
        directory.expire_cache().await;
        assert!(
            directory
                .entries()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn warm_up_retries_a_not_ready_directory_without_blocking_callers() {
        let ready = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let (state, counter) = (ready.clone(), hits.clone());
        let url = serve_with(axum::routing::get(move || {
            let (state, counter) = (state.clone(), counter.clone());
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                if state.load(Ordering::SeqCst) {
                    (
                        axum::http::StatusCode::OK,
                        r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#.to_string(),
                    )
                } else {
                    (axum::http::StatusCode::SERVICE_UNAVAILABLE, r#"{"reason":"warming_up"}"#.to_string())
                }
            }
        }))
        .await;
        let directory = Arc::new(directory(url));
        directory.start_warmup(Duration::from_millis(50), Duration::from_secs(10));

        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = Instant::now();
        assert!(
            directory
                .entries()
                .await
                .is_empty(),
            "not ready yet: stored mediators only"
        );
        assert!(started.elapsed() < Duration::from_millis(100), "a request never waits for the warm-up");
        assert!(hits.load(Ordering::SeqCst) >= 2, "the warm-up keeps asking");

        ready.store(true, Ordering::SeqCst);
        let mut listed = Vec::new();
        for _ in 0..50 {
            listed = directory.entries().await;
            if !listed.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].did, "did:web:m.example");
    }

    #[tokio::test]
    async fn warm_up_gives_up_after_its_window_and_requests_then_fetch_themselves() {
        let ready = Arc::new(AtomicBool::new(false));
        let state = ready.clone();
        let url = serve_with(axum::routing::get(move || {
            let state = state.clone();
            async move {
                if state.load(Ordering::SeqCst) {
                    (
                        axum::http::StatusCode::OK,
                        r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#.to_string(),
                    )
                } else {
                    (axum::http::StatusCode::SERVICE_UNAVAILABLE, String::new())
                }
            }
        }))
        .await;
        let directory = Arc::new(directory(url));
        directory.start_warmup(Duration::from_millis(30), Duration::from_millis(150));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !directory
                .warming_up
                .load(Ordering::SeqCst)
        );
        ready.store(true, Ordering::SeqCst);
        directory.expire_cache().await;
        assert_eq!(
            directory
                .entries()
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn the_startup_fetch_allows_a_slower_first_answer_than_a_request_does() {
        let url = serve_with(axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#
        }))
        .await;
        let mut slow = MediatorDirectory::with_timeout(url, None, Duration::from_millis(100));
        slow.startup_timeout = Duration::from_secs(5);
        let directory = Arc::new(slow);
        assert!(
            directory
                .entries()
                .await
                .is_empty(),
            "a request alone gives up after its own timeout"
        );
        directory.expire_cache().await;
        directory.start_warmup(Duration::from_millis(30), Duration::from_secs(5));
        let mut listed = Vec::new();
        for _ in 0..60 {
            listed = directory.entries().await;
            if !listed.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(listed.len(), 1, "the startup fetch waited for the slow answer");
    }

    #[tokio::test]
    async fn listing_is_unknown_until_a_fetch_succeeds_and_never_fetches() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let url = serve_with(axum::routing::get(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            }
        }))
        .await;
        let directory = directory(url);
        assert!(!directory.has_loaded());
        assert_eq!(
            directory
                .listing("did:web:m.example")
                .await,
            Listing::Unknown,
            "cold"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0, "listing() does not fetch");
        directory.entries().await;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            directory
                .listing("did:web:m.example")
                .await,
            Listing::Unknown,
            "a failed fetch is not an empty answer"
        );
        assert!(!directory.has_loaded());
    }

    #[tokio::test]
    async fn listing_never_reports_not_listed_while_the_first_fetch_completes() {
        let url = serve_with(axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#
        }))
        .await;
        let directory = Arc::new(directory(url));
        let fetching = {
            let directory = directory.clone();
            tokio::spawn(async move { directory.entries().await })
        };
        let mut seen_listed = false;
        for _ in 0..400 {
            match directory
                .listing("did:web:m.example")
                .await
            {
                Listing::NotListed => panic!("a listed DID was reported as not listed"),
                Listing::Listed => seen_listed = true,
                Listing::Unknown => {}
            }
            if fetching.is_finished() && seen_listed {
                break;
            }
            tokio::task::yield_now().await;
        }
        fetching.await.unwrap();
        assert!(seen_listed || directory.has_loaded());
    }

    #[tokio::test]
    async fn listing_follows_the_last_successful_answer_even_when_stale() {
        let state = Arc::new(AtomicUsize::new(0));
        let phase = state.clone();
        let url = serve_with(axum::routing::get(move || {
            let phase = phase.clone();
            async move {
                match phase.load(Ordering::SeqCst) {
                    0 => (
                        axum::http::StatusCode::OK,
                        r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#.to_string(),
                    ),
                    1 => (axum::http::StatusCode::SERVICE_UNAVAILABLE, String::new()),
                    _ => (axum::http::StatusCode::OK, r#"{"items":[]}"#.to_string()),
                }
            }
        }))
        .await;
        let directory = directory(url);
        directory.entries().await;
        assert_eq!(
            directory
                .listing("did:web:m.example")
                .await,
            Listing::Listed
        );
        assert_eq!(
            directory
                .listing("did:web:other.example")
                .await,
            Listing::NotListed
        );

        state.store(1, Ordering::SeqCst);
        directory.expire_cache().await;
        directory.entries().await;
        assert_eq!(
            directory
                .listing("did:web:m.example")
                .await,
            Listing::Listed,
            "a failed refresh keeps the last successful list, stale or not"
        );

        state.store(2, Ordering::SeqCst);
        directory.expire_cache().await;
        directory.entries().await;
        assert_eq!(
            directory
                .listing("did:web:m.example")
                .await,
            Listing::NotListed,
            "a successful empty answer lists nothing"
        );
    }

    #[tokio::test]
    async fn staggered_callers_on_a_cold_slow_directory_all_get_the_list() {
        let url = serve_with(axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_millis(450)).await;
            r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#
        }))
        .await;
        let directory = Arc::new(MediatorDirectory::with_timeout(url, None, Duration::from_millis(600)));
        let mut callers = Vec::new();
        for i in 0..6u64 {
            let directory = directory.clone();
            callers.push(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(i * 60)).await;
                directory
                    .find(&directory_mediator_id("did:web:m.example"))
                    .await
            }));
        }
        for caller in callers {
            assert!(
                caller
                    .await
                    .unwrap()
                    .is_some(),
                "a waiting caller still finds the entry"
            );
        }
    }

    #[test]
    fn control_characters_in_a_name_become_spaces() {
        assert_eq!(clip("Shared\nmediator\tone", 100).as_deref(), Some("Shared mediator one"));
        assert_eq!(clip("  \n\t ", 100), None);
        let entries = sanitize_entries(vec![json!({"did": "did:web:a.example", "name": "A\r\nB"})]);
        assert_eq!(entries[0].name, "A B");
    }
}
