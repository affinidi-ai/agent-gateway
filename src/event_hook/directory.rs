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
/// last list it answered, or an empty list if it has never answered, and no
/// caller ever waits for it. A successful answer, even an empty one, replaces
/// the list. An expired list, or the empty one of a directory that has not
/// answered yet, is returned at once while one background task refreshes it,
/// not more often than every 30 s after a failure.
///
/// At startup the directory may need time to answer its first request, or
/// answer that it is unavailable. A background task asks again every 2 s for up
/// to 30 s, allowing each request up to 10 s.
pub struct MediatorDirectory {
    url: String,
    timeout: Duration,
    startup_timeout: Duration,
    secret: Option<HookSecret>,
    cache: Mutex<Option<CachedEntries>>,
    refresh: Mutex<()>,
    warming_up: AtomicBool,
    loaded: AtomicBool,
    refreshing: AtomicBool,
}

/// Clears the single-flight flag when the refresh task ends, however it ends.
struct RefreshFlag(Arc<MediatorDirectory>);

impl Drop for RefreshFlag {
    fn drop(&mut self) {
        self.0
            .refreshing
            .store(false, Ordering::SeqCst);
    }
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
    pub async fn new(settings: &EventHookSettings) -> Option<Arc<Self>> {
        let url = settings
            .directory_url
            .clone()?;
        let directory = Arc::new(Self::with_timeout(url, settings.hook_secret.clone(), REQUEST_TIMEOUT));
        #[cfg(not(test))]
        directory.start_warmup(WARMUP_RETRY_EVERY, WARMUP_WINDOW);
        #[cfg(test)]
        directory.load_now().await;
        Some(directory)
    }

    fn with_timeout(
        url: String,
        secret: Option<HookSecret>,
        timeout: Duration,
    ) -> Self {
        Self::with_timeouts(url, secret, timeout, timeout.max(STARTUP_REQUEST_TIMEOUT))
    }

    fn with_timeouts(
        url: String,
        secret: Option<HookSecret>,
        timeout: Duration,
        startup_timeout: Duration,
    ) -> Self {
        Self {
            url,
            timeout,
            startup_timeout,
            secret,
            cache: Mutex::new(None),
            refresh: Mutex::new(()),
            warming_up: AtomicBool::new(false),
            loaded: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
        }
    }

    /// Refreshes an expired list, or the empty one of a directory that has not
    /// answered yet, in one background task, whatever the number of callers
    /// asking meanwhile. A failure keeps what is cached and sets the retry time.
    fn refresh_in_background(self: &Arc<Self>) {
        if self
            .refreshing
            .swap(true, Ordering::SeqCst)
        {
            return;
        }
        let directory = Arc::clone(self);
        tokio::spawn(async move {
            let _flag = RefreshFlag(directory.clone());
            let _refresh = directory.refresh.lock().await;
            if directory.is_fresh().await {
                return;
            }
            match tokio::time::timeout(directory.timeout, directory.fetch(directory.timeout)).await {
                Ok(Ok(entries)) => {
                    directory
                        .apply_success(entries)
                        .await
                }
                Ok(Err(reason)) => {
                    warn!("Mediator directory unavailable: {reason}");
                    directory.keep_current().await;
                }
                Err(_) => {
                    warn!("Mediator directory did not answer within {:?}", directory.timeout);
                    directory.keep_current().await;
                }
            }
        });
    }

    async fn is_fresh(&self) -> bool {
        self.cache
            .lock()
            .await
            .as_ref()
            .is_some_and(|cached| cached.fetched_at.elapsed() < cached.ttl)
    }

    async fn keep_current(&self) {
        let current = self.cached_or_empty().await;
        self.store(current, RETRY_TTL)
            .await;
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
            if !directory.has_loaded() {
                directory.keep_current().await;
            }
            directory
                .warming_up
                .store(false, Ordering::SeqCst);
        });
    }

    /// Loads the directory once, in place of the startup warm-up, so a test can
    /// start from an answered (or failed) first request.
    #[cfg(test)]
    pub(crate) async fn load_now(&self) {
        self.fetch_into_cache().await;
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

    /// The cached list, or an empty one when there is none yet. A caller never
    /// waits: when there is no list or it has expired, this starts the
    /// single-flight background refresh (not during the startup warm-up, which is
    /// already asking) and returns what it has at once.
    pub async fn entries(self: &Arc<Self>) -> Vec<DirectoryEntry> {
        let cached = {
            let cache = self.cache.lock().await;
            cache
                .as_ref()
                .map(|cached| (cached.entries.clone(), cached.fetched_at.elapsed() < cached.ttl))
        };
        let warming_up = self
            .warming_up
            .load(Ordering::SeqCst);
        match cached {
            Some((entries, true)) => entries,
            Some((entries, false)) => {
                if !warming_up {
                    self.refresh_in_background();
                }
                entries
            }
            None => {
                if !warming_up {
                    self.refresh_in_background();
                }
                Vec::new()
            }
        }
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

    /// The entry with this id. A directory that has not answered successfully
    /// yet has no entries, so this is `None` until the background refresh has
    /// stored an answer: a caller other than the create path must read `None` as
    /// "unknown", and the create path answers 503 (see [`Self::has_loaded`]).
    pub async fn find(
        self: &Arc<Self>,
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
            serde_json::from_slice(&body).map_err(|_| "the response was not a valid directory".to_string())?;
        Ok(sanitize_entries(response.items))
    }

    #[cfg(test)]
    async fn settle(&self) {
        for _ in 0..200 {
            if !self
                .refreshing
                .load(Ordering::SeqCst)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the background refresh did not finish");
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

/// `did:<method>:<method-specific part>` with a lowercase alphanumeric method and
/// a non-empty rest of ASCII letters, digits, `_`, `.`, `:`, `%` and `-`, at most
/// 1024 bytes: the rule the registering side applies, so an entry that would
/// fail there is never offered.
pub(crate) fn is_well_formed_did(did: &str) -> bool {
    let Some(rest) = did.strip_prefix("did:") else {
        return false;
    };
    let Some((method, specific)) = rest.split_once(':') else {
        return false;
    };
    did.len() <= MAX_DID_BYTES
        && !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !specific.is_empty()
        && specific
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'%' | b'-'))
}

fn sanitize_entry(entry: DirectoryEntry) -> Option<DirectoryEntry> {
    let did = entry.did.trim().to_string();
    let well_formed = is_well_formed_did(&did);
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

    fn directory(url: String) -> Arc<MediatorDirectory> {
        Arc::new(MediatorDirectory::with_timeout(url, None, Duration::from_secs(3)))
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
    fn only_well_formed_dids_are_offered() {
        for valid in [
            "did:web:mediator.example",
            "did:web:mediator.example:path:to",
            "did:web:127.0.0.1%3A7037",
            "did:webvh:QmSkCG4BH4whWhwJvcSj1r8FKyNrr89hhvUuyKQeytDZC7:localhost%3A7037",
            "did:peer:2.Vz6MktaxeC1qTnoCSJY5ouLBNStouhntbo4frM3q2qYrUZCvJ.Ez6LSkSmhYuqMSEs29f31Czk",
        ] {
            assert!(is_well_formed_did(valid), "{valid}");
        }
        let too_long = format!("did:web:{}", "a".repeat(MAX_DID_BYTES));
        for invalid in [
            "did:WEB:mediator.example",
            "did:web:has space",
            "did:web:quo\"te",
            "did:web:slash/path",
            "did:web:",
            "did:web",
            "did::x",
            "did:we-b:x",
            "not-a-did",
            too_long.as_str(),
        ] {
            assert!(!is_well_formed_did(invalid), "{invalid}");
        }
        let entries = sanitize_entries(vec![
            json!({"did": "did:WEB:upper.example", "name": "A"}),
            json!({"did": "did:web:ok.example", "name": "B"}),
            json!({"did": "did:web:bad/slash", "name": "C"}),
        ]);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.did.as_str())
                .collect::<Vec<_>>(),
            ["did:web:ok.example"]
        );
    }

    #[tokio::test]
    async fn no_directory_url_means_no_directory() {
        assert!(
            MediatorDirectory::new(&EventHookSettings::default())
                .await
                .is_none()
        );
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
        let directory =
            Arc::new(MediatorDirectory::with_timeout(url, HookSecret::new(&secret), Duration::from_secs(3)));
        directory.load_now().await;
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
        directory(url)
            .load_now()
            .await;
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
            let directory = directory(url);
            directory.load_now().await;
            assert!(
                directory
                    .entries()
                    .await
                    .is_empty(),
                "{status} {body}"
            );
            assert!(!directory.has_loaded(), "{status} {body}");
        }
    }

    #[tokio::test]
    async fn remote_content_never_reaches_the_reported_reason() {
        for body in [r#"{"items":"leaked-value"}"#, "leaked-value"] {
            let (url, _) = serve(
                200,
                Box::leak(
                    body.to_string()
                        .into_boxed_str(),
                ),
            )
            .await;
            let directory = directory(url);
            let reason = directory
                .fetch(Duration::from_secs(3))
                .await
                .expect_err("not a valid directory");
            assert_eq!(reason, "the response was not a valid directory");
        }
    }

    #[tokio::test]
    async fn an_oversized_answer_is_treated_as_unavailable() {
        let big = Box::leak(
            format!(r#"{{"items":[{{"did":"did:web:m.example","name":"{}"}}]}}"#, "x".repeat(RESPONSE_LIMIT))
                .into_boxed_str(),
        );
        let (url, _) = serve(200, big).await;
        let directory = directory(url);
        directory.load_now().await;
        assert!(
            directory
                .entries()
                .await
                .is_empty()
        );
        assert!(!directory.has_loaded());
    }

    #[tokio::test]
    async fn slow_directory_is_cut_off_by_the_timeout() {
        let url = serve_with(axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            "{}"
        }))
        .await;
        let directory = Arc::new(MediatorDirectory::with_timeouts(
            url,
            None,
            Duration::from_millis(300),
            Duration::from_millis(300),
        ));
        let started = Instant::now();
        directory.load_now().await;
        assert!(
            directory
                .entries()
                .await
                .is_empty()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn concurrent_callers_of_a_directory_that_has_not_loaded_get_the_empty_list_at_once_and_share_one_fetch() {
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
        let directory = directory(url);
        let started = Instant::now();
        let callers: Vec<_> = (0..5)
            .map(|_| {
                let directory = directory.clone();
                tokio::spawn(async move { directory.entries().await })
            })
            .collect();
        for caller in callers {
            assert!(
                caller
                    .await
                    .unwrap()
                    .is_empty(),
                "no caller waits for the first answer"
            );
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        directory.settle().await;
        assert_eq!(hits.load(Ordering::SeqCst), 1, "one fetch for all callers");
        assert_eq!(
            directory
                .entries()
                .await
                .len(),
            1,
            "the answer is used next"
        );
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
        directory.load_now().await;
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
        directory.load_now().await;
        assert_eq!(
            directory
                .entries()
                .await
                .len(),
            1
        );
        healthy.store(false, Ordering::SeqCst);
        directory.expire_cache().await;
        directory.entries().await;
        directory.settle().await;
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
        let directory = directory(url);
        directory.start_warmup(Duration::from_millis(50), Duration::from_secs(10));

        for _ in 0..200 {
            if hits.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(hits.load(Ordering::SeqCst) >= 2, "the warm-up keeps asking");
        let started = Instant::now();
        assert!(
            directory
                .entries()
                .await
                .is_empty(),
            "not ready yet: stored mediators only"
        );
        assert!(started.elapsed() < Duration::from_secs(2), "a request never waits for the warm-up");

        ready.store(true, Ordering::SeqCst);
        let mut listed = Vec::new();
        for _ in 0..200 {
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
        let directory = directory(url);
        directory.start_warmup(Duration::from_millis(30), Duration::from_millis(150));
        for _ in 0..200 {
            if !directory
                .warming_up
                .load(Ordering::SeqCst)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !directory
                .warming_up
                .load(Ordering::SeqCst)
        );
        ready.store(true, Ordering::SeqCst);
        directory.expire_cache().await;
        let started = Instant::now();
        assert!(
            directory
                .entries()
                .await
                .is_empty(),
            "the request gets the empty list at once"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        directory.settle().await;
        assert_eq!(
            directory
                .entries()
                .await
                .len(),
            1,
            "the background refresh found the directory ready"
        );
    }

    #[tokio::test]
    async fn the_startup_fetch_allows_a_slower_first_answer_than_a_request_does() {
        let url = serve_with(axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#
        }))
        .await;
        let directory =
            Arc::new(MediatorDirectory::with_timeouts(url, None, Duration::from_millis(100), Duration::from_secs(5)));
        directory.entries().await;
        directory.settle().await;
        assert!(!directory.has_loaded(), "a request-sized timeout gives up on the slow answer");
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
        directory.load_now().await;
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
        let directory = directory(url);
        let fetching = {
            let directory = directory.clone();
            tokio::spawn(async move { directory.load_now().await })
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
        directory.load_now().await;
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
        directory.settle().await;
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
        directory.settle().await;
        assert_eq!(
            directory
                .listing("did:web:m.example")
                .await,
            Listing::NotListed,
            "a successful empty answer lists nothing"
        );
    }

    #[tokio::test]
    async fn a_stale_list_is_returned_at_once_while_one_slow_refresh_runs() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let url = serve_with(axum::routing::get(move || {
            let counter = counter.clone();
            async move {
                let call = counter.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    r#"{"items":[{"did":"did:web:old.example","name":"Old"}]}"#
                } else {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    r#"{"items":[{"did":"did:web:new.example","name":"New"}]}"#
                }
            }
        }))
        .await;
        let directory = directory(url);
        directory.load_now().await;
        assert_eq!(directory.entries().await[0].did, "did:web:old.example");
        directory.expire_cache().await;

        let started = Instant::now();
        let callers: Vec<_> = (0..5)
            .map(|_| {
                let directory = directory.clone();
                tokio::spawn(async move { directory.entries().await })
            })
            .collect();
        for caller in callers {
            assert_eq!(caller.await.unwrap()[0].did, "did:web:old.example", "the stale list is served");
        }
        assert!(started.elapsed() < Duration::from_secs(2), "no caller waits for the refresh");

        directory.settle().await;
        assert_eq!(hits.load(Ordering::SeqCst), 2, "one refresh for all callers");
        assert_eq!(directory.entries().await[0].did, "did:web:new.example", "the refresh result is used next");
    }

    #[tokio::test]
    async fn the_refresh_flag_is_cleared_even_when_the_refresh_task_panics() {
        let directory = directory("http://127.0.0.1:9/directory".to_string());
        directory
            .refreshing
            .store(true, Ordering::SeqCst);
        let guarded = directory.clone();
        let task = tokio::spawn(async move {
            let _flag = RefreshFlag(guarded);
            panic!("the refresh task failed");
        });
        assert!(task.await.is_err());
        assert!(
            !directory
                .refreshing
                .load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn a_refresh_that_waited_for_the_lock_skips_the_fetch_when_the_cache_became_fresh() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let url = serve_with(axum::routing::get(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                r#"{"items":[{"did":"did:web:m.example","name":"Shared"}]}"#
            }
        }))
        .await;
        let directory = directory(url);
        directory.load_now().await;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        directory.expire_cache().await;

        let held = directory.refresh.lock().await;
        directory.refresh_in_background();
        tokio::time::sleep(Duration::from_millis(50)).await;
        directory
            .apply_success(vec![DirectoryEntry {
                did: "did:web:m.example".into(),
                name: "Shared".into(),
            }])
            .await;
        drop(held);
        directory.settle().await;
        assert_eq!(hits.load(Ordering::SeqCst), 1, "the queued refresh saw a fresh cache and did not fetch");
    }

    #[tokio::test]
    async fn a_directory_that_never_answered_does_not_make_list_callers_wait() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let url = serve_with(axum::routing::get(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(2)).await;
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            }
        }))
        .await;
        let directory = Arc::new(MediatorDirectory::with_timeouts(
            url,
            None,
            Duration::from_millis(150),
            Duration::from_millis(150),
        ));
        directory.start_warmup(Duration::from_millis(30), Duration::from_millis(100));
        for _ in 0..100 {
            if !directory
                .warming_up
                .load(Ordering::SeqCst)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!directory.has_loaded());

        directory.expire_cache().await;
        let started = Instant::now();
        let callers: Vec<_> = (0..5)
            .map(|_| {
                let directory = directory.clone();
                tokio::spawn(async move { directory.entries().await })
            })
            .collect();
        for caller in callers {
            assert!(
                caller
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(started.elapsed() < Duration::from_secs(2), "no list caller waits for a down directory");
        directory.settle().await;
        assert!(!directory.has_loaded());
        let after_failure = hits.load(Ordering::SeqCst);
        directory.entries().await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            after_failure,
            "the retry time-to-live is respected after a failed refresh"
        );
    }

    #[test]
    fn control_characters_in_a_name_become_spaces() {
        assert_eq!(clip("Shared\nmediator\tone", 100).as_deref(), Some("Shared mediator one"));
        assert_eq!(clip("  \n\t ", 100), None);
        let entries = sanitize_entries(vec![json!({"did": "did:web:a.example", "name": "A\r\nB"})]);
        assert_eq!(entries[0].name, "A B");
    }
}
