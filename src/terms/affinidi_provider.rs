use super::{TermsError, validate_terms_version};
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage_strict};
use crate::terms::types::{
    AFFINIDI_TERMS_DOCUMENT_ID, AffinidiProviderState, AffinidiProviderStatus, TermsType, TermsVersion,
};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use reqwest::header::{ETAG, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use url::Url;

const CACHE_ID: &str = "current";
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_REFRESH_INTERVAL_SECONDS: u64 = 3600;

fn refresh_delay_seconds(configured: Option<&str>) -> u64 {
    refresh_delay_seconds_for_build(configured, cfg!(debug_assertions))
}

fn refresh_delay_seconds_for_build(
    configured: Option<&str>,
    debug_build: bool,
) -> u64 {
    let minimum = if debug_build {
        1
    } else {
        60
    };
    configured
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.clamp(minimum, MAX_REFRESH_INTERVAL_SECONDS))
        .unwrap_or_else(|| rand::random_range(3300..=MAX_REFRESH_INTERVAL_SECONDS))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AffinidiTermsManifest {
    pub schema_version: u32,
    pub publication_sequence: u64,
    pub document_id: String,
    pub version_id: String,
    pub version: String,
    pub title: String,
    pub url: String,
    pub requires_reconsent: bool,
    pub published_at: DateTime<Utc>,
}

fn validate_update_history(
    current: Option<&AffinidiTermsManifest>,
    candidate: &AffinidiTermsManifest,
    seen_version_ids: &HashSet<String>,
) -> Result<(), TermsError> {
    if current.is_some_and(|current| current.version_id != candidate.version_id)
        && seen_version_ids.contains(&candidate.version_id)
    {
        return Err(TermsError::Invalid("Affinidi Terms version_id was reused by a later publication".to_string()));
    }
    validate_update(current, candidate)
}

fn validate_update(
    current: Option<&AffinidiTermsManifest>,
    candidate: &AffinidiTermsManifest,
) -> Result<(), TermsError> {
    if let Some(current) = current {
        if candidate.publication_sequence < current.publication_sequence {
            return Err(TermsError::Invalid("Affinidi Terms publication rollback rejected".to_string()));
        }
        if candidate.publication_sequence == current.publication_sequence && candidate != current {
            return Err(TermsError::Invalid(
                "Affinidi Terms publication sequence was reused with changed metadata".to_string(),
            ));
        }
        if candidate.publication_sequence > current.publication_sequence && candidate.version_id == current.version_id {
            return Err(TermsError::Invalid("Affinidi Terms version_id was reused by a new publication".to_string()));
        }
    }
    Ok(())
}

impl AffinidiTermsManifest {
    pub(crate) fn into_version(self) -> Result<TermsVersion, TermsError> {
        let version = TermsVersion {
            terms_type: TermsType::Affinidi,
            document_id: self.document_id,
            version_id: self.version_id,
            version: self.version,
            title: self.title,
            url: self.url,
            requires_reconsent: self.requires_reconsent,
            published_at: self.published_at,
            published_by: None,
        };
        if self.schema_version != 1 {
            return Err(TermsError::Invalid("unsupported Affinidi Terms schema version".to_string()));
        }
        if self.publication_sequence == 0 {
            return Err(TermsError::Invalid("Affinidi Terms publication sequence must be positive".to_string()));
        }
        if version.document_id != AFFINIDI_TERMS_DOCUMENT_ID {
            return Err(TermsError::Invalid("unexpected Affinidi Terms document id".to_string()));
        }
        validate_terms_version(&version).map_err(|error| TermsError::Invalid(error.to_string()))?;
        Ok(version)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedAffinidiTerms {
    id: String,
    manifest: AffinidiTermsManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_successful_refresh: Option<DateTime<Utc>>,
    #[serde(default)]
    seen_version_ids: HashSet<String>,
}

impl StorableEntity for CachedAffinidiTerms {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Default)]
struct ProviderState {
    manifest: Option<AffinidiTermsManifest>,
    etag: Option<String>,
    last_successful_refresh: Option<DateTime<Utc>>,
    seen_version_ids: HashSet<String>,
    healthy: bool,
}

type TermsCache = Arc<dyn StorageBackend<CachedAffinidiTerms>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    Updated,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshFailureKind {
    Transport,
    Validation,
    Rollback,
    Cache,
}

struct RefreshFailure {
    kind: RefreshFailureKind,
    error: TermsError,
}

fn refresh_result_label(result: &Result<RefreshOutcome, RefreshFailure>) -> &'static str {
    match result {
        Ok(RefreshOutcome::Updated) => "updated",
        Ok(RefreshOutcome::Unchanged) => "unchanged",
        Err(error) => match error.kind {
            RefreshFailureKind::Transport => "transport_failure",
            RefreshFailureKind::Validation => "validation_failure",
            RefreshFailureKind::Rollback => "rollback_rejection",
            RefreshFailureKind::Cache => "cache_failure",
        },
    }
}

impl RefreshFailure {
    fn new(
        kind: RefreshFailureKind,
        error: TermsError,
    ) -> Self {
        Self { kind, error }
    }
}

pub(crate) struct AffinidiTermsProvider {
    endpoint: Url,
    client: reqwest::Client,
    cache_path: PathBuf,
    cache: RwLock<Option<TermsCache>>,
    state: RwLock<ProviderState>,
    refresh_lock: Mutex<()>,
}

impl AffinidiTermsProvider {
    pub(crate) async fn open(
        cache_path: &Path,
        endpoint: Url,
    ) -> Result<Self, TermsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| TermsError::Operational(format!("failed to build Affinidi Terms HTTP client: {error}")))?;
        let (cache, state) = match Self::open_cache(cache_path).await {
            Ok((cache, state)) => (Some(cache), state),
            Err(error) => {
                tracing::error!(%error, "Affinidi Terms durable cache is unavailable; provider remains unavailable");
                (None, ProviderState::default())
            }
        };
        Ok(Self {
            endpoint,
            client,
            cache_path: cache_path.to_path_buf(),
            cache: RwLock::new(cache),
            state: RwLock::new(state),
            refresh_lock: Mutex::new(()),
        })
    }

    async fn open_cache(cache_path: &Path) -> Result<(TermsCache, ProviderState), TermsError> {
        let cache: TermsCache = Arc::from(
            cached_storage_strict(cache_path.to_path_buf(), "affinidi_terms")
                .await
                .map_err(|error| TermsError::Operational(format!("failed to open Affinidi Terms cache: {error}")))?,
        );
        let cached = cache
            .get(CACHE_ID)
            .await
            .map_err(|error| TermsError::Operational(format!("failed to read Affinidi Terms cache: {error}")))?;
        let state = cached.map_or_else(ProviderState::default, |cached| {
            let mut seen_version_ids = cached.seen_version_ids;
            seen_version_ids.insert(
                cached
                    .manifest
                    .version_id
                    .clone(),
            );
            ProviderState {
                manifest: Some(cached.manifest),
                etag: cached.etag,
                last_successful_refresh: cached.last_successful_refresh,
                seen_version_ids,
                healthy: false,
            }
        });
        if let Some(manifest) = state.manifest.clone() {
            manifest.into_version()?;
        }
        Ok((cache, state))
    }

    async fn durable_cache(&self) -> Result<TermsCache, RefreshFailure> {
        if let Some(cache) = self
            .cache
            .read()
            .await
            .clone()
        {
            return Ok(cache);
        }
        let (cache, cached_state) = Self::open_cache(&self.cache_path)
            .await
            .map_err(|error| RefreshFailure::new(RefreshFailureKind::Cache, error))?;
        let mut state = self.state.write().await;
        if state.manifest.is_none()
            && cached_state
                .manifest
                .is_some()
        {
            *state = cached_state;
        }
        drop(state);
        *self.cache.write().await = Some(cache.clone());
        Ok(cache)
    }

    async fn persist_unchanged_refresh(
        &self,
        cache: &TermsCache,
        response_etag: Option<String>,
    ) -> Result<RefreshOutcome, RefreshFailure> {
        let state = self.state.read().await;
        let manifest = state
            .manifest
            .clone()
            .ok_or_else(|| {
                RefreshFailure::new(
                    RefreshFailureKind::Validation,
                    TermsError::Invalid(
                        "Affinidi Terms endpoint returned unchanged without cached metadata".to_string(),
                    ),
                )
            })?;
        let etag = response_etag.or_else(|| state.etag.clone());
        let seen_version_ids = state.seen_version_ids.clone();
        drop(state);
        let refreshed_at = Utc::now();
        let cached = CachedAffinidiTerms {
            id: CACHE_ID.to_string(),
            manifest,
            etag: etag.clone(),
            last_successful_refresh: Some(refreshed_at),
            seen_version_ids,
        };
        cache
            .save_atomic(&cached)
            .await
            .map_err(|error| {
                RefreshFailure::new(
                    RefreshFailureKind::Cache,
                    TermsError::Operational(format!("failed to cache Affinidi Terms refresh: {error}")),
                )
            })?;
        let mut state = self.state.write().await;
        state.etag = etag;
        state.last_successful_refresh = Some(refreshed_at);
        Ok(RefreshOutcome::Unchanged)
    }

    pub(crate) async fn current(&self) -> Result<TermsVersion, TermsError> {
        self.state
            .read()
            .await
            .manifest
            .clone()
            .ok_or_else(|| TermsError::Operational("Affinidi Terms metadata is unavailable".to_string()))?
            .into_version()
    }

    async fn update_gauges(&self) {
        let state = self.state.read().await;
        let cache_age = state
            .last_successful_refresh
            .map(|last_refresh| {
                Utc::now()
                    .signed_duration_since(last_refresh)
                    .num_seconds()
                    .max(0) as f64
            })
            .unwrap_or(-1.0);
        let publication_sequence = state
            .manifest
            .as_ref()
            .map_or(0.0, |manifest| manifest.publication_sequence as f64);
        crate::metrics::backends::prometheus::AFFINIDI_TERMS_CACHE_AGE_SECONDS.set(cache_age);
        crate::metrics::backends::prometheus::AFFINIDI_TERMS_PUBLICATION_SEQUENCE.set(publication_sequence);
    }

    pub(crate) async fn status(&self) -> AffinidiProviderStatus {
        self.update_gauges().await;
        let state = self.state.read().await;
        AffinidiProviderStatus {
            state: if state.manifest.is_none() {
                AffinidiProviderState::Unavailable
            } else if state.healthy {
                AffinidiProviderState::Healthy
            } else {
                AffinidiProviderState::Degraded
            },
            last_successful_refresh: state.last_successful_refresh,
        }
    }

    pub(crate) fn spawn_refresh(self: Arc<Self>) {
        let metrics_provider = self.clone();
        tokio::spawn(async move {
            loop {
                metrics_provider
                    .update_gauges()
                    .await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        tokio::spawn(async move {
            loop {
                if let Err(error) = self.refresh().await {
                    tracing::warn!(%error, "Affinidi Terms metadata refresh failed; retaining last-known-good metadata");
                }
                let configured = std::env::var("AFFINIDI_TERMS_REFRESH_INTERVAL_SECONDS").ok();
                let delay = refresh_delay_seconds(configured.as_deref());
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        });
    }

    pub(crate) async fn refresh(&self) -> Result<RefreshOutcome, TermsError> {
        let _guard = self.refresh_lock.lock().await;
        let started = Instant::now();
        let result = self.refresh_inner().await;
        crate::metrics::backends::prometheus::AFFINIDI_TERMS_REFRESH_DURATION_SECONDS.observe(
            started
                .elapsed()
                .as_secs_f64(),
        );
        let result_label = refresh_result_label(&result);
        crate::metrics::backends::prometheus::AFFINIDI_TERMS_REFRESH
            .with_label_values(&[result_label])
            .inc();
        let mut state = self.state.write().await;
        state.healthy = result.is_ok();
        let publication_sequence = state
            .manifest
            .as_ref()
            .map(|manifest| manifest.publication_sequence);
        drop(state);
        tracing::info!(outcome = result_label, publication_sequence, "Affinidi Terms metadata refresh completed");
        self.update_gauges().await;
        result.map_err(|failure| failure.error)
    }

    async fn refresh_inner(&self) -> Result<RefreshOutcome, RefreshFailure> {
        let cache = self.durable_cache().await?;
        let etag = self
            .state
            .read()
            .await
            .etag
            .clone();
        let mut request = self
            .client
            .get(self.endpoint.clone());
        if let Some(etag) = etag.as_deref() {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response = request
            .send()
            .await
            .map_err(|error| {
                RefreshFailure::new(
                    RefreshFailureKind::Transport,
                    TermsError::Operational(format!("failed to refresh Affinidi Terms: {error}")),
                )
            })?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return self
                .persist_unchanged_refresh(&cache, None)
                .await;
        }
        if !response.status().is_success() {
            return Err(RefreshFailure::new(
                RefreshFailureKind::Transport,
                TermsError::Operational(format!("Affinidi Terms endpoint returned {}", response.status())),
            ));
        }
        let response_etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let mut bytes = Vec::new();
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|error| {
                RefreshFailure::new(
                    RefreshFailureKind::Transport,
                    TermsError::Operational(format!("failed to read Affinidi Terms metadata: {error}")),
                )
            })?;
            if bytes.len() + chunk.len() > MAX_METADATA_BYTES {
                return Err(RefreshFailure::new(
                    RefreshFailureKind::Validation,
                    TermsError::Invalid("Affinidi Terms metadata is too large".to_string()),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let candidate = serde_json::from_slice::<AffinidiTermsManifest>(&bytes).map_err(|error| {
            RefreshFailure::new(
                RefreshFailureKind::Validation,
                TermsError::Invalid(format!("invalid Affinidi Terms metadata: {error}")),
            )
        })?;
        candidate
            .clone()
            .into_version()
            .map_err(|error| RefreshFailure::new(RefreshFailureKind::Validation, error))?;
        let state = self.state.read().await;
        let current = state.manifest.clone();
        let mut seen_version_ids = state.seen_version_ids.clone();
        drop(state);
        validate_update_history(current.as_ref(), &candidate, &seen_version_ids)
            .map_err(|error| RefreshFailure::new(RefreshFailureKind::Rollback, error))?;
        if current.as_ref() == Some(&candidate) {
            return self
                .persist_unchanged_refresh(&cache, response_etag)
                .await;
        }
        seen_version_ids.insert(candidate.version_id.clone());
        let refreshed_at = Utc::now();
        let cached = CachedAffinidiTerms {
            id: CACHE_ID.to_string(),
            manifest: candidate.clone(),
            etag: response_etag.clone(),
            last_successful_refresh: Some(refreshed_at),
            seen_version_ids: seen_version_ids.clone(),
        };
        cache
            .save_atomic(&cached)
            .await
            .map_err(|error| {
                RefreshFailure::new(
                    RefreshFailureKind::Cache,
                    TermsError::Operational(format!("failed to cache Affinidi Terms: {error}")),
                )
            })?;
        *self.state.write().await = ProviderState {
            manifest: Some(candidate),
            etag: response_etag,
            last_successful_refresh: Some(refreshed_at),
            seen_version_ids,
            healthy: true,
        };
        Ok(RefreshOutcome::Updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_outcomes_have_distinct_metric_labels() {
        assert_eq!(refresh_result_label(&Ok(RefreshOutcome::Updated)), "updated");
        assert_eq!(refresh_result_label(&Ok(RefreshOutcome::Unchanged)), "unchanged");
        for (kind, expected) in [
            (RefreshFailureKind::Transport, "transport_failure"),
            (RefreshFailureKind::Validation, "validation_failure"),
            (RefreshFailureKind::Rollback, "rollback_rejection"),
            (RefreshFailureKind::Cache, "cache_failure"),
        ] {
            let failure = RefreshFailure::new(kind, TermsError::Operational("test".to_string()));
            assert_eq!(refresh_result_label(&Err(failure)), expected);
        }
    }

    #[test]
    fn refresh_interval_override_is_capped_at_one_hour() {
        assert_eq!(refresh_delay_seconds(Some("7200")), 3600);
        assert_eq!(
            refresh_delay_seconds(Some("15")),
            if cfg!(debug_assertions) {
                15
            } else {
                60
            }
        );
    }

    #[test]
    fn refresh_interval_respects_production_floor_and_debug_override() {
        for (configured, expected) in [("1", 60), ("59", 60), ("60", 60), ("61", 61), ("3600", 3600), ("7200", 3600)] {
            assert_eq!(refresh_delay_seconds_for_build(Some(configured), false), expected);
        }
        assert_eq!(refresh_delay_seconds_for_build(Some("1"), true), 1);
        for configured in [None, Some("0"), Some("invalid")] {
            for debug_build in [false, true] {
                assert!((3300..=3600).contains(&refresh_delay_seconds_for_build(configured, debug_build)));
            }
        }
    }

    fn manifest(
        publication_sequence: u64,
        version_id: &str,
    ) -> AffinidiTermsManifest {
        AffinidiTermsManifest {
            schema_version: 1,
            publication_sequence,
            document_id: "affinidi-terms".to_string(),
            version_id: version_id.to_string(),
            version: "Example".to_string(),
            title: "Affinidi Terms and Conditions".to_string(),
            url: "https://example.com/terms.pdf".to_string(),
            requires_reconsent: true,
            published_at: "2026-09-02T00:00:00Z"
                .parse()
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn refreshes_and_restores_last_known_good_metadata() {
        let manifest = manifest(2, "affinidi:current");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/terms/v1/current.json", axum::routing::get(move || async move { axum::Json(manifest) }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let directory = tempfile::tempdir().unwrap();
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();

        let provider = AffinidiTermsProvider::open(directory.path(), endpoint.clone())
            .await
            .unwrap();
        assert!(matches!(provider.current().await, Err(TermsError::Operational(_))));
        provider
            .refresh()
            .await
            .unwrap();
        assert_eq!(
            provider
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:current"
        );
        assert_eq!(provider.status().await.state, AffinidiProviderState::Healthy);

        server.abort();
        assert!(
            provider
                .refresh()
                .await
                .is_err()
        );
        assert_eq!(
            provider
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:current"
        );
        assert_eq!(provider.status().await.state, AffinidiProviderState::Degraded);

        drop(provider);
        let restored = AffinidiTermsProvider::open(directory.path(), endpoint)
            .await
            .unwrap();
        assert_eq!(
            restored
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:current"
        );
    }

    #[tokio::test]
    async fn cache_write_failure_does_not_activate_metadata() {
        let manifest = manifest(2, "affinidi:current");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/terms/v1/current.json", axum::routing::get(move || async move { axum::Json(manifest) }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let directory = tempfile::tempdir().unwrap();
        let cache_path = directory.path().join("cache");
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();
        let provider = AffinidiTermsProvider::open(&cache_path, endpoint)
            .await
            .unwrap();
        std::fs::remove_dir_all(&cache_path).unwrap();
        std::fs::write(&cache_path, "not a directory").unwrap();

        assert!(matches!(provider.refresh().await, Err(TermsError::Operational(message)) if message.contains("cache")));
        assert!(matches!(provider.current().await, Err(TermsError::Operational(_))));
        assert_eq!(provider.status().await.state, AffinidiProviderState::Unavailable);
        std::fs::remove_file(&cache_path).unwrap();
        std::fs::create_dir_all(&cache_path).unwrap();
        assert_eq!(
            provider
                .refresh()
                .await
                .unwrap(),
            RefreshOutcome::Updated
        );
        assert_eq!(
            provider
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:current"
        );
        server.abort();
    }

    #[tokio::test]
    async fn corrupt_cache_recovers_without_non_durable_activation() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory
                .path()
                .join("current.json"),
            "{",
        )
        .unwrap();
        let manifest = manifest(2, "affinidi:current");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/terms/v1/current.json", axum::routing::get(move || async move { axum::Json(manifest) }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();
        let provider = AffinidiTermsProvider::open(directory.path(), endpoint)
            .await
            .unwrap();

        assert!(
            provider
                .refresh()
                .await
                .is_err()
        );
        assert!(matches!(provider.current().await, Err(TermsError::Operational(_))));
        std::fs::remove_file(
            directory
                .path()
                .join("current.json"),
        )
        .unwrap();
        assert_eq!(
            provider
                .refresh()
                .await
                .unwrap(),
            RefreshOutcome::Updated
        );
        assert_eq!(
            provider
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:current"
        );
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_cache_recovers_before_metadata_activation() {
        let manifest = manifest(2, "affinidi:current");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/terms/v1/current.json", axum::routing::get(move || async move { axum::Json(manifest) }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let directory = tempfile::tempdir().unwrap();
        let cache_path = directory.path().join("cache");
        std::fs::write(&cache_path, "not a directory").unwrap();
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();
        let provider = AffinidiTermsProvider::open(&cache_path, endpoint)
            .await
            .unwrap();

        assert!(
            provider
                .refresh()
                .await
                .is_err()
        );
        assert!(matches!(provider.current().await, Err(TermsError::Operational(_))));
        std::fs::remove_file(&cache_path).unwrap();
        assert_eq!(
            provider
                .refresh()
                .await
                .unwrap(),
            RefreshOutcome::Updated
        );
        assert_eq!(
            provider
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:current"
        );
        server.abort();
    }

    #[tokio::test]
    async fn conditional_refresh_reports_unchanged_for_not_modified() {
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::IntoResponse;

        let manifest = manifest(2, "affinidi:current");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/terms/v1/current.json",
            axum::routing::get(move |headers: HeaderMap| {
                let manifest = manifest.clone();
                async move {
                    if headers
                        .get(IF_NONE_MATCH)
                        .and_then(|value| value.to_str().ok())
                        == Some("\"v2\"")
                    {
                        StatusCode::NOT_MODIFIED.into_response()
                    } else {
                        ([(ETAG, "\"v2\"")], axum::Json(manifest)).into_response()
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let directory = tempfile::tempdir().unwrap();
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();
        let provider = AffinidiTermsProvider::open(directory.path(), endpoint)
            .await
            .unwrap();

        assert_eq!(
            provider
                .refresh()
                .await
                .unwrap(),
            RefreshOutcome::Updated
        );
        assert_eq!(
            provider
                .refresh()
                .await
                .unwrap(),
            RefreshOutcome::Unchanged
        );
        assert_eq!(
            provider
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:current"
        );
        server.abort();
    }

    #[tokio::test]
    async fn concurrent_readers_observe_only_complete_metadata_versions() {
        let response_manifest = Arc::new(Mutex::new(manifest(1, "affinidi:old")));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let served = response_manifest.clone();
        let app = axum::Router::new().route(
            "/terms/v1/current.json",
            axum::routing::get(move || {
                let served = served.clone();
                async move { axum::Json(served.lock().await.clone()) }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let directory = tempfile::tempdir().unwrap();
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();
        let provider = Arc::new(
            AffinidiTermsProvider::open(directory.path(), endpoint)
                .await
                .unwrap(),
        );
        provider
            .refresh()
            .await
            .unwrap();
        *response_manifest.lock().await = manifest(2, "affinidi:new");

        let reader = {
            let provider = provider.clone();
            tokio::spawn(async move {
                for _ in 0..1_000 {
                    let version = provider
                        .current()
                        .await
                        .unwrap();
                    assert!(matches!(version.version_id.as_str(), "affinidi:old" | "affinidi:new"));
                }
            })
        };
        assert_eq!(
            provider
                .refresh()
                .await
                .unwrap(),
            RefreshOutcome::Updated
        );
        reader.await.unwrap();
        assert_eq!(
            provider
                .current()
                .await
                .unwrap()
                .version_id,
            "affinidi:new"
        );
        server.abort();
    }

    #[tokio::test]
    async fn redirect_response_is_not_followed() {
        use axum::response::Redirect;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/terms/v1/current.json",
            axum::routing::get(|| async { Redirect::temporary("http://example.com/terms.json") }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let directory = tempfile::tempdir().unwrap();
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();
        let provider = AffinidiTermsProvider::open(directory.path(), endpoint)
            .await
            .unwrap();

        assert!(matches!(provider.refresh().await, Err(TermsError::Operational(message)) if message.contains("307")));
        assert!(matches!(provider.current().await, Err(TermsError::Operational(_))));
        server.abort();
    }

    #[tokio::test]
    async fn rejects_oversized_metadata_responses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let app =
            axum::Router::new().route("/terms/v1/current.json", axum::routing::get(|| async { "x".repeat(70_000) }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        let directory = tempfile::tempdir().unwrap();
        let endpoint = Url::parse(&format!("http://{address}/terms/v1/current.json")).unwrap();
        let provider = AffinidiTermsProvider::open(directory.path(), endpoint)
            .await
            .unwrap();

        assert!(matches!(
            provider.refresh().await,
            Err(TermsError::Invalid(message)) if message.contains("too large")
        ));
        assert_eq!(provider.status().await.state, AffinidiProviderState::Unavailable);
        server.abort();
    }

    #[test]
    fn rejects_non_https_document_url() {
        let manifest = AffinidiTermsManifest {
            url: "http://example.com/terms.pdf".to_string(),
            ..manifest(2, "affinidi:example")
        };

        assert!(matches!(
            manifest.into_version(),
            Err(TermsError::Invalid(message)) if message.contains("HTTPS")
        ));
    }

    #[test]
    fn rejects_changed_metadata_at_the_same_publication_sequence() {
        let current = manifest(2, "affinidi:current");
        let candidate = manifest(2, "affinidi:replacement");

        assert!(matches!(
            validate_update(Some(&current), &candidate),
            Err(TermsError::Invalid(message)) if message.contains("sequence")
        ));
    }

    #[test]
    fn rejects_reused_version_id() {
        let current = manifest(2, "affinidi:current");
        let candidate = AffinidiTermsManifest {
            publication_sequence: 3,
            version: "Changed".to_string(),
            ..current.clone()
        };

        assert!(matches!(
            validate_update(Some(&current), &candidate),
            Err(TermsError::Invalid(message)) if message.contains("version_id")
        ));
    }

    #[test]
    fn rejects_a_version_id_observed_before_the_current_publication() {
        let current = manifest(2, "affinidi:current");
        let candidate = manifest(3, "affinidi:old");
        let seen = HashSet::from(["affinidi:old".to_string(), "affinidi:current".to_string()]);

        assert!(matches!(
            validate_update_history(Some(&current), &candidate, &seen),
            Err(TermsError::Invalid(message)) if message.contains("version_id")
        ));
    }

    #[test]
    fn rejects_publication_rollback() {
        let current = manifest(2, "affinidi:current");
        let candidate = manifest(1, "affinidi:older");

        assert!(matches!(
            validate_update(Some(&current), &candidate),
            Err(TermsError::Invalid(message)) if message.contains("rollback")
        ));
    }
}
