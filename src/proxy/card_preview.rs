//! The Agent card preview: the agent's own card beside the card the gateway serves
//! for a surface's base route, with how the gateway's fetch of the agent's card went.
//!
//! The preview runs the public card route's own assembly in
//! [`CardMode::Preview`](crate::proxy::handler::agent_card::CardMode), so its "after"
//! is what an anonymous caller gets. When the fetch fails, "after" is the last card
//! served for the same running surface, or empty when there is none. Everything here
//! is per replica and in memory: the snapshots, the refresh limiter, and the last
//! caller fetch and last served card of each surface.

use std::future::Future;
use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use sha2::Digest;
use tracing::info;

use crate::config::TargetAuthMethod;
use crate::config::agent_surface::AgentSurface;
use crate::proxy::handler::agent_card::{
    CardMode, assemble_card, card_declaration, card_payment_gates, card_target_url,
};
use crate::proxy::target_credentials::{TargetCredential, TargetCredentialError};
use crate::state::ProxyState;
use crate::surfaces::save_report::DeclarationEntry;

/// A card larger than this, serialized, is reported by size only.
pub const DISPLAY_LIMIT_BYTES: usize = 256 * 1024;
/// How long a snapshot answers a read without a new fetch.
pub const SNAPSHOT_FRESH: Duration = Duration::from_secs(60);
/// Card fetches one user may start per minute.
pub const FETCHES_PER_MINUTE: NonZeroU32 = match NonZeroU32::new(10) {
    Some(rate) => rate,
    None => panic!("the fetch rate is positive"),
};
/// How long the snapshots, the single-flight locks and the last served card of a
/// surface are kept.
const PREVIEW_MEMORY_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_SURFACES: u64 = 512;
const MAX_PREVIEW_SECS: u64 = 60;
const PREVIEW_SOURCE: &str = "agent-card-preview";

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CardFetchStatus {
    Ok,
    Failed,
    NotServed,
}

/// Why the card was not obtained or not served. Fixed strings only: no upstream
/// body, header, address or error text ever rides along.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CardFetchCause {
    NeedsToken,
    AuthFailed,
    Forbidden,
    NotFound,
    Redirected,
    UpstreamError,
    Unreachable,
    Timeout,
    TooLarge,
    InvalidCard,
    BlockedByEgress,
    ProxyUnavailable,
    IdentityFailed,
    RewriteFailed,
}

impl CardFetchCause {
    /// `not_served` when the card was obtained but the gateway will not serve it.
    pub fn status(self) -> CardFetchStatus {
        match self {
            Self::IdentityFailed | Self::RewriteFailed => CardFetchStatus::NotServed,
            Self::NeedsToken
            | Self::AuthFailed
            | Self::Forbidden
            | Self::NotFound
            | Self::Redirected
            | Self::UpstreamError
            | Self::Unreachable
            | Self::Timeout
            | Self::TooLarge
            | Self::InvalidCard
            | Self::BlockedByEgress
            | Self::ProxyUnavailable => CardFetchStatus::Failed,
        }
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CardAuthKind {
    None,
    StaticSecret,
    CredentialProvider,
    CredentialLookup,
    RemoteGateway,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CardAuthResult {
    NotConfigured,
    Sent,
    NotSent,
    Failed,
}

/// How Target Authentication went on the card fetch. Never a credential, a secret
/// id or a provider id: only the provider's name and the token's expiry.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CardAuthReport {
    pub kind: CardAuthKind,
    pub result: CardAuthResult,
    pub provider_name: Option<String>,
    pub token_expires_at: Option<String>,
    pub failure: Option<&'static str>,
}

impl CardAuthReport {
    /// The report before any fetch: what the surface configures.
    pub fn for_surface(surface: &AgentSurface) -> Self {
        let configured = |kind| Self {
            kind,
            result: CardAuthResult::NotSent,
            provider_name: None,
            token_expires_at: None,
            failure: None,
        };
        if surface
            .target
            .endpoint
            .starts_with("fabric://")
        {
            return Self {
                result: CardAuthResult::NotConfigured,
                ..configured(CardAuthKind::RemoteGateway)
            };
        }
        match surface
            .target_auth()
            .filter(|_| !surface.is_a2a_proxy_target())
            .map(|auth| &auth.method)
        {
            None => Self {
                result: CardAuthResult::NotConfigured,
                ..configured(CardAuthKind::None)
            },
            Some(TargetAuthMethod::StaticSecret { .. }) => configured(CardAuthKind::StaticSecret),
            Some(TargetAuthMethod::CredentialProvider { .. }) => configured(CardAuthKind::CredentialProvider),
            Some(TargetAuthMethod::CredentialLookup) => configured(CardAuthKind::CredentialLookup),
        }
    }

    /// The fallback refused the fetch: the agent was not asked.
    pub(crate) fn rejected(
        &mut self,
        error: Option<TargetCredentialError>,
    ) {
        self.result = CardAuthResult::Failed;
        self.failure = error.map(TargetCredentialError::category);
    }

    /// The credential the fetch carries, or none when resolution withheld it or the
    /// fallback continued without it.
    pub(crate) fn resolved(
        &mut self,
        credential: Option<&TargetCredential>,
    ) {
        let Some(credential) = credential else {
            if self.result != CardAuthResult::NotConfigured {
                self.result = CardAuthResult::NotSent;
            }
            return;
        };
        self.result = CardAuthResult::Sent;
        if self.kind == CardAuthKind::CredentialProvider {
            self.provider_name = credential
                .provenance
                .provider_name
                .clone();
            self.token_expires_at = credential
                .provenance
                .expires_at
                .map(|expires_at| timestamp(DateTime::<Utc>::from(expires_at)));
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CardFetchReport {
    pub status: CardFetchStatus,
    pub cause: Option<CardFetchCause>,
    pub http_status: Option<u16>,
    pub duration_ms: u64,
}

/// The outcome of the last base-route card request a caller made on this replica.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CallerFetch {
    pub status: CardFetchStatus,
    pub cause: Option<CardFetchCause>,
    pub http_status: Option<u16>,
    #[serde(serialize_with = "serialize_timestamp")]
    pub at: DateTime<Utc>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    NotA2a,
    NotRunning,
}

/// `GET /v1/surfaces/{surface_id}/agent-card` and its refresh. Every field is
/// always present.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct AgentCardPreview {
    pub surface_id: String,
    pub supported: bool,
    pub unsupported_reason: Option<UnsupportedReason>,
    pub variant: Option<String>,
    pub generated: bool,
    pub served_url: Option<String>,
    pub source_url: Option<String>,
    pub source_url_query_hidden: bool,
    pub fetched_at: Option<String>,
    pub cached: bool,
    pub fetch: Option<CardFetchReport>,
    pub auth: Option<CardAuthReport>,
    pub payment_required: bool,
    pub outcome: Option<DeclarationEntry>,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub before_bytes: Option<usize>,
    pub after_bytes: Option<usize>,
    pub display_limit_bytes: usize,
    pub last_caller_fetch: Option<CallerFetch>,
}

impl AgentCardPreview {
    /// The preview of a surface whose card the gateway cannot fetch here.
    pub fn unsupported(
        surface_id: &str,
        reason: UnsupportedReason,
    ) -> Self {
        Self {
            surface_id: surface_id.to_string(),
            supported: false,
            unsupported_reason: Some(reason),
            variant: None,
            generated: false,
            served_url: None,
            source_url: None,
            source_url_query_hidden: false,
            fetched_at: None,
            cached: false,
            fetch: None,
            auth: None,
            payment_required: false,
            outcome: None,
            before: None,
            after: None,
            before_bytes: None,
            after_bytes: None,
            display_limit_bytes: 0,
            last_caller_fetch: None,
        }
    }
}

fn timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn serialize_timestamp<S: serde::Serializer>(
    at: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&timestamp(*at))
}

/// A card URL as an operator may see it: no user info, query or fragment, which
/// can carry keys (an Azure-style `?code=`). The flag says whether anything was
/// removed besides a fragment.
pub fn displayable_card_url(card_url: &str) -> (Option<String>, bool) {
    let Ok(mut url) = url::Url::parse(card_url) else {
        return (None, false);
    };
    let hidden = url.query().is_some() || !url.username().is_empty() || url.password().is_some();
    url.set_query(None);
    url.set_fragment(None);
    if url.set_username("").is_err()
        || url
            .set_password(None)
            .is_err()
    {
        return (None, hidden);
    }
    (Some(url.to_string()), hidden)
}

/// The public URL callers fetch the base route's card from, when a listener
/// matches the Access Point.
pub fn served_card_url(
    surface: &AgentSurface,
    network: &crate::config::NetworkConfig,
) -> Option<String> {
    use crate::protocols::protected_resource::{access_point_origin, access_point_path};
    let access_point = format!("{}{}", access_point_origin(surface, network)?, access_point_path(surface, None)?);
    Some(crate::proxy::protocol_router::join_endpoint_path(&access_point, "/.well-known/agent-card.json"))
}

/// The preview's overall deadline: the A2A timeout plus a margin for identity
/// work, at most a minute.
pub fn preview_deadline(a2a_timeout_secs: u64) -> Duration {
    Duration::from_secs(
        a2a_timeout_secs
            .saturating_add(5)
            .min(MAX_PREVIEW_SECS),
    )
}

/// A card as a preview shows it: its serialized size, and the card itself only
/// while that size is within [`DISPLAY_LIMIT_BYTES`].
#[derive(Debug, Clone, PartialEq)]
struct DisplayedCard {
    card: Option<Arc<serde_json::Value>>,
    bytes: usize,
}

impl DisplayedCard {
    fn of(card: &serde_json::Value) -> Self {
        let bytes = serialized_len(card);
        Self {
            card: (bytes <= DISPLAY_LIMIT_BYTES).then(|| Arc::new(card.clone())),
            bytes,
        }
    }

    /// The card and size fields of a preview.
    fn into_fields(displayed: Option<Self>) -> (Option<serde_json::Value>, Option<usize>) {
        match displayed {
            Some(Self { card, bytes }) => (card.map(Arc::unwrap_or_clone), Some(bytes)),
            None => (None, None),
        }
    }
}

/// The length of `card` serialized as compact JSON, counted without buffering it.
fn serialized_len(card: &serde_json::Value) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(
            &mut self,
            buf: &[u8],
        ) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    match serde_json::to_writer(&mut counter, card) {
        Ok(()) => counter.0,
        Err(_) => 0,
    }
}

/// Assemble the base route's card as an anonymous caller would get it, without
/// what serving it records, and report how it went. The request carries only
/// `Accept: application/json` and any Target credential; nothing from the
/// management request reaches the agent. On a failed fetch the served card is the
/// last one served for the same running surface.
pub(crate) async fn fetch_preview(state: &ProxyState) -> AgentCardPreview {
    fetch_preview_within(
        state,
        preview_deadline(
            state
                .config
                .a2a
                .timeout_seconds,
        ),
    )
    .await
}

/// [`fetch_preview`] with the overall `deadline` given. A preview still assembling
/// at the deadline reports a `timeout` with the base route's declaration and the
/// last card served for the same running surface.
pub(crate) async fn fetch_preview_within(
    state: &ProxyState,
    deadline: Duration,
) -> AgentCardPreview {
    let surface = state.surface.as_ref();
    let started = std::time::Instant::now();
    let fetched_at = Utc::now();
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    let mut auth = CardAuthReport::for_surface(surface);
    let assembled =
        tokio::time::timeout(deadline, assemble_card(state, &headers, PREVIEW_SOURCE, CardMode::Preview, &mut auth))
            .await
            .ok();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let (failure, upstream, served, applied) = match assembled {
        Some(assembled) => (
            assembled
                .failure
                .as_ref()
                .map(|failure| (failure.cause, failure.http_status)),
            assembled.upstream,
            assembled.served,
            assembled.outcome,
        ),
        None => (Some((CardFetchCause::Timeout, None)), None, None, None),
    };
    let fetch = CardFetchReport {
        status: failure.map_or(CardFetchStatus::Ok, |(cause, _)| cause.status()),
        cause: failure.map(|(cause, _)| cause),
        http_status: failure.and_then(|(_, http_status)| http_status),
        duration_ms,
    };
    let generated = surface.is_a2a_proxy_target();
    let (source_url, source_url_query_hidden) = if generated {
        (None, false)
    } else {
        displayable_card_url(&card_target_url(surface))
    };
    let (before, before_bytes) = DisplayedCard::into_fields(
        upstream
            .filter(|_| !generated)
            .as_ref()
            .map(DisplayedCard::of),
    );
    let served = card_preview_service()
        .served_card_after(&state.surface, served.filter(|_| fetch.status == CardFetchStatus::Ok))
        .await;
    let (after, after_bytes) = DisplayedCard::into_fields(served);
    let outcome = match applied {
        Some(outcome) => Some(outcome),
        None => card_declaration(state)
            .await
            .ok(),
    };
    info!(
        surface_id = %surface.surface_id,
        cause = ?fetch.cause,
        duration_ms,
        "Agent card preview assembled"
    );
    AgentCardPreview {
        surface_id: surface.surface_id.clone(),
        supported: true,
        unsupported_reason: None,
        variant: None,
        generated,
        served_url: served_card_url(surface, &state.network_config),
        source_url,
        source_url_query_hidden,
        fetched_at: Some(timestamp(fetched_at)),
        cached: false,
        fetch: Some(fetch),
        auth: Some(auth),
        payment_required: card_payment_gates(surface).any(),
        outcome: outcome.map(|outcome| DeclarationEntry::new(surface, None, &outcome, &state.network_config)),
        before,
        after,
        before_bytes,
        after_bytes,
        display_limit_bytes: DISPLAY_LIMIT_BYTES,
        last_caller_fetch: None,
    }
}

/// The SHA-256 digest of the running surface a snapshot was taken from.
pub fn surface_digest(surface: &AgentSurface) -> [u8; 32] {
    sha2::Sha256::digest(serde_json::to_vec(surface).unwrap_or_default()).into()
}

/// Whether a read may answer from a fresh snapshot, or a refresh always fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewRequest {
    Read,
    Refresh,
}

/// The user started more card fetches than [`FETCHES_PER_MINUTE`] and there is no
/// snapshot of the running surface to answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited;

/// Which surface a preview is for, and who asked.
pub struct PreviewKey<'a> {
    pub surface_id: &'a str,
    pub digest: [u8; 32],
    pub user_id: &'a str,
}

struct CardSnapshot {
    preview: AgentCardPreview,
    digest: [u8; 32],
    taken: tokio::time::Instant,
}

/// A card the base route served, kept as a preview shows it, and the running surface
/// it was served for.
struct ServedCard {
    displayed: DisplayedCard,
    surface: Arc<AgentSurface>,
}

/// Snapshots, single-flight fetches, the per-user refresh limit, and the last
/// caller fetch and last served card of every surface on this replica.
pub struct CardPreviewService {
    snapshots: moka::future::Cache<String, Arc<CardSnapshot>>,
    flights: moka::future::Cache<String, Arc<tokio::sync::Mutex<()>>>,
    caller_fetches: moka::future::Cache<String, CallerFetch>,
    served_cards: moka::future::Cache<String, Arc<ServedCard>>,
    fetches: governor::DefaultKeyedRateLimiter<String>,
}

impl CardPreviewService {
    pub fn new(fetches_per_minute: NonZeroU32) -> Self {
        Self {
            snapshots: surface_cache(),
            flights: surface_cache(),
            caller_fetches: moka::future::Cache::builder()
                .max_capacity(MAX_SURFACES)
                .build(),
            served_cards: surface_cache(),
            fetches: governor::RateLimiter::keyed(governor::Quota::per_minute(fetches_per_minute)),
        }
    }

    /// The preview for `key`: a fresh snapshot of the same running surface for a
    /// read, the snapshot a concurrent request fetched while this one waited, or a
    /// new fetch through `fetch`. A fetch counts towards the user's limit; past it a
    /// read falls back to any snapshot of the same running surface.
    pub async fn preview<F, Fut>(
        &self,
        key: &PreviewKey<'_>,
        request: PreviewRequest,
        fetch: F,
    ) -> Result<AgentCardPreview, RateLimited>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = AgentCardPreview>,
    {
        let arrived = tokio::time::Instant::now();
        if request == PreviewRequest::Read
            && let Some(snapshot) = self
                .matching_snapshot(key)
                .await
                .filter(|snapshot| snapshot.taken.elapsed() < SNAPSHOT_FRESH)
        {
            return Ok(self
                .answer(key, &snapshot, true)
                .await);
        }

        let flight = self
            .flights
            .get_with(key.surface_id.to_string(), async { Arc::new(tokio::sync::Mutex::new(())) })
            .await;
        let _flight = flight.lock().await;
        let snapshot = self
            .matching_snapshot(key)
            .await;
        if let Some(snapshot) = &snapshot {
            if snapshot.taken > arrived {
                return Ok(self
                    .answer(key, snapshot, false)
                    .await);
            }
            if request == PreviewRequest::Read && snapshot.taken.elapsed() < SNAPSHOT_FRESH {
                return Ok(self
                    .answer(key, snapshot, true)
                    .await);
            }
        }
        if self
            .fetches
            .check_key(&key.user_id.to_string())
            .is_err()
        {
            return match (request, snapshot) {
                (PreviewRequest::Read, Some(snapshot)) => Ok(self
                    .answer(key, &snapshot, true)
                    .await),
                _ => Err(RateLimited),
            };
        }

        let preview = fetch().await;
        let snapshot = Arc::new(CardSnapshot {
            preview,
            digest: key.digest,
            taken: tokio::time::Instant::now(),
        });
        self.snapshots
            .insert(key.surface_id.to_string(), snapshot.clone())
            .await;
        Ok(self
            .answer(key, &snapshot, false)
            .await)
    }

    async fn matching_snapshot(
        &self,
        key: &PreviewKey<'_>,
    ) -> Option<Arc<CardSnapshot>> {
        self.snapshots
            .get(key.surface_id)
            .await
            .filter(|snapshot| snapshot.digest == key.digest)
    }

    async fn answer(
        &self,
        key: &PreviewKey<'_>,
        snapshot: &CardSnapshot,
        cached: bool,
    ) -> AgentCardPreview {
        let mut preview = snapshot.preview.clone();
        preview.cached = cached;
        preview.last_caller_fetch = self
            .last_caller_fetch(key.surface_id)
            .await;
        preview
    }

    /// The last base-route card request a caller made for `surface_id` here.
    pub async fn last_caller_fetch(
        &self,
        surface_id: &str,
    ) -> Option<CallerFetch> {
        self.caller_fetches
            .get(surface_id)
            .await
    }

    pub async fn record_caller_fetch(
        &self,
        surface_id: &str,
        fetch: CallerFetch,
    ) {
        self.caller_fetches
            .insert(surface_id.to_string(), fetch)
            .await;
    }

    /// Keep `card` as the card the base route of `surface` serves. A card over
    /// [`DISPLAY_LIMIT_BYTES`] is kept by its size only.
    pub(crate) async fn keep_served_card(
        &self,
        surface: &Arc<AgentSurface>,
        card: &serde_json::Value,
    ) {
        self.keep(surface, DisplayedCard::of(card))
            .await;
    }

    async fn keep(
        &self,
        surface: &Arc<AgentSurface>,
        displayed: DisplayedCard,
    ) {
        self.served_cards
            .insert(
                surface.surface_id.clone(),
                Arc::new(ServedCard {
                    displayed,
                    surface: surface.clone(),
                }),
            )
            .await;
    }

    /// The last card the base route served for this running surface. A card served
    /// before the surface changed is never returned.
    async fn served_card(
        &self,
        surface: &AgentSurface,
    ) -> Option<DisplayedCard> {
        let served = self
            .served_cards
            .get(&surface.surface_id)
            .await?;
        (surface_digest(&served.surface) == surface_digest(surface)).then(|| served.displayed.clone())
    }

    /// The served card a preview shows: the card it just assembled, kept as the
    /// served card, or the last card served for the same running surface when the
    /// fetch failed.
    async fn served_card_after(
        &self,
        surface: &Arc<AgentSurface>,
        assembled: Option<serde_json::Value>,
    ) -> Option<DisplayedCard> {
        match assembled {
            Some(card) => {
                let displayed = DisplayedCard::of(&card);
                self.keep(surface, displayed.clone())
                    .await;
                Some(displayed)
            }
            None => {
                self.served_card(surface)
                    .await
            }
        }
    }
}

fn surface_cache<V: Clone + Send + Sync + 'static>() -> moka::future::Cache<String, V> {
    moka::future::Cache::builder()
        .max_capacity(MAX_SURFACES)
        .time_to_live(PREVIEW_MEMORY_TTL)
        .build()
}

/// The preview service every surface on this replica shares.
pub fn card_preview_service() -> &'static CardPreviewService {
    static SERVICE: LazyLock<CardPreviewService> = LazyLock::new(|| CardPreviewService::new(FETCHES_PER_MINUTE));
    &SERVICE
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;

    fn preview(surface_id: &str) -> AgentCardPreview {
        AgentCardPreview {
            supported: true,
            unsupported_reason: None,
            fetch: Some(CardFetchReport {
                status: CardFetchStatus::Ok,
                cause: None,
                http_status: None,
                duration_ms: 3,
            }),
            display_limit_bytes: DISPLAY_LIMIT_BYTES,
            ..AgentCardPreview::unsupported(surface_id, UnsupportedReason::NotRunning)
        }
    }

    struct Counted {
        fetches: Arc<AtomicUsize>,
    }

    impl Counted {
        fn new() -> Self {
            Self {
                fetches: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn fetch(&self) -> impl FnOnce() -> std::pin::Pin<Box<dyn Future<Output = AgentCardPreview> + Send>> {
            let fetches = self.fetches.clone();
            move || {
                Box::pin(async move {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    preview("surface-1")
                })
            }
        }

        fn count(&self) -> usize {
            self.fetches
                .load(Ordering::SeqCst)
        }
    }

    fn key<'a>(
        digest: u8,
        user_id: &'a str,
    ) -> PreviewKey<'a> {
        PreviewKey {
            surface_id: "surface-1",
            digest: [digest; 32],
            user_id,
        }
    }

    #[test]
    fn test_preview_fields_and_enums_have_their_contract_spellings() {
        let mut full = preview("surface-1");
        full.fetch = Some(CardFetchReport {
            status: CardFetchStatus::NotServed,
            cause: Some(CardFetchCause::RewriteFailed),
            http_status: None,
            duration_ms: 7,
        });
        full.auth = Some(CardAuthReport {
            kind: CardAuthKind::CredentialProvider,
            result: CardAuthResult::NotSent,
            provider_name: None,
            token_expires_at: None,
            failure: None,
        });
        full.last_caller_fetch = Some(CallerFetch {
            status: CardFetchStatus::Failed,
            cause: Some(CardFetchCause::NeedsToken),
            http_status: Some(401),
            at: DateTime::parse_from_rfc3339("2026-10-23T09:58:12.345Z")
                .expect("timestamp")
                .with_timezone(&Utc),
        });
        let value = serde_json::to_value(&full).expect("serialize");
        let keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = vec![
            "surface_id",
            "supported",
            "unsupported_reason",
            "variant",
            "generated",
            "served_url",
            "source_url",
            "source_url_query_hidden",
            "fetched_at",
            "cached",
            "fetch",
            "auth",
            "payment_required",
            "outcome",
            "before",
            "after",
            "before_bytes",
            "after_bytes",
            "display_limit_bytes",
            "last_caller_fetch",
        ];
        let mut sorted_keys = keys.clone();
        sorted_keys.sort_unstable();
        expected.sort_unstable();
        assert_eq!(sorted_keys, expected);
        assert_eq!(
            value["fetch"],
            json!({"status": "not_served", "cause": "rewrite_failed", "http_status": null, "duration_ms": 7})
        );
        assert_eq!(
            value["auth"],
            json!({"kind": "credential_provider", "result": "not_sent", "provider_name": null,
                "token_expires_at": null, "failure": null})
        );
        assert_eq!(
            value["last_caller_fetch"],
            json!({"status": "failed", "cause": "needs_token", "http_status": 401, "at": "2026-10-23T09:58:12Z"})
        );

        let spellings = |values: Vec<serde_json::Value>| -> Vec<String> {
            values
                .into_iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("string")
                        .to_string()
                })
                .collect()
        };
        let causes = [
            CardFetchCause::NeedsToken,
            CardFetchCause::AuthFailed,
            CardFetchCause::Forbidden,
            CardFetchCause::NotFound,
            CardFetchCause::Redirected,
            CardFetchCause::UpstreamError,
            CardFetchCause::Unreachable,
            CardFetchCause::Timeout,
            CardFetchCause::TooLarge,
            CardFetchCause::InvalidCard,
            CardFetchCause::BlockedByEgress,
            CardFetchCause::ProxyUnavailable,
            CardFetchCause::IdentityFailed,
            CardFetchCause::RewriteFailed,
        ];
        assert_eq!(
            spellings(
                causes
                    .iter()
                    .map(|cause| json!(cause))
                    .collect()
            ),
            [
                "needs_token",
                "auth_failed",
                "forbidden",
                "not_found",
                "redirected",
                "upstream_error",
                "unreachable",
                "timeout",
                "too_large",
                "invalid_card",
                "blocked_by_egress",
                "proxy_unavailable",
                "identity_failed",
                "rewrite_failed"
            ]
        );
        assert_eq!(
            spellings(vec![
                json!(CardAuthKind::None),
                json!(CardAuthKind::StaticSecret),
                json!(CardAuthKind::CredentialProvider),
                json!(CardAuthKind::CredentialLookup),
                json!(CardAuthKind::RemoteGateway),
                json!(CardAuthResult::NotConfigured),
                json!(CardAuthResult::Sent),
                json!(CardAuthResult::NotSent),
                json!(CardAuthResult::Failed),
                json!(UnsupportedReason::NotA2a),
                json!(UnsupportedReason::NotRunning),
                json!(CardFetchStatus::Ok),
            ]),
            [
                "none",
                "static_secret",
                "credential_provider",
                "credential_lookup",
                "remote_gateway",
                "not_configured",
                "sent",
                "not_sent",
                "failed",
                "not_a2a",
                "not_running",
                "ok"
            ]
        );
    }

    #[test]
    fn test_an_unsupported_preview_is_empty_below_its_reason() {
        let value =
            serde_json::to_value(AgentCardPreview::unsupported("s-1", UnsupportedReason::NotA2a)).expect("serialize");
        assert_eq!(
            value,
            json!({
                "surface_id": "s-1", "supported": false, "unsupported_reason": "not_a2a", "variant": null,
                "generated": false, "served_url": null, "source_url": null, "source_url_query_hidden": false,
                "fetched_at": null, "cached": false, "fetch": null, "auth": null, "payment_required": false,
                "outcome": null, "before": null, "after": null, "before_bytes": null, "after_bytes": null,
                "display_limit_bytes": 0, "last_caller_fetch": null
            })
        );
    }

    #[test]
    fn test_displayable_card_url_removes_user_info_query_and_fragment() {
        assert_eq!(
            displayable_card_url("https://agent.example/api/.well-known/agent-card.json"),
            (Some("https://agent.example/api/.well-known/agent-card.json".to_string()), false)
        );
        assert_eq!(
            displayable_card_url("https://agent.example/api/.well-known/agent-card.json?code=SECRET-KEY"),
            (Some("https://agent.example/api/.well-known/agent-card.json".to_string()), true)
        );
        assert_eq!(
            displayable_card_url("https://user:pa55@agent.example/card.json#frag"),
            (Some("https://agent.example/card.json".to_string()), true)
        );
        assert_eq!(
            displayable_card_url("https://agent.example/card.json#frag"),
            (Some("https://agent.example/card.json".to_string()), false),
            "a fragment alone hides nothing"
        );
        assert_eq!(displayable_card_url("not a url"), (None, false));
    }

    #[test]
    fn test_preview_deadline_adds_a_margin_and_is_capped_at_a_minute() {
        assert_eq!(preview_deadline(30), Duration::from_secs(35));
        assert_eq!(preview_deadline(1), Duration::from_secs(6));
        assert_eq!(preview_deadline(55), Duration::from_secs(60));
        assert_eq!(preview_deadline(u64::MAX), Duration::from_secs(60));
    }

    #[test]
    fn test_a_card_over_the_display_limit_is_reported_by_size_only() {
        let small = json!({"name": "agent"});
        let shown = |card: &serde_json::Value| DisplayedCard::into_fields(Some(DisplayedCard::of(card)));
        assert_eq!(shown(&small), (Some(small.clone()), Some(16)));
        let big = json!({"name": "x".repeat(DISPLAY_LIMIT_BYTES)});
        assert_eq!(shown(&big), (None, Some(DISPLAY_LIMIT_BYTES + 11)));
        let at_limit = json!({"name": "x".repeat(DISPLAY_LIMIT_BYTES - 11)});
        assert_eq!(shown(&at_limit), (Some(at_limit.clone()), Some(DISPLAY_LIMIT_BYTES)));
        assert_eq!(DisplayedCard::into_fields(None), (None, None));
    }

    #[test]
    fn test_serialized_len_counts_the_compact_json() {
        for card in [json!({"name": "agent", "skills": [1, 2, {"id": "é"}]}), json!([]), json!("x")] {
            assert_eq!(
                serialized_len(&card),
                serde_json::to_vec(&card)
                    .expect("serialize")
                    .len(),
                "{card}"
            );
        }
    }

    #[test]
    fn test_surface_digest_changes_with_the_surface() {
        let surface = |route: &str| -> AgentSurface {
            serde_json::from_value(json!({"surface_id": "s", "name": "s",
                "access_point": {"listen_address": "127.0.0.1:0", "route": route, "protocol": "a2a"},
                "target": {"endpoint": "https://agent.example"}}))
            .expect("surface JSON")
        };
        assert_eq!(surface_digest(&surface("/a")), surface_digest(&surface("/a")));
        assert_ne!(surface_digest(&surface("/a")), surface_digest(&surface("/b")));
    }

    #[test]
    fn test_auth_report_names_the_configured_method() {
        let surface = |target: serde_json::Value| -> AgentSurface {
            serde_json::from_value(json!({"surface_id": "s", "name": "s",
                "access_point": {"listen_address": "127.0.0.1:0", "route": "/a", "protocol": "a2a"},
                "target": target}))
            .expect("surface JSON")
        };
        let kind_and_result = |target| {
            let report = CardAuthReport::for_surface(&surface(target));
            (report.kind, report.result)
        };
        assert_eq!(
            kind_and_result(json!({"endpoint": "https://agent.example"})),
            (CardAuthKind::None, CardAuthResult::NotConfigured)
        );
        assert_eq!(
            kind_and_result(json!({"endpoint": "fabric://peer/agent"})),
            (CardAuthKind::RemoteGateway, CardAuthResult::NotConfigured)
        );
        assert_eq!(
            kind_and_result(json!({"endpoint": "https://agent.example", "auth": {
                "method": {"static_secret": {"secret_id": "S", "header_name": "X-Key"}}, "fallback": "reject"}})),
            (CardAuthKind::StaticSecret, CardAuthResult::NotSent)
        );
        assert_eq!(
            kind_and_result(json!({"endpoint": "https://agent.example", "auth": {
                "method": {"credential_provider": {"credential_provider_id": "cp"}}, "fallback": "reject"}})),
            (CardAuthKind::CredentialProvider, CardAuthResult::NotSent)
        );

        let mut rejected = CardAuthReport::for_surface(&surface(json!({"endpoint": "https://agent.example", "auth": {
            "method": {"credential_provider": {"credential_provider_id": "cp"}}, "fallback": "reject"}})));
        rejected.rejected(Some(TargetCredentialError::TokenUnavailable));
        assert_eq!(rejected.result, CardAuthResult::Failed);
        assert_eq!(rejected.failure, Some("token_unavailable"));

        let mut unconfigured = CardAuthReport::for_surface(&surface(json!({"endpoint": "https://agent.example"})));
        unconfigured.resolved(None);
        assert_eq!(unconfigured.result, CardAuthResult::NotConfigured, "nothing configured is not 'not sent'");
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_read_reuses_a_fresh_snapshot_of_the_same_surface_only() {
        let service = CardPreviewService::new(FETCHES_PER_MINUTE);
        let counted = Counted::new();

        let first = service
            .preview(&key(1, "u-fresh"), PreviewRequest::Read, counted.fetch())
            .await
            .expect("first read fetches");
        assert!(!first.cached);
        let again = service
            .preview(&key(1, "u-fresh"), PreviewRequest::Read, counted.fetch())
            .await
            .expect("second read");
        assert!(again.cached, "a fresh snapshot answers the read");
        assert_eq!(counted.count(), 1);

        let changed = service
            .preview(&key(2, "u-fresh"), PreviewRequest::Read, counted.fetch())
            .await
            .expect("changed surface");
        assert!(!changed.cached, "a saved or reloaded surface is never shown stale");
        assert_eq!(counted.count(), 2);

        tokio::time::advance(SNAPSHOT_FRESH + Duration::from_secs(1)).await;
        let stale = service
            .preview(&key(2, "u-fresh"), PreviewRequest::Read, counted.fetch())
            .await
            .expect("stale read");
        assert!(!stale.cached, "a snapshot older than a minute is fetched again");
        assert_eq!(counted.count(), 3);

        let refreshed = service
            .preview(&key(2, "u-fresh"), PreviewRequest::Refresh, counted.fetch())
            .await
            .expect("refresh");
        assert!(!refreshed.cached, "a refresh always fetches");
        assert_eq!(counted.count(), 4);
    }

    #[tokio::test]
    async fn test_concurrent_requests_for_one_surface_share_one_fetch() {
        let service = CardPreviewService::new(FETCHES_PER_MINUTE);
        let counted = Counted::new();
        let previews = futures::future::join_all((0..8).map(|index| {
            let request = if index % 2 == 0 {
                PreviewRequest::Read
            } else {
                PreviewRequest::Refresh
            };
            let fetch = counted.fetch();
            let service = &service;
            async move {
                service
                    .preview(&key(1, "u-flight"), request, fetch)
                    .await
            }
        }))
        .await;
        assert!(
            previews
                .iter()
                .all(Result::is_ok)
        );
        assert_eq!(counted.count(), 1, "one fetch serves every concurrent request");
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_eleventh_fetch_is_limited_and_a_read_falls_back_to_the_snapshot() {
        let service = CardPreviewService::new(FETCHES_PER_MINUTE);
        let counted = Counted::new();
        for _ in 0..FETCHES_PER_MINUTE.get() {
            service
                .preview(&key(1, "u-limit"), PreviewRequest::Refresh, counted.fetch())
                .await
                .expect("within the limit");
        }
        assert_eq!(
            service
                .preview(&key(1, "u-limit"), PreviewRequest::Refresh, counted.fetch())
                .await,
            Err(RateLimited)
        );
        assert_eq!(counted.count(), 10);

        tokio::time::advance(SNAPSHOT_FRESH + Duration::from_secs(1)).await;
        let fallback = service
            .preview(&key(1, "u-limit"), PreviewRequest::Read, counted.fetch())
            .await
            .expect("a read falls back to the snapshot");
        assert!(fallback.cached);
        assert_eq!(counted.count(), 10, "the limited read fetched nothing");
        assert_eq!(
            service
                .preview(&key(9, "u-limit"), PreviewRequest::Read, counted.fetch())
                .await,
            Err(RateLimited),
            "with no snapshot of the running surface a limited read is refused"
        );
        service
            .preview(&key(1, "u-other"), PreviewRequest::Refresh, counted.fetch())
            .await
            .expect("another user has their own limit");
    }

    #[test]
    fn test_a_sent_credential_reports_its_provider_and_expiry_and_never_its_value() {
        use crate::proxy::target_credentials::CredentialProvenance;
        let surface: AgentSurface = serde_json::from_value(json!({"surface_id": "s", "name": "s",
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/a", "protocol": "a2a"},
            "target": {"endpoint": "https://agent.example", "auth": {
                "method": {"credential_provider": {"credential_provider_id": "cp-secret-id"}}, "fallback": "reject"}}}))
        .expect("surface JSON");
        let credential = || TargetCredential {
            name: axum::http::HeaderName::from_static("authorization"),
            value: HeaderValue::from_static("Bearer SECRET-TOKEN"),
            provenance: CredentialProvenance {
                provider_name: Some("Agent provider".into()),
                expires_at: Some(std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000)),
            },
        };

        let mut report = CardAuthReport::for_surface(&surface);
        report.resolved(Some(&credential()));
        assert_eq!(
            serde_json::to_value(&report).expect("serialize"),
            json!({"kind": "credential_provider", "result": "sent", "provider_name": "Agent provider",
                "token_expires_at": "2027-01-15T08:00:00Z", "failure": null})
        );
        let serialized = serde_json::to_string(&report).expect("serialize");
        assert!(!serialized.contains("SECRET-TOKEN"), "{serialized}");
        assert!(!serialized.contains("cp-secret-id"), "{serialized}");

        let mut withheld = CardAuthReport::for_surface(&surface);
        withheld.resolved(None);
        assert_eq!(
            (withheld.result, withheld.provider_name, withheld.token_expires_at),
            (CardAuthResult::NotSent, None, None)
        );

        let static_secret: AgentSurface = serde_json::from_value(json!({"surface_id": "s", "name": "s",
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/a", "protocol": "a2a"},
            "target": {"endpoint": "https://agent.example", "auth": {
                "method": {"static_secret": {"secret_id": "S", "header_name": "X-Key"}}, "fallback": "reject"}}}))
        .expect("surface JSON");
        let mut sent = CardAuthReport::for_surface(&static_secret);
        sent.resolved(Some(&credential()));
        assert_eq!(
            (sent.result, sent.provider_name, sent.token_expires_at),
            (CardAuthResult::Sent, None, None),
            "only a credential provider names a provider and an expiry"
        );
    }

    fn running(route: &str) -> Arc<AgentSurface> {
        Arc::new(
            serde_json::from_value(json!({"surface_id": "surface-1", "name": "s",
                "access_point": {"listen_address": "127.0.0.1:0", "route": route, "protocol": "a2a"},
                "target": {"endpoint": "https://agent.example"}}))
            .expect("surface JSON"),
        )
    }

    fn card_of(displayed: Option<DisplayedCard>) -> Option<serde_json::Value> {
        DisplayedCard::into_fields(displayed).0
    }

    #[tokio::test]
    async fn test_a_failed_fetch_shows_the_last_card_served_for_the_same_running_surface() {
        let service = CardPreviewService::new(FETCHES_PER_MINUTE);
        let surface = running("/a");
        assert_eq!(
            service
                .served_card_after(&surface, None)
                .await,
            None,
            "nothing served yet"
        );

        let served = json!({"name": "agent", "url": "https://gw.example/a"});
        assert_eq!(
            card_of(
                service
                    .served_card_after(&surface, Some(served.clone()))
                    .await
            ),
            Some(served.clone())
        );
        assert_eq!(
            card_of(
                service
                    .served_card_after(&running("/a"), None)
                    .await
            ),
            Some(served.clone()),
            "a failed fetch keeps the served card of the same running surface"
        );
        assert_eq!(
            service
                .served_card_after(&running("/b"), None)
                .await,
            None,
            "a card served before the surface changed is never shown"
        );

        let caller_served = json!({"name": "agent", "url": "https://gw.example/b"});
        let changed = running("/b");
        service
            .keep_served_card(&changed, &caller_served)
            .await;
        assert_eq!(
            card_of(
                service
                    .served_card(&changed)
                    .await
            ),
            Some(caller_served)
        );
        assert_eq!(
            service
                .served_card(&surface)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_a_served_card_over_the_display_limit_is_kept_by_size_only() {
        let service = CardPreviewService::new(FETCHES_PER_MINUTE);
        let surface = running("/a");
        let big = json!({"name": "x".repeat(DISPLAY_LIMIT_BYTES)});
        service
            .keep_served_card(&surface, &big)
            .await;
        assert_eq!(
            service
                .served_card(&surface)
                .await,
            Some(DisplayedCard {
                card: None,
                bytes: DISPLAY_LIMIT_BYTES + 11
            }),
            "the size is kept for after_bytes, the card itself is not"
        );

        let small = json!({"name": "agent"});
        service
            .keep_served_card(&surface, &small)
            .await;
        assert_eq!(
            service
                .served_card(&surface)
                .await,
            Some(DisplayedCard {
                card: Some(Arc::new(small)),
                bytes: 16
            })
        );
    }

    #[tokio::test]
    async fn test_the_last_caller_fetch_rides_on_every_answer() {
        let service = CardPreviewService::new(FETCHES_PER_MINUTE);
        let counted = Counted::new();
        let before = service
            .preview(&key(1, "u-caller"), PreviewRequest::Read, counted.fetch())
            .await
            .expect("preview");
        assert_eq!(before.last_caller_fetch, None);
        let fetch = CallerFetch {
            status: CardFetchStatus::Failed,
            cause: Some(CardFetchCause::NeedsToken),
            http_status: Some(401),
            at: Utc::now(),
        };
        service
            .record_caller_fetch("surface-1", fetch.clone())
            .await;
        let cached = service
            .preview(&key(1, "u-caller"), PreviewRequest::Read, counted.fetch())
            .await
            .expect("cached preview");
        assert_eq!(cached.last_caller_fetch, Some(fetch));
    }
}
