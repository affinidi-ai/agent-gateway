//! The agent card preview: the agent's own card beside the card the gateway serves
//! for a surface's base route, with how the gateway's fetch of the agent's card went.
//!
//! The preview builds the public card in [`CardMode::Preview`], so its "after" is
//! what an anonymous caller gets, without what serving it records. When the fetch
//! fails, "after" is the preview's last good card of the same running surface, kept
//! for ten minutes after it was fetched. Everything here is per replica and in
//! memory: the last preview of each surface, the last good card and the fetch limits.

use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};
use chrono::{SecondsFormat, Utc};
use governor::clock::Clock;
use serde::Serialize;
use sha2::Digest;
use tracing::info;

use crate::config::TargetAuthMethod;
use crate::config::agent_surface::AgentSurface;
use crate::proxy::handler::TargetAuthError;
use crate::proxy::handler::agent_card::{CardMode, FetchFault, build_public_card, card_target_url};
use crate::state::ProxyState;

/// A card larger than this, serialized, is reported by size only.
pub const DISPLAY_LIMIT_BYTES: usize = 256 * 1024;
/// Card fetches one user, and one surface, may start per minute.
pub const FETCHES_PER_MINUTE: NonZeroU32 = match NonZeroU32::new(10) {
    Some(rate) => rate,
    None => panic!("the fetch rate is positive"),
};
/// How long the last preview of a surface, and its last good card, are kept.
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
    /// The card is served, but without an identity credential, because the agent's
    /// card carries no identity.
    ServedWithoutIdentity,
}

/// Why the card was not obtained or not served, or why a served card carries no
/// identity credential. Fixed strings only: no upstream
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
    IdentityMissing,
}

impl CardFetchCause {
    /// `not_served` when the card was obtained but the gateway will not serve it.
    pub fn status(self) -> CardFetchStatus {
        match self {
            Self::IdentityMissing => CardFetchStatus::ServedWithoutIdentity,
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

/// Why the gateway did not obtain its Target credential. `Forbidden` is a credential
/// a `[credential_policy]` rule in `enforce` withholds, and `InvalidHeader` a stored one
/// whose header breaks a header rule. `OutsideTargetBase` and `HeaderConflict` are never
/// reported; they keep the spellings the dashboard accepts.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(test), expect(dead_code))]
pub enum CardAuthFailure {
    SecretUnavailable,
    ProviderNotFound,
    TokenUnavailable,
    Forbidden,
    Unsupported,
    InvalidHeader,
    OutsideTargetBase,
    HeaderConflict,
}

impl CardAuthFailure {
    /// The failure a Target Authentication error reports. A secret or provider of
    /// another tenant is refused as missing, so it reports as missing too.
    pub(crate) fn of(error: TargetAuthError) -> Self {
        use crate::delegation_vault::service_token::ServiceTokenError;
        match error {
            TargetAuthError::StoreUnavailable
            | TargetAuthError::SecretNotFound
            | TargetAuthError::ServiceToken(ServiceTokenError::SecretUnavailable) => Self::SecretUnavailable,
            TargetAuthError::ProviderNotFound => Self::ProviderNotFound,
            TargetAuthError::Withheld(_) => Self::Forbidden,
            TargetAuthError::InvalidHeader => Self::InvalidHeader,
            TargetAuthError::ProviderNeedsConsent | TargetAuthError::ServiceToken(ServiceTokenError::Unsupported) => {
                Self::Unsupported
            }
            TargetAuthError::ServiceToken(_) => Self::TokenUnavailable,
        }
    }
}

/// How Target Authentication went on the card fetch. Never a credential, a secret
/// id or a provider id. `provider_name` and `token_expires_at` are always `null`.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CardAuthReport {
    pub kind: CardAuthKind,
    pub result: CardAuthResult,
    pub provider_name: Option<String>,
    pub token_expires_at: Option<String>,
    pub failure: Option<CardAuthFailure>,
}

impl CardAuthReport {
    /// The report before any fetch: what the surface configures.
    pub fn for_surface(surface: &AgentSurface) -> Self {
        let report = |kind, result| Self {
            kind,
            result,
            provider_name: None,
            token_expires_at: None,
            failure: None,
        };
        if surface
            .target
            .endpoint
            .starts_with("fabric://")
        {
            return report(CardAuthKind::RemoteGateway, CardAuthResult::NotConfigured);
        }
        match surface
            .target_auth()
            .filter(|_| !surface.is_a2a_proxy_target())
            .map(|auth| &auth.method)
        {
            None => report(CardAuthKind::None, CardAuthResult::NotConfigured),
            Some(TargetAuthMethod::StaticSecret { .. }) => report(CardAuthKind::StaticSecret, CardAuthResult::NotSent),
            Some(TargetAuthMethod::CredentialProvider { .. }) => {
                report(CardAuthKind::CredentialProvider, CardAuthResult::NotSent)
            }
            Some(TargetAuthMethod::CredentialLookup) => report(CardAuthKind::CredentialLookup, CardAuthResult::NotSent),
        }
    }

    /// Whether the fetch carried the configured credential.
    fn sent(
        &mut self,
        credential_sent: bool,
    ) {
        if credential_sent {
            self.result = CardAuthResult::Sent;
        }
    }

    /// The credential could not be obtained, so the agent was not asked.
    fn rejected(
        &mut self,
        error: TargetAuthError,
    ) {
        self.result = CardAuthResult::Failed;
        self.failure = Some(CardAuthFailure::of(error));
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CardFetchReport {
    pub status: CardFetchStatus,
    pub cause: Option<CardFetchCause>,
    pub http_status: Option<u16>,
    pub duration_ms: u64,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    NotA2a,
    NotRunning,
    /// A tenant token asked for an appliance-wide surface, whose fetch would use
    /// the appliance's Target credential.
    OperatorOnly,
}

/// `GET /v1/surfaces/{surface_id}/agent-card` and its refresh. Every field is
/// always present; `variant`, `outcome` and `last_caller_fetch` are always `null`.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct AgentCardPreview {
    pub surface_id: String,
    pub supported: bool,
    pub unsupported_reason: Option<UnsupportedReason>,
    variant: (),
    pub generated: bool,
    pub served_url: Option<String>,
    pub source_url: Option<String>,
    pub source_url_query_hidden: bool,
    pub fetched_at: Option<String>,
    pub cached: bool,
    pub fetch: Option<CardFetchReport>,
    pub auth: Option<CardAuthReport>,
    outcome: (),
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub before_bytes: Option<usize>,
    pub after_bytes: Option<usize>,
    pub display_limit_bytes: usize,
    last_caller_fetch: (),
}

impl AgentCardPreview {
    /// The preview of a surface whose card the gateway does not fetch here.
    pub fn unsupported(
        surface_id: &str,
        reason: UnsupportedReason,
    ) -> Self {
        Self {
            surface_id: surface_id.to_string(),
            supported: false,
            unsupported_reason: Some(reason),
            variant: (),
            generated: false,
            served_url: None,
            source_url: None,
            source_url_query_hidden: false,
            fetched_at: None,
            cached: false,
            fetch: None,
            auth: None,
            outcome: (),
            before: None,
            after: None,
            before_bytes: None,
            after_bytes: None,
            display_limit_bytes: 0,
            last_caller_fetch: (),
        }
    }
}

/// Why a stored surface gets no preview, before its running state is looked up: a
/// tenant token on an appliance-wide surface, a surface without an agent card, or
/// a Standby replica, which runs no surface.
pub(crate) fn unsupported_reason(
    surface: &AgentSurface,
    tenant_token: bool,
    standby: bool,
) -> Option<UnsupportedReason> {
    if tenant_token && surface.tenant_id.is_none() {
        Some(UnsupportedReason::OperatorOnly)
    } else if !surface.uses_a2a_settings() {
        Some(UnsupportedReason::NotA2a)
    } else if standby {
        Some(UnsupportedReason::NotRunning)
    } else {
        None
    }
}

/// The cause an HTTP status of the agent's answer reports. A `401` names a
/// missing token when the gateway sent none, a rejected credential otherwise.
pub fn classify_status(
    status: u16,
    credential_sent: bool,
) -> CardFetchCause {
    match status {
        401 if credential_sent => CardFetchCause::AuthFailed,
        401 => CardFetchCause::NeedsToken,
        403 => CardFetchCause::Forbidden,
        404 | 410 => CardFetchCause::NotFound,
        300..=399 => CardFetchCause::Redirected,
        _ => CardFetchCause::UpstreamError,
    }
}

/// The cause and HTTP status a fetch fault reports. A remote gateway's `401` or
/// `403` is its refusal of this gateway's authorization.
fn classify_fault(
    fault: FetchFault,
    remote_gateway: bool,
) -> (CardFetchCause, Option<u16>) {
    match fault {
        FetchFault::ProxyUnavailable => (CardFetchCause::ProxyUnavailable, None),
        FetchFault::CredentialRejected(_) => (CardFetchCause::AuthFailed, None),
        FetchFault::BlockedByEgress => (CardFetchCause::BlockedByEgress, None),
        FetchFault::Unreachable => (CardFetchCause::Unreachable, None),
        FetchFault::TimedOut => (CardFetchCause::Timeout, None),
        FetchFault::Status {
            status: status @ (401 | 403), ..
        } if remote_gateway => (CardFetchCause::AuthFailed, Some(status)),
        FetchFault::Status { status, credential_sent } => (classify_status(status, credential_sent), Some(status)),
        FetchFault::TooLarge => (CardFetchCause::TooLarge, None),
        FetchFault::InvalidCard => (CardFetchCause::InvalidCard, None),
        FetchFault::IdentityFailed => (CardFetchCause::IdentityFailed, None),
        FetchFault::RewriteFailed => (CardFetchCause::RewriteFailed, None),
    }
}

fn timestamp(at: chrono::DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
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

/// The public URL callers fetch the base route's card from: the first external
/// URL of the listener the Access Point runs on, its route and the well-known path.
pub fn served_card_url(
    surface: &AgentSurface,
    network: &crate::config::NetworkConfig,
) -> Option<String> {
    let origin = network
        .map_url_to_port(
            &surface
                .access_point
                .listen_address,
        )
        .and_then(|port| network.get_listener_by_port(port))?
        .external_urls
        .first()?;
    let access_point = format!("{}{}", origin.trim_end_matches('/'), surface.access_point.route);
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
    card: Option<serde_json::Value>,
    bytes: usize,
}

impl DisplayedCard {
    fn of(card: serde_json::Value) -> Self {
        let bytes = serialized_len(&card);
        Self {
            card: (bytes <= DISPLAY_LIMIT_BYTES).then_some(card),
            bytes,
        }
    }

    /// The card and size fields of a preview.
    fn into_fields(displayed: Option<Self>) -> (Option<serde_json::Value>, Option<usize>) {
        match displayed {
            Some(Self { card, bytes }) => (card, Some(bytes)),
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

/// The SHA-256 digest of the running surface a preview was built from.
pub fn surface_digest(surface: &AgentSurface) -> [u8; 32] {
    sha2::Sha256::digest(serde_json::to_vec(surface).unwrap_or_default()).into()
}

/// A read, which may answer from the last preview past the fetch limit, or a
/// refresh, which never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewRequest {
    Read,
    Refresh,
}

/// The user or the surface used up its burst of [`FETCHES_PER_MINUTE`] fetches, which refill one
/// every `60 / FETCHES_PER_MINUTE` seconds, and there is no preview of the running surface to
/// answer with. `retry_after_secs` is the wait until the next fetch is allowed, at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited {
    pub retry_after_secs: u64,
}

/// Who asked for a preview: the management user and, for a tenant token, its tenant.
pub struct PreviewCaller<'a> {
    pub user_id: &'a str,
    pub tenant_id: Option<&'a str>,
}

/// A preview of a surface, or its last good card, and the running surface it was
/// built from.
struct Kept<T> {
    value: T,
    digest: [u8; 32],
}

/// The last preview and the last good card of every surface on this replica, and
/// the per-user and per-surface fetch limits.
pub struct PreviewMemory {
    previews: moka::future::Cache<String, Arc<Kept<AgentCardPreview>>>,
    good_cards: moka::future::Cache<String, Arc<Kept<DisplayedCard>>>,
    user_fetches: governor::DefaultKeyedRateLimiter<String>,
    surface_fetches: governor::DefaultKeyedRateLimiter<String>,
}

impl PreviewMemory {
    pub fn new(fetches_per_minute: NonZeroU32) -> Self {
        let quota = governor::Quota::per_minute(fetches_per_minute);
        Self {
            previews: surface_cache(),
            good_cards: surface_cache(),
            user_fetches: governor::RateLimiter::keyed(quota),
            surface_fetches: governor::RateLimiter::keyed(quota),
        }
    }

    /// Whether `user_id` and `surface_id` may each start another fetch; otherwise how long the
    /// refused one must wait. The user is checked first, so a user past their own limit takes
    /// nothing from the surface.
    fn admit(
        &self,
        user_id: &str,
        surface_id: &str,
    ) -> Result<(), RateLimited> {
        self.user_fetches
            .retain_recent();
        self.surface_fetches
            .retain_recent();
        let now = governor::clock::DefaultClock::default().now();
        let refused = |not_until: governor::NotUntil<governor::clock::QuantaInstant>| {
            let wait = not_until.wait_time_from(now);
            RateLimited {
                retry_after_secs: (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1),
            }
        };
        self.user_fetches
            .check_key(&user_id.to_string())
            .map_err(refused)?;
        self.surface_fetches
            .check_key(&surface_id.to_string())
            .map_err(refused)
    }

    async fn kept<T: Clone + Send + Sync + 'static>(
        cache: &moka::future::Cache<String, Arc<Kept<T>>>,
        surface_id: &str,
        digest: [u8; 32],
    ) -> Option<T> {
        cache
            .get(surface_id)
            .await
            .filter(|kept| kept.digest == digest)
            .map(|kept| kept.value.clone())
    }

    /// The preview of the running `state`, fetched for `caller` within the fetch
    /// limits. A surface deriving a DID from an API key it may not use gets no
    /// preview and no fetch. Past either limit, a read answers with the last preview of the same
    /// running surface, marked `cached`; a refresh, or a read without one, is
    /// [`RateLimited`]. Every fetch is audited.
    pub(crate) async fn preview(
        &self,
        state: &ProxyState,
        caller: &PreviewCaller<'_>,
        request: PreviewRequest,
    ) -> Result<AgentCardPreview, RateLimited> {
        let surface_id = state
            .surface
            .surface_id
            .as_str();
        if crate::identity::provider_key_gate::gate()
            .refuses(&state.surface)
            .await
            .is_some()
        {
            return Ok(AgentCardPreview::unsupported(surface_id, UnsupportedReason::NotRunning));
        }
        let digest = surface_digest(&state.surface);
        if let Err(limited) = self.admit(caller.user_id, surface_id) {
            if request == PreviewRequest::Refresh {
                return Err(limited);
            }
            let mut last = Self::kept(&self.previews, surface_id, digest)
                .await
                .ok_or(limited)?;
            last.cached = true;
            return Ok(last);
        }

        let deadline = preview_deadline(
            state
                .config
                .a2a
                .timeout_seconds,
        );
        let (preview, good) = fetch_preview(state, deadline).await;
        let preview = match good {
            Some(good) => {
                self.good_cards
                    .insert(surface_id.to_string(), Arc::new(Kept { value: good, digest }))
                    .await;
                preview
            }
            None => {
                let (after, after_bytes) =
                    DisplayedCard::into_fields(Self::kept(&self.good_cards, surface_id, digest).await);
                AgentCardPreview { after, after_bytes, ..preview }
            }
        };
        self.previews
            .insert(surface_id.to_string(), Arc::new(Kept { value: preview.clone(), digest }))
            .await;
        audit_preview_fetch(caller, request, &preview);
        Ok(preview)
    }
}

fn surface_cache<V: Clone + Send + Sync + 'static>() -> moka::future::Cache<String, V> {
    moka::future::Cache::builder()
        .max_capacity(MAX_SURFACES)
        .time_to_live(PREVIEW_MEMORY_TTL)
        .build()
}

/// The preview memory every surface on this replica shares.
pub fn preview_memory() -> &'static PreviewMemory {
    static MEMORY: LazyLock<PreviewMemory> = LazyLock::new(|| PreviewMemory::new(FETCHES_PER_MINUTE));
    &MEMORY
}

/// Build the base route's card as an anonymous caller would get it, without what
/// serving it records, and report how it went, with the served card when the fetch
/// succeeded. The request carries only `Accept: application/json` and any Target
/// credential; nothing from the management request reaches the agent. A build
/// still running at `deadline` reports a `timeout`.
async fn fetch_preview(
    state: &ProxyState,
    deadline: Duration,
) -> (AgentCardPreview, Option<DisplayedCard>) {
    let surface = state.surface.as_ref();
    let started = std::time::Instant::now();
    let fetched_at = Utc::now();
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    let built =
        tokio::time::timeout(deadline, build_public_card(state, &headers, PREVIEW_SOURCE, CardMode::Preview, None))
            .await
            .ok();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let mut auth = CardAuthReport::for_surface(surface);
    let (reported, upstream, served) = match built {
        Some(Ok(card)) => {
            auth.sent(card.credential_sent);
            let cause = card
                .served_without_identity
                .then_some((CardFetchCause::IdentityMissing, None));
            (cause, card.upstream, Some(card.served))
        }
        Some(Err(failure)) => {
            auth.sent(failure.credential_sent);
            if let FetchFault::CredentialRejected(error) = failure.fault {
                auth.rejected(error);
            }
            let remote_gateway = auth.kind == CardAuthKind::RemoteGateway;
            (Some(classify_fault(failure.fault, remote_gateway)), failure.upstream, None)
        }
        None => (Some((CardFetchCause::Timeout, None)), None, None),
    };
    let fetch = CardFetchReport {
        status: reported.map_or(CardFetchStatus::Ok, |(cause, _)| cause.status()),
        cause: reported.map(|(cause, _)| cause),
        http_status: reported.and_then(|(_, http_status)| http_status),
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
            .map(DisplayedCard::of),
    );
    let good = served.map(DisplayedCard::of);
    let (after, after_bytes) = DisplayedCard::into_fields(good.clone());
    info!(
        surface_id = %surface.surface_id,
        cause = ?fetch.cause,
        duration_ms,
        "Agent card preview fetched"
    );
    let preview = AgentCardPreview {
        surface_id: surface.surface_id.clone(),
        supported: true,
        unsupported_reason: None,
        generated,
        served_url: served_card_url(surface, &state.network_config),
        source_url,
        source_url_query_hidden,
        fetched_at: Some(timestamp(fetched_at)),
        fetch: Some(fetch),
        auth: Some(auth),
        before,
        after,
        before_bytes,
        after_bytes,
        display_limit_bytes: DISPLAY_LIMIT_BYTES,
        ..AgentCardPreview::unsupported(&surface.surface_id, UnsupportedReason::NotRunning)
    };
    (preview, good)
}

/// The wire spelling of a preview enum, empty for none.
fn spelling<T: Serialize>(value: Option<T>) -> String {
    value
        .and_then(|value| serde_json::to_value(value).ok())
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// Records on the `audit` target that a management user started a card fetch.
/// Never a credential, a provider, a URL or card content.
fn audit_preview_fetch(
    caller: &PreviewCaller<'_>,
    request: PreviewRequest,
    preview: &AgentCardPreview,
) {
    let auth = preview.auth.as_ref();
    let fetch = preview.fetch.as_ref();
    info!(
        target: "audit",
        event = "agent_card.preview_fetch",
        request = match request {
            PreviewRequest::Read => "read",
            PreviewRequest::Refresh => "refresh",
        },
        caller_user_id = %caller.user_id,
        tenant_id = caller.tenant_id.unwrap_or(""),
        surface_id = %preview.surface_id,
        auth_kind = %spelling(auth.map(|auth| auth.kind)),
        auth_result = %spelling(auth.map(|auth| auth.result)),
        auth_failure = %spelling(auth.and_then(|auth| auth.failure)),
        fetch_status = %spelling(fetch.map(|fetch| fetch.status)),
        cause = %spelling(fetch.and_then(|fetch| fetch.cause)),
        "Agent card preview fetch"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    use serde_json::json;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;
    use crate::component_tests::helpers::audit_events::AuditEvents;
    use crate::component_tests::helpers::{MockServer, RecordingTarget};
    use crate::delegation_vault::service_token::ServiceTokenError;

    fn surface_with(
        surface_id: &str,
        target: serde_json::Value,
    ) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": surface_id, "name": surface_id,
            "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
            "target": target
        }))
        .unwrap()
    }

    async fn running(surface: AgentSurface) -> ProxyState {
        let surface_id = surface.surface_id.clone();
        crate::proxy::handler::variant_routing_tests::router(surface)
            .base_proxy_state(&surface_id)
            .await
            .unwrap()
    }

    async fn state(target: serde_json::Value) -> ProxyState {
        running(surface_with("orders", target)).await
    }

    fn assert_limited(
        result: Result<AgentCardPreview, RateLimited>,
        why: &str,
    ) {
        let limited = result.expect_err(why);
        assert!(
            (1..=60 / FETCHES_PER_MINUTE.get() as u64).contains(&limited.retry_after_secs),
            "{why}: waits {} s, not a minute",
            limited.retry_after_secs
        );
    }

    fn caller(user_id: &str) -> PreviewCaller<'_> {
        PreviewCaller { user_id, tenant_id: None }
    }

    fn agent_card() -> serde_json::Value {
        json!({"name": "Orders agent", "url": "http://agent.internal/a2a", "skills": []})
    }

    fn fetch_of(preview: &AgentCardPreview) -> (CardFetchStatus, Option<CardFetchCause>, Option<u16>) {
        let fetch = preview
            .fetch
            .as_ref()
            .expect("a supported preview reports its fetch");
        (fetch.status, fetch.cause, fetch.http_status)
    }

    fn auth_of(preview: &AgentCardPreview) -> (CardAuthKind, CardAuthResult, Option<CardAuthFailure>) {
        let auth = preview
            .auth
            .as_ref()
            .expect("a supported preview reports its auth");
        (auth.kind, auth.result, auth.failure)
    }

    #[test]
    fn every_preview_key_and_enum_has_its_wire_spelling() {
        let value = serde_json::to_value(AgentCardPreview::unsupported("s-1", UnsupportedReason::NotA2a)).unwrap();
        assert_eq!(
            value,
            json!({
                "surface_id": "s-1", "supported": false, "unsupported_reason": "not_a2a", "variant": null,
                "generated": false, "served_url": null, "source_url": null, "source_url_query_hidden": false,
                "fetched_at": null, "cached": false, "fetch": null, "auth": null, "outcome": null,
                "before": null, "after": null, "before_bytes": null, "after_bytes": null,
                "display_limit_bytes": 0, "last_caller_fetch": null
            })
        );

        let spellings = |values: Vec<serde_json::Value>| -> Vec<String> {
            values
                .into_iter()
                .map(|value| {
                    value
                        .as_str()
                        .unwrap()
                        .to_string()
                })
                .collect()
        };
        use CardFetchCause::*;
        assert_eq!(
            spellings(
                [
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
                    IdentityMissing
                ]
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
                "rewrite_failed",
                "identity_missing"
            ]
        );
        assert_eq!(
            spellings(vec![
                json!(CardAuthFailure::SecretUnavailable),
                json!(CardAuthFailure::ProviderNotFound),
                json!(CardAuthFailure::TokenUnavailable),
                json!(CardAuthFailure::Forbidden),
                json!(CardAuthFailure::Unsupported),
                json!(CardAuthFailure::InvalidHeader),
                json!(CardAuthFailure::OutsideTargetBase),
                json!(CardAuthFailure::HeaderConflict),
            ]),
            [
                "secret_unavailable",
                "provider_not_found",
                "token_unavailable",
                "forbidden",
                "unsupported",
                "invalid_header",
                "outside_target_base",
                "header_conflict"
            ]
        );
        assert_eq!(
            spellings(vec![
                json!(CardFetchStatus::Ok),
                json!(CardFetchStatus::Failed),
                json!(CardFetchStatus::NotServed),
                json!(CardFetchStatus::ServedWithoutIdentity),
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
                json!(UnsupportedReason::OperatorOnly),
            ]),
            [
                "ok",
                "failed",
                "not_served",
                "served_without_identity",
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
                "operator_only"
            ]
        );
        assert_eq!(IdentityFailed.status(), CardFetchStatus::NotServed);
        assert_eq!(RewriteFailed.status(), CardFetchStatus::NotServed);
        assert_eq!(NeedsToken.status(), CardFetchStatus::Failed);
        assert_eq!(IdentityMissing.status(), CardFetchStatus::ServedWithoutIdentity);
    }

    #[test]
    fn an_answer_status_names_its_cause() {
        assert_eq!(classify_status(401, false), CardFetchCause::NeedsToken);
        assert_eq!(classify_status(401, true), CardFetchCause::AuthFailed);
        assert_eq!(classify_status(403, false), CardFetchCause::Forbidden);
        assert_eq!(classify_status(403, true), CardFetchCause::Forbidden);
        assert_eq!(classify_status(404, false), CardFetchCause::NotFound);
        assert_eq!(classify_status(410, true), CardFetchCause::NotFound);
        for status in [301, 302, 307, 308] {
            assert_eq!(classify_status(status, true), CardFetchCause::Redirected, "{status}");
        }
        for status in [400, 429, 500, 503] {
            assert_eq!(classify_status(status, false), CardFetchCause::UpstreamError, "{status}");
        }

        let refused = FetchFault::Status {
            status: 403,
            credential_sent: false,
        };
        assert_eq!(classify_fault(refused, true), (CardFetchCause::AuthFailed, Some(403)));
        assert_eq!(classify_fault(refused, false), (CardFetchCause::Forbidden, Some(403)));
        assert_eq!(
            classify_fault(
                FetchFault::Status {
                    status: 503,
                    credential_sent: false
                },
                true
            ),
            (CardFetchCause::UpstreamError, Some(503)),
            "only a refusal is the remote gateway's sign-in"
        );
        assert_eq!(
            classify_fault(FetchFault::CredentialRejected(TargetAuthError::SecretNotFound), false),
            (CardFetchCause::AuthFailed, None)
        );
    }

    #[test]
    fn a_target_authentication_error_names_its_failure() {
        for (error, expected) in [
            (TargetAuthError::StoreUnavailable, CardAuthFailure::SecretUnavailable),
            (TargetAuthError::SecretNotFound, CardAuthFailure::SecretUnavailable),
            (TargetAuthError::ProviderNotFound, CardAuthFailure::ProviderNotFound),
            (TargetAuthError::ProviderNeedsConsent, CardAuthFailure::Unsupported),
            (
                TargetAuthError::Withheld(crate::config::target_auth_rules::TargetCredentialRule::Https),
                CardAuthFailure::Forbidden,
            ),
            (TargetAuthError::InvalidHeader, CardAuthFailure::InvalidHeader),
            (TargetAuthError::ServiceToken(ServiceTokenError::TokenRequestFailed), CardAuthFailure::TokenUnavailable),
            (TargetAuthError::ServiceToken(ServiceTokenError::TokenEndpointRefused), CardAuthFailure::TokenUnavailable),
            (
                TargetAuthError::ServiceToken(ServiceTokenError::TokenEndpointNotHttps),
                CardAuthFailure::TokenUnavailable,
            ),
            (TargetAuthError::ServiceToken(ServiceTokenError::SecretUnavailable), CardAuthFailure::SecretUnavailable),
            (TargetAuthError::ServiceToken(ServiceTokenError::Unsupported), CardAuthFailure::Unsupported),
        ] {
            assert_eq!(CardAuthFailure::of(error), expected, "{error:?}");
        }
    }

    #[test]
    fn the_auth_report_names_the_configured_method() {
        let kind_and_result = |target| {
            let report = CardAuthReport::for_surface(&surface_with("s", target));
            (report.kind, report.result, report.provider_name, report.token_expires_at)
        };
        for (target, kind, result) in [
            (json!({"endpoint": "https://agent.example"}), CardAuthKind::None, CardAuthResult::NotConfigured),
            (json!({"endpoint": "fabric://peer/agent"}), CardAuthKind::RemoteGateway, CardAuthResult::NotConfigured),
            (
                json!({"endpoint": "https://agent.example", "auth": {"method": {"static_secret": {"secret_id": "S", "header_name": "x-key"}}}}),
                CardAuthKind::StaticSecret,
                CardAuthResult::NotSent,
            ),
            (
                json!({"endpoint": "https://agent.example", "auth": {"method": {"credential_provider": {"provider_id": "cp"}}}}),
                CardAuthKind::CredentialProvider,
                CardAuthResult::NotSent,
            ),
        ] {
            assert_eq!(kind_and_result(target.clone()), (kind, result, None, None), "{target}");
        }

        let mut report = CardAuthReport::for_surface(&surface_with("s", json!({"endpoint": "https://agent.example"})));
        report.sent(false);
        assert_eq!(report.result, CardAuthResult::NotConfigured, "nothing configured is not 'not sent'");
    }

    #[test]
    fn a_tenant_token_never_previews_an_appliance_wide_surface() {
        let appliance = surface_with("s", json!({"endpoint": "https://agent.example"}));
        let mut tenant = appliance.clone();
        tenant.tenant_id = Some("tenant-a".into());
        let mut mcp = tenant.clone();
        mcp.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;

        assert_eq!(unsupported_reason(&appliance, true, false), Some(UnsupportedReason::OperatorOnly));
        assert_eq!(unsupported_reason(&appliance, false, false), None);
        assert_eq!(unsupported_reason(&tenant, true, false), None);
        assert_eq!(unsupported_reason(&mcp, true, false), Some(UnsupportedReason::NotA2a));
        assert_eq!(unsupported_reason(&tenant, true, true), Some(UnsupportedReason::NotRunning));
        assert_eq!(
            unsupported_reason(&appliance, true, true),
            Some(UnsupportedReason::OperatorOnly),
            "a tenant learns nothing more of an appliance-wide surface on a Standby replica"
        );
    }

    #[test]
    fn a_displayed_card_url_hides_user_info_and_query() {
        assert_eq!(
            displayable_card_url("https://agent.example/api/.well-known/agent-card.json"),
            (Some("https://agent.example/api/.well-known/agent-card.json".to_string()), false)
        );
        assert_eq!(
            displayable_card_url("https://agent.example/card.json?code=SECRET-KEY"),
            (Some("https://agent.example/card.json".to_string()), true)
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
    fn the_served_url_is_the_listener_origin_and_the_route() {
        let network: crate::config::NetworkConfig = serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
                "protocol": "http", "external_urls": ["https://gateway.example", "https://other.example"]}],
            "routes": {"identity": {"type": "identity_api", "prefix": "/api"}}
        }))
        .unwrap();
        let surface = surface_with("s", json!({"endpoint": "https://agent.example"}));
        assert_eq!(
            served_card_url(&surface, &network).as_deref(),
            Some("https://gateway.example/a2a/.well-known/agent-card.json")
        );
        let mut elsewhere = surface;
        elsewhere
            .access_point
            .listen_address = "https://unknown.example".into();
        assert_eq!(served_card_url(&elsewhere, &network), None);
    }

    #[test]
    fn the_deadline_adds_a_margin_and_is_capped_at_a_minute() {
        assert_eq!(preview_deadline(30), Duration::from_secs(35));
        assert_eq!(preview_deadline(1), Duration::from_secs(6));
        assert_eq!(preview_deadline(55), Duration::from_secs(60));
        assert_eq!(preview_deadline(u64::MAX), Duration::from_secs(60));
    }

    #[test]
    fn a_card_over_the_display_limit_is_reported_by_size_only() {
        let shown = |card: serde_json::Value| DisplayedCard::into_fields(Some(DisplayedCard::of(card)));
        let small = json!({"name": "agent"});
        assert_eq!(shown(small.clone()), (Some(small), Some(16)));
        let big = json!({"name": "x".repeat(DISPLAY_LIMIT_BYTES)});
        assert_eq!(shown(big), (None, Some(DISPLAY_LIMIT_BYTES + 11)));
        let at_limit = json!({"name": "x".repeat(DISPLAY_LIMIT_BYTES - 11)});
        assert_eq!(shown(at_limit.clone()), (Some(at_limit), Some(DISPLAY_LIMIT_BYTES)));
        assert_eq!(DisplayedCard::into_fields(None), (None, None));
        for card in [json!({"name": "agent", "skills": [1, 2, {"id": "é"}]}), json!([])] {
            assert_eq!(
                serialized_len(&card),
                serde_json::to_vec(&card)
                    .unwrap()
                    .len(),
                "{card}"
            );
        }
    }

    #[test]
    fn the_digest_changes_with_the_surface() {
        let surface = |endpoint: &str| surface_with("s", json!({"endpoint": endpoint}));
        assert_eq!(surface_digest(&surface("https://a.example")), surface_digest(&surface("https://a.example")));
        assert_ne!(surface_digest(&surface("https://a.example")), surface_digest(&surface("https://b.example")));
    }

    #[tokio::test]
    async fn a_card_without_an_identity_previews_as_served_without_identity() {
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let mut surface = surface_with("orders", json!({"endpoint": target.url()}));
        surface
            .identity_slots
            .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
            crate::source_auth::models::PayloadExtractionConfig {
                meta_field: "agentIdentity".to_string(),
                ..Default::default()
            },
        ));
        let state = running(surface).await;

        let memory = PreviewMemory::new(FETCHES_PER_MINUTE);
        let preview = memory
            .preview(&state, &caller("u-no-identity"), PreviewRequest::Read)
            .await
            .unwrap();

        assert_eq!(
            fetch_of(&preview),
            (CardFetchStatus::ServedWithoutIdentity, Some(CardFetchCause::IdentityMissing), None)
        );
        assert_eq!(preview.before, Some(agent_card()));
        let served = preview
            .after
            .clone()
            .expect("the served card is shown");
        assert_ne!(served["url"], agent_card()["url"], "the card points at the gateway");
        assert!(
            memory
                .good_cards
                .get("orders")
                .await
                .is_some(),
            "the card counts as the last good card"
        );
    }

    #[tokio::test]
    async fn a_card_without_an_identity_on_a_surface_without_managed_identity_previews_ok() {
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let state = state(json!({"endpoint": target.url()})).await;

        let preview = PreviewMemory::new(FETCHES_PER_MINUTE)
            .preview(&state, &caller("u-unmanaged"), PreviewRequest::Read)
            .await
            .unwrap();

        assert_eq!(fetch_of(&preview), (CardFetchStatus::Ok, None, None));
    }

    #[tokio::test]
    async fn a_preview_shows_the_agents_card_beside_the_card_callers_get() {
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let state = state(json!({"endpoint": target.url()})).await;

        let preview = PreviewMemory::new(FETCHES_PER_MINUTE)
            .preview(&state, &caller("u-shown"), PreviewRequest::Read)
            .await
            .unwrap();

        assert_eq!(fetch_of(&preview), (CardFetchStatus::Ok, None, None));
        assert_eq!(auth_of(&preview), (CardAuthKind::None, CardAuthResult::NotConfigured, None));
        assert!(preview.supported && !preview.cached && !preview.generated);
        assert_eq!(preview.before, Some(agent_card()));
        assert_eq!(preview.before_bytes, Some(serialized_len(&agent_card())));
        let after = preview.after.clone().unwrap();
        assert_eq!(after["name"], "Orders agent");
        assert_ne!(after["url"], "http://agent.internal/a2a", "the served card points at the Access Point");
        assert_eq!(preview.after_bytes, Some(serialized_len(&after)));
        assert_eq!(preview.served_url.as_deref(), Some("https://gateway.example/a2a/.well-known/agent-card.json"));
        assert_eq!(preview.source_url, Some(format!("{}/.well-known/agent-card.json", target.url())));
        assert!(!preview.source_url_query_hidden);
        assert_eq!(preview.display_limit_bytes, DISPLAY_LIMIT_BYTES);
        assert!(
            preview
                .fetched_at
                .as_deref()
                .is_some_and(|at| at.ends_with('Z'))
        );
        let received = target
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        assert_eq!(received.path, "/.well-known/agent-card.json");
        assert_eq!(
            received
                .headers
                .get("accept")
                .map(String::as_str),
            Some("application/json")
        );
        assert!(
            !received
                .headers
                .contains_key("authorization")
                && !received
                    .headers
                    .contains_key("cookie")
        );
    }

    #[tokio::test]
    async fn a_surface_naming_another_tenants_api_key_gets_no_preview_and_no_fetch() {
        let _gate = crate::identity::provider_key_gate::test_support::enforced_gate(
            &[("own", Some("tenant-a")), ("owner-b", Some("tenant-b"))],
            &[("own", "atgk_preview_a"), ("owner-b", "atgk_preview_b")],
        )
        .await;
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let naming = |surface_id: &str, key_id: &str| {
            let mut surface = surface_with(surface_id, json!({"endpoint": target.url()}));
            surface.tenant_id = Some("tenant-a".into());
            surface
                .identity_slots
                .external =
                Some(serde_json::from_value(json!({"type": "from_api_key", "api_key_id": key_id})).unwrap());
            surface
        };
        let memory = PreviewMemory::new(FETCHES_PER_MINUTE);

        let refused = memory
            .preview(&running(naming("cross", "atgk_preview_b")).await, &caller("u-gate"), PreviewRequest::Read)
            .await
            .unwrap();
        assert_eq!(refused, AgentCardPreview::unsupported("cross", UnsupportedReason::NotRunning));
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0,
            "a not-ready surface is never fetched"
        );
        assert!(
            memory
                .previews
                .get("cross")
                .await
                .is_none()
                && memory
                    .good_cards
                    .get("cross")
                    .await
                    .is_none(),
            "nothing is kept"
        );

        let shown = memory
            .preview(&running(naming("own", "atgk_preview_a")).await, &caller("u-gate"), PreviewRequest::Read)
            .await
            .unwrap();
        assert_eq!(fetch_of(&shown), (CardFetchStatus::Ok, None, None));
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn a_surface_naming_its_revoked_api_key_gets_no_preview_and_no_fetch() {
        use crate::api_keys::store::ApiKeyStore as _;
        let gate = crate::identity::provider_key_gate::test_support::enforced_gate(
            &[("own", Some("tenant-a"))],
            &[("own", "atgk_preview_revoked")],
        )
        .await;
        crate::config::credential_policy::use_thread_credential_policy(Default::default());
        gate.api_keys
            .revoke("own", "atgk_preview_revoked", "test")
            .await
            .unwrap();
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let mut surface = surface_with("own", json!({"endpoint": target.url()}));
        surface.tenant_id = Some("tenant-a".into());
        surface
            .identity_slots
            .external = Some(
            serde_json::from_value(json!({"type": "from_api_key", "api_key_id": "atgk_preview_revoked"})).unwrap(),
        );
        let memory = PreviewMemory::new(FETCHES_PER_MINUTE);

        let refused = memory
            .preview(&running(surface).await, &caller("u-gate"), PreviewRequest::Read)
            .await
            .unwrap();

        assert_eq!(refused, AgentCardPreview::unsupported("own", UnsupportedReason::NotRunning));
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0,
            "a surface naming a revoked key is never fetched"
        );
    }

    #[tokio::test]
    async fn a_failed_fetch_shows_the_last_good_card_of_the_same_running_surface_only() {
        let (target, answer) = MockServer::start_with_response_channel(agent_card().to_string()).await;
        let state = state(json!({"endpoint": target.url()})).await;
        let memory = PreviewMemory::new(FETCHES_PER_MINUTE);
        let good = memory
            .preview(&state, &caller("u-good"), PreviewRequest::Read)
            .await
            .unwrap();
        assert_eq!(fetch_of(&good).0, CardFetchStatus::Ok);

        answer
            .send("not a card".to_string())
            .unwrap();
        let failed = memory
            .preview(&state, &caller("u-good"), PreviewRequest::Refresh)
            .await
            .unwrap();
        assert_eq!(fetch_of(&failed), (CardFetchStatus::Failed, Some(CardFetchCause::InvalidCard), None));
        assert_eq!(failed.before, None);
        assert_eq!(failed.after, good.after, "the last good card stays on screen");
        assert_eq!(failed.after_bytes, good.after_bytes);
        assert!(!failed.cached, "the failure is a new fetch");

        let mut changed = surface_with("orders", json!({"endpoint": target.url()}));
        changed.name = "Orders renamed".into();
        let changed = running(changed).await;
        let failed = memory
            .preview(&changed, &caller("u-good"), PreviewRequest::Refresh)
            .await
            .unwrap();
        assert_eq!(fetch_of(&failed).1, Some(CardFetchCause::InvalidCard));
        assert_eq!((failed.after, failed.after_bytes), (None, None), "a card of a changed surface is never shown");
    }

    #[tokio::test]
    async fn the_eleventh_fetch_of_a_user_is_limited_and_a_read_answers_with_the_last_preview() {
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let orders = state(json!({"endpoint": target.url()})).await;
        let billing = running(surface_with("billing", json!({"endpoint": target.url()}))).await;
        let memory = PreviewMemory::new(FETCHES_PER_MINUTE);
        let mut last = None;
        for _ in 0..FETCHES_PER_MINUTE.get() {
            last = Some(
                memory
                    .preview(&orders, &caller("u-limit"), PreviewRequest::Refresh)
                    .await
                    .unwrap(),
            );
        }
        let fetched = target
            .request_count
            .load(Ordering::SeqCst);
        assert_eq!(fetched, 10);

        assert_limited(
            memory
                .preview(&orders, &caller("u-limit"), PreviewRequest::Refresh)
                .await,
            "",
        );
        let cached = memory
            .preview(&orders, &caller("u-limit"), PreviewRequest::Read)
            .await
            .unwrap();
        assert!(cached.cached);
        let last = last.unwrap();
        assert_eq!((cached.fetched_at, cached.after), (last.fetched_at, last.after));
        assert_limited(
            memory
                .preview(&billing, &caller("u-limit"), PreviewRequest::Read)
                .await,
            "the user's limit covers every surface, and billing has no preview to answer with",
        );
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            fetched,
            "a limited request fetches nothing"
        );
    }

    #[tokio::test]
    async fn the_eleventh_fetch_of_a_surface_is_limited_whoever_asks() {
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let orders = state(json!({"endpoint": target.url()})).await;
        let billing = running(surface_with("billing", json!({"endpoint": target.url()}))).await;
        let memory = PreviewMemory::new(FETCHES_PER_MINUTE);
        for user in 0..FETCHES_PER_MINUTE.get() {
            memory
                .preview(&orders, &caller(&format!("u-{user}")), PreviewRequest::Refresh)
                .await
                .unwrap();
        }
        assert_limited(
            memory
                .preview(&orders, &caller("u-new"), PreviewRequest::Refresh)
                .await,
            "",
        );
        let other = memory
            .preview(&billing, &caller("u-new"), PreviewRequest::Refresh)
            .await
            .unwrap();
        assert!(!other.cached, "another surface has its own limit");
    }

    #[tokio::test]
    async fn a_user_past_their_limit_takes_nothing_from_the_surface_limit() {
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let orders = state(json!({"endpoint": target.url()})).await;
        let billing = running(surface_with("billing", json!({"endpoint": target.url()}))).await;
        let memory = PreviewMemory::new(FETCHES_PER_MINUTE);
        for _ in 0..FETCHES_PER_MINUTE.get() {
            memory
                .preview(&billing, &caller("u-busy"), PreviewRequest::Refresh)
                .await
                .unwrap();
        }
        for _ in 0..FETCHES_PER_MINUTE.get() {
            assert_limited(
                memory
                    .preview(&orders, &caller("u-busy"), PreviewRequest::Refresh)
                    .await,
                "",
            );
        }
        for user in 0..FETCHES_PER_MINUTE.get() {
            let preview = memory
                .preview(&orders, &caller(&format!("u-{user}")), PreviewRequest::Refresh)
                .await
                .unwrap();
            assert!(!preview.cached, "refused requests left the surface's whole quota to others");
        }
        assert_limited(
            memory
                .preview(&orders, &caller("u-new"), PreviewRequest::Refresh)
                .await,
            "the surface limit still applies once its own quota is used",
        );
    }

    #[tokio::test]
    async fn a_build_past_the_deadline_is_a_timeout() {
        let target = MockServer::start_with_delay(Duration::from_secs(5), agent_card().to_string()).await;
        let state = state(json!({"endpoint": target.url()})).await;

        let (preview, good) = fetch_preview(&state, Duration::from_millis(200)).await;

        assert_eq!(fetch_of(&preview), (CardFetchStatus::Failed, Some(CardFetchCause::Timeout), None));
        assert_eq!(good, None);
        assert_eq!(preview.after, None);
    }

    #[tokio::test]
    async fn a_private_metadata_target_is_blocked_by_egress_and_records_nothing() {
        let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
        let state = ProxyState {
            metrics_store: Some(metrics.clone()),
            ..state(json!({"endpoint": "http://169.254.169.254/agent"})).await
        };

        let (preview, _) = fetch_preview(&state, Duration::from_secs(5)).await;

        assert_eq!(fetch_of(&preview), (CardFetchStatus::Failed, Some(CardFetchCause::BlockedByEgress), None));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            metrics
                .get_recent_connections(10)
                .await
                .is_empty(),
            "a preview records no connection"
        );
    }

    #[tokio::test]
    async fn an_unobtainable_credential_fails_without_asking_the_agent() {
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let state = state(json!({"endpoint": target.url(), "auth": {
            "method": {"static_secret": {"secret_id": "missing", "header_name": "x-key"}}}}))
        .await;

        let ((preview, _), events) =
            crate::audit::producer::capture(fetch_preview(&state, Duration::from_secs(5))).await;

        let records: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.event {
                crate::delegation_vault::audit::DelegationAuditAction::RequestRejected {
                    reason, target_auth, ..
                } => Some((
                    *reason,
                    target_auth
                        .as_ref()
                        .map(|detail| detail.outcome),
                    event.surface_id.clone(),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            records,
            vec![(
                crate::audit::request_events::RejectionReason::TargetAuthFailed,
                Some(crate::audit::request_events::TargetAuthOutcome::Rejected),
                Some("orders".to_string())
            )],
            "the preview records the credential it could not obtain once"
        );
        assert_eq!(fetch_of(&preview), (CardFetchStatus::Failed, Some(CardFetchCause::AuthFailed), None));
        assert_eq!(
            auth_of(&preview),
            (CardAuthKind::StaticSecret, CardAuthResult::Failed, Some(CardAuthFailure::SecretUnavailable))
        );
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_credential_providers_token_is_sent_and_never_reported() {
        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};

        let directory = tempfile::tempdir().unwrap();
        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                directory
                    .path()
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "api key".into(),
                secret_id: "CARD_API_KEY".into(),
                description: None,
                value: "API-KEY-VALUE".into(),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        let providers = FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        providers
            .create(
                serde_json::from_value(json!({
                    "id": "card-provider", "name": "Card provider", "provider_id": "card-provider",
                    "provider_type": "api_key", "api_key_secret_ref": "CARD_API_KEY",
                    "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let providers: Arc<dyn CredentialProviderStorage> = Arc::new(providers);
        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
            FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let target = MockServer::start_with_response(agent_card().to_string()).await;
        let state = ProxyState {
            secrets_store: Some(secrets),
            credential_provider_store: Some(providers),
            delegation_vault_store: Some(vault),
            ..state(json!({"endpoint": target.url(), "auth": {"method": {"credential_provider": {
                "provider_id": "card-provider", "header_name": "x-api-key", "header_format": "{value}"}}}}))
            .await
        };

        let (preview, _) = fetch_preview(&state, Duration::from_secs(5)).await;

        assert_eq!(fetch_of(&preview), (CardFetchStatus::Ok, None, None));
        assert_eq!(auth_of(&preview), (CardAuthKind::CredentialProvider, CardAuthResult::Sent, None));
        let received = target
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        assert_eq!(
            received
                .headers
                .get("x-api-key")
                .map(String::as_str),
            Some("API-KEY-VALUE")
        );
        let serialized = serde_json::to_value(&preview).unwrap();
        assert_eq!(
            serialized["auth"],
            json!({"kind": "credential_provider", "result": "sent", "provider_name": null,
                "token_expires_at": null, "failure": null})
        );
        let serialized = serialized.to_string();
        assert!(!serialized.contains("API-KEY-VALUE") && !serialized.contains("card-provider"), "{serialized}");
    }

    /// Every event on the gateway's own targets and the `audit` target, formatted.
    struct GatewayLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for GatewayLogs {
        fn write(
            &mut self,
            buf: &[u8],
        ) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap()
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A layer formatting the gateway's own and `audit` events at `level` and above
    /// into the returned buffer.
    fn gateway_logs<S>(level: tracing::Level) -> (Arc<Mutex<Vec<u8>>>, impl Layer<S>)
    where
        S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
    {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = buffer.clone();
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(move || GatewayLogs(writer.clone()))
            .with_ansi(false)
            .with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target("agent_gateway", level)
                    .with_target("audit", level),
            );
        (buffer, layer)
    }

    #[tokio::test]
    async fn a_credentialed_fetch_is_logged_and_audited_without_its_secret_query_or_card() {
        let directory = tempfile::tempdir().unwrap();
        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                directory
                    .path()
                    .to_str()
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "agent key".into(),
                secret_id: "AGENT_KEY".into(),
                description: None,
                value: "SECRET-VALUE".into(),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        let card = json!({"name": "CARD-MARKER", "url": "http://agent.internal/a2a", "skills": []});
        let target = MockServer::start_with_response(card.to_string()).await;
        let mut surface = surface_with(
            "orders",
            json!({"endpoint": target.url(), "auth": {
                "method": {"static_secret": {"secret_id": "AGENT_KEY", "header_name": "x-agent-key"}}}}),
        );
        surface
            .access_point
            .agent_card_path = Some("/card.json?code=QUERY-SECRET".into());
        let state = ProxyState {
            secrets_store: Some(secrets),
            ..running(surface).await
        };

        let (every_level, trace_layer) = gateway_logs(tracing::Level::TRACE);
        let (info_level, info_layer) = gateway_logs(tracing::Level::INFO);
        let preview = {
            let _logs = crate::component_tests::helpers::thread_subscriber::set_thread_default(
                tracing_subscriber::registry()
                    .with(trace_layer)
                    .with(info_layer),
            );
            PreviewMemory::new(FETCHES_PER_MINUTE)
                .preview(
                    &state,
                    &PreviewCaller {
                        user_id: "u-logs",
                        tenant_id: Some("tenant-a"),
                    },
                    PreviewRequest::Refresh,
                )
                .await
                .unwrap()
        };

        assert_eq!(fetch_of(&preview), (CardFetchStatus::Ok, None, None));
        assert_eq!(auth_of(&preview), (CardAuthKind::StaticSecret, CardAuthResult::Sent, None));
        assert_eq!(preview.source_url, Some(format!("{}/card.json", target.url())));
        assert!(preview.source_url_query_hidden);
        let received = target
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        assert_eq!(
            received
                .headers
                .get("x-agent-key")
                .map(String::as_str),
            Some("SECRET-VALUE")
        );
        let serialized = serde_json::to_string(&preview).unwrap();
        assert!(!serialized.contains("SECRET-VALUE") && !serialized.contains("AGENT_KEY"), "{serialized}");

        let text = |buffer: Arc<Mutex<Vec<u8>>>| String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        let every_level = text(every_level);
        assert!(every_level.contains("agent_card.preview_fetch"), "{every_level}");
        for leaked in ["SECRET-VALUE", "QUERY-SECRET"] {
            assert!(!every_level.contains(leaked), "{leaked} in {every_level}");
        }
        let info_level = text(info_level);
        for leaked in ["CARD-MARKER", "agent.internal"] {
            assert!(!info_level.contains(leaked), "{leaked} in {info_level}");
        }
    }

    #[tokio::test]
    async fn a_fetch_is_audited_with_its_outcome_and_a_cached_answer_is_not() {
        let audit = AuditEvents::capture();
        let target = RecordingTarget::start(axum::http::StatusCode::UNAUTHORIZED, &[]).await;
        let state = state(json!({"endpoint": target.url})).await;
        let memory = PreviewMemory::new(NonZeroU32::new(1).unwrap());

        let preview = memory
            .preview(
                &state,
                &PreviewCaller {
                    user_id: "u-audit",
                    tenant_id: Some("tenant-a"),
                },
                PreviewRequest::Read,
            )
            .await
            .unwrap();
        assert_eq!(fetch_of(&preview), (CardFetchStatus::Failed, Some(CardFetchCause::NeedsToken), Some(401)));
        let cached = memory
            .preview(&state, &caller("u-audit"), PreviewRequest::Read)
            .await
            .unwrap();
        assert!(cached.cached);

        let events = audit.named("agent_card.preview_fetch");
        assert_eq!(events.len(), 1, "only the fetch is audited");
        for (field, expected) in [
            ("request", "read"),
            ("caller_user_id", "u-audit"),
            ("tenant_id", "tenant-a"),
            ("surface_id", "orders"),
            ("auth_kind", "none"),
            ("auth_result", "not_configured"),
            ("auth_failure", ""),
            ("fetch_status", "failed"),
            ("cause", "needs_token"),
        ] {
            assert_eq!(events[0].get(field), Some(expected), "{field}");
        }
        for field in ["url", "source_url", "served_url", "provider_name", "before", "after"] {
            assert_eq!(events[0].get(field), None, "{field}");
        }
    }
}
