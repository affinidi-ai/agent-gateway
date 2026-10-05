use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::modern::{ModernResponseError, ResultSource, complete_response, validate_response};
use super::request_validation::{McpMessageKind, McpRequestValidationError, ValidatedModernMessage};

const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
const MAX_RESOURCE_SUBSCRIPTIONS: usize = 128;
const MAX_RESOURCE_URI_BYTES: usize = 4096;
const ACCESS_RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const ACCESS_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

fn access_changes() -> &'static tokio::sync::watch::Sender<()> {
    static CHANGES: std::sync::OnceLock<tokio::sync::watch::Sender<()>> = std::sync::OnceLock::new();
    CHANGES.get_or_init(|| tokio::sync::watch::channel(()).0)
}

pub fn invalidate_access() {
    access_changes().send_replace(());
}

pub struct AccessChange;

impl AccessChange {
    pub fn begin() -> Self {
        invalidate_access();
        Self
    }
}

impl Drop for AccessChange {
    fn drop(&mut self) {
        invalidate_access();
    }
}

/// Concurrent `subscriptions/listen` streams one caller may hold, and one
/// surface may hold across callers. Each listen holds an upstream connection
/// and a task for up to `stream_max_lifetime_secs`.
const MAX_LISTENS_PER_CALLER: usize = 16;
const MAX_LISTENS_PER_SURFACE: usize = 256;

/// Counts the open listens per caller and per surface.
pub struct ListenSlots {
    max_per_caller: usize,
    max_per_surface: usize,
    counts: std::sync::Mutex<ListenCounts>,
}

#[derive(Default)]
struct ListenCounts {
    callers: std::collections::HashMap<String, usize>,
    surfaces: std::collections::HashMap<String, usize>,
}

impl ListenSlots {
    fn new(
        max_per_caller: usize,
        max_per_surface: usize,
    ) -> Self {
        Self {
            max_per_caller,
            max_per_surface,
            counts: std::sync::Mutex::new(ListenCounts::default()),
        }
    }

    /// The process-wide counts every listen path shares.
    pub fn global() -> &'static Self {
        static SLOTS: std::sync::OnceLock<ListenSlots> = std::sync::OnceLock::new();
        SLOTS.get_or_init(|| ListenSlots::new(MAX_LISTENS_PER_CALLER, MAX_LISTENS_PER_SURFACE))
    }

    /// Takes a slot for `caller` on `surface`, held until the slot drops, or
    /// `None` when either is at its limit.
    pub fn acquire(
        &'static self,
        surface: &str,
        caller: &str,
    ) -> Option<ListenSlot> {
        let mut counts = self.counts.lock().ok()?;
        if counts
            .callers
            .get(caller)
            .is_some_and(|count| *count >= self.max_per_caller)
            || counts
                .surfaces
                .get(surface)
                .is_some_and(|count| *count >= self.max_per_surface)
        {
            return None;
        }
        *counts
            .callers
            .entry(caller.to_string())
            .or_default() += 1;
        *counts
            .surfaces
            .entry(surface.to_string())
            .or_default() += 1;
        Some(ListenSlot {
            slots: self,
            surface: surface.to_string(),
            caller: caller.to_string(),
        })
    }
}

/// One open listen's share of [`ListenSlots`].
pub struct ListenSlot {
    slots: &'static ListenSlots,
    surface: String,
    caller: String,
}

impl Drop for ListenSlot {
    fn drop(&mut self) {
        let Ok(mut counts) = self.slots.counts.lock() else {
            return;
        };
        let ListenCounts { callers, surfaces } = &mut *counts;
        for (map, key) in [(callers, &self.caller), (surfaces, &self.surface)] {
            if let Some(count) = map.get_mut(key) {
                *count -= 1;
                if *count == 0 {
                    map.remove(key);
                }
            }
        }
    }
}

/// The caller a listen is counted against: the authenticated principal, or
/// `fallback` (the peer address or DID) for an unauthenticated one.
pub fn listen_caller(
    identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    fallback: &str,
) -> String {
    identity.map_or_else(|| format!("peer:{fallback}"), crate::source_auth::AuthenticatedIdentity::principal_key)
}

/// The answer to a listen refused by [`ListenSlots`].
pub fn listen_limit_error(request: &ValidatedModernMessage) -> McpRequestValidationError {
    McpRequestValidationError {
        status: axum::http::StatusCode::TOO_MANY_REQUESTS,
        id: request.id.clone(),
        code: super::error_codes::INTERNAL_ERROR,
        message: "Too many open MCP subscriptions".into(),
        data: None,
    }
}

pub struct SubscriptionLifetime {
    changes: tokio::sync::watch::Receiver<()>,
    deadline: tokio::time::Instant,
    vault_access: Option<VaultAccess>,
    /// Released when the subscription's response ends or is dropped.
    slot: Option<ListenSlot>,
}

struct VaultAccess {
    vault: std::sync::Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>,
    revision: Option<uuid::Uuid>,
    next_check: tokio::time::Instant,
}

impl VaultAccess {
    async fn read_revision(
        vault: &dyn crate::delegation_vault::storage::DelegationVaultStorage
    ) -> Result<Option<uuid::Uuid>, std::io::Error> {
        tokio::time::timeout(ACCESS_CHECK_TIMEOUT, vault.access_revision())
            .await
            .map_err(|_| std::io::Error::other("MCP subscription access check timed out"))?
            .map_err(|_| std::io::Error::other("MCP subscription authorization unavailable"))
    }

    async fn revalidate(&mut self) -> Result<(), std::io::Error> {
        if Self::read_revision(self.vault.as_ref()).await? != self.revision {
            return Err(std::io::Error::other("MCP subscription credentials were revoked"));
        }
        self.next_check = tokio::time::Instant::now() + ACCESS_RECHECK_INTERVAL;
        Ok(())
    }
}

impl SubscriptionLifetime {
    pub fn new(
        lifetime: std::time::Duration,
        identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    ) -> Self {
        let mut guard = Self {
            changes: access_changes().subscribe(),
            deadline: tokio::time::Instant::now() + lifetime,
            vault_access: None,
            slot: None,
        };
        guard.restrict_to_identity(identity);
        guard
    }

    /// Holds `slot` for as long as the subscription's response lives.
    pub fn hold(
        &mut self,
        slot: ListenSlot,
    ) {
        self.slot = Some(slot);
    }

    pub async fn watch_vault(
        &mut self,
        vault: std::sync::Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>,
    ) -> Result<(), std::io::Error> {
        let revision = VaultAccess::read_revision(vault.as_ref()).await?;
        self.vault_access = Some(VaultAccess {
            vault,
            revision,
            next_check: tokio::time::Instant::now(),
        });
        Ok(())
    }

    pub fn restrict_to_identity(
        &mut self,
        identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    ) {
        if let Some(expiry) = identity
            .and_then(crate::source_auth::AuthenticatedIdentity::jwt_claims)
            .and_then(|claims| claims.get("exp"))
            .and_then(Value::as_u64)
        {
            self.restrict_to_expiry(expiry);
        }
    }

    pub fn restrict_to_expiry(
        &mut self,
        expiry: u64,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let remaining = std::time::Duration::from_secs(expiry)
            .saturating_sub(now)
            .min(
                self.deadline
                    .saturating_duration_since(tokio::time::Instant::now()),
            );
        self.deadline = self
            .deadline
            .min(tokio::time::Instant::now() + remaining);
    }

    pub fn restrict_lifetime(
        &mut self,
        lifetime: std::time::Duration,
    ) {
        self.deadline = self
            .deadline
            .min(tokio::time::Instant::now() + lifetime);
    }

    pub fn wrap(
        self,
        response: axum::response::Response,
    ) -> axum::response::Response {
        use futures::StreamExt;
        let (parts, body) = response.into_parts();
        let body = futures::stream::try_unfold(
            (body.into_data_stream(), self),
            |(mut source, mut lifetime)| async move {
                loop {
                    if lifetime
                        .changes
                        .has_changed()
                        .unwrap_or(true)
                        || tokio::time::Instant::now() >= lifetime.deadline
                    {
                        return Err(std::io::Error::other("MCP subscription access must be revalidated"));
                    }
                    let next_check = lifetime
                        .vault_access
                        .as_ref()
                        .map_or(lifetime.deadline, |access| access.next_check);
                    let next = tokio::select! {
                        biased;
                        _ = lifetime.changes.changed() => return Err(std::io::Error::other("MCP subscription access changed")),
                        _ = tokio::time::sleep_until(lifetime.deadline) => return Err(std::io::Error::other("MCP subscription authorization expired")),
                        _ = tokio::time::sleep_until(next_check), if lifetime.vault_access.is_some() => {
                            if let Some(access) = lifetime.vault_access.as_mut() {
                                tokio::select! {
                                    biased;
                                    _ = lifetime.changes.changed() => return Err(std::io::Error::other("MCP subscription access changed")),
                                    _ = tokio::time::sleep_until(lifetime.deadline) => return Err(std::io::Error::other("MCP subscription authorization expired")),
                                    result = access.revalidate() => result?,
                                }
                            }
                            continue;
                        }
                        next = source.next() => next,
                    };
                    return match next {
                        Some(Ok(bytes)) => Ok(Some((bytes, (source, lifetime)))),
                        Some(Err(error)) => Err(std::io::Error::other(error)),
                        None => Ok(None),
                    };
                }
            },
        );
        axum::response::Response::from_parts(parts, axum::body::Body::from_stream(body))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscriptionFilter {
    #[serde(skip_serializing_if = "is_false")]
    pub tools_list_changed: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub prompts_list_changed: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub resources_list_changed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resource_subscriptions: Vec<String>,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl SubscriptionFilter {
    pub fn parse(value: &Value) -> Result<Self, SubscriptionError> {
        if !value.is_object() {
            return Err(SubscriptionError::InvalidFilter);
        }
        let filter: Self = serde_json::from_value(value.clone()).map_err(|_| SubscriptionError::InvalidFilter)?;
        if filter
            .resource_subscriptions
            .len()
            > MAX_RESOURCE_SUBSCRIPTIONS
            || filter
                .resource_subscriptions
                .iter()
                .any(|uri| {
                    uri.is_empty()
                        || uri.len() > MAX_RESOURCE_URI_BYTES
                        || uri
                            .chars()
                            .any(char::is_control)
                        || url::Url::parse(uri).is_err()
                })
        {
            return Err(SubscriptionError::InvalidFilter);
        }
        Ok(filter)
    }

    pub fn from_request(request: &ValidatedModernMessage) -> Result<Self, Box<McpRequestValidationError>> {
        let parsed = request
            .params
            .as_ref()
            .and_then(|params| params.get("notifications"))
            .ok_or(SubscriptionError::InvalidFilter)
            .and_then(Self::parse);
        if request.method != "subscriptions/listen" || request.kind != McpMessageKind::Request || request.id.is_none() {
            return Err(Self::request_error(request));
        }
        parsed.map_err(|_| Self::request_error(request))
    }

    fn request_error(request: &ValidatedModernMessage) -> Box<McpRequestValidationError> {
        Box::new(McpRequestValidationError {
            status: axum::http::StatusCode::BAD_REQUEST,
            id: request.id.clone(),
            code: super::error_codes::INVALID_PARAMS,
            message: "subscriptions/listen requires a bounded notifications filter".to_string(),
            data: None,
        })
    }

    pub fn is_subset_of(
        &self,
        requested: &Self,
    ) -> bool {
        (!self.tools_list_changed || requested.tools_list_changed)
            && (!self.prompts_list_changed || requested.prompts_list_changed)
            && (!self.resources_list_changed || requested.resources_list_changed)
            && self
                .resource_subscriptions
                .iter()
                .all(|uri| {
                    requested
                        .resource_subscriptions
                        .contains(uri)
                })
    }

    pub fn is_empty(&self) -> bool {
        !self.tools_list_changed
            && !self.prompts_list_changed
            && !self.resources_list_changed
            && self
                .resource_subscriptions
                .is_empty()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubscriptionError {
    #[error("Invalid or excessive subscription notification filter")]
    InvalidFilter,
    #[error("Invalid subscription JSON-RPC message")]
    InvalidMessage,
    #[error("Subscription identifier does not match its request")]
    IdMismatch,
    #[error("Subscription acknowledgement must precede notifications")]
    MissingAcknowledgement,
    #[error("Subscription acknowledgement is repeated or exceeds the requested filter")]
    InvalidAcknowledgement,
    #[error("Notification is outside the acknowledged subscription filter")]
    UnrequestedNotification,
    #[error("Subscription has already completed")]
    AlreadyCompleted,
    #[error(transparent)]
    Response(#[from] ModernResponseError),
}

pub struct SubscriptionState {
    request: ValidatedModernMessage,
    requested: SubscriptionFilter,
    acknowledged: Option<SubscriptionFilter>,
    completed: bool,
}

fn resource_update_matches(
    subscribed: &str,
    updated: &str,
) -> bool {
    if updated.is_empty()
        || updated.len() > MAX_RESOURCE_URI_BYTES
        || updated
            .chars()
            .any(char::is_control)
    {
        return false;
    }
    let (Ok(subscribed), Ok(updated)) = (url::Url::parse(subscribed), url::Url::parse(updated)) else {
        return false;
    };
    if subscribed == updated {
        return true;
    }
    if subscribed.cannot_be_a_base()
        || updated.cannot_be_a_base()
        || subscribed
            .fragment()
            .is_some()
        || subscribed.scheme() != updated.scheme()
        || subscribed.host() != updated.host()
        || subscribed.port_or_known_default() != updated.port_or_known_default()
        || subscribed.username() != updated.username()
        || subscribed.password() != updated.password()
        || subscribed.query() != updated.query()
    {
        return false;
    }
    updated.path() == subscribed.path()
        || updated
            .path()
            .strip_prefix(subscribed.path())
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && (subscribed
                        .path()
                        .ends_with('/')
                        || suffix.starts_with('/'))
            })
}

impl SubscriptionState {
    pub fn new(request: ValidatedModernMessage) -> Result<Self, Box<McpRequestValidationError>> {
        let requested = SubscriptionFilter::from_request(&request)?;
        Ok(Self {
            request,
            requested,
            acknowledged: None,
            completed: false,
        })
    }

    pub fn accept(
        &mut self,
        message: &Value,
    ) -> Result<bool, SubscriptionError> {
        if self.completed {
            return Err(SubscriptionError::AlreadyCompleted);
        }
        if message
            .get("method")
            .is_none()
        {
            let result = validate_response(&self.request, message, ResultSource::ModernServer)?;
            if result == Some("complete") {
                if self.acknowledged.is_none() {
                    return Err(SubscriptionError::MissingAcknowledgement);
                }
                if message
                    .pointer("/result/_meta")
                    .and_then(|meta| meta.get(SUBSCRIPTION_ID))
                    != self.request.id.as_ref()
                {
                    return Err(SubscriptionError::IdMismatch);
                }
            } else if result.is_some() {
                return Err(SubscriptionError::InvalidMessage);
            }
            self.completed = true;
            return Ok(true);
        }
        if message
            .get("jsonrpc")
            .and_then(Value::as_str)
            != Some("2.0")
            || message.get("id").is_some()
            || message
                .get("result")
                .is_some()
            || message.get("error").is_some()
        {
            return Err(SubscriptionError::InvalidMessage);
        }
        let params = message
            .get("params")
            .and_then(Value::as_object)
            .ok_or(SubscriptionError::InvalidMessage)?;
        if params
            .get("_meta")
            .and_then(|meta| meta.get(SUBSCRIPTION_ID))
            != self.request.id.as_ref()
        {
            return Err(SubscriptionError::IdMismatch);
        }
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or(SubscriptionError::InvalidMessage)?;
        if method == "notifications/subscriptions/acknowledged" {
            let filter = params
                .get("notifications")
                .ok_or(SubscriptionError::InvalidFilter)
                .and_then(SubscriptionFilter::parse)?;
            if self.acknowledged.is_some() || !filter.is_subset_of(&self.requested) {
                return Err(SubscriptionError::InvalidAcknowledgement);
            }
            self.acknowledged = Some(filter);
            return Ok(false);
        }
        let filter = self
            .acknowledged
            .as_ref()
            .ok_or(SubscriptionError::MissingAcknowledgement)?;
        let allowed = match method {
            "notifications/tools/list_changed" => filter.tools_list_changed,
            "notifications/prompts/list_changed" => filter.prompts_list_changed,
            "notifications/resources/list_changed" => filter.resources_list_changed,
            "notifications/resources/updated" => params
                .get("uri")
                .and_then(Value::as_str)
                .is_some_and(|uri| {
                    filter
                        .resource_subscriptions
                        .iter()
                        .any(|subscribed| resource_update_matches(subscribed, uri))
                }),
            _ => false,
        };
        if !allowed {
            return Err(SubscriptionError::UnrequestedNotification);
        }
        Ok(false)
    }
}

pub fn acknowledgement(
    request: &ValidatedModernMessage,
    supported: &SubscriptionFilter,
) -> Result<Value, Box<McpRequestValidationError>> {
    let requested = SubscriptionFilter::from_request(request)?;
    if !supported.is_subset_of(&requested) {
        return Err(SubscriptionFilter::request_error(request));
    }
    Ok(json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": {
        "_meta": {SUBSCRIPTION_ID: request.id}, "notifications": supported,
    }}))
}

pub fn completion(request: &ValidatedModernMessage) -> Result<Value, ModernResponseError> {
    if request.method != "subscriptions/listen" {
        return Err(ModernResponseError::InvalidRequest);
    }
    complete_response(
        request,
        serde_json::Map::from_iter([("_meta".to_string(), json!({SUBSCRIPTION_ID: request.id}))]),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogChange {
    Unchanged,
    Changed,
    Closed,
}

pub struct CatalogSubscriptions {
    subscribers:
        std::sync::Mutex<std::collections::HashMap<uuid::Uuid, (String, tokio::sync::watch::Sender<CatalogChange>)>>,
}

impl CatalogSubscriptions {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            subscribers: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn subscribe(
        self: &std::sync::Arc<Self>,
        proxy_id: &str,
    ) -> Result<CatalogSubscription, String> {
        let mut subscribers = self
            .subscribers
            .lock()
            .map_err(|_| "Catalog subscriptions are unavailable")?;
        if subscribers.len() >= 128
            || subscribers
                .values()
                .filter(|(proxy, _)| proxy == proxy_id)
                .count()
                >= 16
        {
            return Err("Catalog subscription capacity reached".to_string());
        }
        let id = uuid::Uuid::new_v4();
        let (sender, changes) = tokio::sync::watch::channel(CatalogChange::Unchanged);
        subscribers.insert(id, (proxy_id.to_string(), sender));
        Ok(CatalogSubscription { hub: self.clone(), id, changes })
    }

    pub fn publish(
        &self,
        proxy_id: &str,
        change: CatalogChange,
    ) {
        if let Ok(subscribers) = self.subscribers.lock() {
            for (proxy, sender) in subscribers.values() {
                if proxy == proxy_id && *sender.borrow() != CatalogChange::Closed {
                    sender.send_replace(change);
                }
            }
        }
    }
}

pub struct CatalogSubscription {
    hub: std::sync::Arc<CatalogSubscriptions>,
    id: uuid::Uuid,
    changes: tokio::sync::watch::Receiver<CatalogChange>,
}

impl Drop for CatalogSubscription {
    fn drop(&mut self) {
        if let Ok(mut subscribers) = self.hub.subscribers.lock() {
            subscribers.remove(&self.id);
        }
    }
}

pub fn catalog_subscriptions() -> &'static std::sync::Arc<CatalogSubscriptions> {
    static CATALOG: std::sync::OnceLock<std::sync::Arc<CatalogSubscriptions>> = std::sync::OnceLock::new();
    CATALOG.get_or_init(CatalogSubscriptions::new)
}

pub fn owned_catalog_response(
    request: ValidatedModernMessage,
    subscription: CatalogSubscription,
    limits: super::modern_sse::SseLimits,
) -> Result<axum::response::Response, Box<McpRequestValidationError>> {
    use axum::response::IntoResponse;
    let requested = SubscriptionFilter::from_request(&request)?;
    let supported = SubscriptionFilter {
        tools_list_changed: requested.tools_list_changed,
        ..Default::default()
    };
    let acknowledged = acknowledgement(&request, &supported)?;
    let done = completion(&request).map_err(|_| SubscriptionFilter::request_error(&request))?;
    let deadline = tokio::time::Instant::now() + limits.max_lifetime;
    let events = futures::stream::try_unfold(
        (subscription, Some(acknowledged), done, request.id, supported.is_empty(), false),
        move |(mut subscription, mut acknowledged, done, id, empty, finished)| async move {
            if finished {
                return Ok(None);
            }
            let (message, finished) = if let Some(acknowledged) = acknowledged.take() {
                (acknowledged, false)
            } else if empty || *subscription.changes.borrow() == CatalogChange::Closed {
                (done.clone(), true)
            } else {
                let changed = tokio::time::timeout_at(deadline, subscription.changes.changed()).await;
                if !matches!(changed, Ok(Ok(())))
                    || *subscription
                        .changes
                        .borrow_and_update()
                        == CatalogChange::Closed
                {
                    (done.clone(), true)
                } else {
                    (
                        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {
                            "_meta": {SUBSCRIPTION_ID: id}
                        }}),
                        false,
                    )
                }
            };
            let encoded =
                serde_json::to_string(&message).map_err(|_| super::modern_sse::SseReadError::InvalidMessage)?;
            if encoded.len() > limits.max_event_bytes.get() {
                return Err(super::modern_sse::SseReadError::EventTooLarge);
            }
            let event = axum::response::sse::Event::default().data(encoded);
            Ok::<_, super::modern_sse::SseReadError>(Some((
                event,
                (subscription, acknowledged, done, id, empty, finished),
            )))
        },
    );
    let mut response = axum::response::Sse::new(events)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response();
    response
        .headers_mut()
        .insert("cache-control", axum::http::HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("x-accel-buffering", axum::http::HeaderValue::from_static("no"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn credential_strategy_changes_close_quiet_subscription_streams() {
        use std::time::Duration;

        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
        use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
        use http_body_util::BodyExt;

        if std::env::var_os("ATG_MCP_SUBSCRIPTION_REVOCATION_CHILD").is_none() {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env("ATG_MCP_SUBSCRIPTION_REVOCATION_CHILD", "1")
                .kill_on_drop(true)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "isolated subscription test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let strategies = FileSystemJwtVerificationStrategyStore::new(
            directory
                .path()
                .join("strategies"),
        )
        .await
        .unwrap();
        let mut strategy = strategies
            .create(
                crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &json!({"keys": []}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let providers = FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        let mut provider = providers
            .create(
                serde_json::from_value(json!({
                    "id": "provider", "name": "Provider", "provider_id": "provider",
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let vault = FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap();
        let vault_reader = FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap();
        for id in ["first", "second"] {
            vault
                .store(
                    serde_json::from_value(json!({
                        "id": id, "agent_did": "did:example:agent", "user_identity_hash": id,
                        "credential_provider_id": "provider", "provider_id": "provider", "access_token": "fixture",
                        "consent_granted_at": "2026-09-01T00:00:00Z", "created_at": "2026-09-01T00:00:00Z",
                        "updated_at": "2026-09-01T00:00:00Z"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        for action in [
            "read",
            "update",
            "reload",
            "delete",
            "provider-read",
            "provider-update",
            "provider-delete",
            "vault-read",
            "vault-delete",
            "vault-delete-user",
        ] {
            let vault_revision = vault_reader
                .access_revision()
                .await
                .unwrap();
            let lifetime = SubscriptionLifetime::new(Duration::from_secs(60), None);
            let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
            let response = axum::response::Response::new(axum::body::Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
            ));
            let mut body = lifetime
                .wrap(response)
                .into_body();
            assert!(futures::poll!(body.frame()).is_pending());
            match action {
                "read" => {
                    assert!(
                        strategies
                            .get(&strategy.id)
                            .await
                            .unwrap()
                            .is_some()
                    );
                }
                "update" => {
                    strategy.expected_issuer = "https://replacement.example/".into();
                    strategy = strategies
                        .update(strategy)
                        .await
                        .unwrap();
                }
                "reload" => strategies
                    .reload()
                    .await
                    .unwrap(),
                "delete" => strategies
                    .delete(&strategy.id)
                    .await
                    .unwrap(),
                "provider-read" => {
                    assert!(
                        providers
                            .get(&provider.id)
                            .await
                            .unwrap()
                            .is_some()
                    );
                }
                "provider-update" => {
                    provider.resource = Some("https://replacement.example/resource".into());
                    provider = providers
                        .update(provider)
                        .await
                        .unwrap();
                }
                "provider-delete" => {
                    assert!(
                        providers
                            .delete(&provider.id)
                            .await
                            .unwrap()
                    );
                }
                "vault-read" => {
                    assert!(
                        vault
                            .get("first")
                            .await
                            .unwrap()
                            .is_some()
                    );
                }
                "vault-delete" => {
                    assert!(
                        vault
                            .delete("first")
                            .await
                            .unwrap()
                    );
                }
                "vault-delete-user" => {
                    assert_eq!(
                        vault
                            .delete_by_user("second")
                            .await
                            .unwrap(),
                        1
                    );
                }
                _ => unreachable!(),
            }
            let next_revision = vault_reader
                .access_revision()
                .await
                .unwrap();
            if matches!(action, "vault-delete" | "vault-delete-user") {
                assert_ne!(next_revision, vault_revision, "{action}");
                assert!(next_revision.is_some());
            } else {
                assert_eq!(next_revision, vault_revision, "{action}");
            }
            if matches!(action, "read" | "provider-read" | "vault-read") {
                assert!(futures::poll!(body.frame()).is_pending());
                assert!(!sender.is_closed());
                drop(body);
            } else {
                let result = tokio::time::timeout(Duration::from_secs(1), body.frame())
                    .await
                    .expect("a credential change must close a quiet stream")
                    .unwrap();
                assert!(result.is_err(), "{action}");
            }
            assert!(sender.is_closed());
        }
    }

    #[tokio::test]
    async fn vault_revocation_in_another_process_closes_quiet_subscription() {
        use std::time::Duration;

        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
        use http_body_util::BodyExt;

        if let Some(path) = std::env::var_os("ATG_MCP_SUBSCRIPTION_VAULT_CHILD_DIR") {
            let vault = FileSystemDelegationVaultStore::new(path.into())
                .await
                .unwrap();
            assert!(
                !vault
                    .delete("absent-fixture")
                    .await
                    .unwrap()
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let vault = std::sync::Arc::new(
            FileSystemDelegationVaultStore::new(directory.path().into())
                .await
                .unwrap(),
        );
        let (changes, receiver) = tokio::sync::watch::channel(());
        let mut lifetime = SubscriptionLifetime::new(Duration::from_secs(60), None);
        lifetime.changes = receiver;
        lifetime
            .watch_vault(vault.clone())
            .await
            .unwrap();
        lifetime
            .vault_access
            .as_mut()
            .unwrap()
            .revalidate()
            .await
            .unwrap();
        let (sender, upstream) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
        let response = axum::response::Response::new(axum::body::Body::from_stream(
            tokio_stream::wrappers::ReceiverStream::new(upstream),
        ));
        let mut body = lifetime
            .wrap(response)
            .into_body();
        sender
            .send(Ok(bytes::Bytes::from_static(b"accepted")))
            .await
            .unwrap();
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            "accepted"
        );
        assert!(futures::poll!(body.frame()).is_pending());
        assert_eq!(
            vault
                .access_revision()
                .await
                .unwrap(),
            None
        );
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("ATG_MCP_SUBSCRIPTION_VAULT_CHILD_DIR", directory.path())
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "child revocation failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            vault
                .access_revision()
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), body.frame())
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(sender.is_closed());
        assert_eq!(changes.receiver_count(), 0);

        let (changes, receiver) = tokio::sync::watch::channel(());
        let mut lifetime = SubscriptionLifetime::new(Duration::from_secs(60), None);
        lifetime.changes = receiver;
        lifetime
            .watch_vault(vault.clone())
            .await
            .unwrap();
        lifetime
            .vault_access
            .as_mut()
            .unwrap()
            .revalidate()
            .await
            .unwrap();
        let (sender, upstream) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
        let response = axum::response::Response::new(axum::body::Body::from_stream(
            tokio_stream::wrappers::ReceiverStream::new(upstream),
        ));
        let mut body = lifetime
            .wrap(response)
            .into_body();
        assert!(futures::poll!(body.frame()).is_pending());
        tokio::fs::write(
            directory
                .path()
                .join("mcp_consent_state/revocation.json"),
            b"invalid epoch",
        )
        .await
        .unwrap();
        assert!(
            vault
                .access_revision()
                .await
                .is_err()
        );
        let mut refused = SubscriptionLifetime::new(Duration::from_secs(60), None);
        assert!(
            refused
                .watch_vault(vault.clone())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), body.frame())
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(sender.is_closed());
        assert_eq!(changes.receiver_count(), 0);
    }

    #[test]
    fn listens_are_capped_per_caller_and_per_surface_until_they_end() {
        let slots: &'static ListenSlots = Box::leak(Box::new(ListenSlots::new(2, 3)));
        let first = slots
            .acquire("surface:a", "caller:1")
            .unwrap();
        let _second = slots
            .acquire("surface:b", "caller:1")
            .unwrap();
        assert!(
            slots
                .acquire("surface:c", "caller:1")
                .is_none(),
            "per-caller cap spans surfaces"
        );
        let _third = slots
            .acquire("surface:a", "caller:2")
            .unwrap();
        let _fourth = slots
            .acquire("surface:a", "caller:3")
            .unwrap();
        assert!(
            slots
                .acquire("surface:a", "caller:4")
                .is_none(),
            "per-surface cap spans callers"
        );
        drop(first);
        assert!(
            slots
                .acquire("surface:c", "caller:1")
                .is_some()
        );
        assert!(
            slots
                .acquire("surface:a", "caller:4")
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_held_listen_slot_is_released_when_the_response_ends() {
        use http_body_util::BodyExt;
        let slots: &'static ListenSlots = Box::leak(Box::new(ListenSlots::new(1, 1)));
        let mut lifetime = SubscriptionLifetime::new(std::time::Duration::from_secs(60), None);
        lifetime.hold(
            slots
                .acquire("surface", "caller")
                .unwrap(),
        );
        let body = lifetime
            .wrap(axum::response::Response::new(axum::body::Body::from("done")))
            .into_body();
        assert!(
            slots
                .acquire("surface", "caller")
                .is_none()
        );

        drop(body.collect().await.unwrap());

        assert!(
            slots
                .acquire("surface", "caller")
                .is_some()
        );
    }

    #[test]
    fn unauthenticated_listens_are_counted_by_peer_and_never_collide_with_principals() {
        let identity = crate::source_auth::AuthenticatedIdentity::ApiKey { key_name: "10.0.0.1".into() };
        assert_ne!(listen_caller(Some(&identity), "10.0.0.1"), listen_caller(None, "10.0.0.1"));
        assert_eq!(listen_caller(None, "10.0.0.1"), listen_caller(None, "10.0.0.1"));
    }

    #[tokio::test]
    async fn subscription_lifetime_drops_quiet_upstream_on_access_change_or_expiry() {
        use http_body_util::BodyExt;
        for expire in [false, true] {
            let (changes, receiver) = tokio::sync::watch::channel(());
            let lifetime = SubscriptionLifetime {
                changes: receiver,
                vault_access: None,
                slot: None,
                deadline: tokio::time::Instant::now()
                    + if expire {
                        std::time::Duration::ZERO
                    } else {
                        std::time::Duration::from_secs(60)
                    },
            };
            let (sender, upstream) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
            let response = axum::response::Response::new(axum::body::Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(upstream),
            ));
            let mut body = lifetime
                .wrap(response)
                .into_body();
            let read = async {
                let event = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(event.is_err());
            };
            let invalidate = async {
                tokio::task::yield_now().await;
                changes.send_replace(());
            };
            tokio::join!(read, invalidate);
            assert!(sender.is_closed());
        }
    }

    #[test]
    fn subscription_expiry_uses_only_verified_identity_claims() {
        let claims = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "caller".into(),
            claims: json!({"exp": 1}),
        };
        let expired = SubscriptionLifetime::new(std::time::Duration::from_secs(60), Some(&claims));
        assert!(expired.deadline <= tokio::time::Instant::now());
        let anonymous = SubscriptionLifetime::new(std::time::Duration::from_secs(60), None);
        assert!(anonymous.deadline > tokio::time::Instant::now());
        let mut captured = SubscriptionLifetime::new(std::time::Duration::from_secs(60), None);
        let (changes, receiver) = tokio::sync::watch::channel(());
        captured.changes = receiver;
        changes.send_replace(());
        captured.restrict_to_identity(Some(&claims));
        assert!(
            captured
                .changes
                .has_changed()
                .unwrap()
        );
        assert!(captured.deadline <= tokio::time::Instant::now());
        let mut transit = SubscriptionLifetime::new(std::time::Duration::from_secs(60), None);
        let initial = transit.deadline;
        transit.restrict_to_expiry(u64::MAX / 2);
        assert_eq!(transit.deadline, initial);
        transit.restrict_to_expiry(1);
        assert!(transit.deadline <= tokio::time::Instant::now());
    }

    async fn next_event(body: &mut axum::body::Body) -> Value {
        use eventsource_stream::Eventsource;
        use futures::StreamExt;
        use http_body_util::BodyExt;
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let events = futures::stream::iter([Ok::<_, std::io::Error>(bytes)]).eventsource();
        futures::pin_mut!(events);
        serde_json::from_str(
            &events
                .next()
                .await
                .unwrap()
                .unwrap()
                .data,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn owned_catalog_streams_changes_and_closes_independent_subscriptions() {
        use http_body_util::BodyExt;
        let hub = CatalogSubscriptions::new();
        let limits = super::super::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
        let request = request(json!(9), json!({"toolsListChanged": true, "promptsListChanged": true}));
        let first = hub
            .subscribe("first")
            .unwrap();
        let second = hub
            .subscribe("second")
            .unwrap();
        let mut first = owned_catalog_response(request.clone(), first, limits)
            .unwrap()
            .into_body();
        let mut second = owned_catalog_response(request.clone(), second, limits)
            .unwrap()
            .into_body();
        for body in [&mut first, &mut second] {
            let ack = next_event(body).await;
            assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
            assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
            assert_eq!(ack["params"]["_meta"][SUBSCRIPTION_ID], 9);
        }
        hub.publish("first", CatalogChange::Changed);
        assert_eq!(next_event(&mut first).await["method"], "notifications/tools/list_changed");
        assert!(
            !hub.subscribers
                .lock()
                .unwrap()
                .values()
                .find(|(id, _)| id == "second")
                .unwrap()
                .1
                .borrow()
                .eq(&CatalogChange::Changed)
        );
        hub.publish("first", CatalogChange::Closed);
        hub.publish("first", CatalogChange::Changed);
        assert_eq!(next_event(&mut first).await, completion(&request).unwrap());
        assert!(first.frame().await.is_none());
        assert_eq!(
            hub.subscribers
                .lock()
                .unwrap()
                .len(),
            1
        );
        drop(second);
        assert!(
            hub.subscribers
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn owned_empty_filters_and_lifetime_expiry_close_gracefully() {
        use http_body_util::BodyExt;
        for notifications in [json!({}), json!({"promptsListChanged": true}), json!({"toolsListChanged": true})] {
            let hub = CatalogSubscriptions::new();
            let request = request(json!("close"), notifications);
            let mut limits = super::super::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
            limits.max_lifetime = std::time::Duration::ZERO;
            let mut body = owned_catalog_response(
                request.clone(),
                hub.subscribe("proxy")
                    .unwrap(),
                limits,
            )
            .unwrap()
            .into_body();
            assert_eq!(next_event(&mut body).await["method"], "notifications/subscriptions/acknowledged");
            assert_eq!(next_event(&mut body).await, completion(&request).unwrap());
            assert!(body.frame().await.is_none());
            assert!(
                hub.subscribers
                    .lock()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn owned_catalog_subscription_capacity_is_released_on_drop() {
        let hub = CatalogSubscriptions::new();
        let mut leases = (0..16)
            .map(|_| {
                hub.subscribe("proxy")
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            hub.subscribe("proxy")
                .is_err()
        );
        leases.pop();
        assert!(hub.subscribe("proxy").is_ok());
        drop(leases);
        assert!(
            hub.subscribers
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    fn request(
        id: Value,
        notifications: Value,
    ) -> ValidatedModernMessage {
        ValidatedModernMessage {
            protocol_version: super::super::MCP_MODERN_VERSION.to_string(),
            client_capabilities: Some(json!({})),
            client_info: None,
            method: "subscriptions/listen".to_string(),
            params: Some(json!({"notifications": notifications})),
            id: Some(id),
            kind: McpMessageKind::Request,
        }
    }

    fn notification(
        id: Value,
        method: &str,
        uri: Option<&str>,
    ) -> Value {
        let mut message = json!({"jsonrpc": "2.0", "method": method, "params": {"_meta": {SUBSCRIPTION_ID: id}}});
        if let Some(uri) = uri {
            message["params"]["uri"] = json!(uri);
        }
        message
    }

    #[test]
    fn subscription_filters_are_typed_opt_in_and_bounded() {
        assert!(
            SubscriptionFilter::parse(&json!({}))
                .unwrap()
                .is_empty()
        );
        for invalid in [
            json!(null),
            json!([]),
            json!({"toolsListChanged": null}),
            json!({"toolsListChanged": "true"}),
            json!({"filterCriteria": {}}),
            json!({"resourceSubscriptions": [null]}),
            json!({"resourceSubscriptions": ["relative"]}),
            json!({"resourceSubscriptions": vec!["https://example.org/resource"; MAX_RESOURCE_SUBSCRIPTIONS + 1]}),
        ] {
            assert_eq!(SubscriptionFilter::parse(&invalid), Err(SubscriptionError::InvalidFilter));
        }
        let error =
            SubscriptionFilter::from_request(&request(json!(5), json!({"resourcesListChanged": "yes"}))).unwrap_err();
        assert_eq!(error.id, Some(json!(5)));
        assert_eq!(error.code, super::super::error_codes::INVALID_PARAMS);
    }

    #[test]
    fn acknowledgement_and_notifications_are_isolated_by_typed_request_id() {
        for id in [json!(7), json!("7")] {
            let request = request(
                id.clone(),
                json!({"toolsListChanged": true, "resourceSubscriptions": ["file:///project/config.json"]}),
            );
            let filter = SubscriptionFilter::from_request(&request).unwrap();
            let mut state = SubscriptionState::new(request.clone()).unwrap();
            let tool_event = notification(id.clone(), "notifications/tools/list_changed", None);
            assert_eq!(state.accept(&tool_event), Err(SubscriptionError::MissingAcknowledgement));
            let ack = acknowledgement(&request, &filter).unwrap();
            assert_eq!(state.accept(&ack), Ok(false));
            assert_eq!(state.accept(&ack), Err(SubscriptionError::InvalidAcknowledgement));
            assert_eq!(state.accept(&tool_event), Ok(false));
            let other = if id.is_string() {
                json!(7)
            } else {
                json!("7")
            };
            assert_eq!(
                state.accept(&notification(other, "notifications/tools/list_changed", None)),
                Err(SubscriptionError::IdMismatch)
            );
            assert_eq!(
                state.accept(&notification(
                    id.clone(),
                    "notifications/resources/updated",
                    Some("file:///project/config.json")
                )),
                Ok(false)
            );
            for (method, uri) in [
                ("notifications/resources/updated", Some("file:///project/secret.json")),
                ("notifications/prompts/list_changed", None),
                ("notifications/progress", None),
                ("notifications/message", None),
            ] {
                assert_eq!(
                    state.accept(&notification(id.clone(), method, uri)),
                    Err(SubscriptionError::UnrequestedNotification)
                );
            }
            let done = completion(&request).unwrap();
            assert_eq!(state.accept(&done), Ok(true));
            assert_eq!(state.accept(&tool_event), Err(SubscriptionError::AlreadyCompleted));
            assert_eq!(done["result"]["_meta"][SUBSCRIPTION_ID], id);
        }
    }

    #[test]
    fn resource_updates_include_bounded_subresources_without_widening_the_filter() {
        for (subscribed, updated) in [
            ("file:///project", "file:///project/src/main.rs"),
            ("https://example.org/project/", "https://example.org/project/config.json"),
            ("git://repo.example/project", "git://repo.example/project/src/lib.rs"),
            ("https://example.org/config.json", "https://example.org/config.json#/enabled"),
            ("https://example.org/project?revision=1", "https://example.org/project/config.json?revision=1"),
            ("https://example.org/config.json#/enabled", "https://example.org/config.json#/enabled"),
            ("file:///project%20files", "file:///project%20files/config.json"),
            ("urn:example:resource", "urn:example:resource"),
        ] {
            let request = request(json!("resources"), json!({"resourceSubscriptions": [subscribed]}));
            let filter = SubscriptionFilter::from_request(&request).unwrap();
            let mut state = SubscriptionState::new(request.clone()).unwrap();
            state
                .accept(&acknowledgement(&request, &filter).unwrap())
                .unwrap();
            assert_eq!(
                state.accept(&notification(json!("resources"), "notifications/resources/updated", Some(updated))),
                Ok(false),
                "{subscribed} -> {updated}"
            );
        }
        for updated in [
            "file:///project-other/config.json",
            "file:///private/config.json",
            "file:///project/../private/config.json",
            "file://other/project/config.json",
            "https://example.org/project/config.json",
            "relative",
            "file:///project?other",
            "file:///project\n/config.json",
            "file:///project/%2e%2e/private/config.json",
            "file:///project%2Fother/config.json",
        ] {
            let request = request(json!("resources"), json!({"resourceSubscriptions": ["file:///project"]}));
            let filter = SubscriptionFilter::from_request(&request).unwrap();
            let mut state = SubscriptionState::new(request.clone()).unwrap();
            state
                .accept(&acknowledgement(&request, &filter).unwrap())
                .unwrap();
            assert_eq!(
                state.accept(&notification(json!("resources"), "notifications/resources/updated", Some(updated))),
                Err(SubscriptionError::UnrequestedNotification),
                "{updated}"
            );
        }
        for (subscribed, updated) in [
            ("https://example.org/project?revision=1", "https://example.org/project/config.json?revision=2"),
            ("https://example.org/project?revision=1", "https://example.org/project/config.json"),
            ("https://example.org/config.json#/enabled", "https://example.org/config.json#/secret"),
            ("https://example.org/config.json#/enabled", "https://example.org/config.json/child"),
            ("https://example.org/project", "https://example.org:8443/project/config.json"),
            ("https://example.org/project", "https://user@example.org/project/config.json"),
            ("https://example.org/project", "https://example.org.other/project/config.json"),
            ("urn:example:resource", "urn:example:resource:child"),
        ] {
            assert!(!resource_update_matches(subscribed, updated), "{subscribed} -> {updated}");
        }
        let request = request(json!("resources"), json!({"resourceSubscriptions": ["file:///project"]}));
        let mut state = SubscriptionState::new(request.clone()).unwrap();
        state
            .accept(&acknowledgement(&request, &SubscriptionFilter::default()).unwrap())
            .unwrap();
        assert_eq!(
            state.accept(&notification(
                json!("resources"),
                "notifications/resources/updated",
                Some("file:///project/file")
            )),
            Err(SubscriptionError::UnrequestedNotification)
        );
    }

    #[test]
    fn unsupported_filters_acknowledge_empty_and_close_without_notifications() {
        let request = request(json!("empty"), json!({"promptsListChanged": true}));
        let supported = SubscriptionFilter::default();
        let mut state = SubscriptionState::new(request.clone()).unwrap();
        let done = completion(&request).unwrap();
        assert_eq!(state.accept(&done), Err(SubscriptionError::MissingAcknowledgement));
        let ack = acknowledgement(&request, &supported).unwrap();
        assert_eq!(ack["params"]["notifications"], json!({}));
        assert_eq!(state.accept(&ack), Ok(false));
        assert_eq!(
            state.accept(&notification(json!("empty"), "notifications/prompts/list_changed", None)),
            Err(SubscriptionError::UnrequestedNotification)
        );
        let mut wrong = done.clone();
        wrong["result"]["_meta"][SUBSCRIPTION_ID] = json!("different");
        assert_eq!(state.accept(&wrong), Err(SubscriptionError::IdMismatch));
        assert_eq!(state.accept(&done), Ok(true));
        let unsupported = SubscriptionFilter {
            tools_list_changed: true,
            ..Default::default()
        };
        assert!(acknowledgement(&request, &unsupported).is_err());
    }
}
