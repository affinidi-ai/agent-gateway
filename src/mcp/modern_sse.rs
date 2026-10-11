use std::fmt::Display;
use std::future::Future;
use std::num::NonZeroUsize;
use std::time::Duration;

use bytes::Bytes;
use eventsource_stream::{Event, Eventsource};
use futures::{Stream, StreamExt};

const PARSER_CHUNK_BYTES: usize = 4096;
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

#[derive(Debug, Clone, Copy)]
pub struct SseLimits {
    pub max_event_bytes: NonZeroUsize,
    pub max_chunk_bytes: NonZeroUsize,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl SseLimits {
    /// A subscription is quiet between notifications by design, so only its
    /// lifetime bounds the upstream read; the gateway's own keepalive comments
    /// keep the caller's connection open meanwhile.
    fn for_method(
        self,
        method: &str,
    ) -> Self {
        if method == "subscriptions/listen" {
            Self {
                idle_timeout: self.max_lifetime,
                ..self
            }
        } else {
            self
        }
    }
}

impl From<&crate::config::McpHttpConfig> for SseLimits {
    fn from(config: &crate::config::McpHttpConfig) -> Self {
        Self {
            max_event_bytes: config.max_response_bytes,
            max_chunk_bytes: config.max_chunk_bytes,
            idle_timeout: Duration::from_secs(
                config
                    .stream_idle_timeout_secs
                    .get(),
            ),
            max_lifetime: Duration::from_secs(
                config
                    .stream_max_lifetime_secs
                    .get(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponseOutcome {
    pub bytes: u64,
    pub completed: bool,
    pub failed: bool,
}

#[derive(Clone)]
pub(crate) struct TransportCompletion {
    pub requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub outcome: tokio::sync::watch::Receiver<Option<bool>>,
}

impl TransportCompletion {
    async fn wait(mut self) -> Result<(), SseReadError> {
        loop {
            if let Some(completed) = *self
                .outcome
                .borrow_and_update()
            {
                return if completed {
                    Ok(())
                } else {
                    Err(SseReadError::ResponseRejected)
                };
            }
            self.outcome
                .changed()
                .await
                .map_err(|_| SseReadError::ResponseRejected)?;
        }
    }
}

struct ResponseObserver<Complete: FnOnce(ResponseOutcome)> {
    complete: Option<Complete>,
    outcome: ResponseOutcome,
}

impl<Complete: FnOnce(ResponseOutcome)> Drop for ResponseObserver<Complete> {
    fn drop(&mut self) {
        let Some(complete) = self.complete.take() else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            complete(self.outcome);
        } else {
            tracing::warn!("Response dropped outside the async runtime; completion skipped");
        }
    }
}

pub fn observe_response<Complete>(
    response: axum::response::Response,
    complete: Complete,
) -> axum::response::Response
where
    Complete: FnOnce(ResponseOutcome) + Send + 'static,
{
    let (parts, body) = response.into_parts();
    let observer = ResponseObserver {
        complete: Some(complete),
        outcome: ResponseOutcome::default(),
    };
    let source =
        futures::stream::try_unfold((body.into_data_stream(), observer), |(mut source, mut observer)| async move {
            match source.next().await {
                Some(Ok(bytes)) => {
                    observer.outcome.bytes = observer
                        .outcome
                        .bytes
                        .saturating_add(bytes.len() as u64);
                    Ok(Some((bytes, (source, observer))))
                }
                Some(Err(error)) => {
                    observer.outcome.failed = true;
                    drop(observer);
                    Err(error)
                }
                None => {
                    observer.outcome.completed = true;
                    drop(observer);
                    Ok(None)
                }
            }
        });
    axum::response::Response::from_parts(parts, axum::body::Body::from_stream(source))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SseReadError {
    #[error("Modern MCP response exceeded its idle timeout")]
    IdleTimeout,
    #[error("Modern MCP response exceeded its maximum lifetime")]
    LifetimeExceeded,
    #[error("Modern MCP stream limits are invalid")]
    InvalidLimits,
    #[error("Modern MCP response requires one application/json or text/event-stream Content-Type")]
    UnsupportedContentType,
    #[error("Modern MCP response processing rejected the upstream result")]
    ResponseRejected,
    #[error("Upstream SSE chunk exceeds the configured byte limit")]
    ChunkTooLarge,
    #[error("Upstream SSE event exceeds the configured byte limit")]
    EventTooLarge,
    #[error("Incomplete UTF-8 byte-order mark")]
    IncompleteBom,
    #[error("Upstream SSE transport failed: {0}")]
    Transport(String),
    #[error("Invalid SSE encoding or field: {0}")]
    Parse(String),
    #[error("Invalid JSON-RPC message on a request SSE stream")]
    InvalidMessage,
    #[error("Independent server requests are not permitted on modern SSE")]
    ServerRequest,
    #[error("Notification does not belong to the originating request")]
    UnrelatedNotification,
    #[error("SSE stream ended before its final JSON-RPC response")]
    MissingResponse,
    #[error(transparent)]
    Response(#[from] super::modern::ModernResponseError),
    #[error(transparent)]
    Subscription(#[from] super::subscriptions::SubscriptionError),
}

#[derive(Default)]
struct ByteBudget {
    event_bytes: usize,
    line_has_bytes: bool,
    after_cr: bool,
    bom_prefix: Vec<u8>,
    bom_checked: bool,
}

fn with_deadlines<Source, SourceError>(
    source: Source,
    limits: SseLimits,
) -> impl Stream<Item = Result<Bytes, SseReadError>>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send,
    SourceError: Display,
{
    let started = tokio::time::Instant::now();
    futures::stream::try_unfold((Box::pin(source), started), move |(mut source, last_activity)| async move {
        let lifetime = started
            .checked_add(limits.max_lifetime)
            .ok_or(SseReadError::InvalidLimits)?;
        let idle = last_activity
            .checked_add(limits.idle_timeout)
            .ok_or(SseReadError::InvalidLimits)?;
        let deadline = lifetime.min(idle);
        let timeout_error = || {
            if lifetime <= idle {
                SseReadError::LifetimeExceeded
            } else {
                SseReadError::IdleTimeout
            }
        };
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(timeout_error());
            }
            let next = tokio::time::timeout_at(deadline, source.next())
                .await
                .map_err(|_| timeout_error())?;
            match next {
                Some(Ok(bytes)) if bytes.is_empty() => tokio::task::yield_now().await,
                Some(Ok(bytes)) => return Ok(Some((bytes, (source, tokio::time::Instant::now())))),
                Some(Err(error)) => return Err(SseReadError::Transport(error.to_string())),
                None => return Ok(None),
            }
        }
    })
}

impl ByteBudget {
    fn strip_bom(
        &mut self,
        chunk: Bytes,
    ) -> Bytes {
        if self.bom_checked {
            return chunk;
        }
        let mut offset = 0;
        while offset < chunk.len() && !self.bom_checked {
            self.bom_prefix
                .push(chunk[offset]);
            offset += 1;
            if !UTF8_BOM.starts_with(&self.bom_prefix) {
                self.bom_checked = true;
                let mut bytes = std::mem::take(&mut self.bom_prefix);
                bytes.extend_from_slice(&chunk[offset..]);
                return Bytes::from(bytes);
            }
            if self.bom_prefix.len() == UTF8_BOM.len() {
                self.bom_prefix.clear();
                self.bom_checked = true;
            }
        }
        if self.bom_checked {
            chunk.slice(offset..)
        } else {
            Bytes::new()
        }
    }

    fn normalize_and_check(
        &mut self,
        bytes: &[u8],
        limit: NonZeroUsize,
    ) -> Result<Bytes, SseReadError> {
        let mut normalized = Vec::with_capacity(bytes.len());
        for byte in bytes {
            if self.after_cr && *byte == b'\n' {
                self.after_cr = false;
                continue;
            }
            self.after_cr = false;
            self.event_bytes = self
                .event_bytes
                .checked_add(1)
                .ok_or(SseReadError::EventTooLarge)?;
            if self.event_bytes > limit.get() {
                return Err(SseReadError::EventTooLarge);
            }
            if matches!(*byte, b'\r' | b'\n') {
                if !self.line_has_bytes {
                    self.event_bytes = 0;
                }
                self.line_has_bytes = false;
                self.after_cr = *byte == b'\r';
                normalized.push(b'\n');
            } else {
                self.line_has_bytes = true;
                normalized.push(*byte);
            }
        }
        Ok(Bytes::from(normalized))
    }
}

pub fn decode_events<Source, SourceError>(
    source: Source,
    limits: SseLimits,
) -> impl Stream<Item = Result<Event, SseReadError>>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send,
    SourceError: Display,
{
    let chunks = futures::stream::try_unfold(
        (Box::pin(with_deadlines(source, limits)), Bytes::new(), ByteBudget::default()),
        move |(mut source, mut pending, mut budget)| async move {
            loop {
                if pending.is_empty() {
                    match source.next().await {
                        Some(Ok(chunk)) => {
                            if chunk.len() > limits.max_chunk_bytes.get() {
                                return Err(SseReadError::ChunkTooLarge);
                            }
                            pending = chunk;
                        }
                        Some(Err(error)) => return Err(error),
                        None if !budget.bom_prefix.is_empty() => return Err(SseReadError::IncompleteBom),
                        None => return Ok(None),
                    }
                }
                tokio::task::yield_now().await;
                let piece = pending.split_to(
                    pending
                        .len()
                        .min(PARSER_CHUNK_BYTES),
                );
                let piece = budget.strip_bom(piece);
                if piece.is_empty() {
                    continue;
                }
                let piece = budget.normalize_and_check(&piece, limits.max_event_bytes)?;
                return Ok(Some((piece, (source, pending, budget))));
            }
        },
    );
    futures::stream::once(async { Ok::<Bytes, SseReadError>(Bytes::from_static(b"\n")) })
        .chain(chunks)
        .eventsource()
        .map(|result| {
            result.map_err(|error| match error {
                eventsource_stream::EventStreamError::Transport(error) => error,
                error => SseReadError::Parse(error.to_string()),
            })
        })
}

fn validate_notification(
    message: &serde_json::Value,
    request: &super::request_validation::ValidatedModernMessage,
) -> Result<(), SseReadError> {
    use super::request_validation::is_logging_level;
    use serde_json::Value;
    if message
        .get("jsonrpc")
        .and_then(Value::as_str)
        != Some("2.0")
        || message
            .get("result")
            .is_some()
        || message.get("error").is_some()
    {
        return Err(SseReadError::InvalidMessage);
    }
    if message.get("id").is_some() {
        return Err(SseReadError::ServerRequest);
    }
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .ok_or(SseReadError::InvalidMessage)?;
    let params = message.get("params");
    if params.is_some_and(|params| !params.is_object()) {
        return Err(SseReadError::InvalidMessage);
    }
    if params
        .and_then(|params| params.get("_meta"))
        .is_some_and(|meta| !meta.is_object())
    {
        return Err(SseReadError::InvalidMessage);
    }
    if params
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get("io.modelcontextprotocol/subscriptionId"))
        .is_some()
        || matches!(
            method,
            "notifications/subscriptions/acknowledged"
                | "notifications/tools/list_changed"
                | "notifications/prompts/list_changed"
                | "notifications/resources/list_changed"
                | "notifications/resources/updated"
        )
    {
        return Err(SseReadError::UnrelatedNotification);
    }
    let meta = request
        .params
        .as_ref()
        .and_then(|params| params.get("_meta"));
    match method {
        "notifications/progress" => {
            let token = params.and_then(|params| params.get("progressToken"));
            if token.is_none() || token != meta.and_then(|meta| meta.get("progressToken")) {
                return Err(SseReadError::UnrelatedNotification);
            }
            if !token.is_some_and(|token| token.is_string() || token.is_number())
                || !params
                    .and_then(|params| params.get("progress"))
                    .is_some_and(Value::is_number)
                || params
                    .and_then(|params| params.get("total"))
                    .is_some_and(|total| !total.is_number())
                || params
                    .and_then(|params| params.get("message"))
                    .is_some_and(|message| !message.is_string())
            {
                return Err(SseReadError::InvalidMessage);
            }
        }
        "notifications/message" => {
            if !meta
                .and_then(|meta| meta.get("io.modelcontextprotocol/logLevel"))
                .is_some_and(is_logging_level)
            {
                return Err(SseReadError::UnrelatedNotification);
            }
            if !params
                .and_then(|params| params.get("level"))
                .is_some_and(is_logging_level)
                || params
                    .and_then(|params| params.get("data"))
                    .is_none()
                || params
                    .and_then(|params| params.get("logger"))
                    .is_some_and(|logger| !logger.is_string())
            {
                return Err(SseReadError::InvalidMessage);
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
pub fn request_events<Source, SourceError, Rewrite, RewriteFuture>(
    source: Source,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    rewrite_complete: Rewrite,
) -> impl Stream<Item = Result<axum::response::sse::Event, SseReadError>>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send,
    SourceError: Display,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture,
    RewriteFuture: Future<Output = Result<serde_json::Value, SseReadError>>,
{
    request_events_with_finalizer(source, request, limits, rewrite_complete, |message| async { Ok(message) }, None)
}

fn request_events_with_finalizer<Source, SourceError, Rewrite, RewriteFuture, Finalize, FinalizeFuture>(
    source: Source,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    rewrite_complete: Rewrite,
    finalize: Finalize,
    completion: Option<TransportCompletion>,
) -> impl Stream<Item = Result<axum::response::sse::Event, SseReadError>>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send,
    SourceError: Display,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture,
    RewriteFuture: Future<Output = Result<serde_json::Value, SseReadError>>,
    Finalize: FnOnce(serde_json::Value) -> FinalizeFuture,
    FinalizeFuture: Future<Output = Result<serde_json::Value, SseReadError>>,
{
    use super::modern::{ResultSource, validate_response};
    let limits = limits.for_method(&request.method);
    let subscription = if request.method == "subscriptions/listen" {
        Some(
            super::subscriptions::SubscriptionState::new(request.clone())
                .map_err(|_| super::subscriptions::SubscriptionError::InvalidFilter),
        )
    } else {
        None
    };
    futures::stream::try_unfold(
        (
            Box::pin(decode_events(source, limits)),
            request,
            Some(rewrite_complete),
            Some(finalize),
            subscription,
            completion,
            false,
        ),
        move |(mut events, request, mut rewrite_complete, mut finalize, mut subscription, completion, finished)| async move {
            if finished {
                if let Some(completion) = completion {
                    completion
                        .requested
                        .store(true, std::sync::atomic::Ordering::Release);
                    drop(events);
                    completion.wait().await?;
                }
                return Ok(None);
            }
            if let Some(Err(error)) = subscription.as_ref() {
                return Err(match error {
                    super::subscriptions::SubscriptionError::InvalidFilter => {
                        SseReadError::Subscription(super::subscriptions::SubscriptionError::InvalidFilter)
                    }
                    _ => SseReadError::InvalidMessage,
                });
            }
            let event = events
                .next()
                .await
                .ok_or(SseReadError::MissingResponse)??;
            let mut message: serde_json::Value =
                serde_json::from_str(&event.data).map_err(|_| SseReadError::InvalidMessage)?;
            let finished = if let Some(Ok(subscription)) = subscription.as_mut() {
                subscription.accept(&message)?
            } else if message
                .get("method")
                .is_some()
            {
                validate_notification(&message, &request)?;
                false
            } else {
                if validate_response(&request, &message, ResultSource::ModernServer)? == Some("complete") {
                    message = rewrite_complete
                        .take()
                        .ok_or(SseReadError::ResponseRejected)?(message)
                    .await?;
                    if validate_response(&request, &message, ResultSource::ModernServer)? != Some("complete") {
                        return Err(SseReadError::Response(super::modern::ModernResponseError::NotComplete));
                    }
                }
                true
            };
            if finished && subscription.is_none() {
                let kind = validate_response(&request, &message, ResultSource::ModernServer)?.map(str::to_string);
                message = finalize
                    .take()
                    .ok_or(SseReadError::ResponseRejected)?(message)
                .await?;
                if validate_response(&request, &message, ResultSource::ModernServer)? != kind.as_deref() {
                    return Err(SseReadError::ResponseRejected);
                }
            }
            let data = serde_json::to_string(&message).map_err(|_| SseReadError::InvalidMessage)?;
            if data.len() > limits.max_event_bytes.get() {
                return Err(SseReadError::EventTooLarge);
            }
            let output = axum::response::sse::Event::default()
                .event(event.event)
                .data(data);
            Ok(Some((output, (events, request, rewrite_complete, finalize, subscription, completion, finished))))
        },
    )
}

#[cfg(test)]
pub fn request_sse_response<Source, SourceError, Rewrite, RewriteFuture>(
    source: Source,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    rewrite_complete: Rewrite,
) -> axum::response::Response
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture + Send + 'static,
    RewriteFuture: Future<Output = Result<serde_json::Value, SseReadError>> + Send + 'static,
{
    request_sse_response_with_finalizer(
        source,
        status,
        headers,
        request,
        limits,
        rewrite_complete,
        |message| async { Ok(message) },
        None,
    )
}

fn request_sse_response_with_finalizer<Source, SourceError, Rewrite, RewriteFuture, Finalize, FinalizeFuture>(
    source: Source,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    rewrite_complete: Rewrite,
    finalize: Finalize,
    completion: Option<TransportCompletion>,
) -> axum::response::Response
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture + Send + 'static,
    RewriteFuture: Future<Output = Result<serde_json::Value, SseReadError>> + Send + 'static,
    Finalize: FnOnce(serde_json::Value) -> FinalizeFuture + Send + 'static,
    FinalizeFuture: Future<Output = Result<serde_json::Value, SseReadError>> + Send + 'static,
{
    use axum::response::IntoResponse;

    // The status is already sent, so an error can only end the stream; record
    // why, since the client sees nothing but a truncated body.
    let events = futures::TryStreamExt::inspect_err(
        request_events_with_finalizer(source, request, limits, rewrite_complete, finalize, completion),
        |error| tracing::warn!(%error, ?error, "Modern MCP SSE response ended with an error after the status was sent"),
    );
    let mut response = axum::response::Sse::new(events)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response();
    *response.status_mut() = status;
    copy_response_headers(&mut response, headers);
    response
        .headers_mut()
        .insert("x-accel-buffering", axum::http::HeaderValue::from_static("no"));
    response
}

fn copy_response_headers(
    response: &mut axum::response::Response,
    headers: &axum::http::HeaderMap,
) {
    let connection_headers: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| {
            name.trim()
                .to_ascii_lowercase()
        })
        .collect();
    for (name, value) in headers {
        if !matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "content-length"
                | "content-type"
                | "content-encoding"
                | "mcp-session-id"
                | "last-event-id"
                | "cache-control"
                | "x-accel-buffering"
        ) && !connection_headers
            .iter()
            .any(|header| header == name.as_str())
        {
            response
                .headers_mut()
                .append(name, value.clone());
        }
    }
    response
        .headers_mut()
        .insert("cache-control", axum::http::HeaderValue::from_static("no-store"));
}

pub struct ProcessedResponse {
    pub message: serde_json::Value,
    pub headers: Option<axum::http::HeaderMap>,
}

impl From<serde_json::Value> for ProcessedResponse {
    fn from(message: serde_json::Value) -> Self {
        Self { message, headers: None }
    }
}

#[cfg(test)]
pub async fn forwarding_response<Source, SourceError, Rewrite, RewriteFuture, Processed>(
    source: Source,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    support: super::modern::ForwardingSupport<'static>,
    rewrite_complete: Rewrite,
) -> Result<axum::response::Response, SseReadError>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture + Send + 'static,
    RewriteFuture: Future<Output = Result<Processed, SseReadError>> + Send + 'static,
    Processed: Into<ProcessedResponse>,
{
    forwarding_response_with_finalizer(
        source,
        status,
        headers,
        request,
        limits,
        support,
        rewrite_complete,
        |message| async { Ok(message) },
    )
    .await
}

pub async fn forwarding_response_with_finalizer<
    Source,
    SourceError,
    Rewrite,
    RewriteFuture,
    Processed,
    Finalize,
    FinalizeFuture,
>(
    source: Source,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    support: super::modern::ForwardingSupport<'static>,
    rewrite_complete: Rewrite,
    finalize: Finalize,
) -> Result<axum::response::Response, SseReadError>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture + Send + 'static,
    RewriteFuture: Future<Output = Result<Processed, SseReadError>> + Send + 'static,
    Processed: Into<ProcessedResponse>,
    Finalize: FnOnce(serde_json::Value) -> FinalizeFuture + Send + 'static,
    FinalizeFuture: Future<Output = Result<serde_json::Value, SseReadError>> + Send + 'static,
{
    forwarding_response_with_completion(
        source,
        status,
        headers,
        request,
        limits,
        support,
        rewrite_complete,
        finalize,
        None,
    )
    .await
}

pub(crate) async fn forwarding_response_with_completion<
    Source,
    SourceError,
    Rewrite,
    RewriteFuture,
    Processed,
    Finalize,
    FinalizeFuture,
>(
    source: Source,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    mut support: super::modern::ForwardingSupport<'static>,
    rewrite_complete: Rewrite,
    finalize: Finalize,
    completion: Option<TransportCompletion>,
) -> Result<axum::response::Response, SseReadError>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture + Send + 'static,
    RewriteFuture: Future<Output = Result<Processed, SseReadError>> + Send + 'static,
    Processed: Into<ProcessedResponse>,
    Finalize: FnOnce(serde_json::Value) -> FinalizeFuture + Send + 'static,
    FinalizeFuture: Future<Output = Result<serde_json::Value, SseReadError>> + Send + 'static,
{
    let discovery_request = request.clone();
    let learned_versions = support
        .learned_versions
        .take()
        .filter(|_| request.method == "server/discover");
    request_response_with_finalizer(
        source,
        status,
        headers,
        request,
        limits,
        move |mut message| async move {
            super::modern::constrain_forwarded_discovery(&discovery_request, &mut message, &support)?;
            rewrite_complete(message).await
        },
        move |message| async move {
            let message = finalize(message).await?;
            if let Some(key) = learned_versions {
                super::upstream_versions::record_discovery(key, &message);
            }
            Ok(message)
        },
        completion,
    )
    .await
}

#[cfg(test)]
pub async fn request_response<Source, SourceError, Rewrite, RewriteFuture, Processed>(
    source: Source,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    rewrite_complete: Rewrite,
) -> Result<axum::response::Response, SseReadError>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture + Send + 'static,
    RewriteFuture: Future<Output = Result<Processed, SseReadError>> + Send + 'static,
    Processed: Into<ProcessedResponse>,
{
    request_response_with_finalizer(
        source,
        status,
        headers,
        request,
        limits,
        rewrite_complete,
        |message| async { Ok(message) },
        None,
    )
    .await
}

async fn request_response_with_finalizer<
    Source,
    SourceError,
    Rewrite,
    RewriteFuture,
    Processed,
    Finalize,
    FinalizeFuture,
>(
    source: Source,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    request: super::request_validation::ValidatedModernMessage,
    limits: SseLimits,
    rewrite_complete: Rewrite,
    finalize: Finalize,
    completion: Option<TransportCompletion>,
) -> Result<axum::response::Response, SseReadError>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Rewrite: FnOnce(serde_json::Value) -> RewriteFuture + Send + 'static,
    RewriteFuture: Future<Output = Result<Processed, SseReadError>> + Send + 'static,
    Processed: Into<ProcessedResponse>,
    Finalize: FnOnce(serde_json::Value) -> FinalizeFuture + Send + 'static,
    FinalizeFuture: Future<Output = Result<serde_json::Value, SseReadError>> + Send + 'static,
{
    use super::modern::{ResultSource, validate_response};
    use axum::response::IntoResponse;

    if request.kind == super::request_validation::McpMessageKind::Notification {
        let accepted = status == axum::http::StatusCode::ACCEPTED;
        if request.id.is_some() || !(accepted || status.is_client_error() || status.is_server_error()) {
            return Err(SseReadError::InvalidMessage);
        }
        let mut source = Box::pin(with_deadlines(source, limits));
        let mut body = Vec::new();
        while let Some(chunk) = source.next().await {
            let chunk = chunk?;
            if accepted && !chunk.is_empty() {
                return Err(SseReadError::InvalidMessage);
            }
            if chunk.len() > limits.max_chunk_bytes.get() {
                return Err(SseReadError::ChunkTooLarge);
            }
            if body
                .len()
                .saturating_add(chunk.len())
                > limits.max_event_bytes.get()
            {
                return Err(SseReadError::EventTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        if !body.is_empty() {
            let message: serde_json::Value = serde_json::from_slice(&body).map_err(|_| SseReadError::InvalidMessage)?;
            let valid_error = message
                .get("error")
                .is_some_and(|error| {
                    error
                        .get("code")
                        .is_some_and(|code| code.as_i64().is_some() || code.as_u64().is_some())
                        && error
                            .get("message")
                            .is_some_and(serde_json::Value::is_string)
                });
            if message
                .get("jsonrpc")
                .and_then(serde_json::Value::as_str)
                != Some("2.0")
                || message.get("id").is_some()
                || message
                    .get("method")
                    .is_some()
                || message
                    .get("result")
                    .is_some()
                || !valid_error
            {
                return Err(SseReadError::InvalidMessage);
            }
        }
        let empty = body.is_empty();
        let mut response = axum::response::Response::new(axum::body::Body::from(body));
        *response.status_mut() = status;
        copy_response_headers(&mut response, headers);
        if empty {
            response
                .headers_mut()
                .remove(axum::http::header::CONTENT_TYPE);
        } else {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/json"));
        }
        return Ok(response);
    }

    let mut content_types = headers
        .get_all(axum::http::header::CONTENT_TYPE)
        .iter();
    let content_type: mime::Mime = content_types
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or(SseReadError::UnsupportedContentType)?;
    if content_types.next().is_some()
        || content_type
            .params()
            .any(|(name, value)| name == mime::CHARSET && value != mime::UTF_8)
    {
        return Err(SseReadError::UnsupportedContentType);
    }
    if content_type.essence_str() == "text/event-stream" {
        let mut advertised = axum::response::Response::new(axum::body::Body::empty());
        copy_response_headers(&mut advertised, headers);
        let advertised = advertised
            .into_parts()
            .0
            .headers;
        return Ok(request_sse_response_with_finalizer(
            source,
            status,
            headers,
            request,
            limits,
            move |message| async move {
                let processed: ProcessedResponse = rewrite_complete(message)
                    .await?
                    .into();
                if let Some(headers) = processed.headers {
                    let mut updated = axum::response::Response::new(axum::body::Body::empty());
                    copy_response_headers(&mut updated, &headers);
                    if updated.headers() != &advertised {
                        return Err(SseReadError::ResponseRejected);
                    }
                }
                Ok(processed.message)
            },
            finalize,
            completion,
        ));
    }
    if content_type.essence_str() != "application/json" {
        return Err(SseReadError::UnsupportedContentType);
    }
    let mut source = Box::pin(with_deadlines(source, limits));
    let mut body = Vec::new();
    while let Some(chunk) = source.next().await {
        let chunk = chunk?;
        if chunk.len() > limits.max_chunk_bytes.get() {
            return Err(SseReadError::ChunkTooLarge);
        }
        if body
            .len()
            .saturating_add(chunk.len())
            > limits.max_event_bytes.get()
        {
            return Err(SseReadError::EventTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let mut message: serde_json::Value = serde_json::from_slice(&body).map_err(|_| SseReadError::InvalidMessage)?;
    if request.method == "subscriptions/listen"
        && validate_response(&request, &message, ResultSource::ModernServer)?.is_some()
    {
        return Err(SseReadError::UnsupportedContentType);
    }
    let mut processed_headers = None;
    if validate_response(&request, &message, ResultSource::ModernServer)? == Some("complete") {
        let processed: ProcessedResponse = rewrite_complete(message)
            .await?
            .into();
        message = processed.message;
        processed_headers = processed.headers;
        if validate_response(&request, &message, ResultSource::ModernServer)? != Some("complete") {
            return Err(SseReadError::Response(super::modern::ModernResponseError::NotComplete));
        }
    }
    let kind = validate_response(&request, &message, ResultSource::ModernServer)?.map(str::to_string);
    message = finalize(message).await?;
    if validate_response(&request, &message, ResultSource::ModernServer)? != kind.as_deref() {
        return Err(SseReadError::ResponseRejected);
    }
    let bytes = serde_json::to_vec(&message).map_err(|_| SseReadError::InvalidMessage)?;
    if bytes.len() > limits.max_event_bytes.get() {
        return Err(SseReadError::EventTooLarge);
    }
    let mut response = bytes.into_response();
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/json"));
    copy_response_headers(
        &mut response,
        processed_headers
            .as_ref()
            .unwrap_or(headers),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use futures::TryStreamExt;

    fn limits(event_bytes: usize) -> SseLimits {
        SseLimits {
            max_event_bytes: NonZeroUsize::new(event_bytes).unwrap(),
            max_chunk_bytes: NonZeroUsize::new(8192).unwrap(),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(3600),
        }
    }

    // Carries multi-byte characters so a chunk split can land inside one.
    const PRESERVATION_ID: &str = "préservation-✓";

    fn pinned_result_fixtures() -> Vec<(String, serde_json::Value)> {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/mcp/2026-07-28.json")).unwrap();
        fixtures["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|fixture| {
                (
                    fixture["method"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    fixture["result"].clone(),
                )
            })
            .collect()
    }

    fn fixture_request(method: &str) -> super::super::request_validation::ValidatedModernMessage {
        super::super::request_validation::ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: method.into(),
            params: None,
            id: Some(serde_json::json!(PRESERVATION_ID)),
            kind: super::super::request_validation::McpMessageKind::Request,
        }
    }

    async fn forwarded_fixture_result(
        method: &str,
        envelope: &serde_json::Value,
        chunks: Vec<Bytes>,
        content_type: &str,
    ) -> serde_json::Value {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::CONTENT_TYPE, content_type.parse().unwrap());
        let response = forwarding_response(
            futures::stream::iter(
                chunks
                    .into_iter()
                    .map(Ok::<_, io::Error>),
            ),
            axum::http::StatusCode::OK,
            &headers,
            fixture_request(method),
            limits(65536),
            super::super::modern::ForwardingSupport::for_endpoint(
                false,
                crate::mcp::request_validation::McpPathKind::DirectAccessPoint,
            ),
            |message| async move { Ok::<_, SseReadError>(message) },
        )
        .await
        .unwrap_or_else(|error| panic!("{method} fixture was rejected while forwarding: {error}"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let forwarded: serde_json::Value = if content_type.starts_with("text/event-stream") {
            let events: Vec<_> = decode_events(futures::stream::iter([Ok::<_, io::Error>(body)]), limits(65536))
                .try_collect()
                .await
                .unwrap();
            serde_json::from_str(&events.last().unwrap().data).unwrap()
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        assert_eq!(forwarded["id"], envelope["id"], "{method} lost request correlation");
        forwarded["result"].clone()
    }

    #[tokio::test]
    async fn pinned_result_fixtures_survive_json_and_chunk_split_sse_forwarding() {
        for (method, result) in pinned_result_fixtures() {
            let envelope = serde_json::json!({"jsonrpc": "2.0", "id": PRESERVATION_ID, "result": result});
            let json_bytes = Bytes::from(serde_json::to_vec(&envelope).unwrap());

            let forwarded =
                forwarded_fixture_result(&method, &envelope, vec![json_bytes.clone()], "application/json").await;
            assert_eq!(forwarded, result, "{method} was altered on the buffered JSON path");

            let event = format!("event: message\r\ndata: {}\r\n\r\n", serde_json::to_string(&envelope).unwrap());
            let bytes = event.as_bytes();
            // Split inside a multi-byte character and inside the CRLF delimiter, where
            // per-chunk lossy decoding would corrupt the payload.
            let mid_character = event
                .find('é')
                .expect("the request id carries a multi-byte character")
                + 1;
            let mid_delimiter = event
                .rfind("\r\n\r\n")
                .expect("the event ends with a CRLF delimiter")
                + 1;
            assert!(!event.is_char_boundary(mid_character), "the split must land inside a character");
            for split in [1, mid_character, bytes.len() / 2, mid_delimiter, bytes.len() - 1] {
                let (head, tail) = bytes.split_at(split);
                let forwarded = forwarded_fixture_result(
                    &method,
                    &envelope,
                    vec![Bytes::copy_from_slice(head), Bytes::copy_from_slice(tail)],
                    "text/event-stream",
                )
                .await;
                assert_eq!(forwarded, result, "{method} was altered by an SSE chunk split at byte {split}");
            }

            // `$ref` targets and icon sources must never be dereferenced or rewritten in transit.
            let rendered = serde_json::to_string(
                &forwarded_fixture_result(&method, &envelope, vec![json_bytes], "application/json").await,
            )
            .unwrap();
            for preserved in ["#/$defs/value", "https://example.org/icon.png", "https://example.org/resource"] {
                assert_eq!(
                    rendered.contains(preserved),
                    serde_json::to_string(&result)
                        .unwrap()
                        .contains(preserved),
                    "{method} changed whether {preserved} is present"
                );
            }
        }
    }

    #[tokio::test]
    async fn accepted_notifications_return_empty_202_without_result_processing() {
        let request = super::super::request_validation::ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: "com.example/notifications/changed".into(),
            params: Some(serde_json::json!({"revision": 1})),
            id: None,
            kind: super::super::request_validation::McpMessageKind::Notification,
        };
        let response = request_response_with_finalizer(
            futures::stream::empty::<Result<Bytes, io::Error>>(),
            axum::http::StatusCode::ACCEPTED,
            &axum::http::HeaderMap::new(),
            request.clone(),
            limits(4096),
            |_message| async { Err::<serde_json::Value, _>(SseReadError::ResponseRejected) },
            |_message| async { Err(SseReadError::ResponseRejected) },
            None,
        )
        .await
        .expect("an accepted notification needs no content type or JSON-RPC response");
        assert_eq!(response.status(), axum::http::StatusCode::ACCEPTED);
        assert!(
            !response
                .headers()
                .contains_key(axum::http::header::CONTENT_TYPE)
        );
        assert!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .is_empty()
        );
        for (status, body) in [
            (200, Bytes::new()),
            (204, Bytes::new()),
            (302, Bytes::new()),
            (202, Bytes::from_static(b"unexpected")),
            (400, Bytes::from_static(br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"Unknown"}}"#)),
            (400, Bytes::from_static(br#"{"jsonrpc":"2.0","result":{}}"#)),
        ] {
            let result = request_response(
                futures::stream::iter([Ok::<_, io::Error>(body)]),
                axum::http::StatusCode::from_u16(status).unwrap(),
                &axum::http::HeaderMap::new(),
                request.clone(),
                limits(4096),
                |_| async { Err::<serde_json::Value, _>(SseReadError::ResponseRejected) },
            )
            .await;
            assert!(matches!(result, Err(SseReadError::InvalidMessage)), "status {status}");
        }
        for body in [
            Bytes::new(),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Unknown notification","data":{"retry":false}}}"#,
            ),
        ] {
            let response = request_response_with_finalizer(
                futures::stream::iter([Ok::<_, io::Error>(body.clone())]),
                axum::http::StatusCode::NOT_FOUND,
                &axum::http::HeaderMap::new(),
                request.clone(),
                limits(4096),
                |_| async { Err::<serde_json::Value, _>(SseReadError::ResponseRejected) },
                |_| async { Err(SseReadError::ResponseRejected) },
                None,
            )
            .await
            .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
            assert_eq!(response.headers()[axum::http::header::CACHE_CONTROL], "no-store");
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
                body
            );
        }
        let oversized = request_response(
            futures::stream::iter([Ok::<_, io::Error>(Bytes::from(vec![b'x'; 4097]))]),
            axum::http::StatusCode::BAD_REQUEST,
            &axum::http::HeaderMap::new(),
            request.clone(),
            limits(4096),
            |_| async { Err::<serde_json::Value, _>(SseReadError::ResponseRejected) },
        )
        .await;
        assert!(matches!(oversized, Err(SseReadError::EventTooLarge)));
        let quiet = request_response(
            futures::stream::pending::<Result<Bytes, io::Error>>(),
            axum::http::StatusCode::ACCEPTED,
            &axum::http::HeaderMap::new(),
            request,
            SseLimits {
                idle_timeout: Duration::ZERO,
                ..limits(4096)
            },
            |_| async { Err::<serde_json::Value, _>(SseReadError::ResponseRejected) },
        )
        .await;
        assert!(matches!(quiet, Err(SseReadError::IdleTimeout)));
    }

    #[tokio::test]
    async fn continuation_finalizers_handle_interim_json_and_sse_without_application_enrichment() {
        for content_type in ["application/json", "text/event-stream"] {
            for change_kind in [false, true] {
                let message = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {
                    "resultType": "input_required", "requestState": "upstream opaque state"
                }});
                let bytes = if content_type == "application/json" {
                    Bytes::from(message.to_string())
                } else {
                    frame(message)
                };
                let headers = axum::http::HeaderMap::from_iter([(
                    axum::http::header::CONTENT_TYPE,
                    content_type.parse().unwrap(),
                )]);
                let response = request_response_with_finalizer(
                    futures::stream::iter([Ok::<_, io::Error>(bytes)]),
                    axum::http::StatusCode::OK,
                    &headers,
                    request(),
                    limits(2048),
                    |_| async { Err::<ProcessedResponse, _>(SseReadError::ResponseRejected) },
                    move |mut message| async move {
                        message["result"]["requestState"] = serde_json::json!("protected gateway wrapper");
                        if change_kind {
                            message["result"]["resultType"] = serde_json::json!("complete");
                        }
                        Ok(message)
                    },
                    None,
                )
                .await;
                if change_kind && content_type == "application/json" {
                    assert!(response.is_err());
                    continue;
                }
                let response = response.unwrap();
                assert_eq!(response.headers()[axum::http::header::CACHE_CONTROL], "no-store");
                let bytes = axum::body::to_bytes(response.into_body(), 4096).await;
                if change_kind {
                    assert!(bytes.is_err());
                    continue;
                }
                let bytes = bytes.unwrap();
                let received: serde_json::Value = if content_type == "application/json" {
                    serde_json::from_slice(&bytes).unwrap()
                } else {
                    let events: Vec<_> =
                        decode_events(futures::stream::iter([Ok::<_, io::Error>(bytes)]), limits(4096))
                            .try_collect()
                            .await
                            .unwrap();
                    serde_json::from_str(&events[0].data).unwrap()
                };
                assert_eq!(received["result"]["resultType"], "input_required");
                assert_eq!(received["result"]["requestState"], "protected gateway wrapper");
                assert!(
                    received["result"]
                        .get("_meta")
                        .is_none()
                );
            }
        }
    }

    #[tokio::test]
    async fn forwarded_discovery_uses_the_same_path_constraints_in_json_and_sse() {
        for sse in [false, true] {
            let mut request = request();
            request.method = "server/discover".to_string();
            let message = serde_json::json!({"jsonrpc": "2.0", "id": request.id, "result": {
                "resultType": "complete", "supportedVersions": [super::super::MCP_MODERN_VERSION, "2025-11-25"],
                "capabilities": {"tools": {"listChanged": true}, "resources": {"subscribe": true}},
                "ttlMs": 1000, "cacheScope": "public", "instructions": "Upstream",
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "Upstream", "version": "1"}}
            }});
            let headers = axum::http::HeaderMap::from_iter([
                (
                    axum::http::header::CONTENT_TYPE,
                    if sse {
                        "text/event-stream"
                    } else {
                        "application/json"
                    }
                    .parse()
                    .unwrap(),
                ),
                (
                    axum::http::header::CACHE_CONTROL,
                    "public, max-age=3600"
                        .parse()
                        .unwrap(),
                ),
            ]);
            let source = if sse {
                format!("data: {message}\n\n")
            } else {
                message.to_string()
            };
            let support = super::super::modern::ForwardingSupport {
                versions: super::super::request_validation::McpVersionPolicy::new(
                    &[super::super::MCP_MODERN_VERSION],
                    &[super::super::MCP_MODERN_VERSION],
                ),
                request_streams: true,
                subscriptions: false,
                capabilities: &["tools", "resources"],
                extensions: &[],
                learned_versions: None,
            };
            let response = forwarding_response(
                futures::stream::iter([Ok::<_, io::Error>(Bytes::from(source))]),
                axum::http::StatusCode::OK,
                &headers,
                request,
                limits(4096),
                support,
                |message| async { Ok(message) },
            )
            .await
            .unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            let bytes = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            let received: serde_json::Value = if sse {
                let events = futures::stream::iter([Ok::<_, io::Error>(bytes)]).eventsource();
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
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            assert_eq!(received["result"]["capabilities"], serde_json::json!({"tools": {}, "resources": {}}));
            assert_eq!(received["result"]["supportedVersions"], serde_json::json!([super::super::MCP_MODERN_VERSION]));
            assert_eq!(received["result"]["_meta"], message["result"]["_meta"]);
            assert_eq!(received["result"]["ttlMs"], 0);
            assert_eq!(received["result"]["cacheScope"], "private");
        }
    }

    #[tokio::test]
    async fn forwarded_discovery_records_the_versions_the_client_received_over_json_and_sse() {
        use super::super::request_validation::{McpRequestValidationError, McpVersionPolicy};
        use super::super::upstream_versions::{UpstreamKey, UpstreamRoute, restrict_unsupported};
        use super::super::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION};
        use serde_json::json;

        let dual = McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]);
        let advertised = |key: &UpstreamKey| {
            restrict_unsupported(McpRequestValidationError::unsupported(None, "2025-11-25", dual), key)
                .data
                .unwrap()["supported"]
                .clone()
        };
        let path_set = json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION]);
        let result = |versions: serde_json::Value| {
            json!({"jsonrpc": "2.0", "id": 7, "result": {
                "resultType": "complete", "supportedVersions": versions, "tools": [],
                "capabilities": {"tools": {}}, "ttlMs": 0, "cacheScope": "private"
            }})
        };
        let error = |code: i32| json!({"jsonrpc": "2.0", "id": 7, "error": {"code": code, "message": "failed"}});
        let cases = [
            ("server/discover", result(json!([MCP_MODERN_VERSION, "2025-11-25"])), true, json!([MCP_MODERN_VERSION])),
            ("server/discover", error(crate::mcp::error_codes::METHOD_NOT_FOUND), true, json!([MCP_LEGACY_VERSION])),
            ("server/discover", error(crate::mcp::error_codes::INTERNAL_ERROR), true, path_set.clone()),
            ("server/discover", result(json!([MCP_LEGACY_VERSION])), false, path_set.clone()),
            ("tools/list", result(json!([MCP_MODERN_VERSION])), true, path_set.clone()),
        ];
        for sse in [false, true] {
            for (index, (method, upstream, delivered, expected)) in cases.iter().enumerate() {
                let key = UpstreamKey {
                    surface_id: format!("forwarded-discovery-{sse}-{index}"),
                    route: UpstreamRoute::AccessPoint(None),
                    target: "https://upstream.example/mcp".into(),
                };
                let mut request = request();
                request.method = method.to_string();
                let (content_type, source) = if sse {
                    ("text/event-stream", format!("data: {upstream}\n\n"))
                } else {
                    ("application/json", upstream.to_string())
                };
                let headers = axum::http::HeaderMap::from_iter([(
                    axum::http::header::CONTENT_TYPE,
                    content_type.parse().unwrap(),
                )]);
                let support = super::super::modern::ForwardingSupport {
                    versions: dual,
                    request_streams: true,
                    subscriptions: true,
                    capabilities: &["tools"],
                    extensions: &[],
                    learned_versions: None,
                }
                .recording_versions(key.clone());
                let response = forwarding_response(
                    futures::stream::iter([Ok::<_, io::Error>(Bytes::from(source))]),
                    axum::http::StatusCode::OK,
                    &headers,
                    request,
                    limits(4096),
                    support,
                    |message| async { Ok(message) },
                )
                .await;
                let received = match response {
                    Ok(response) => {
                        if sse {
                            assert_eq!(advertised(&key), path_set, "{method} {index} recorded before delivery");
                        }
                        axum::body::to_bytes(response.into_body(), 8192)
                            .await
                            .is_ok()
                    }
                    Err(error) => {
                        assert!(!sse, "{method} {index}: {error}");
                        false
                    }
                };
                assert_eq!(received, *delivered, "sse={sse} {method} {index}");
                assert_eq!(advertised(&key), *expected, "sse={sse} {method} {index}");
            }
        }
    }

    #[tokio::test]
    async fn subscription_sse_validates_ack_filters_and_completion_without_result_enrichment() {
        for id in [serde_json::json!(4), serde_json::json!("4")] {
            let mut request = request();
            request.id = Some(id.clone());
            request.method = "subscriptions/listen".into();
            request.params = Some(serde_json::json!({"notifications": {"toolsListChanged": true}}));
            let filter = super::super::subscriptions::SubscriptionFilter::from_request(&request).unwrap();
            let ack = super::super::subscriptions::acknowledgement(&request, &filter).unwrap();
            let changed = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {
                "_meta": {"io.modelcontextprotocol/subscriptionId": id}, "vendor": [true, null]
            }});
            let done = super::super::subscriptions::completion(&request).unwrap();
            let source = futures::stream::iter(
                [ack.clone(), changed.clone(), done.clone()]
                    .into_iter()
                    .map(|message| Ok::<_, io::Error>(Bytes::from(format!("data: {message}\r\n\r\n")))),
            );
            let headers = axum::http::HeaderMap::from_iter([(
                axum::http::header::CONTENT_TYPE,
                "text/event-stream"
                    .parse()
                    .unwrap(),
            )]);
            let response =
                request_response(source, axum::http::StatusCode::OK, &headers, request, limits(4096), |_| async {
                    panic!("subscription completion must not invoke application-result enrichment");
                    #[allow(unreachable_code)]
                    Ok::<serde_json::Value, SseReadError>(serde_json::Value::Null)
                })
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap();
            let events = futures::stream::iter([Ok::<_, io::Error>(bytes)]).eventsource();
            futures::pin_mut!(events);
            for expected in [ack, changed, done] {
                let message: serde_json::Value = serde_json::from_str(
                    &events
                        .next()
                        .await
                        .unwrap()
                        .unwrap()
                        .data,
                )
                .unwrap();
                assert_eq!(message, expected);
            }
            assert!(events.next().await.is_none());
        }
    }

    #[tokio::test]
    async fn subscription_sse_rejects_unacknowledged_wrong_id_and_unrequested_events() {
        let mut request = request();
        request.method = "subscriptions/listen".to_string();
        request.params = Some(serde_json::json!({"notifications": {"toolsListChanged": true}}));
        let filter = super::super::subscriptions::SubscriptionFilter::from_request(&request).unwrap();
        let ack = super::super::subscriptions::acknowledgement(&request, &filter).unwrap();
        let changed = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {
            "_meta": {"io.modelcontextprotocol/subscriptionId": request.id}
        }});
        let mut wrong_id = changed.clone();
        wrong_id["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] = serde_json::json!("wrong");
        let mut unrequested = changed.clone();
        unrequested["method"] = serde_json::json!("notifications/prompts/list_changed");
        for messages in
            [vec![changed], vec![ack.clone(), wrong_id], vec![ack.clone(), unrequested], vec![ack.clone(), ack]]
        {
            let source = futures::stream::iter(
                messages
                    .into_iter()
                    .map(|message| Ok::<_, io::Error>(Bytes::from(format!("data: {message}\n\n")))),
            );
            let mut events =
                Box::pin(request_events(source, request.clone(), limits(4096), |message| async { Ok(message) }));
            let mut rejected = false;
            while let Some(event) = events.next().await {
                if event.is_err() {
                    rejected = true;
                    break;
                }
            }
            assert!(rejected);
        }
        let done = super::super::subscriptions::completion(&request).unwrap();
        let headers = axum::http::HeaderMap::from_iter([(
            axum::http::header::CONTENT_TYPE,
            "application/json"
                .parse()
                .unwrap(),
        )]);
        let response = request_response(
            futures::stream::iter([Ok::<_, io::Error>(Bytes::from(done.to_string()))]),
            axum::http::StatusCode::OK,
            &headers,
            request,
            limits(4096),
            |message| async { Ok(message) },
        )
        .await;
        assert!(matches!(response, Err(SseReadError::UnsupportedContentType)));
    }

    /// A peer refuses a request on admission, before it reads the body, with
    /// an error that has no id (an untrusted Origin over Fabric). The status
    /// and error reach the caller unchanged instead of becoming a 502.
    #[tokio::test]
    async fn an_id_less_admission_error_is_relayed_with_its_status() {
        let refusal = serde_json::json!({"jsonrpc": "2.0", "error": {
            "code": super::super::error_codes::INVALID_REQUEST, "message": "Origin is not permitted on this MCP endpoint"
        }});
        let headers = axum::http::HeaderMap::from_iter([(
            axum::http::header::CONTENT_TYPE,
            "application/json"
                .parse()
                .unwrap(),
        )]);
        let response = request_response(
            futures::stream::iter([Ok::<_, io::Error>(Bytes::from(refusal.to_string()))]),
            axum::http::StatusCode::FORBIDDEN,
            &headers,
            request(),
            limits(4096),
            |message| async { Ok(message) },
        )
        .await
        .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body, refusal);
    }

    #[tokio::test]
    async fn deadlines_cancel_quiet_sources_and_empty_chunks_do_not_reset_idle() {
        for (idle_timeout, max_lifetime, expected) in [
            (Duration::ZERO, Duration::from_secs(1), SseReadError::IdleTimeout),
            (Duration::from_secs(1), Duration::ZERO, SseReadError::LifetimeExceeded),
        ] {
            let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(1);
            let mut stream = Box::pin(with_deadlines(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
                SseLimits {
                    idle_timeout,
                    max_lifetime,
                    ..limits(1024)
                },
            ));
            assert_eq!(
                stream
                    .next()
                    .await
                    .unwrap()
                    .unwrap_err(),
                expected
            );
            assert!(sender.is_closed());
            assert!(stream.next().await.is_none());
        }
        let source = futures::stream::repeat_with(|| Ok::<_, io::Error>(Bytes::new()));
        let mut stream = Box::pin(with_deadlines(
            source,
            SseLimits {
                idle_timeout: Duration::from_millis(5),
                ..limits(1024)
            },
        ));
        let result = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap();
        assert_eq!(result.unwrap().unwrap_err(), SseReadError::IdleTimeout);
    }

    #[tokio::test]
    async fn a_quiet_subscription_outlives_the_idle_limit_but_not_its_lifetime() {
        let configured = SseLimits {
            idle_timeout: Duration::from_millis(5),
            max_lifetime: Duration::from_millis(300),
            ..limits(1024)
        };
        assert_eq!(
            configured
                .for_method("tools/call")
                .idle_timeout,
            Duration::from_millis(5)
        );
        let listen = configured.for_method("subscriptions/listen");
        assert_eq!(listen.idle_timeout, listen.max_lifetime);

        let (_sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(1);
        let mut stream = Box::pin(with_deadlines(tokio_stream::wrappers::ReceiverStream::new(receiver), listen));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.next())
                .await
                .is_err(),
            "a quiet subscription is still open well past the idle limit"
        );
        let ended = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("the lifetime ends the subscription");
        assert_eq!(ended.unwrap().unwrap_err(), SseReadError::LifetimeExceeded);
    }

    #[test]
    fn configured_stream_limits_are_positive_and_bounded() {
        for config in [
            serde_json::json!({"stream_idle_timeout_secs": 120, "stream_max_lifetime_secs": 60}),
            serde_json::json!({"stream_max_lifetime_secs": 86401}),
        ] {
            let config: crate::config::McpHttpConfig = serde_json::from_value(config).unwrap();
            assert!(config.validate().is_err());
        }
        for config in [
            serde_json::json!({"stream_idle_timeout_secs": 0}),
            serde_json::json!({"max_response_bytes": 0}),
            serde_json::json!({"max_chunk_bytes": 0}),
        ] {
            assert!(serde_json::from_value::<crate::config::McpHttpConfig>(config).is_err());
        }
        let config = crate::config::McpHttpConfig::default();
        assert_eq!(config.validate(), Ok(()));
        let limits = SseLimits::from(&config);
        assert_eq!(limits.idle_timeout, Duration::from_secs(60));
        assert_eq!(limits.max_lifetime, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn utf8_crlf_and_multiline_data_survive_every_byte_split() {
        let wire = b"\xef\xbb\xbf: keepalive\r\n\r\nevent: old\r\nevent: message\r\ndata: {\"value\":\"s\xc3\xb8k\",\r\ndata: \"ready\":true}\r\n\r\nunknown: ignored\rdata: next\r\r";
        for split in 0..=wire.len() {
            let source = futures::stream::iter([
                Ok::<_, io::Error>(Bytes::copy_from_slice(&wire[..split])),
                Ok(Bytes::copy_from_slice(&wire[split..])),
            ]);
            let events: Vec<_> = decode_events(source, limits(1024))
                .try_collect()
                .await
                .unwrap();
            assert_eq!(events.len(), 2, "split at {split}");
            assert_eq!(events[0].event, "message");
            let expected = String::from_utf8(b"{\"value\":\"s\xc3\xb8k\",\n\"ready\":true}".to_vec()).unwrap();
            assert_eq!(events[0].data, expected, "split at {split}");
            assert_eq!(events[1].data, "next");
        }
    }

    #[tokio::test]
    async fn field_rules_accept_ignored_fields_and_reset_event_names() {
        let source = futures::stream::iter([Ok::<_, io::Error>(Bytes::from_static(
            b"event: old\nevent: updated\nid: first\nid: second\nunknown: ignore\nno-colon\nretry: not-a-number\ndata:  spaced \n\nid\ndata\n\n",
        ))]);
        let events: Vec<_> = decode_events(source, limits(1024))
            .try_collect()
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "updated");
        assert_eq!(events[0].id, "second");
        assert_eq!(events[0].data, " spaced ");
        assert_eq!(events[1].event, "message");
        assert_eq!(events[1].id, "");
        assert_eq!(events[1].data, "");
    }

    #[tokio::test]
    async fn bom_is_only_removed_once_without_panicking() {
        for prefix in [b"\xef\xbb\xbf\xef\xbb\xbf".as_slice(), b"\n\xef\xbb\xbf".as_slice()] {
            let mut wire = prefix.to_vec();
            wire.extend_from_slice(b"data: ignored\n\ndata: accepted\n\n");
            let source = futures::stream::iter(
                wire.into_iter()
                    .map(|byte| Ok::<_, io::Error>(Bytes::from(vec![byte]))),
            );
            let events: Vec<_> = decode_events(source, limits(128))
                .try_collect()
                .await
                .unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].data, "accepted");
        }
    }

    #[tokio::test]
    async fn event_budget_covers_unterminated_lines_and_multiline_events() {
        for wire in [b"data: over-limit-without-a-newline".as_slice(), b"data: a\ndata: b\ndata: c\n\n".as_slice()] {
            let source = futures::stream::iter(
                wire.chunks(3)
                    .map(|chunk| Ok::<_, io::Error>(Bytes::copy_from_slice(chunk))),
            );
            let mut events = Box::pin(decode_events(source, limits(16)));
            assert_eq!(
                events
                    .next()
                    .await
                    .unwrap()
                    .unwrap_err(),
                SseReadError::EventTooLarge
            );
        }
        let wire = b"data: ok\n\ndata: ok\n\n";
        let source = futures::stream::iter([Ok::<_, io::Error>(Bytes::from_static(wire))]);
        let events: Vec<_> = decode_events(source, limits(10))
            .try_collect()
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn oversized_source_chunks_and_invalid_encoding_are_errors() {
        let source = futures::stream::iter([Ok::<_, io::Error>(Bytes::from_static(b"data: large\n\n"))]);
        let mut events = Box::pin(decode_events(
            source,
            SseLimits {
                max_chunk_bytes: NonZeroUsize::new(5).unwrap(),
                ..limits(32)
            },
        ));
        assert_eq!(
            events
                .next()
                .await
                .unwrap()
                .unwrap_err(),
            SseReadError::ChunkTooLarge
        );

        let source = futures::stream::iter([Ok::<_, io::Error>(Bytes::from_static(b"data: \xff\n\n"))]);
        assert!(matches!(
            Box::pin(decode_events(source, limits(32)))
                .next()
                .await,
            Some(Err(SseReadError::Parse(_)))
        ));
        let source = futures::stream::iter([Ok::<_, io::Error>(Bytes::from_static(b"\xef\xbb"))]);
        assert_eq!(
            Box::pin(decode_events(source, limits(32)))
                .next()
                .await
                .unwrap()
                .unwrap_err(),
            SseReadError::IncompleteBom
        );
    }

    #[tokio::test]
    async fn decoder_drop_closes_a_quiet_source_without_waiting_for_another_event() {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(1);
        sender
            .send(Ok(Bytes::from_static(b"data: first\n\n")))
            .await
            .unwrap();
        let mut events = Box::pin(decode_events(tokio_stream::wrappers::ReceiverStream::new(receiver), limits(32)));
        assert_eq!(
            events
                .next()
                .await
                .unwrap()
                .unwrap()
                .data,
            "first"
        );
        assert!(!sender.is_closed());
        drop(events);
        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn incomplete_events_are_not_synthesized_on_disconnect() {
        let source = futures::stream::iter([Ok::<_, io::Error>(Bytes::from_static(b"data: partial\n"))]);
        let events: Vec<_> = decode_events(source, limits(32))
            .try_collect()
            .await
            .unwrap();
        assert!(events.is_empty());
        let source = futures::stream::iter([Err::<Bytes, _>(io::Error::other("failed source"))]);
        let mut events = Box::pin(decode_events(source, limits(32)));
        assert_eq!(
            events
                .next()
                .await
                .unwrap()
                .unwrap_err(),
            SseReadError::Transport("failed source".to_string())
        );
    }

    fn request() -> super::super::request_validation::ValidatedModernMessage {
        super::super::request_validation::ValidatedModernMessage {
            protocol_version: super::super::MCP_MODERN_VERSION.to_string(),
            client_capabilities: Some(serde_json::json!({})),
            client_info: None,
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({"name": "echo", "_meta": {"progressToken": "work"}})),
            id: Some(serde_json::json!(7)),
            kind: super::super::request_validation::McpMessageKind::Request,
        }
    }

    fn frame(value: serde_json::Value) -> Bytes {
        Bytes::from(format!("data: {value}\n\n"))
    }

    #[tokio::test]
    async fn network_adapter_streams_progress_and_cancels_quiet_upstream_work() {
        use axum::http::{HeaderMap, StatusCode};
        use std::sync::Arc;

        let mut servers = tokio::task::JoinSet::new();
        let release = Arc::new(tokio::sync::Notify::new());
        let (outcome_tx, mut outcome_rx) = tokio::sync::mpsc::channel(2);
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let upstream_url = format!(
            "http://{}",
            upstream_listener
                .local_addr()
                .unwrap()
        );
        let upstream = axum::Router::new().route("/", axum::routing::post({
            let release = release.clone();
            move || {
                let release = release.clone();
                let outcomes = outcome_tx.clone();
                async move {
                    let progress = frame(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "work", "progress": 1}}));
                    let source = futures::stream::once(async { Ok::<_, io::Error>(progress) }).chain(
                        futures::stream::once(async move {
                            release.notified().await;
                            Ok(frame(serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"resultType": "complete", "content": []}})))
                        }),
                    );
                    let response = axum::response::Response::builder().header("content-type", "text/event-stream")
                        .body(axum::body::Body::from_stream(source)).unwrap();
                    observe_response(response, move |outcome| { let _ = outcomes.try_send(outcome); })
                }
            }
        }));
        servers.spawn(async move {
            axum::serve(upstream_listener, upstream)
                .await
                .unwrap();
        });
        let proxy_client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let proxy_url = format!(
            "http://{}",
            proxy_listener
                .local_addr()
                .unwrap()
        );
        let proxy = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let client = proxy_client.clone();
                let target = upstream_url.clone();
                async move {
                    let upstream = client
                        .post(target)
                        .send()
                        .await
                        .unwrap();
                    let headers: HeaderMap = upstream.headers().clone();
                    request_response(
                        upstream.bytes_stream(),
                        StatusCode::OK,
                        &headers,
                        request(),
                        limits(4096),
                        |mut message| async {
                            message["result"]["_meta"] = serde_json::json!({"com.example/processed": true});
                            Ok(message)
                        },
                    )
                    .await
                    .unwrap()
                }
            }),
        );
        servers.spawn(async move {
            axum::serve(proxy_listener, proxy)
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        for finish in [true, false] {
            let response = client
                .post(&proxy_url)
                .send()
                .await
                .unwrap();
            assert_eq!(response.headers()["x-accel-buffering"], "no");
            let mut events = Box::pin(decode_events(response.bytes_stream(), limits(4096)));
            let first = tokio::time::timeout(Duration::from_secs(2), events.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let first: serde_json::Value = serde_json::from_str(&first.data).unwrap();
            assert_eq!(first["method"], "notifications/progress");
            assert!(outcome_rx.try_recv().is_err());
            if finish {
                release.notify_one();
                let final_event = tokio::time::timeout(Duration::from_secs(2), events.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let final_result: serde_json::Value = serde_json::from_str(&final_event.data).unwrap();
                assert_eq!(final_result["result"]["_meta"]["com.example/processed"], true);
                assert!(events.next().await.is_none());
            }
            drop(events);
            let outcome = tokio::time::timeout(Duration::from_secs(2), outcome_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(outcome.completed, finish);
            assert!(!outcome.failed);
            assert!(outcome.bytes > 0);
        }
        servers.abort_all();
        while servers
            .join_next()
            .await
            .is_some()
        {}
    }

    #[tokio::test]
    async fn response_observer_reports_completion_error_and_quiet_disconnect_once() {
        for mode in ["complete", "failure", "disconnect"] {
            let outcome = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed = outcome.clone();
            let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(2);
            sender
                .send(Ok(Bytes::from_static(b"payload")))
                .await
                .unwrap();
            if mode == "failure" {
                sender
                    .send(Err(io::Error::other("upstream fault")))
                    .await
                    .unwrap();
            }
            let response = observe_response(
                axum::response::Response::new(axum::body::Body::from_stream(
                    tokio_stream::wrappers::ReceiverStream::new(receiver),
                )),
                move |result| {
                    observed
                        .lock()
                        .unwrap()
                        .push(result)
                },
            );
            assert!(
                outcome
                    .lock()
                    .unwrap()
                    .is_empty()
            );
            if mode == "disconnect" {
                drop(response);
                assert!(sender.is_closed());
            } else {
                drop(sender);
                let result = axum::body::to_bytes(response.into_body(), 1024).await;
                assert_eq!(result.is_ok(), mode == "complete");
            }
            let outcomes = outcome.lock().unwrap();
            assert_eq!(outcomes.len(), 1);
            assert_eq!(
                outcomes[0],
                ResponseOutcome {
                    bytes: if mode == "disconnect" {
                        0
                    } else {
                        7
                    },
                    completed: mode == "complete",
                    failed: mode == "failure",
                }
            );
        }
    }

    #[test]
    fn response_dropped_outside_a_runtime_skips_its_completion_without_panicking() {
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = completed.clone();
        let response = observe_response(axum::response::Response::new(axum::body::Body::empty()), move |_| {
            tokio::spawn(async {});
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        drop(response);

        assert!(!completed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn response_dropped_inside_a_runtime_runs_its_completion() {
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = completed.clone();
        let response = observe_response(axum::response::Response::new(axum::body::Body::empty()), move |_| {
            tokio::spawn(async {});
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        drop(response);

        assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn established_receipt_headers_survive_complete_and_interim_responses() {
        for content_type in ["application/json", "text/event-stream"] {
            for result in [
                serde_json::json!({"resultType": "complete", "content": []}),
                serde_json::json!({"resultType": "input_required", "requestState": "opaque"}),
            ] {
                let message = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": result});
                let bytes = if content_type == "application/json" {
                    Bytes::from(message.to_string())
                } else {
                    frame(message.clone())
                };
                let mut headers = axum::http::HeaderMap::new();
                headers.insert("content-type", content_type.parse().unwrap());
                headers.append(
                    "payment-response",
                    "settled-first"
                        .parse()
                        .unwrap(),
                );
                headers.append(
                    "payment-response",
                    "settled-second"
                        .parse()
                        .unwrap(),
                );
                let processed_headers = headers.clone();
                let response = request_response(
                    futures::stream::iter([Ok::<_, io::Error>(bytes)]),
                    axum::http::StatusCode::OK,
                    &headers,
                    request(),
                    limits(2048),
                    move |message| async move {
                        Ok(ProcessedResponse {
                            message,
                            headers: Some(processed_headers),
                        })
                    },
                )
                .await
                .unwrap();
                assert_eq!(
                    response
                        .headers()
                        .get_all("payment-response")
                        .iter()
                        .collect::<Vec<_>>(),
                    headers
                        .get_all("payment-response")
                        .iter()
                        .collect::<Vec<_>>()
                );
                assert!(
                    !response
                        .headers()
                        .contains_key("x-gateway-tenant")
                );
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let received: serde_json::Value = if content_type == "application/json" {
                    serde_json::from_slice(&bytes).unwrap()
                } else {
                    let events: Vec<_> =
                        decode_events(futures::stream::iter([Ok::<_, io::Error>(bytes)]), limits(4096))
                            .try_collect()
                            .await
                            .unwrap();
                    serde_json::from_str(&events[0].data).unwrap()
                };
                assert_eq!(received, message);
            }
        }
    }

    #[tokio::test]
    async fn complete_json_preserves_new_headers_but_sse_rejects_late_header_changes() {
        for content_type in ["application/json", "text/event-stream"] {
            let message =
                serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"resultType": "complete", "content": []}});
            let bytes = if content_type == "application/json" {
                Bytes::from(message.to_string())
            } else {
                frame(message)
            };
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("content-type", content_type.parse().unwrap());
            let response = request_response(
                futures::stream::iter([Ok::<_, io::Error>(bytes)]),
                axum::http::StatusCode::OK,
                &headers,
                request(),
                limits(2048),
                |message| async {
                    let mut headers = axum::http::HeaderMap::new();
                    headers.append("x-gateway-tenant", "first".parse().unwrap());
                    headers.append("x-gateway-tenant", "second".parse().unwrap());
                    Ok(ProcessedResponse {
                        message,
                        headers: Some(headers),
                    })
                },
            )
            .await
            .unwrap();
            if content_type == "application/json" {
                assert_eq!(
                    response
                        .headers()
                        .get_all("x-gateway-tenant")
                        .iter()
                        .count(),
                    2
                );
                assert!(
                    axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .is_ok()
                );
            } else {
                assert!(
                    !response
                        .headers()
                        .contains_key("x-gateway-tenant")
                );
                assert!(
                    axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .is_err()
                );
            }
        }
    }

    #[tokio::test]
    async fn json_and_sse_responses_share_validation_and_complete_rewrites() {
        let message = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {
            "resultType": "complete", "content": [], "isError": true,
            "structuredContent": [false, null, {"value": "kept"}]
        }});
        for content_type in ["application/json", "text/event-stream"] {
            let bytes = if content_type == "application/json" {
                Bytes::from(serde_json::to_vec(&message).unwrap())
            } else {
                frame(message.clone())
            };
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("content-type", content_type.parse().unwrap());
            headers.insert("mcp-session-id", "drop".parse().unwrap());
            let response = request_response(
                futures::stream::iter([Ok::<_, io::Error>(bytes)]),
                axum::http::StatusCode::OK,
                &headers,
                request(),
                limits(2048),
                |mut message| async {
                    tokio::task::yield_now().await;
                    message["result"]["_meta"] = serde_json::json!({"com.example/checked": true});
                    Ok(message)
                },
            )
            .await
            .unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(
                !response
                    .headers()
                    .contains_key("mcp-session-id")
            );
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let received: serde_json::Value = if content_type == "application/json" {
                serde_json::from_slice(&bytes).unwrap()
            } else {
                let events: Vec<_> = decode_events(futures::stream::iter([Ok::<_, io::Error>(bytes)]), limits(4096))
                    .try_collect()
                    .await
                    .unwrap();
                serde_json::from_str(&events[0].data).unwrap()
            };
            let mut expected = message.clone();
            expected["result"]["_meta"] = serde_json::json!({"com.example/checked": true});
            assert_eq!(received, expected);
        }
    }

    #[tokio::test]
    async fn json_response_rejects_bad_media_correlation_and_oversized_results() {
        let body = Bytes::from_static(br#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","content":[]}}"#);
        for content_type in ["text/plain", "application/problem+json", "text/event-stream; charset=iso-8859-1"] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("content-type", content_type.parse().unwrap());
            let result = request_response(
                futures::stream::iter([Ok::<_, io::Error>(body.clone())]),
                axum::http::StatusCode::OK,
                &headers,
                request(),
                limits(1024),
                |message| async { Ok(message) },
            )
            .await;
            assert_eq!(result.unwrap_err(), SseReadError::UnsupportedContentType);
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "content-type",
            "application/json"
                .parse()
                .unwrap(),
        );
        let result = request_response(
            futures::stream::iter([Ok::<_, io::Error>(body.clone())]),
            axum::http::StatusCode::OK,
            &headers,
            request(),
            limits(body.len() - 1),
            |message| async { Ok(message) },
        )
        .await;
        assert_eq!(result.unwrap_err(), SseReadError::EventTooLarge);
        let mut other_request = request();
        other_request.id = Some(serde_json::json!("wrong"));
        let result = request_response(
            futures::stream::iter([Ok::<_, io::Error>(body)]),
            axum::http::StatusCode::OK,
            &headers,
            other_request,
            limits(1024),
            |message| async { Ok(message) },
        )
        .await;
        assert_eq!(result.unwrap_err(), SseReadError::Response(super::super::modern::ModernResponseError::IdMismatch));
    }

    #[tokio::test]
    async fn request_stream_delivers_progress_then_one_rewritten_final_response() {
        let progress = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "work", "progress": 1}});
        let response = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"resultType": "complete", "content": [], "structuredContent": [true, null]}});
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(1);
        sender
            .send(Ok(frame(progress)))
            .await
            .unwrap();
        let rewrites = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = rewrites.clone();
        let mut events = Box::pin(request_events(
            tokio_stream::wrappers::ReceiverStream::new(receiver),
            request(),
            limits(1024),
            move |mut message| {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    tokio::task::yield_now().await;
                    message["result"]["_meta"] = serde_json::json!({"com.example/checked": true});
                    Ok(message)
                }
            },
        ));
        assert!(
            events
                .next()
                .await
                .unwrap()
                .is_ok()
        );
        assert_eq!(rewrites.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!sender.is_closed());
        sender
            .send(Ok(frame(response)))
            .await
            .unwrap();
        assert!(
            events
                .next()
                .await
                .unwrap()
                .is_ok()
        );
        assert_eq!(rewrites.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(events.next().await.is_none());
        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn nonfinal_application_results_end_the_rpc_without_completion_rewrite() {
        for result in [
            serde_json::json!({"resultType": "input_required", "requestState": "opaque"}),
            serde_json::json!({"resultType": "task", "taskId": "task"}),
        ] {
            let source = futures::stream::iter([Ok::<_, io::Error>(frame(
                serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": result}),
            ))]);
            let mut events = Box::pin(request_events(source, request(), limits(1024), |_| async {
                panic!("nonfinal result must not be enriched")
            }));
            assert!(
                events
                    .next()
                    .await
                    .unwrap()
                    .is_ok()
            );
            assert!(events.next().await.is_none());
        }
    }

    #[tokio::test]
    async fn request_stream_rejects_server_requests_and_unrelated_notifications() {
        for (message, expected) in [
            (
                serde_json::json!({"jsonrpc": "2.0", "id": "server", "method": "roots/list"}),
                SseReadError::ServerRequest,
            ),
            (
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "other", "progress": 1}}),
                SseReadError::UnrelatedNotification,
            ),
            (
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "unsolicited"}}),
                SseReadError::UnrelatedNotification,
            ),
            (
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
                SseReadError::UnrelatedNotification,
            ),
        ] {
            let source = futures::stream::iter([Ok::<_, io::Error>(frame(message))]);
            let mut events = Box::pin(request_events(source, request(), limits(1024), |message| async { Ok(message) }));
            assert_eq!(
                events
                    .next()
                    .await
                    .unwrap()
                    .unwrap_err(),
                expected
            );
        }
        let source = futures::stream::empty::<Result<Bytes, io::Error>>();
        let mut events = Box::pin(request_events(source, request(), limits(1024), |message| async { Ok(message) }));
        assert_eq!(
            events
                .next()
                .await
                .unwrap()
                .unwrap_err(),
            SseReadError::MissingResponse
        );
    }

    #[tokio::test]
    async fn request_stream_validates_log_and_progress_payloads_per_request() {
        use http_body_util::BodyExt;
        use serde_json::json;

        let mut logging_request = request();
        logging_request
            .params
            .as_mut()
            .unwrap()["_meta"]["io.modelcontextprotocol/logLevel"] = json!("info");
        let notifications = [
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {
                "level": "info", "logger": "fixture", "data": null, "com.example/detail": [1, false]
            }}),
            json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {
                "progressToken": "work", "progress": 1.5, "total": 3, "message": "Working",
                "_meta": {"com.example/detail": [true, null]}
            }}),
            json!({"jsonrpc": "2.0", "method": "com.example/notifications/changed", "params": {
                "state": {"opaque": [true, null]}, "_meta": {"com.example/detail": 1}
            }}),
        ];
        let complete = json!({"jsonrpc": "2.0", "id": 7, "result": {"resultType": "complete", "content": []}});
        let messages = notifications
            .iter()
            .cloned()
            .chain([complete.clone()])
            .collect::<Vec<_>>();
        let source = futures::stream::iter(
            messages
                .iter()
                .cloned()
                .map(|message| Ok::<_, io::Error>(frame(message)))
                .collect::<Vec<_>>(),
        );
        let response = request_sse_response(
            source,
            axum::http::StatusCode::OK,
            &axum::http::HeaderMap::new(),
            logging_request.clone(),
            limits(4096),
            |message| async { Ok(message) },
        );
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let mut events = Box::pin(decode_events(futures::stream::iter([Ok::<_, io::Error>(bytes)]), limits(4096)));
        for expected in messages {
            let event = events
                .next()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(serde_json::from_str::<serde_json::Value>(&event.data).unwrap(), expected);
        }
        assert!(events.next().await.is_none());

        let invalid_notifications = [
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "verbose", "data": "invalid"}}),
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}}),
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "logger": false, "data": null}}),
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": null, "_meta": []}}),
            json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "work", "progress": 1, "total": "3"}}),
            json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "work", "progress": 1, "message": false}}),
            json!({"jsonrpc": "2.0", "method": "com.example/notifications/changed", "params": {"_meta": null}}),
        ];
        for message in invalid_notifications {
            let source = futures::stream::iter([Ok::<_, io::Error>(frame(message.clone()))]);
            let mut events = Box::pin(request_events(source, logging_request.clone(), limits(4096), |message| async {
                Ok(message)
            }));
            assert_eq!(
                events
                    .next()
                    .await
                    .unwrap()
                    .unwrap_err(),
                SseReadError::InvalidMessage,
                "{message}"
            );
        }

        for invalid_level in [json!(null), json!(false), json!("verbose")] {
            let mut invalid_request = logging_request.clone();
            invalid_request
                .params
                .as_mut()
                .unwrap()["_meta"]["io.modelcontextprotocol/logLevel"] = invalid_level;
            assert_eq!(
                validate_notification(&notifications[0], &invalid_request),
                Err(SseReadError::UnrelatedNotification)
            );
        }
        assert_eq!(validate_notification(&notifications[0], &request()), Err(SseReadError::UnrelatedNotification));
        for invalid_token in [json!(null), json!({"token": "work"}), json!(false)] {
            let mut invalid_request = request();
            invalid_request
                .params
                .as_mut()
                .unwrap()["_meta"]["progressToken"] = invalid_token.clone();
            let mut notification = notifications[1].clone();
            notification["params"]["progressToken"] = invalid_token;
            assert_eq!(validate_notification(&notification, &invalid_request), Err(SseReadError::InvalidMessage));
        }
    }

    #[tokio::test]
    async fn quiet_request_response_body_drop_cancels_its_source() {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(1);
        let response = request_sse_response(
            tokio_stream::wrappers::ReceiverStream::new(receiver),
            axum::http::StatusCode::OK,
            &axum::http::HeaderMap::new(),
            request(),
            limits(1024),
            |message| async { Ok(message) },
        );
        assert!(!sender.is_closed());
        drop(response);
        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn response_adapter_preserves_rewrites_status_and_safe_header_multiplicity() {
        use axum::http::{HeaderMap, HeaderValue, StatusCode};
        let message = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {
            "resultType": "complete", "content": [], "structuredContent": [false, {"value": "kept"}],
            "isError": true, "_meta": {"com.example/opaque": [1, true]}
        }});
        let source = futures::stream::iter([Ok::<_, io::Error>(frame(message.clone()))]);
        let mut headers = HeaderMap::new();
        for name in ["mcp-session-id", "last-event-id", "content-length", "content-encoding", "cache-control", "x-hop"]
        {
            headers.insert(name, HeaderValue::from_static("remove"));
        }
        headers.insert("connection", HeaderValue::from_static("X-Hop"));
        headers.append("x-example", HeaderValue::from_static("one"));
        headers.append("x-example", HeaderValue::from_static("two"));
        let response =
            request_sse_response(source, StatusCode::OK, &headers, request(), limits(1024), |mut value| async {
                value["result"]["_meta"]["com.example/checked"] = serde_json::json!(true);
                Ok(value)
            });
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(response.headers()["x-accel-buffering"], "no");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response
                .headers()
                .get_all("x-example")
                .iter()
                .count(),
            2
        );
        for name in ["connection", "mcp-session-id", "last-event-id", "content-length", "content-encoding", "x-hop"] {
            assert!(
                !response
                    .headers()
                    .contains_key(name),
                "{name}"
            );
        }
        let bytes = axum::body::to_bytes(response.into_body(), 2048)
            .await
            .unwrap();
        let events: Vec<_> = decode_events(futures::stream::iter([Ok::<_, io::Error>(bytes)]), limits(2048))
            .try_collect()
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        let mut expected = message;
        expected["result"]["_meta"]["com.example/checked"] = serde_json::json!(true);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&events[0].data).unwrap(), expected);
        assert_eq!(events[0].id, "");
        assert_eq!(events[0].retry, None);
    }
}
