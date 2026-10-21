//! Event-by-event forwarding of an A2A JSON-RPC `text/event-stream` response.
//!
//! Each event carries one JSON-RPC response whose `result` is a `StreamResponse`
//! (a v1.0 `task`, `message`, `statusUpdate` or `artifactUpdate` member, or a
//! v0.3 result with a `kind`). Events are read, processed and forwarded one at a
//! time, in order: the next event is not read until the caller has taken the
//! previous one, so a slow caller slows the Target instead of growing a buffer.
//!
//! The status and headers are sent before the first event, so a failure after
//! that cannot change them. It ends the stream with a JSON-RPC error event
//! instead, and the upstream connection is dropped.

use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use tracing::warn;

use crate::mcp::modern_sse::{ResponseOutcome, SseLimits, SseReadError, decode_events, observe_response};

/// The members of a v1.0 `StreamResponse`, exactly one of which wraps an
/// event's payload.
const STREAM_RESPONSE_MEMBERS: [&str; 4] = ["task", "message", "statusUpdate", "artifactUpdate"];

/// JSON-RPC `Internal error`, the code of every error event the gateway sends.
const INTERNAL_ERROR: i64 = -32603;

/// Why the gateway ended a stream early. It reaches the caller as a JSON-RPC
/// error event whose `data.code` is [`StreamStop::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamStop {
    pub code: &'static str,
    pub message: &'static str,
}

impl StreamStop {
    pub const fn new(
        code: &'static str,
        message: &'static str,
    ) -> Self {
        Self { code, message }
    }

    fn from_read(error: &SseReadError) -> Self {
        match error {
            SseReadError::IdleTimeout => {
                Self::new("upstream_stream_idle", "Upstream event stream sent nothing within its idle timeout")
            }
            SseReadError::LifetimeExceeded => {
                Self::new("upstream_stream_lifetime", "Upstream event stream exceeded its maximum lifetime")
            }
            SseReadError::EventTooLarge | SseReadError::ChunkTooLarge => EVENT_TOO_LARGE,
            SseReadError::Transport(_) => Self::new("upstream_stream_failed", "Upstream event stream failed"),
            _ => INVALID_EVENT,
        }
    }

    fn error_event(
        &self,
        request_id: &Value,
    ) -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": INTERNAL_ERROR,
                "message": self.message,
                "data": { "code": self.code },
            },
        })
    }
}

const INVALID_EVENT: StreamStop = StreamStop::new("upstream_event_invalid", "Upstream sent an invalid stream event");
const EVENT_TOO_LARGE: StreamStop = StreamStop::new("upstream_event_too_large", "Upstream stream event is too large");

/// The response checks the gateway runs on each event.
pub trait EventProcessor: Send + 'static {
    /// Rewrites an event whose v1.0 `StreamResponse` member has been unwrapped
    /// into `result`, so it reads like a non-streaming reply.
    fn rewrite(
        &mut self,
        event: Value,
    ) -> impl Future<Output = Result<Value, StreamStop>> + Send;

    /// Admits the rewritten event exactly as it will be sent.
    fn admit(
        &mut self,
        event: &Value,
    ) -> impl Future<Output = Result<(), StreamStop>> + Send;
}

/// Whether a response's `Content-Type` is `text/event-stream`, whatever its
/// parameters or letter case.
pub fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .parse::<mime::Mime>()
                .ok()
        })
        .is_some_and(|content_type| content_type.essence_str() == mime::TEXT_EVENT_STREAM.essence_str())
}

/// The JSON-RPC `id` of a request body, echoed by the error event that ends a
/// stream; `null` when the body has none.
pub fn request_id(body: &[u8]) -> Value {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("id").cloned())
        .unwrap_or(Value::Null)
}

/// Forwards an upstream event stream through `processor`, keeping the upstream
/// status and end-to-end headers. `complete` runs once the body ends, fails or
/// is dropped; a stream the gateway ended with an error event counts as failed.
pub fn event_stream_response<Source, SourceError, Processor, Complete>(
    source: Source,
    status: StatusCode,
    headers: &HeaderMap,
    limits: SseLimits,
    request_id: Value,
    channel_name: String,
    processor: Processor,
    complete: Complete,
) -> axum::response::Response
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Processor: EventProcessor,
    Complete: FnOnce(ResponseOutcome) + Send + 'static,
{
    let stopped = Arc::new(AtomicBool::new(false));
    let events = forward_events(
        source,
        limits,
        Forwarding {
            processor,
            request_id,
            channel_name,
            max_event_bytes: limits.max_event_bytes.get(),
            stopped: Arc::clone(&stopped),
        },
    );
    let mut response = Sse::new(events)
        .keep_alive(KeepAlive::default())
        .into_response();
    *response.status_mut() = status;
    crate::mcp::modern_sse::copy_response_headers(&mut response, headers);
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    observe_response(response, move |outcome| {
        complete(ResponseOutcome {
            failed: outcome.failed || stopped.load(Ordering::Acquire),
            ..outcome
        })
    })
}

struct Forwarding<Processor> {
    processor: Processor,
    request_id: Value,
    channel_name: String,
    max_event_bytes: usize,
    stopped: Arc<AtomicBool>,
}

fn forward_events<Source, SourceError, Processor>(
    source: Source,
    limits: SseLimits,
    forwarding: Forwarding<Processor>,
) -> impl Stream<Item = Result<Event, std::convert::Infallible>>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send + 'static,
    SourceError: Display + Send + 'static,
    Processor: EventProcessor,
{
    futures::stream::unfold(Some((Box::pin(decode_events(source, limits)), forwarding)), |state| async move {
        let (mut events, mut forwarding) = state?;
        let forwarded = match events.next().await? {
            Ok(event) => forward_event(event, &mut forwarding).await,
            Err(error) => {
                warn!(channel = forwarding.channel_name, %error, "Reading the upstream A2A event stream failed");
                Err(StreamStop::from_read(&error))
            }
        };
        match forwarded {
            Ok(event) => Some((Ok(event), Some((events, forwarding)))),
            Err(stop) => {
                warn!(
                    channel = forwarding.channel_name,
                    code = stop.code,
                    "Ending the A2A event stream with an error event"
                );
                forwarding
                    .stopped
                    .store(true, Ordering::Release);
                let data = stop
                    .error_event(&forwarding.request_id)
                    .to_string();
                Some((Ok(Event::default().data(data)), None))
            }
        }
    })
}

async fn forward_event<Processor: EventProcessor>(
    event: eventsource_stream::Event,
    forwarding: &mut Forwarding<Processor>,
) -> Result<Event, StreamStop> {
    let mut message: Value = serde_json::from_str(&event.data).map_err(|_| INVALID_EVENT)?;
    if !message.is_object() {
        return Err(INVALID_EVENT);
    }
    let member = unwrap_stream_response(&mut message);
    let mut message = forwarding
        .processor
        .rewrite(message)
        .await?;
    rewrap_stream_response(&mut message, member);
    forwarding
        .processor
        .admit(&message)
        .await?;
    let data = message.to_string();
    if data.len() > forwarding.max_event_bytes {
        return Err(EVENT_TOO_LARGE);
    }
    Ok(Event::default()
        .event(event.event)
        .data(data))
}

/// Moves the payload of a v1.0 `StreamResponse` member into `result`, and
/// returns the member so it can be restored. A `result` with any other shape
/// is left as it is.
fn unwrap_stream_response(message: &mut Value) -> Option<&'static str> {
    let result = message
        .get_mut("result")?
        .as_object_mut()?;
    if result.len() != 1 {
        return None;
    }
    let member = STREAM_RESPONSE_MEMBERS
        .into_iter()
        .find(|member| {
            result
                .get(*member)
                .is_some_and(Value::is_object)
        })?;
    let payload = result.remove(member)?;
    message["result"] = payload;
    Some(member)
}

fn rewrap_stream_response(
    message: &mut Value,
    member: Option<&'static str>,
) {
    if let (Some(member), Some(result)) = (member, message.get_mut("result")) {
        let mut wrapped = serde_json::Map::new();
        wrapped.insert(member.to_string(), result.take());
        *result = Value::Object(wrapped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::num::NonZeroUsize;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct Recorded {
        rewritten: Vec<Value>,
        admitted: Vec<Value>,
    }

    struct Recorder {
        recorded: Arc<Mutex<Recorded>>,
        refuse_rewrite: Option<&'static str>,
        refuse_admit: Option<&'static str>,
    }

    impl Recorder {
        fn new() -> (Self, Arc<Mutex<Recorded>>) {
            let recorded = Arc::new(Mutex::new(Recorded::default()));
            (
                Self {
                    recorded: Arc::clone(&recorded),
                    refuse_rewrite: None,
                    refuse_admit: None,
                },
                recorded,
            )
        }
    }

    const REFUSED: StreamStop = StreamStop::new("refused", "Refused");

    impl EventProcessor for Recorder {
        async fn rewrite(
            &mut self,
            mut event: Value,
        ) -> Result<Value, StreamStop> {
            if self
                .refuse_rewrite
                .is_some_and(|needle| {
                    event
                        .to_string()
                        .contains(needle)
                })
            {
                return Err(REFUSED);
            }
            self.recorded
                .lock()
                .unwrap()
                .rewritten
                .push(event.clone());
            if let Some(result) = event
                .get_mut("result")
                .and_then(Value::as_object_mut)
            {
                result.insert("seen".to_string(), json!(true));
            }
            Ok(event)
        }

        async fn admit(
            &mut self,
            event: &Value,
        ) -> Result<(), StreamStop> {
            if self
                .refuse_admit
                .is_some_and(|needle| {
                    event
                        .to_string()
                        .contains(needle)
                })
            {
                return Err(REFUSED);
            }
            self.recorded
                .lock()
                .unwrap()
                .admitted
                .push(event.clone());
            Ok(())
        }
    }

    fn limits() -> SseLimits {
        SseLimits {
            max_event_bytes: NonZeroUsize::new(4096).unwrap(),
            max_chunk_bytes: NonZeroUsize::new(4096).unwrap(),
            idle_timeout: Duration::from_secs(5),
            max_lifetime: Duration::from_secs(60),
        }
    }

    fn sse(event: &Value) -> String {
        format!("event: message\ndata: {event}\n\n")
    }

    fn rpc(result: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": "req-1", "result": result })
    }

    fn task_events() -> Vec<Value> {
        vec![
            rpc(json!({ "task": { "id": "t-1", "status": { "state": "TASK_STATE_SUBMITTED" } } })),
            rpc(json!({ "statusUpdate": { "taskId": "t-1", "status": { "state": "TASK_STATE_WORKING" } } })),
            rpc(
                json!({ "artifactUpdate": { "taskId": "t-1", "artifact": { "artifactId": "a-1", "parts": [{ "text": "draft" }] } } }),
            ),
            rpc(json!({ "statusUpdate": { "taskId": "t-1", "status": { "state": "TASK_STATE_COMPLETED" } } })),
        ]
    }

    type Chunks = Vec<Result<Bytes, std::io::Error>>;

    fn chunks(events: &[Value]) -> Chunks {
        events
            .iter()
            .map(|event| Ok(Bytes::from(sse(event))))
            .collect()
    }

    fn upstream_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/event-stream"));
        headers.insert("x-agent-trace", HeaderValue::from_static("abc"));
        headers.insert("content-length", HeaderValue::from_static("10"));
        headers
    }

    fn respond<Source>(
        source: Source,
        processor: Recorder,
    ) -> (axum::response::Response, Arc<Mutex<Option<ResponseOutcome>>>)
    where
        Source: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
    {
        let outcome = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&outcome);
        let response = event_stream_response(
            source,
            StatusCode::OK,
            &upstream_headers(),
            limits(),
            json!("req-1"),
            "test".to_string(),
            processor,
            move |result| *recorded.lock().unwrap() = Some(result),
        );
        (response, outcome)
    }

    async fn body_events(response: axum::response::Response) -> Vec<(String, Value)> {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec())
            .unwrap()
            .split("\n\n")
            .filter_map(|block| {
                let mut name = "message".to_string();
                let mut data = None;
                for line in block.lines() {
                    if let Some(value) = line.strip_prefix("event: ") {
                        name = value.to_string();
                    } else if let Some(value) = line.strip_prefix("data: ") {
                        data = Some(serde_json::from_str(value).unwrap());
                    }
                }
                data.map(|data| (name, data))
            })
            .collect()
    }

    fn error_code(event: &Value) -> &str {
        event["error"]["data"]["code"]
            .as_str()
            .unwrap()
    }

    #[tokio::test]
    async fn every_event_is_forwarded_once_in_order() {
        let events = task_events();
        let (processor, recorded) = Recorder::new();
        let (response, outcome) = respond(futures::stream::iter(chunks(&events)), processor);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(response.headers()["x-agent-trace"], "abc");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-accel-buffering"], "no");
        assert!(
            response
                .headers()
                .get("content-length")
                .is_none()
        );

        let forwarded = body_events(response).await;
        let members: Vec<_> = forwarded
            .iter()
            .map(|(_, event)| {
                event["result"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .next()
                    .unwrap()
                    .clone()
            })
            .collect();
        assert_eq!(members, ["task", "statusUpdate", "artifactUpdate", "statusUpdate"]);
        assert!(
            forwarded
                .iter()
                .all(|(name, _)| name == "message")
        );
        assert_eq!(forwarded[3].1["result"]["statusUpdate"]["status"]["state"], "TASK_STATE_COMPLETED");
        assert_eq!(
            recorded
                .lock()
                .unwrap()
                .admitted
                .len(),
            4
        );
        let outcome = outcome
            .lock()
            .unwrap()
            .unwrap();
        assert!(outcome.completed && !outcome.failed && outcome.bytes > 0, "{outcome:?}");
    }

    #[tokio::test]
    async fn rewrite_sees_the_payload_and_admit_sees_the_wire_shape() {
        let event = rpc(json!({ "statusUpdate": { "taskId": "t-1", "status": { "state": "TASK_STATE_WORKING" } } }));
        let (processor, recorded) = Recorder::new();
        let (response, _) = respond(futures::stream::iter(chunks(std::slice::from_ref(&event))), processor);
        let forwarded = body_events(response).await;

        let recorded = recorded.lock().unwrap();
        assert_eq!(
            recorded.rewritten[0]["result"],
            json!({ "taskId": "t-1", "status": { "state": "TASK_STATE_WORKING" } })
        );
        assert_eq!(recorded.admitted[0]["result"]["statusUpdate"]["seen"], true);
        assert_eq!(forwarded[0].1, recorded.admitted[0]);
    }

    #[tokio::test]
    async fn v0_3_results_and_errors_are_passed_as_they_are() {
        let events = vec![
            rpc(json!({ "kind": "status-update", "taskId": "t-1", "final": true, "status": { "state": "completed" } })),
            json!({ "jsonrpc": "2.0", "id": "req-1", "error": { "code": -32001, "message": "Task not found" } }),
        ];
        let (processor, recorded) = Recorder::new();
        let (response, _) = respond(futures::stream::iter(chunks(&events)), processor);
        let forwarded = body_events(response).await;
        assert_eq!(
            recorded
                .lock()
                .unwrap()
                .rewritten,
            events
        );
        assert_eq!(forwarded[0].1["result"]["kind"], "status-update");
        assert_eq!(forwarded[1].1, events[1]);
    }

    #[tokio::test]
    async fn event_names_are_kept() {
        let event = rpc(json!({ "message": { "messageId": "m", "role": "ROLE_AGENT", "parts": [] } }));
        let source = futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from(format!(
            "id: 7\nretry: 100\nevent: update\ndata: {event}\n\n"
        )))]);
        let (processor, _) = Recorder::new();
        let (response, _) = respond(source, processor);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.starts_with("event: update\ndata: "), "{body}");
        assert!(!body.contains("id:") && !body.contains("retry:"), "{body}");
    }

    #[tokio::test]
    async fn a_refused_rewrite_ends_the_stream_with_an_error_event() {
        let events = task_events();
        let (mut processor, recorded) = Recorder::new();
        processor.refuse_rewrite = Some("a-1");
        let (response, outcome) = respond(futures::stream::iter(chunks(&events)), processor);
        let forwarded = body_events(response).await;

        assert_eq!(forwarded.len(), 3, "events after the refusal are not forwarded");
        let error = &forwarded[2].1;
        assert_eq!(error["id"], "req-1");
        assert_eq!(error["error"]["code"], -32603);
        assert_eq!(error["error"]["message"], "Refused");
        assert_eq!(error_code(error), "refused");
        assert!(error.get("result").is_none());
        assert_eq!(
            recorded
                .lock()
                .unwrap()
                .admitted
                .len(),
            2
        );
        let outcome = outcome
            .lock()
            .unwrap()
            .unwrap();
        assert!(outcome.completed && outcome.failed, "{outcome:?}");
    }

    #[tokio::test]
    async fn a_refused_admit_never_sends_the_event() {
        let events = task_events();
        let (mut processor, _) = Recorder::new();
        processor.refuse_admit = Some("TASK_STATE_COMPLETED");
        let (response, _) = respond(futures::stream::iter(chunks(&events)), processor);
        let forwarded = body_events(response).await;
        assert_eq!(forwarded.len(), 4);
        assert!(
            !forwarded
                .iter()
                .any(|(_, event)| event
                    .to_string()
                    .contains("TASK_STATE_COMPLETED"))
        );
        assert_eq!(error_code(&forwarded[3].1), "refused");
    }

    #[tokio::test]
    async fn an_event_that_is_not_a_json_object_ends_the_stream() {
        for data in ["not json", "[1,2]", "\"text\""] {
            let source = futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from(format!("data: {data}\n\n")))]);
            let (processor, recorded) = Recorder::new();
            let (response, _) = respond(source, processor);
            let forwarded = body_events(response).await;
            assert_eq!(forwarded.len(), 1, "{data}");
            assert_eq!(error_code(&forwarded[0].1), "upstream_event_invalid", "{data}");
            assert!(
                recorded
                    .lock()
                    .unwrap()
                    .rewritten
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn an_oversized_event_ends_the_stream() {
        let event = rpc(json!({ "message": { "parts": [{ "text": "x".repeat(5000) }] } }));
        let (processor, _) = Recorder::new();
        let (response, _) = respond(futures::stream::iter(chunks(&[event])), processor);
        let forwarded = body_events(response).await;
        assert_eq!(forwarded.len(), 1);
        assert_eq!(error_code(&forwarded[0].1), "upstream_event_too_large");
    }

    #[tokio::test]
    async fn an_upstream_read_failure_ends_the_stream_after_the_events_before_it() {
        let mut source = chunks(&task_events()[..1]);
        source.push(Err(std::io::Error::other("connection reset")));
        let (processor, _) = Recorder::new();
        let (response, outcome) = respond(futures::stream::iter(source), processor);
        let forwarded = body_events(response).await;
        assert_eq!(forwarded.len(), 2);
        assert_eq!(error_code(&forwarded[1].1), "upstream_stream_failed");
        assert!(
            outcome
                .lock()
                .unwrap()
                .unwrap()
                .failed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_upstream_ends_at_the_idle_timeout() {
        let source = futures::stream::iter(chunks(&task_events()[..1])).chain(futures::stream::pending());
        let (processor, _) = Recorder::new();
        let (response, _) = respond(source, processor);
        let forwarded = body_events(response).await;
        assert_eq!(forwarded.len(), 2);
        assert_eq!(error_code(&forwarded[1].1), "upstream_stream_idle");
    }

    #[tokio::test]
    async fn an_event_is_forwarded_before_the_next_one_arrives() {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<Result<Bytes, std::io::Error>>();
        let (processor, _) = Recorder::new();
        let (response, _) = respond(tokio_stream::wrappers::UnboundedReceiverStream::new(receiver), processor);
        let mut body = response
            .into_body()
            .into_data_stream();
        let events = task_events();

        sender
            .send(Ok(Bytes::from(sse(&events[0]))))
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .expect("the first event is forwarded while the upstream stays open")
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&first).contains("TASK_STATE_SUBMITTED"));

        sender
            .send(Ok(Bytes::from(sse(&events[3]))))
            .unwrap();
        drop(sender);
        let rest = body
            .map(|chunk| chunk.unwrap())
            .collect::<Vec<_>>()
            .await
            .concat();
        assert!(String::from_utf8_lossy(&rest).contains("TASK_STATE_COMPLETED"));
    }

    #[tokio::test]
    async fn a_dropped_caller_completes_without_a_clean_end() {
        let source = futures::stream::iter(chunks(&task_events()[..1])).chain(futures::stream::pending());
        let (processor, _) = Recorder::new();
        let (response, outcome) = respond(source, processor);
        let mut body = response
            .into_body()
            .into_data_stream();
        body.next()
            .await
            .unwrap()
            .unwrap();
        drop(body);
        let outcome = outcome
            .lock()
            .unwrap()
            .unwrap();
        assert!(!outcome.completed && !outcome.failed, "{outcome:?}");
    }

    #[test]
    fn only_a_single_object_member_is_unwrapped() {
        let mut wrapped = rpc(json!({ "task": { "id": "t" } }));
        assert_eq!(unwrap_stream_response(&mut wrapped), Some("task"));
        assert_eq!(wrapped["result"], json!({ "id": "t" }));
        rewrap_stream_response(&mut wrapped, Some("task"));
        assert_eq!(wrapped, rpc(json!({ "task": { "id": "t" } })));

        for result in [
            json!({ "task": { "id": "t" }, "message": {} }),
            json!({ "task": "t" }),
            json!({ "kind": "task", "id": "t" }),
            json!({ "other": {} }),
            json!("text"),
        ] {
            let mut event = rpc(result.clone());
            assert_eq!(unwrap_stream_response(&mut event), None, "{result}");
            assert_eq!(event["result"], result);
        }
    }

    #[test]
    fn event_streams_are_recognised_by_media_type() {
        for (value, expected) in [
            ("text/event-stream", true),
            ("text/event-stream; charset=utf-8", true),
            ("Text/Event-Stream", true),
            ("application/json", false),
            ("text/event-streamx", false),
            ("", false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_str(value).unwrap());
            assert_eq!(is_event_stream(&headers), expected, "{value}");
        }
        assert!(!is_event_stream(&HeaderMap::new()));
    }

    #[test]
    fn the_request_id_is_read_from_the_body() {
        assert_eq!(request_id(br#"{"jsonrpc":"2.0","id":7,"method":"SendStreamingMessage"}"#), json!(7));
        assert_eq!(request_id(br#"{"jsonrpc":"2.0","id":"a","method":"x"}"#), json!("a"));
        assert_eq!(request_id(br#"{"jsonrpc":"2.0","method":"x"}"#), Value::Null);
        assert_eq!(request_id(b"not json"), Value::Null);
    }
}
