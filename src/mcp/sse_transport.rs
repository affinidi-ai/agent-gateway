//! SSE / Streamable HTTP transport for upstream MCP agents.
//!
//! Handles both:
//! - **Streamable HTTP (2025-03-26)**: POST with `Accept: text/event-stream, application/json`
//!   and the upstream may respond with `text/event-stream` (SSE) or `application/json`.
//! - **Legacy SSE (2024-11-05)**: GET to the SSE endpoint, POST messages to a separate endpoint.
//!
//! The gateway auto-detects which transport the upstream supports based on
//! the response `Content-Type` header.

use axum::response::{
    Sse,
    sse::{Event as SseEvent, KeepAlive},
};
use bytes::Bytes;
use futures::stream::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::convert::Infallible;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

/// Result of probing/sending to an upstream MCP endpoint.
pub enum UpstreamMcpResponse {
    /// Upstream responded with JSON (non-streaming).
    Json {
        status: reqwest::StatusCode,
        #[allow(dead_code)]
        headers: reqwest::header::HeaderMap,
        body: Bytes,
    },
    /// Upstream responded with SSE stream (text/event-stream).
    SseStream {
        status: reqwest::StatusCode,
        #[allow(dead_code)]
        headers: reqwest::header::HeaderMap,
        response: reqwest::Response,
    },
}

/// Content-type constants
const CT_EVENT_STREAM: &str = "text/event-stream";
const CT_JSON: &str = "application/json";

/// Determines if a content-type header value indicates SSE.
pub fn is_sse_content_type(content_type: &str) -> bool {
    content_type.starts_with(CT_EVENT_STREAM)
}

/// Byte cap on one SSE event a Legacy SSE roundtrip holds while it is
/// incomplete: the default `a2a.max_body_size`, which that path cannot reach.
fn legacy_sse_event_limit() -> usize {
    crate::config::A2aConfig::default().max_body_size
}

/// An upstream SSE event grew past its byte cap before it was complete.
#[derive(Debug, thiserror::Error)]
#[error("upstream SSE event exceeds {0} bytes")]
pub(crate) struct SseEventTooLarge(usize);

/// Splits an upstream SSE byte stream into complete events.
///
/// CRLF and CR line endings are normalised to LF as bytes arrive, including a
/// CRLF split across chunks, and each event is decoded as UTF-8 only once
/// complete, so a character split across chunks survives. At most
/// `max_event_bytes` of an incomplete event is held.
pub(crate) struct SseEventBuffer {
    pending: Vec<u8>,
    after_cr: bool,
    max_event_bytes: usize,
}

impl SseEventBuffer {
    pub(crate) fn new(max_event_bytes: usize) -> Self {
        Self {
            pending: Vec::new(),
            after_cr: false,
            max_event_bytes,
        }
    }

    /// Append a chunk and return the events it completes, without their
    /// terminating blank line.
    pub(crate) fn push(
        &mut self,
        chunk: &[u8],
    ) -> Result<Vec<String>, SseEventTooLarge> {
        let mut events = Vec::new();
        for &byte in chunk {
            if std::mem::take(&mut self.after_cr) && byte == b'\n' {
                continue;
            }
            let byte = if byte == b'\r' {
                self.after_cr = true;
                b'\n'
            } else {
                byte
            };
            if byte == b'\n' && self.pending.last() == Some(&b'\n') {
                self.pending.pop();
                events.push(String::from_utf8_lossy(&self.pending).into_owned());
                self.pending.clear();
                continue;
            }
            if self.pending.len() >= self.max_event_bytes {
                return Err(SseEventTooLarge(self.max_event_bytes));
            }
            self.pending.push(byte);
        }
        Ok(events)
    }
}

/// Send an MCP JSON-RPC request to the upstream target and auto-detect
/// whether the response is SSE or plain JSON.
///
/// The request is sent as POST with `Accept: text/event-stream, application/json`
/// which tells the upstream we can handle either format (Streamable HTTP spec).
/// A JSON body is read within `limits`; an SSE stream is returned unread.
pub(crate) async fn send_mcp_request(
    client: &reqwest::Client,
    target_url: &str,
    body: Bytes,
    extra_headers: Option<&reqwest::header::HeaderMap>,
    limits: crate::proxy::upstream_body::UpstreamBodyLimits,
) -> Result<UpstreamMcpResponse, crate::proxy::upstream_body::UpstreamBodyError> {
    let mut req = client
        .post(target_url)
        .header(CONTENT_TYPE, CT_JSON)
        .header(ACCEPT, format!("{}, {}", CT_EVENT_STREAM, CT_JSON))
        .body(body);

    // Forward any extra headers (auth, trace, custom metadata, etc.)
    if let Some(headers) = extra_headers {
        for (key, value) in headers.iter() {
            req = req.header(key, value);
        }
    }

    let response = req.send().await?;
    let status = response.status();
    let headers = response.headers().clone();

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if is_sse_content_type(content_type) {
        debug!("Upstream responded with SSE (Content-Type: {})", content_type);
        Ok(UpstreamMcpResponse::SseStream { status, headers, response })
    } else {
        let body = crate::proxy::upstream_body::read_bounded(response, limits).await?;
        Ok(UpstreamMcpResponse::Json { status, headers, body })
    }
}

/// Connect to a Legacy SSE endpoint (MCP 2024-11-05).
///
/// Legacy SSE uses a GET request to an `/sse` endpoint which returns an SSE stream.
/// The SSE stream sends an `endpoint` event with the URL to POST messages to.
///
/// Returns the SSE response for streaming, plus the message endpoint URL
/// once it arrives via the first SSE event.
#[allow(dead_code)]
pub async fn connect_legacy_sse(
    client: &reqwest::Client,
    sse_url: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    let response = client
        .get(sse_url)
        .header(ACCEPT, CT_EVENT_STREAM)
        .send()
        .await?;

    Ok(response)
}

/// Convert an upstream SSE reqwest::Response into an axum SSE response
/// that can be streamed back to the client.
///
/// This function creates a tokio channel, spawns a task to read from the
/// upstream SSE stream, and returns an axum-compatible streaming response.
///
/// An event that grows past `max_event_bytes` before it is complete ends the
/// stream, as does an upstream that sends nothing for `idle_timeout` or that
/// is still streaming after `max_lifetime`.
pub fn create_sse_passthrough_response(
    upstream_response: reqwest::Response,
    upstream_headers: reqwest::header::HeaderMap,
    channel_name: String,
    max_event_bytes: usize,
    idle_timeout: std::time::Duration,
    max_lifetime: std::time::Duration,
) -> axum::response::Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<SseEvent, Infallible>>(32);

    // Spawn a task to read from upstream and forward SSE events
    let channel_name_clone = channel_name.clone();
    tokio::spawn(async move {
        let mut byte_stream = upstream_response.bytes_stream();
        let mut events = SseEventBuffer::new(max_event_bytes);
        let lifetime_deadline = tokio::time::Instant::now() + max_lifetime;

        loop {
            let idle_deadline = tokio::time::Instant::now() + idle_timeout;
            let chunk_result =
                match tokio::time::timeout_at(idle_deadline.min(lifetime_deadline), byte_stream.next()).await {
                    Ok(Some(chunk_result)) => chunk_result,
                    Ok(None) => break,
                    Err(_) => {
                        let limit = if lifetime_deadline <= idle_deadline {
                            "maximum lifetime"
                        } else {
                            "idle timeout"
                        };
                        warn!(channel = channel_name_clone, limit, "Ending upstream SSE stream");
                        break;
                    }
                };
            match chunk_result {
                Ok(chunk) => {
                    let raw_events = match events.push(&chunk) {
                        Ok(raw_events) => raw_events,
                        Err(e) => {
                            warn!(channel = channel_name_clone, error = %e, "Ending upstream SSE stream");
                            break;
                        }
                    };
                    for raw_event in raw_events {
                        if let Some(sse_event) = parse_sse_event(&raw_event)
                            && tx
                                .send(Ok(sse_event))
                                .await
                                .is_err()
                        {
                            debug!(channel = channel_name_clone, "Client disconnected from SSE stream");
                            return;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        channel = channel_name_clone,
                        error = %e,
                        "Error reading upstream SSE stream"
                    );
                    break;
                }
            }
        }

        debug!(channel = channel_name_clone, "Upstream SSE stream ended");
    });

    // Build the SSE response
    let stream = ReceiverStream::new(rx);
    let sse = Sse::new(stream).keep_alive(KeepAlive::default());

    let mut response = axum::response::IntoResponse::into_response(sse);

    // Forward relevant upstream headers (but not hop-by-hop or content headers)
    let resp_headers = response.headers_mut();
    for (key, value) in upstream_headers.iter() {
        let key_str = key.as_str().to_lowercase();
        if !is_filtered_header(&key_str) {
            resp_headers.insert(key, value.clone());
        }
    }

    response
}

/// Failure to reduce an upstream SSE response to its final JSON-RPC response.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SseConsumeError {
    #[error(transparent)]
    Body(#[from] crate::proxy::upstream_body::UpstreamBodyError),
    #[error("no JSON-RPC response found in SSE stream")]
    NoResponse,
}

/// Consume an upstream SSE response down to a single JSON-RPC response. Used
/// where the response must be buffered rather than streamed: the GW2 path
/// (sent back through a DIDComm channel) and a `tools/list` that has to be
/// gated before it is returned.
///
/// The stream is read within `limits` (size, idle gap and total time). When
/// `request` is a single JSON-RPC request, the read stops at the response
/// carrying its `id` and the rest of the stream is dropped: MCP only says a
/// server SHOULD close the stream after it. Otherwise the last response seen is
/// returned (which per MCP spec is the final result), at the end of the stream
/// or when the read fails or stalls after one arrived. An oversized stream is
/// refused either way.
pub(crate) async fn consume_sse_response(
    upstream_response: reqwest::Response,
    request: &[u8],
    limits: crate::proxy::upstream_body::UpstreamBodyLimits,
) -> Result<String, SseConsumeError> {
    use crate::proxy::upstream_body::UpstreamBodyError;

    let request_id = single_request_id(request);
    let mut chunks = crate::proxy::upstream_body::BoundedChunks::new(upstream_response, limits)?;
    // `chunks` already caps the whole stream, and so every event in it.
    let mut events = SseEventBuffer::new(usize::MAX);
    let mut last: Option<String> = None;
    loop {
        let (chunk, ended) = match chunks.next().await {
            Ok(Some(chunk)) => (chunk, false),
            // Terminate an event the stream ended without a blank line after.
            Ok(None) => (Bytes::from_static(b"\n\n"), true),
            Err(error @ UpstreamBodyError::TooLarge(_)) => return Err(error.into()),
            Err(error) => {
                let Some(response) = last else {
                    return Err(error.into());
                };
                debug!(error = %error, "Upstream SSE stream failed after a JSON-RPC response; returning it");
                return Ok(response);
            }
        };
        let raw_events = events
            .push(&chunk)
            .map_err(|error| UpstreamBodyError::TooLarge(error.0))?;
        for raw_event in raw_events {
            let Some((data, message)) = sse_event_json_rpc_response(&raw_event) else {
                continue;
            };
            if request_id.is_some() && response_id(&message) == request_id.as_ref() {
                return Ok(data);
            }
            last = Some(data);
        }
        if ended {
            return last.ok_or(SseConsumeError::NoResponse);
        }
    }
}

/// The `id` of `body` when it is a single JSON-RPC request expecting a
/// response, not a notification or a batch.
fn single_request_id(body: &[u8]) -> Option<serde_json::Value> {
    let message = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let message = message.as_object()?;
    if !message.contains_key("method") {
        return None;
    }
    message
        .get("id")
        .filter(|id| !id.is_null())
        .cloned()
}

/// The data of one SSE event and its parsed message, when it is a JSON-RPC
/// **response** (a message carrying `result` or `error`).
fn sse_event_json_rpc_response(raw_event: &str) -> Option<(String, serde_json::Value)> {
    let data_lines: Vec<&str> = raw_event
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .collect();
    let data = data_lines.join("\n");
    if data.is_empty() {
        return None;
    }
    let json = serde_json::from_str::<serde_json::Value>(&data).ok()?;
    (json.get("result").is_some() || json.get("error").is_some()).then_some((data, json))
}

/// Extract the last JSON-RPC **response** (a message carrying `result` or
/// `error`) from a fully-buffered SSE body. Returns the raw JSON string, or
/// `None` when the bytes are not SSE or carry no JSON-RPC response. Filters a
/// buffered `tools/list` that came back as `text/event-stream` on the outbound
/// transit path.
pub fn extract_last_json_rpc_from_sse_bytes(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    text.split("\n\n")
        .filter_map(sse_event_json_rpc_response)
        .map(|(data, _)| data)
        .last()
}

#[cfg(test)]
mod bytes_sse_tests {
    use super::extract_last_json_rpc_from_sse_bytes;

    #[test]
    fn extracts_json_rpc_result_from_sse_frames() {
        let body =
            b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"}]}}\n\n";
        let got = extract_last_json_rpc_from_sse_bytes(body).unwrap();
        let v: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["result"]["tools"][0]["name"], "a");
    }

    #[test]
    fn returns_none_for_plain_json_or_no_response() {
        // Plain JSON (no SSE framing) has no `data:` lines.
        assert!(extract_last_json_rpc_from_sse_bytes(b"{\"result\":{}}").is_none());
        // SSE notification (has `method`, no result/error) is not a response.
        let notif = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/ping\"}\n\n";
        assert!(extract_last_json_rpc_from_sse_bytes(notif).is_none());
    }
}

#[cfg(test)]
mod event_buffer_tests {
    use super::SseEventBuffer;

    fn split_into_chunks(
        stream: &[u8],
        at: &[usize],
    ) -> Vec<String> {
        let mut buffer = SseEventBuffer::new(1024);
        let mut events = Vec::new();
        let mut start = 0;
        for &end in at
            .iter()
            .chain(std::iter::once(&stream.len()))
        {
            events.extend(
                buffer
                    .push(&stream[start..end])
                    .unwrap(),
            );
            start = end;
        }
        events
    }

    #[test]
    fn splits_events_with_any_line_ending_wherever_the_chunks_break() {
        let stream = b"event: a\r\ndata: 1\r\n\r\ndata: 2\r\rdata: 3\n\n";
        let expected = ["event: a\ndata: 1", "data: 2", "data: 3"];
        for at in 0..=stream.len() {
            assert_eq!(split_into_chunks(stream, &[at]), expected, "split at {at}");
        }
    }

    #[test]
    fn keeps_a_character_split_across_chunks() {
        let stream = "data: caf\u{e9}\n\n".as_bytes();
        let split = stream
            .iter()
            .position(|&byte| byte == 0xC3)
            .unwrap()
            + 1;

        assert_eq!(split_into_chunks(stream, &[split]), ["data: caf\u{e9}"]);
    }

    #[test]
    fn holds_an_incomplete_event_until_its_blank_line() {
        let mut buffer = SseEventBuffer::new(1024);

        assert!(
            buffer
                .push(b"data: 1\n")
                .unwrap()
                .is_empty()
        );
        assert_eq!(buffer.push(b"\n").unwrap(), ["data: 1"]);
    }

    #[test]
    fn refuses_an_incomplete_event_past_the_cap_but_not_complete_ones() {
        let mut buffer = SseEventBuffer::new(8);
        for _ in 0..4 {
            assert_eq!(
                buffer
                    .push(b"data: 1\n\n")
                    .unwrap(),
                ["data: 1"]
            );
        }

        assert!(
            buffer
                .push(b"data: 12")
                .is_ok()
        );
        assert!(buffer.push(b"3").is_err());
    }
}

#[cfg(test)]
mod consume_sse_tests {
    use std::time::Duration;

    use super::{SseConsumeError, consume_sse_response};
    use crate::proxy::upstream_body::UpstreamBodyError;
    use crate::proxy::upstream_body::tests::{PATIENT, chunk, limits, upstream};

    const SSE_HEAD: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";

    #[tokio::test]
    async fn returns_the_last_response_from_a_stream_split_mid_event() {
        let stream = b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\r\n\r\n\
            data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\r\n\r\n";
        let response = upstream(
            SSE_HEAD.to_string(),
            vec![
                (Duration::ZERO, chunk(&stream[..40])),
                (Duration::ZERO, chunk(&stream[40..])),
                (Duration::ZERO, chunk(b"")),
            ],
        )
        .await;

        let json = consume_sse_response(response, b"", limits(1024, Some(PATIENT), PATIENT))
            .await
            .unwrap();

        assert_eq!(json, r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#);
    }

    #[tokio::test]
    async fn rejects_a_stream_once_it_grows_past_the_limit() {
        let event = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n";
        let response = upstream(
            SSE_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(event)), (Duration::ZERO, chunk(event)), (Duration::ZERO, chunk(event))],
        )
        .await;

        let error = consume_sse_response(response, b"", limits(event.len() * 2, Some(PATIENT), PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, SseConsumeError::Body(UpstreamBodyError::TooLarge(_))), "{error:?}");
    }

    #[tokio::test]
    async fn gives_up_when_the_stream_stalls_for_the_idle_deadline() {
        let response = upstream(
            SSE_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(b"data: {\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n\n"))],
        )
        .await;

        let error = consume_sse_response(response, b"", limits(1024, Some(Duration::from_millis(200)), PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, SseConsumeError::Body(UpstreamBodyError::TimedOut)), "{error:?}");
    }

    #[tokio::test]
    async fn reports_a_complete_stream_without_a_response() {
        let response = upstream(
            SSE_HEAD.to_string(),
            vec![
                (Duration::ZERO, chunk(b"data: {\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n\n")),
                (Duration::ZERO, chunk(b"")),
            ],
        )
        .await;

        let error = consume_sse_response(response, b"", limits(1024, Some(PATIENT), PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, SseConsumeError::NoResponse), "{error:?}");
    }

    const TOOLS_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#;
    const PROGRESS_EVENT: &[u8] = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n";
    const RESPONSE_EVENT: &[u8] = b"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n\n";
    const RESPONSE: &str = r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}"#;

    /// Serves `head` and `body` raw, then drops the connection mid-chunk.
    async fn upstream_that_drops(
        head: &'static str,
        body: Vec<u8>,
    ) -> reqwest::Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap();
            let mut request = [0u8; 4096];
            let _ = socket
                .read(&mut request)
                .await;
            let _ = socket
                .write_all(head.as_bytes())
                .await;
            let _ = socket.write_all(&body).await;
        });
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(url)
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn returns_the_requests_response_without_waiting_for_the_stream_to_close() {
        let response = upstream(
            SSE_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(PROGRESS_EVENT)), (Duration::ZERO, chunk(RESPONSE_EVENT))],
        )
        .await;

        let json = tokio::time::timeout(
            Duration::from_secs(5),
            consume_sse_response(response, TOOLS_LIST, limits(1024, Some(PATIENT), PATIENT)),
        )
        .await
        .expect("returned before the stream closed")
        .unwrap();

        assert_eq!(json, RESPONSE);
    }

    #[tokio::test]
    async fn skips_responses_to_other_ids_before_the_requests_own() {
        let other = b"data: {\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{}}\n\n";
        let response = upstream(
            SSE_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(other)), (Duration::ZERO, chunk(RESPONSE_EVENT))],
        )
        .await;

        let json = consume_sse_response(response, TOOLS_LIST, limits(1024, Some(PATIENT), PATIENT))
            .await
            .unwrap();

        assert_eq!(json, RESPONSE);
    }

    #[tokio::test]
    async fn returns_the_last_response_when_the_stream_resets_after_it() {
        let mut body = chunk(RESPONSE_EVENT);
        body.extend_from_slice(b"40\r\ndata: {\"jsonrpc\"");
        let response = upstream_that_drops(SSE_HEAD, body).await;

        let json = consume_sse_response(response, b"", limits(1024, Some(PATIENT), PATIENT))
            .await
            .unwrap();

        assert_eq!(json, RESPONSE);
    }

    #[tokio::test]
    async fn returns_the_last_response_when_the_stream_stalls_after_it() {
        let response = upstream(SSE_HEAD.to_string(), vec![(Duration::ZERO, chunk(RESPONSE_EVENT))]).await;

        let json = consume_sse_response(response, b"", limits(1024, Some(Duration::from_millis(200)), PATIENT))
            .await
            .unwrap();

        assert_eq!(json, RESPONSE);
    }

    #[tokio::test]
    async fn fails_a_reset_before_any_response() {
        let mut body = chunk(PROGRESS_EVENT);
        body.extend_from_slice(b"40\r\ndata: {\"jsonrpc\"");
        let response = upstream_that_drops(SSE_HEAD, body).await;

        let error = consume_sse_response(response, TOOLS_LIST, limits(1024, Some(PATIENT), PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, SseConsumeError::Body(UpstreamBodyError::Read(_))), "{error:?}");
    }

    #[tokio::test]
    async fn reads_a_final_event_without_a_trailing_blank_line() {
        let response = upstream(
            SSE_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(&RESPONSE_EVENT[..RESPONSE_EVENT.len() - 2])), (Duration::ZERO, chunk(b""))],
        )
        .await;

        let json = consume_sse_response(response, b"", limits(1024, Some(PATIENT), PATIENT))
            .await
            .unwrap();

        assert_eq!(json, RESPONSE);
    }
}

/// Resolve the Legacy-SSE session POST URL from an `endpoint` event, locked to
/// the SSE stream's own origin.
///
/// An absolute `endpoint` value whose scheme, host or port differs from the SSE
/// URL is refused: following it would let an upstream redirect the session POST
/// to an internal or cloud-metadata address, escaping the vetted/pinned SSE
/// host. Relative values resolve against the SSE URL and stay same-origin.
fn resolve_session_post_url(
    raw_endpoint: &str,
    sse_url: &str,
) -> Result<String, String> {
    let base = reqwest::Url::parse(sse_url).map_err(|e| format!("Invalid SSE base URL: {e}"))?;
    let resolved = base
        .join(raw_endpoint)
        .map_err(|e| format!("Invalid SSE endpoint URL: {e}"))?;
    if resolved.scheme() != base.scheme()
        || resolved.host_str() != base.host_str()
        || resolved.port_or_known_default() != base.port_or_known_default()
    {
        return Err("SSE endpoint event points to a different origin; refusing cross-origin session POST".to_string());
    }
    Ok(resolved.to_string())
}

/// Perform a complete Legacy SSE round-trip for a single JSON-RPC request.
///
/// Used by GW2 when the upstream only supports Legacy SSE transport (not
/// Streamable HTTP).  The flow is:
///
/// 1. `GET {base_url}/sse` → establish SSE stream
/// 2. Read the first `endpoint` event to obtain the session POST URL
/// 3. `POST` the JSON-RPC body to that session URL
/// 4. Continue reading the SSE stream until a JSON-RPC response arrives
/// 5. Return the JSON-RPC response as a string
///
/// The SSE connection is dropped when this function returns.
#[allow(dead_code)]
pub async fn legacy_sse_roundtrip(
    client: &reqwest::Client,
    base_url: &str,
    json_rpc_body: &[u8],
    channel_name: &str,
) -> Result<String, String> {
    use tokio::time::{Duration, timeout};

    let sse_url = format!("{}/sse", base_url.trim_end_matches('/'));
    debug!(channel = channel_name, "Legacy SSE roundtrip: connecting to {}", sse_url);

    let response = client
        .get(&sse_url)
        .header(ACCEPT, CT_EVENT_STREAM)
        .send()
        .await
        .map_err(|e| format!("SSE connect failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("SSE endpoint returned {}", response.status()));
    }

    let mut byte_stream = response.bytes_stream();
    let mut events = SseEventBuffer::new(legacy_sse_event_limit());

    // Step 1: read events until we get the endpoint URL (max 10 s)
    let deadline = Duration::from_secs(10);
    let endpoint_result = timeout(deadline, async {
        while let Some(chunk) = byte_stream.next().await {
            match chunk {
                Ok(bytes) => {
                    for raw in events
                        .push(&bytes)
                        .map_err(|e| e.to_string())?
                    {
                        // Look for "event: endpoint" (or "event:endpoint")
                        let is_endpoint_event = raw.lines().any(|l| {
                            l.strip_prefix("event:")
                                .map(|v| v.trim() == "endpoint")
                                .unwrap_or(false)
                        });

                        if is_endpoint_event {
                            for line in raw.lines() {
                                if let Some(data) = line.strip_prefix("data:") {
                                    return Ok::<String, String>(data.trim().to_string());
                                }
                            }
                        }
                    }
                }
                Err(e) => return Err(format!("SSE stream error: {e}")),
            }
        }
        Err("SSE stream closed before endpoint event".to_string())
    })
    .await;

    let raw_endpoint = match endpoint_result {
        Ok(Ok(url)) => url,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("Timeout waiting for endpoint event from SSE".to_string()),
    };

    let post_url = resolve_session_post_url(&raw_endpoint, &sse_url)?;

    debug!(channel = channel_name, "Legacy SSE roundtrip: posting to {}", post_url);

    // Step 2: POST the JSON-RPC body to the session endpoint
    let post_resp = client
        .post(&post_url)
        .header(CONTENT_TYPE, CT_JSON)
        .body(json_rpc_body.to_vec())
        .send()
        .await
        .map_err(|e| format!("POST to session endpoint failed: {e}"))?;

    let post_status = post_resp.status();
    if !post_status.is_success() && post_status.as_u16() != 202 {
        return Err(format!("Session POST returned {}", post_status));
    }

    // Check if the request was a notification (no id → no response expected)
    if let Ok(req_json) = serde_json::from_slice::<serde_json::Value>(json_rpc_body)
        && req_json.get("id").is_none()
    {
        return Ok(String::new()); // notifications don't get responses
    }

    // Step 3: read SSE stream for the JSON-RPC response (max 30 s)
    let response_deadline = Duration::from_secs(30);
    let response_result = timeout(response_deadline, async {
        loop {
            match byte_stream.next().await {
                Some(Ok(bytes)) => {
                    for raw in events
                        .push(&bytes)
                        .map_err(|e| e.to_string())?
                    {
                        let mut data_lines: Vec<String> = Vec::new();
                        for line in raw.lines() {
                            if let Some(d) = line.strip_prefix("data:") {
                                data_lines.push(d.trim_start().to_string());
                            }
                        }
                        if !data_lines.is_empty() {
                            let data = data_lines.join("\n");
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data)
                                && (json.get("result").is_some() || json.get("error").is_some())
                            {
                                return Ok::<String, String>(data);
                            }
                        }
                    }
                }
                Some(Err(e)) => return Err(format!("SSE stream error reading response: {e}")),
                None => return Err("SSE stream ended without response".to_string()),
            }
        }
    })
    .await;

    match response_result {
        Ok(Ok(json)) => {
            debug!(channel = channel_name, "Legacy SSE roundtrip: got response");
            Ok(json)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err("Timeout waiting for JSON-RPC response from SSE".to_string()),
    }
}

/// Parse a raw SSE event text block into an axum SseEvent.
///
/// Supports `event:`, `data:`, `id:`, and `retry:` fields.
fn parse_sse_event(raw: &str) -> Option<SseEvent> {
    let mut event_type: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();
    let mut id: Option<String> = None;

    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_type = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.trim_start().to_string());
        } else if let Some(value) = line.strip_prefix("id:") {
            id = Some(value.trim().to_string());
        } else if line
            .strip_prefix("retry:")
            .is_some()
        {
            // We don't forward retry to the client
        } else if line.starts_with(':') {
            // SSE comment - skip
        }
    }

    if data_lines.is_empty() && event_type.is_none() {
        return None;
    }

    let data = data_lines.join("\n");
    let mut event = SseEvent::default().data(data);

    if let Some(evt) = event_type {
        event = event.event(evt);
    }
    if let Some(event_id) = id {
        event = event.id(event_id);
    }

    Some(event)
}

/// Headers that should NOT be forwarded from upstream SSE responses.
fn is_filtered_header(key: &str) -> bool {
    matches!(
        key,
        "transfer-encoding" | "connection" | "keep-alive" | "content-length" | "content-type" | "content-encoding"
    )
}

// ── Persistent upstream SSE session (GW2) ───────────────────────────────────
//
// Legacy SSE servers expect `initialize` → `notifications/initialized` →
// other requests all on the **same** SSE session.  `legacy_sse_roundtrip`
// opens a fresh connection per request which breaks that invariant.
//
// `UpstreamSseSession` keeps one GET /sse connection alive, runs a
// background reader task that routes responses by JSON-RPC `id`, and
// exposes `send_request` for posting to the session endpoint.
//
// `UpstreamSseSessionManager` caches sessions by base_url.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::info;

/// A single persistent connection to an upstream Legacy SSE server.
struct UpstreamSseSessionInner {
    post_url: String,
    client: reqwest::Client,
    /// Pending response waiters keyed by the gateway-assigned JSON-RPC `id`
    /// the request was sent upstream with.
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<String>>>>,
    /// Source of the gateway-assigned ids. The session is shared by every
    /// caller of the same upstream, so callers' own ids can collide.
    next_id: std::sync::atomic::AtomicU64,
    /// Set to `false` when the background SSE reader exits.
    alive: Arc<std::sync::atomic::AtomicBool>,
}

/// Handle to a persistent upstream SSE session.
pub struct UpstreamSseSession {
    inner: Arc<UpstreamSseSessionInner>,
}

impl UpstreamSseSession {
    /// Connect to an upstream Legacy SSE endpoint.
    ///
    /// Opens `GET {base_url}/sse`, reads the `endpoint` event, spawns a
    /// background task to read responses, and returns the session handle.
    pub async fn connect(
        client: &reqwest::Client,
        base_url: &str,
        channel_name: &str,
        max_event_bytes: usize,
    ) -> Result<Self, String> {
        use tokio::time::{Duration, timeout};

        let sse_url = format!("{}/sse", base_url.trim_end_matches('/'));
        info!(channel = channel_name, "UpstreamSseSession: connecting to {}", sse_url);

        let response = client
            .get(&sse_url)
            .header(ACCEPT, CT_EVENT_STREAM)
            .send()
            .await
            .map_err(|e| format!("SSE connect failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("SSE endpoint returned {}", response.status()));
        }

        let mut byte_stream = response.bytes_stream();
        let mut events = SseEventBuffer::new(max_event_bytes);

        // Read until we get the endpoint event (max 10s)
        let raw_endpoint = timeout(Duration::from_secs(10), async {
            while let Some(chunk) = byte_stream.next().await {
                match chunk {
                    Ok(bytes) => {
                        for raw in events
                            .push(&bytes)
                            .map_err(|e| e.to_string())?
                        {
                            let is_endpoint = raw.lines().any(|l| {
                                l.strip_prefix("event:")
                                    .map(|v| v.trim() == "endpoint")
                                    .unwrap_or(false)
                            });

                            if is_endpoint {
                                for line in raw.lines() {
                                    if let Some(data) = line.strip_prefix("data:") {
                                        return Ok::<String, String>(data.trim().to_string());
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => return Err(format!("SSE stream error: {e}")),
                }
            }
            Err("SSE stream closed before endpoint event".to_string())
        })
        .await
        .map_err(|_| "Timeout waiting for endpoint event".to_string())??;

        let post_url = resolve_session_post_url(&raw_endpoint, &sse_url)?;

        info!(channel = channel_name, "UpstreamSseSession: post_url={}", post_url);

        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<String>>>> = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // Spawn background reader
        let pending_clone = pending.clone();
        let alive_clone = alive.clone();
        let ch_name = channel_name.to_string();
        tokio::spawn(async move {
            while let Some(chunk_result) = byte_stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        let raw_events = match events.push(&bytes) {
                            Ok(raw_events) => raw_events,
                            Err(e) => {
                                warn!(channel = ch_name, error = %e, "UpstreamSseSession: ending session");
                                break;
                            }
                        };
                        for raw in raw_events {
                            let mut data_lines: Vec<String> = Vec::new();
                            for line in raw.lines() {
                                if let Some(d) = line.strip_prefix("data:") {
                                    data_lines.push(d.trim_start().to_string());
                                }
                            }
                            if data_lines.is_empty() {
                                continue;
                            }
                            let data = data_lines.join("\n");

                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data)
                                && let Some(upstream_id) = upstream_response_id(&json)
                                && let Some(tx) = pending_clone
                                    .lock()
                                    .await
                                    .remove(&upstream_id)
                            {
                                let _ = tx.send(data);
                                continue;
                            }
                            debug!(channel = ch_name, "UpstreamSseSession: unrouted SSE data");
                        }
                    }
                    Err(e) => {
                        warn!(channel = ch_name, error = %e, "UpstreamSseSession: stream error");
                        break;
                    }
                }
            }
            info!(channel = ch_name, "UpstreamSseSession: stream ended");
            alive_clone.store(false, std::sync::atomic::Ordering::SeqCst);
            // Drain all pending waiters so they don't block forever
            let mut map = pending_clone.lock().await;
            for (_, tx) in map.drain() {
                let _ = tx.send(String::new());
            }
        });

        let session = Self {
            inner: Arc::new(UpstreamSseSessionInner {
                post_url,
                client: client.clone(),
                pending,
                next_id: std::sync::atomic::AtomicU64::new(1),
                alive,
            }),
        };

        // Auto-initialize: Legacy SSE servers require `initialize` →
        // `notifications/initialized` before accepting other methods.
        let init_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "agent-gateway", "version": "1.0.0" }
            }
        });
        match session
            .send_request(
                init_req
                    .to_string()
                    .as_bytes(),
            )
            .await
        {
            Ok(resp) => {
                info!(channel = channel_name, "UpstreamSseSession: initialized upstream, response={}", resp);
            }
            Err(e) => {
                session
                    .inner
                    .alive
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                return Err(format!("SSE session initialize failed: {e}"));
            }
        }

        // Fire-and-forget the initialized notification
        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        if let Err(e) = session
            .send_request(notif.to_string().as_bytes())
            .await
        {
            tracing::warn!(channel = channel_name, error = %e, "UpstreamSseSession: notifications/initialized failed");
        }

        Ok(session)
    }

    /// Returns `true` if the background SSE reader is still running.
    pub fn is_alive(&self) -> bool {
        self.inner
            .alive
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Send a JSON-RPC request and wait for the response (up to 30s).
    ///
    /// For notifications (no `id`), fires and forgets — returns `Ok("")`.
    /// A JSON-RPC batch is refused: its elements would go upstream under the
    /// callers' own ids.
    ///
    /// A request goes upstream under a gateway-assigned id, and the response
    /// is returned with the caller's id restored, so two callers sharing the
    /// session with the same id each get their own response.
    pub async fn send_request(
        &self,
        json_rpc_body: &[u8],
    ) -> Result<String, String> {
        if !self.is_alive() {
            return Err("SSE session is no longer alive".to_string());
        }

        use tokio::time::{Duration, timeout};

        let mut req_json: serde_json::Value =
            serde_json::from_slice(json_rpc_body).map_err(|e| format!("Invalid JSON: {e}"))?;
        if req_json.is_array() {
            return Err("JSON-RPC batches are not supported on the Legacy SSE transport".to_string());
        }

        let caller_id = req_json
            .as_object_mut()
            .and_then(|request| request.remove("id"));

        let (waiter, upstream_body) = match caller_id {
            Some(caller_id) => {
                let upstream_id = self
                    .inner
                    .next_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                req_json["id"] = serde_json::Value::from(upstream_id);
                // Register the waiter before sending, so the reader can deliver.
                let (tx, rx) = oneshot::channel();
                self.inner
                    .pending
                    .lock()
                    .await
                    .insert(upstream_id, tx);
                let registration = PendingResponse {
                    pending: self.inner.pending.clone(),
                    upstream_id,
                };
                (
                    Some((registration, rx, caller_id)),
                    req_json
                        .to_string()
                        .into_bytes(),
                )
            }
            None => (None, json_rpc_body.to_vec()),
        };

        let resp = self
            .inner
            .client
            .post(&self.inner.post_url)
            .header(CONTENT_TYPE, CT_JSON)
            .body(upstream_body)
            .send()
            .await
            .map_err(|e| format!("POST failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() && status.as_u16() != 202 {
            return Err(format!("Session POST returned {}", status));
        }

        let Some((_registration, rx, caller_id)) = waiter else {
            return Ok(String::new());
        };
        match timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(data)) if !data.is_empty() => with_caller_id(&data, caller_id),
            Ok(Ok(_)) => Err("SSE session closed before response was received".to_string()),
            Ok(Err(_)) => Err("SSE session closed before response".to_string()),
            Err(_) => Err("Timeout waiting for response from upstream SSE".to_string()),
        }
    }
}

/// A caller's registered response waiter, removed when the caller finishes,
/// fails or is dropped, so a disconnected caller leaves no entry behind.
struct PendingResponse {
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<String>>>>,
    upstream_id: u64,
}

impl Drop for PendingResponse {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.pending.try_lock() {
            pending.remove(&self.upstream_id);
            return;
        }
        let pending = self.pending.clone();
        let upstream_id = self.upstream_id;
        tokio::spawn(async move {
            pending
                .lock()
                .await
                .remove(&upstream_id);
        });
    }
}

/// The gateway-assigned id a message from the upstream answers, if it is a
/// response. A server request (`method`) with a matching id is not one.
fn upstream_response_id(message: &serde_json::Value) -> Option<u64> {
    response_id(message)?.as_u64()
}

/// The `id` a message answers, if it is a response. A request (`method`)
/// carrying an `id` is not one.
fn response_id(message: &serde_json::Value) -> Option<&serde_json::Value> {
    let message = message.as_object()?;
    if message.contains_key("method") || !(message.contains_key("result") || message.contains_key("error")) {
        return None;
    }
    message.get("id")
}

/// Put the caller's JSON-RPC `id` back on an upstream response.
fn with_caller_id(
    data: &str,
    caller_id: serde_json::Value,
) -> Result<String, String> {
    let mut response: serde_json::Value =
        serde_json::from_str(data).map_err(|e| format!("Invalid upstream SSE response: {e}"))?;
    response
        .as_object_mut()
        .ok_or("Upstream SSE response is not a JSON-RPC object")?
        .insert("id".to_string(), caller_id);
    Ok(response.to_string())
}

/// Caches persistent upstream SSE sessions by base URL.
///
/// Used by GW2's message processor to maintain one SSE connection per
/// upstream MCP server.
pub struct UpstreamSseSessionManager {
    pub sessions: RwLock<HashMap<String, Arc<UpstreamSseSession>>>,
}

impl UpstreamSseSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create a persistent session for the given base URL.
    /// Evicts dead sessions automatically.
    pub async fn get_or_connect(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        channel_name: &str,
        max_event_bytes: usize,
    ) -> Result<Arc<UpstreamSseSession>, String> {
        // Fast path: read lock — return cached session if alive
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(base_url) {
                if session.is_alive() {
                    return Ok(session.clone());
                }
                info!(channel = channel_name, "UpstreamSseSession: cached session is dead, will reconnect");
            }
        }

        // Slow path: take write lock BEFORE connecting to prevent
        // concurrent connect attempts for the same URL.
        let mut sessions = self.sessions.write().await;

        // Double-check: another task may have connected while we waited for the lock
        if let Some(existing) = sessions.get(base_url) {
            if existing.is_alive() {
                return Ok(existing.clone());
            }
            // Dead — remove before inserting new one
            sessions.remove(base_url);
        }

        let session = UpstreamSseSession::connect(client, base_url, channel_name, max_event_bytes).await?;
        let session = Arc::new(session);
        sessions.insert(base_url.to_string(), session.clone());
        Ok(session)
    }
}

/// Global upstream SSE session manager for GW2.
pub static UPSTREAM_SSE_SESSIONS: std::sync::LazyLock<UpstreamSseSessionManager> =
    std::sync::LazyLock::new(UpstreamSseSessionManager::new);

/// Send a JSON-RPC request via a persistent upstream Legacy SSE session.
///
/// If the cached session dies mid-request (upstream closed the connection),
/// evicts it and retries once with a fresh session. `max_event_bytes` caps one
/// incomplete SSE event (`a2a.max_body_size`); a session shared by several
/// callers keeps the cap it connected with.
pub async fn send_via_persistent_sse(
    client: &reqwest::Client,
    base_url: &str,
    json_rpc_body: &[u8],
    channel_name: &str,
    max_event_bytes: usize,
) -> Result<String, String> {
    let session = UPSTREAM_SSE_SESSIONS
        .get_or_connect(client, base_url, channel_name, max_event_bytes)
        .await?;
    match session
        .send_request(json_rpc_body)
        .await
    {
        Ok(resp) => Ok(resp),
        Err(e) if !session.is_alive() => {
            tracing::warn!(
                channel = channel_name,
                error = %e,
                "SSE session died during request, evicting and retrying"
            );
            // Evict the dead session so get_or_connect creates a fresh one
            UPSTREAM_SSE_SESSIONS
                .sessions
                .write()
                .await
                .remove(base_url);
            let new_session = UPSTREAM_SSE_SESSIONS
                .get_or_connect(client, base_url, channel_name, max_event_bytes)
                .await?;
            new_session
                .send_request(json_rpc_body)
                .await
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two callers sharing an upstream session with the same JSON-RPC id each
    /// get their own response, with their own id, even when the upstream
    /// answers out of order.
    #[tokio::test]
    async fn callers_sharing_a_legacy_sse_session_get_their_own_responses() {
        use axum::response::sse::Event;
        use tokio::sync::mpsc;

        let (events, receiver) = mpsc::channel::<Event>(16);
        let receiver = Arc::new(Mutex::new(Some(receiver)));
        let held = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let app = axum::Router::new()
            .route(
                "/sse",
                axum::routing::get(move || {
                    let receiver = receiver.clone();
                    async move {
                        let receiver = receiver
                            .lock()
                            .await
                            .take()
                            .expect("one SSE connection");
                        let endpoint = futures::stream::once(async {
                            Event::default()
                                .event("endpoint")
                                .data("/messages")
                        });
                        Sse::new(
                            endpoint
                                .chain(ReceiverStream::new(receiver))
                                .map(Ok::<_, Infallible>),
                        )
                    }
                }),
            )
            .route(
                "/messages",
                axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                    let events = events.clone();
                    let held = held.clone();
                    async move {
                        let answer = |request: &serde_json::Value| {
                            Event::default().data(
                                serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": request["params"]})
                                    .to_string(),
                            )
                        };
                        if request["method"] == "initialize" {
                            events
                                .send(answer(&request))
                                .await
                                .unwrap();
                        } else if request.get("id").is_some() {
                            let mut held = held.lock().await;
                            held.push(request);
                            if held.len() == 2 {
                                for request in held.drain(..).rev() {
                                    events
                                        .send(answer(&request))
                                        .await
                                        .unwrap();
                                }
                            }
                        }
                        axum::http::StatusCode::ACCEPTED
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let session =
            UpstreamSseSession::connect(&reqwest::Client::new(), &format!("http://{address}"), "test", 1024 * 1024)
                .await
                .expect("the session connects");
        let call = |who: &'static str| {
            let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"who": who}});
            let session = &session;
            async move {
                let response = session
                    .send_request(body.to_string().as_bytes())
                    .await
                    .unwrap();
                serde_json::from_str::<serde_json::Value>(&response).unwrap()
            }
        };
        let (a, b) = tokio::join!(call("a"), call("b"));
        assert_eq!((&a["id"], &a["result"]["who"]), (&serde_json::json!(1), &serde_json::json!("a")), "{a}");
        assert_eq!((&b["id"], &b["result"]["who"]), (&serde_json::json!(1), &serde_json::json!("b")), "{b}");
    }

    /// Only a response answers a waiter: a server request or a string id that
    /// matches a gateway-assigned id is not delivered, a batch never goes
    /// upstream, and a dropped caller leaves no waiter behind.
    #[tokio::test]
    async fn legacy_sse_session_delivers_only_responses_and_refuses_batches() {
        use axum::response::sse::Event;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::mpsc;

        let (events, receiver) = mpsc::channel::<Event>(16);
        let receiver = Arc::new(Mutex::new(Some(receiver)));
        let posts = Arc::new(AtomicUsize::new(0));
        let counted = posts.clone();
        let app = axum::Router::new()
            .route(
                "/sse",
                axum::routing::get(move || {
                    let receiver = receiver.clone();
                    async move {
                        let receiver = receiver
                            .lock()
                            .await
                            .take()
                            .expect("one SSE connection");
                        let endpoint = futures::stream::once(async {
                            Event::default()
                                .event("endpoint")
                                .data("/messages")
                        });
                        Sse::new(
                            endpoint
                                .chain(ReceiverStream::new(receiver))
                                .map(Ok::<_, Infallible>),
                        )
                    }
                }),
            )
            .route(
                "/messages",
                axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                    let events = events.clone();
                    let counted = counted.clone();
                    async move {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let id = request["id"].clone();
                        let send = |message: serde_json::Value| {
                            let events = events.clone();
                            async move {
                                events
                                    .send(Event::default().data(message.to_string()))
                                    .await
                                    .unwrap();
                            }
                        };
                        match request["method"].as_str() {
                            Some("initialize") => {
                                send(serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {}})).await
                            }
                            Some("tools/call") if request["params"]["answer"] == true => {
                                send(serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "ping"})).await;
                                send(
                                    serde_json::json!({"jsonrpc": "2.0", "id": id.to_string(), "result": "string id"}),
                                )
                                .await;
                                send(serde_json::json!({"jsonrpc": "2.0", "id": id, "result": "response"})).await;
                            }
                            _ => {}
                        }
                        axum::http::StatusCode::ACCEPTED
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let session =
            UpstreamSseSession::connect(&reqwest::Client::new(), &format!("http://{address}"), "test", 1024 * 1024)
                .await
                .expect("the session connects");
        let request = |answer: bool| {
            serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"answer": answer}})
                .to_string()
        };

        let response: serde_json::Value = serde_json::from_str(
            &session
                .send_request(request(true).as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response, serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": "response"}));

        let before = posts.load(Ordering::SeqCst);
        let batch = format!("[{}]", request(true));
        assert!(
            session
                .send_request(batch.as_bytes())
                .await
                .is_err()
        );
        assert_eq!(posts.load(Ordering::SeqCst), before, "a batch never goes upstream");

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(200),
                session.send_request(request(false).as_bytes())
            )
            .await
            .is_err(),
            "the upstream never answers"
        );
        assert!(
            session
                .inner
                .pending
                .lock()
                .await
                .is_empty(),
            "a dropped caller leaves no waiter"
        );
    }

    #[test]
    fn only_a_response_with_a_numeric_id_answers_a_waiter() {
        assert_eq!(upstream_response_id(&serde_json::json!({"id": 3, "result": {}})), Some(3));
        assert_eq!(upstream_response_id(&serde_json::json!({"id": 3, "error": {"code": -1}})), Some(3));
        for message in [
            serde_json::json!({"id": 3, "method": "ping"}),
            serde_json::json!({"id": 3, "method": "ping", "result": {}}),
            serde_json::json!({"id": "3", "result": {}}),
            serde_json::json!({"id": 3}),
            serde_json::json!([{"id": 3, "result": {}}]),
        ] {
            assert_eq!(upstream_response_id(&message), None, "{message}");
        }
    }

    #[test]
    fn test_is_sse_content_type() {
        assert!(is_sse_content_type("text/event-stream"));
        assert!(is_sse_content_type("text/event-stream; charset=utf-8"));
        assert!(!is_sse_content_type("application/json"));
        assert!(!is_sse_content_type("text/plain"));
    }

    #[test]
    fn test_parse_sse_event_with_data() {
        let raw = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        let _event = parse_sse_event(raw).unwrap();
        // SseEvent doesn't expose fields — we just verify it parses
        assert!(parse_sse_event(raw).is_some());
    }

    #[test]
    fn test_parse_sse_event_with_event_type() {
        let raw = "event: message\ndata: hello world";
        assert!(parse_sse_event(raw).is_some());
    }

    #[test]
    fn test_parse_sse_event_with_id() {
        let raw = "id: 42\ndata: test";
        assert!(parse_sse_event(raw).is_some());
    }

    #[test]
    fn test_parse_sse_event_multiline_data() {
        let raw = "data: line1\ndata: line2\ndata: line3";
        assert!(parse_sse_event(raw).is_some());
    }

    #[test]
    fn test_parse_sse_event_empty() {
        let raw = "";
        assert!(parse_sse_event(raw).is_none());
    }

    #[test]
    fn test_parse_sse_event_comment_only() {
        let raw = ": this is a comment";
        assert!(parse_sse_event(raw).is_none());
    }

    #[test]
    fn test_is_filtered_header() {
        assert!(is_filtered_header("transfer-encoding"));
        assert!(is_filtered_header("content-length"));
        assert!(is_filtered_header("content-type"));
        assert!(is_filtered_header("content-encoding"));
        assert!(is_filtered_header("connection"));
        assert!(is_filtered_header("keep-alive"));
        assert!(!is_filtered_header("x-custom-header"));
        assert!(!is_filtered_header("x-request-id"));
        assert!(!is_filtered_header("authorization"));
    }

    #[test]
    fn test_parse_sse_event_with_event_and_data() {
        let raw = "event: endpoint\ndata: /api/mcp/message";
        let event = parse_sse_event(raw);
        assert!(event.is_some());
    }

    #[test]
    fn test_parse_sse_event_retry_ignored() {
        let raw = "retry: 5000\ndata: reconnect";
        let event = parse_sse_event(raw);
        assert!(event.is_some());
    }

    #[test]
    fn test_resolve_session_post_url_relative_same_origin() {
        let url = resolve_session_post_url("/api/mcp/message", "http://mcp.example.com/sse")
            .expect("relative endpoint resolves to same origin");
        assert_eq!(url, "http://mcp.example.com/api/mcp/message");
    }

    #[test]
    fn test_resolve_session_post_url_absolute_same_origin_allowed() {
        let url = resolve_session_post_url("http://mcp.example.com/session?id=1", "http://mcp.example.com/sse")
            .expect("same-origin absolute endpoint is allowed");
        assert_eq!(url, "http://mcp.example.com/session?id=1");
    }

    #[test]
    fn test_resolve_session_post_url_cross_origin_rejected() {
        match resolve_session_post_url("http://169.254.169.254/latest/meta-data", "http://mcp.example.com/sse") {
            Err(msg) => assert!(msg.contains("different origin"), "unexpected error: {msg}"),
            Ok(url) => panic!("cross-origin endpoint must be rejected, got {url}"),
        }
    }

    #[test]
    fn test_parse_sse_event_json_rpc_response() {
        let raw = r#"data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather"}]}}"#;
        let event = parse_sse_event(raw);
        assert!(event.is_some());
    }

    #[test]
    fn test_parse_sse_event_json_rpc_error() {
        let raw = r#"data: {"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid request"}}"#;
        let event = parse_sse_event(raw);
        assert!(event.is_some());
    }

    #[test]
    fn test_is_sse_content_type_edge_cases() {
        assert!(!is_sse_content_type(""));
        assert!(!is_sse_content_type("text/html"));
        assert!(!is_sse_content_type("application/octet-stream"));
        assert!(is_sse_content_type("text/event-stream;charset=utf-8"));
    }
}
