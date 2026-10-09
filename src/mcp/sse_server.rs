//! SSE Server transport for the gateway's built-in MCP proxy.
//!
//! When the gateway IS the MCP server (wrapping REST APIs via OpenAPI specs),
//! this module lets clients connect using:
//!
//! - **Legacy SSE (2024-11-05)**: `GET /sse` → `endpoint` event → POST to session URL
//! - **Streamable HTTP (2025-03-26)**: `POST /` with `Accept: text/event-stream`
//!
//! # Architecture
//!
//! ```text
//! Client                        Gateway (MCP proxy server)
//!   │                                    │
//!   │── GET /sse ──────────────────────► │ create session, return SSE stream
//!   │◄── event: endpoint ──────────────  │ send session POST URL
//!   │                                    │
//!   │── POST /mcp/messages?session_id=X ► │ process JSON-RPC, send response via SSE
//!   │◄── event: message ───────────────  │
//!   │                                    │
//!   │── POST / (Accept: text/event-stream) ► │ process JSON-RPC, return SSE response
//!   │◄── event: message ───────────────  │
//! ```

use axum::response::{
    Sse,
    sse::{Event as SseEvent, KeepAlive},
};
use futures::StreamExt;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info};
use uuid::Uuid;

/// Channel buffer size for SSE event delivery.
const SSE_CHANNEL_BUFFER: usize = 64;

/// Default idle timeout for SSE sessions (5 minutes).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// Cleanup interval for the background reaper task.
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// Hard cap on concurrent Legacy SSE sessions to bound memory. Beyond this
/// limit, `create_session` returns `None` and the caller responds 429.
const MAX_SESSIONS: usize = 10_000;

/// An active SSE session with a sender channel for pushing events.
struct SseSession {
    /// Sender end — used by POST handlers to push responses to the SSE stream.
    tx: mpsc::Sender<Result<SseEvent, Infallible>>,
    /// When the session was created.
    #[allow(dead_code)]
    created_at: Instant,
    /// Last time a request was processed on this session.
    last_active: Instant,
}

/// Manages SSE sessions for the MCP proxy server.
///
/// Thread-safe and Clone-able — shared across handlers via axum Extension.
#[derive(Clone)]
pub struct SseSessionManager {
    sessions: Arc<RwLock<HashMap<String, SseSession>>>,
    idle_timeout: Duration,
    max_sessions: usize,
}

impl SseSessionManager {
    /// Create a new session manager and spawn the background cleanup task.
    pub fn new(idle_timeout_secs: Option<u64>) -> Self {
        let idle_timeout = Duration::from_secs(idle_timeout_secs.unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS));
        let manager = Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            idle_timeout,
            max_sessions: MAX_SESSIONS,
        };

        // Spawn background reaper
        let cleanup_sessions = manager.sessions.clone();
        let cleanup_timeout = manager.idle_timeout;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let mut sessions = cleanup_sessions.write().await;
                let before = sessions.len();
                sessions.retain(|id, session| {
                    let alive = session.last_active.elapsed() < cleanup_timeout && !session.tx.is_closed();
                    if !alive {
                        debug!(session_id = %id, "Cleaning up idle/disconnected SSE session");
                    }
                    alive
                });
                let removed = before - sessions.len();
                if removed > 0 {
                    info!("Cleaned up {} idle SSE session(s), {} remaining", removed, sessions.len());
                }
            }
        });

        manager
    }

    /// Create a new SSE session.
    ///
    /// Returns `(session_id, receiver_stream)` — the receiver is used to build
    /// the axum SSE response; the session_id is communicated to the client via
    /// the `endpoint` event. Returns `None` when the session cap is reached
    /// even after dropping sessions whose client has disconnected.
    pub async fn create_session(&self) -> Option<(String, ReceiverStream<Result<SseEvent, Infallible>>)> {
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= self.max_sessions {
            sessions.retain(|_, session| !session.tx.is_closed());
            if sessions.len() >= self.max_sessions {
                return None;
            }
        }
        let session_id = Uuid::new_v4()
            .to_string()
            .replace('-', "");
        let (tx, rx) = mpsc::channel(SSE_CHANNEL_BUFFER);
        let now = Instant::now();

        sessions.insert(
            session_id.clone(),
            SseSession {
                tx,
                created_at: now,
                last_active: now,
            },
        );
        debug!(session_id = %session_id, "Created new SSE session");

        Some((session_id, ReceiverStream::new(rx)))
    }

    /// Send a JSON-RPC response to a session's SSE stream as a `message` event.
    ///
    /// Returns `false` if the session doesn't exist or the client disconnected.
    pub async fn send_response(
        &self,
        session_id: &str,
        json_body: &str,
    ) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_active = Instant::now();
            let event = SseEvent::default()
                .event("message")
                .data(json_body);
            if session
                .tx
                .send(Ok(event))
                .await
                .is_ok()
            {
                return true;
            }
            // Client disconnected — remove session
            debug!(session_id = %session_id, "Client disconnected, removing session");
            sessions.remove(session_id);
        }
        false
    }

    /// Check whether a session exists and is still alive.
    pub async fn session_exists(
        &self,
        session_id: &str,
    ) -> bool {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .is_some_and(|s| !s.tx.is_closed())
    }

    /// Remove a session (called when the SSE stream closes).
    #[allow(dead_code)]
    pub async fn remove_session(
        &self,
        session_id: &str,
    ) {
        if self
            .sessions
            .write()
            .await
            .remove(session_id)
            .is_some()
        {
            debug!(session_id = %session_id, "Removed SSE session");
        }
    }

    /// Return the number of active sessions (for diagnostics).
    #[allow(dead_code)]
    pub async fn session_count(&self) -> usize {
        self.sessions
            .read()
            .await
            .len()
    }
}

// ─── Handler helpers ─────────────────────────────────────────────────────────

/// Build the Legacy SSE response for `GET /sse`.
///
/// Creates a session, emits the `endpoint` event with the POST URL, then
/// keeps the stream open for response delivery.
///
/// `endpoint_base` is the base path the client should POST to, e.g.
/// `/mcp/eternal/dilemma`.  The function appends `/mcp/messages/?session_id=<id>`.
pub fn build_legacy_sse_response(
    session_id: String,
    rx_stream: ReceiverStream<Result<SseEvent, Infallible>>,
    endpoint_base: &str,
) -> axum::response::Response {
    let messages_path = format!("{}/mcp/messages/?session_id={}", endpoint_base.trim_end_matches('/'), session_id);

    // Prefix the stream with the endpoint event, then chain the session stream
    let endpoint_event: Result<SseEvent, Infallible> = Ok(SseEvent::default()
        .event("endpoint")
        .data(messages_path));
    let prefix = futures::stream::once(async move { endpoint_event });
    let combined = prefix.chain(rx_stream);

    let sse = Sse::new(combined).keep_alive(KeepAlive::default());
    axum::response::IntoResponse::into_response(sse)
}

/// Build a Streamable HTTP SSE response for a single JSON-RPC response.
///
/// This wraps a synchronous JSON-RPC response as a single SSE `message` event
/// followed by stream close.
pub fn build_streamable_http_response(json_body: &str) -> axum::response::Response {
    let event: Result<SseEvent, Infallible> = Ok(SseEvent::default()
        .event("message")
        .data(json_body));
    let stream = futures::stream::once(async move { event });
    let sse = Sse::new(stream);
    axum::response::IntoResponse::into_response(sse)
}

/// Wrap a JSON-RPC response body as a single SSE `message` event payload
/// suitable for use as the body of a Streamable-HTTP response.
///
/// The body must be a single line (no embedded `\n`); callers should re-encode
/// pretty-printed JSON to compact form first.
pub fn wrap_json_as_sse_event(json_body: &str) -> String {
    format!("event: message\ndata: {}\n\n", json_body)
}

/// Returns `true` if the Accept header indicates the client wants SSE.
pub fn client_wants_sse(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/event-stream"))
}

/// Extract `session_id` from query string like `?session_id=abc123`.
pub fn extract_session_id(query: Option<&str>) -> Option<String> {
    query.and_then(|q| {
        q.split('&').find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("session_id"), Some(id)) if !id.is_empty() => Some(id.to_string()),
                _ => None,
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_session_id() {
        assert_eq!(extract_session_id(Some("session_id=abc123")), Some("abc123".to_string()));
        assert_eq!(extract_session_id(Some("foo=bar&session_id=xyz&baz=1")), Some("xyz".to_string()));
        assert_eq!(extract_session_id(Some("foo=bar")), None);
        assert_eq!(extract_session_id(Some("session_id=")), None);
        assert_eq!(extract_session_id(None), None);
    }

    #[test]
    fn test_client_wants_sse() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "text/event-stream"
                .parse()
                .unwrap(),
        );
        assert!(client_wants_sse(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "text/event-stream, application/json"
                .parse()
                .unwrap(),
        );
        assert!(client_wants_sse(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/json"
                .parse()
                .unwrap(),
        );
        assert!(!client_wants_sse(&headers));

        let headers = HeaderMap::new();
        assert!(!client_wants_sse(&headers));
    }

    #[test]
    fn test_wrap_json_as_sse_event() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}"#;
        let wrapped = wrap_json_as_sse_event(body);
        assert_eq!(
            wrapped,
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}\n\n"
        );
        // SSE frame must end with double newline so clients can detect frame boundary.
        assert!(wrapped.ends_with("\n\n"));
        // The data: line must be a single line (no embedded newlines in the JSON body).
        let data_line_count = wrapped
            .matches("data: ")
            .count();
        assert_eq!(data_line_count, 1);
    }

    #[tokio::test]
    async fn create_session_refuses_beyond_the_cap_until_a_client_disconnects() {
        let manager = SseSessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            idle_timeout: Duration::from_secs(300),
            max_sessions: 2,
        };

        let (_, first) = manager
            .create_session()
            .await
            .unwrap();
        let (_, _second) = manager
            .create_session()
            .await
            .unwrap();
        assert!(
            manager
                .create_session()
                .await
                .is_none()
        );
        assert_eq!(manager.session_count().await, 2);

        drop(first);
        let (third, _third_rx) = manager
            .create_session()
            .await
            .unwrap();
        assert!(
            manager
                .session_exists(&third)
                .await
        );
        assert_eq!(manager.session_count().await, 2);
        assert!(
            manager
                .create_session()
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_session_lifecycle() {
        let manager = SseSessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            idle_timeout: Duration::from_secs(300),
            max_sessions: MAX_SESSIONS,
        };

        // Create session
        let (session_id, _rx) = manager
            .create_session()
            .await
            .unwrap();
        assert!(
            manager
                .session_exists(&session_id)
                .await
        );
        assert_eq!(manager.session_count().await, 1);

        // Send response
        let sent = manager
            .send_response(&session_id, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#)
            .await;
        assert!(sent);

        // Remove session
        manager
            .remove_session(&session_id)
            .await;
        assert!(
            !manager
                .session_exists(&session_id)
                .await
        );
        assert_eq!(manager.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_send_to_nonexistent_session() {
        let manager = SseSessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            idle_timeout: Duration::from_secs(300),
            max_sessions: MAX_SESSIONS,
        };

        let sent = manager
            .send_response("nonexistent", "{}")
            .await;
        assert!(!sent);
    }
}
