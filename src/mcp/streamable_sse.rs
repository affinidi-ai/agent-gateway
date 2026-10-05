//! MCP Streamable HTTP — server→client SSE response surface.
//!
//! Per the MCP Streamable HTTP transport (spec rev 2025-03-26 onwards), the
//! server can push messages to the client over a long-lived SSE stream opened
//! by the client via `GET <route>` with `Accept: text/event-stream`. The
//! gateway uses this surface to write server-initiated JSON-RPC requests —
//! today specifically `elicitation/create` — onto the open connection while
//! upstream JSON-RPC responses are still wrapped synchronously in the POST
//! response (`text/event-stream` body).
//!
//! Design notes:
//!
//! - Sessions are keyed by `Mcp-Session-Id`, the same id the gateway mints
//!   on the `initialize` response (see `proxy::handler` SSE wrapping site).
//! - The registry stores a bounded `mpsc::Sender<sse::Event>` per session.
//!   Bounded to prevent a slow/stalled client from causing unbounded memory
//!   growth. If the buffer fills, new events are dropped and `send` returns
//!   false (same semantics as a disconnected client).
//! - When the GET stream ends (client disconnect / EOF / channel close), the
//!   `Sender` half is dropped automatically when the registry entry is
//!   removed via [`StreamableSessionRegistry::drop_session`]. Best practice:
//!   wire `drop_session` from the DELETE handler and from the GET stream's
//!   on-drop hook in a follow-up phase.

use axum::response::sse::Event;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender};

/// Maximum number of buffered SSE events per session. Prevents unbounded
/// memory growth from slow or stalled clients.
const SSE_CHANNEL_BUFFER: usize = 256;

/// Hard cap on concurrent SSE sessions to bound memory. Beyond this
/// limit, `register` returns `None` and the caller responds 429.
const MAX_SESSIONS: usize = 10_000;

#[derive(Debug, Default)]
pub struct StreamableSessionRegistry {
    inner: Mutex<HashMap<String, Sender<Result<Event, Infallible>>>>,
}

impl StreamableSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session. Returns the receiver half of the stream so the
    /// caller can wrap it in `axum::response::Sse` and return it to the
    /// client. If a previous sender existed under this id (reconnect), it
    /// is replaced and the old one is dropped — the old stream will see
    /// the channel close and end gracefully.
    pub async fn register(
        &self,
        session_id: &str,
    ) -> Option<Receiver<Result<Event, Infallible>>> {
        let mut guard = self.inner.lock().await;
        if !guard.contains_key(session_id) && guard.len() >= MAX_SESSIONS {
            return None;
        }
        let (tx, rx) = tokio::sync::mpsc::channel(SSE_CHANNEL_BUFFER);
        guard.insert(session_id.to_string(), tx);
        Some(rx)
    }

    /// Push an SSE event onto the named session's stream. Returns `false`
    /// if no session is registered or if the receiver has been dropped
    /// (client disconnected) — caller treats that as "client unreachable".
    pub async fn send(
        &self,
        session_id: &str,
        event: Event,
    ) -> bool {
        let tx_opt = self
            .inner
            .lock()
            .await
            .get(session_id)
            .cloned();
        let Some(tx) = tx_opt else {
            return false;
        };
        tx.try_send(Ok(event)).is_ok()
    }

    /// Drop the session — closes any in-flight receiver and removes the
    /// entry. Idempotent.
    pub async fn drop_session(
        &self,
        session_id: &str,
    ) {
        self.inner
            .lock()
            .await
            .remove(session_id);
    }

    /// Report whether the registry currently holds a live sender for this
    /// session. Used to decide between elicitation and fallback.
    pub async fn has_session(
        &self,
        session_id: &str,
    ) -> bool {
        self.inner
            .lock()
            .await
            .contains_key(session_id)
    }
}

pub type SharedStreamableSessionRegistry = Arc<StreamableSessionRegistry>;

static GLOBAL_STREAMABLE_SESSION_REGISTRY: std::sync::OnceLock<SharedStreamableSessionRegistry> =
    std::sync::OnceLock::new();

/// Process-wide Streamable-HTTP session registry, keyed by `Mcp-Session-Id`.
pub fn global_streamable_session_registry() -> &'static SharedStreamableSessionRegistry {
    GLOBAL_STREAMABLE_SESSION_REGISTRY.get_or_init(|| Arc::new(StreamableSessionRegistry::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_returns_independent_receiver_per_session() {
        let reg = StreamableSessionRegistry::new();
        let mut rx_a = reg
            .register("sess-a")
            .await
            .unwrap();
        let mut rx_b = reg
            .register("sess-b")
            .await
            .unwrap();

        assert!(
            reg.has_session("sess-a")
                .await
        );
        assert!(
            reg.has_session("sess-b")
                .await
        );

        assert!(
            reg.send("sess-a", Event::default().data("hello-a"))
                .await
        );
        assert!(
            reg.send("sess-b", Event::default().data("hello-b"))
                .await
        );

        let got_a = rx_a
            .recv()
            .await
            .unwrap()
            .unwrap();
        let got_b = rx_b
            .recv()
            .await
            .unwrap()
            .unwrap();
        // SSE event Display includes `data: ...\n`
        let s_a = format!("{:?}", got_a);
        let s_b = format!("{:?}", got_b);
        assert!(s_a.contains("hello-a"), "expected hello-a, got {s_a}");
        assert!(s_b.contains("hello-b"), "expected hello-b, got {s_b}");
    }

    #[tokio::test]
    async fn send_to_unknown_session_returns_false() {
        let reg = StreamableSessionRegistry::new();
        assert!(
            !reg.send("missing", Event::default().data("x"))
                .await
        );
    }

    #[tokio::test]
    async fn drop_session_closes_receiver() {
        let reg = StreamableSessionRegistry::new();
        let mut rx = reg
            .register("sess-z")
            .await
            .unwrap();
        reg.drop_session("sess-z")
            .await;
        // After drop, send returns false (no sender) and the receiver sees
        // channel closure.
        assert!(
            !reg.send("sess-z", Event::default().data("late"))
                .await
        );
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn re_register_replaces_previous_sender() {
        let reg = StreamableSessionRegistry::new();
        let mut rx_old = reg
            .register("sess-r")
            .await
            .unwrap();
        let mut rx_new = reg
            .register("sess-r")
            .await
            .unwrap();
        // Old receiver sees channel close because its sender was dropped.
        assert!(rx_old.recv().await.is_none());
        // New receiver still works.
        assert!(
            reg.send("sess-r", Event::default().data("fresh"))
                .await
        );
        assert!(rx_new.recv().await.is_some());
    }

    #[tokio::test]
    async fn global_registry_is_singleton() {
        let a = global_streamable_session_registry().clone();
        let b = global_streamable_session_registry().clone();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
