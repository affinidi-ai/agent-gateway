//! Held funds for a response whose body streams: the first byte is not delayed,
//! the funds are captured once the stream completes without a JSON-RPC error and
//! voided when the upstream stream fails or the client goes away first.

use std::sync::Arc;

use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use serde_json::json;

use super::{Authorization, ChannelProtocol, MAX_RECEIPT_BODY_BYTES, Receipt};

/// The event type of the final event an event stream carries the capture
/// receipt in. Clients reading only `message` events skip it.
pub(super) const RECEIPT_EVENT: &str = "payment-receipt";

/// Tells from the bytes of a streamed body whether it carried a JSON-RPC error.
struct Judge {
    rpc: bool,
    events: bool,
    pending: Vec<u8>,
    /// More than [`MAX_RECEIPT_BODY_BYTES`] of one event line or JSON body: the
    /// body is judged by its status alone.
    overflowed: bool,
    failed: bool,
}

impl Judge {
    fn new(
        protocol: &ChannelProtocol,
        content_type: &str,
    ) -> Self {
        Self {
            rpc: matches!(protocol, ChannelProtocol::Mcp | ChannelProtocol::A2a | ChannelProtocol::Ap2),
            events: content_type.starts_with("text/event-stream"),
            pending: Vec::new(),
            overflowed: false,
            failed: false,
        }
    }

    fn observe(
        &mut self,
        chunk: &[u8],
    ) {
        if !self.rpc || self.overflowed || self.failed {
            return;
        }
        self.pending
            .extend_from_slice(chunk);
        if self.events {
            while let Some(end) = self
                .pending
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let line: Vec<u8> = self
                    .pending
                    .drain(..=end)
                    .collect();
                if !super::delivered(&ChannelProtocol::Mcp, axum::http::StatusCode::OK, Some(&line)) {
                    self.failed = true;
                    return;
                }
            }
        }
        if self.pending.len() > MAX_RECEIPT_BODY_BYTES {
            self.overflowed = true;
            self.pending = Vec::new();
        }
    }

    /// Whether the completed body was delivered.
    fn delivered(&mut self) -> bool {
        if self.failed {
            return false;
        }
        if !self.rpc || self.overflowed || self.pending.is_empty() {
            return true;
        }
        let rest = std::mem::take(&mut self.pending);
        super::delivered(&ChannelProtocol::Mcp, axum::http::StatusCode::OK, Some(&rest))
    }
}

/// Voids the held funds when the stream is dropped before it completed.
struct Unfinished(Option<Arc<Authorization>>);

impl Unfinished {
    fn take(&mut self) -> Option<Arc<Authorization>> {
        self.0.take()
    }
}

impl Drop for Unfinished {
    fn drop(&mut self) {
        let Some(authorization) = self.0.take() else {
            return;
        };
        let action = authorization.decide(false);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            authorization.spawn_settle(&runtime, action);
        }
    }
}

struct State {
    upstream: axum::body::BodyDataStream,
    judge: Judge,
    receipt: Receipt,
    guard: Unfinished,
    finished: bool,
}

/// The final event of an event stream carrying `receipt`.
pub(super) fn receipt_event(
    receipt: &Receipt,
    authorization_id: &str,
) -> Bytes {
    let data = json!({
        "rail": receipt.rail.as_str(),
        "receipt": receipt.value,
        "authorization_id": authorization_id,
    });
    Bytes::from(format!("event: {RECEIPT_EVENT}\ndata: {data}\n\n"))
}

/// `response` with a body that settles `authorization` when it completes. The
/// response carries `receipt`'s headers, which name the authorization.
pub(super) fn settle_when_streamed(
    receipt: &Receipt,
    authorization: Arc<Authorization>,
    protocol: &ChannelProtocol,
    response: Response,
) -> Response {
    let (mut parts, body) = response.into_parts();
    receipt.apply(&mut parts.headers);
    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let state = State {
        upstream: body.into_data_stream(),
        judge: Judge::new(protocol, &content_type),
        receipt: receipt.clone(),
        guard: Unfinished(Some(authorization)),
        finished: false,
    };
    let stream = futures::stream::unfold(state, |mut state| async move {
        if state.finished {
            return None;
        }
        match state.upstream.next().await {
            Some(Ok(chunk)) => {
                state.judge.observe(&chunk);
                Some((Ok::<Bytes, axum::Error>(chunk), state))
            }
            Some(Err(error)) => {
                state.finished = true;
                if let Some(authorization) = state.guard.take() {
                    authorization
                        .settle(false)
                        .await;
                }
                Some((Err(error), state))
            }
            None => {
                state.finished = true;
                let delivered = state.judge.delivered();
                let authorization = state.guard.take()?;
                let (action, settled) = authorization
                    .settle(delivered)
                    .await;
                let captured = action == crate::payments_ledger::SettleAction::Capture
                    && settled.outcome != crate::payments_ledger::LedgerOutcome::Voided;
                if !(captured && state.judge.events) {
                    return None;
                }
                let mut receipt = state.receipt.clone();
                if let Some(value) = settled
                    .receipt
                    .as_deref()
                    .and_then(Receipt::header_value)
                {
                    receipt.value = value;
                }
                let event = receipt_event(
                    &receipt,
                    &authorization
                        .held
                        .authorization_id,
                );
                Some((Ok(event), state))
            }
        }
    });
    Response::from_parts(parts, axum::body::Body::from_stream(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judge_fails_an_event_stream_with_a_json_rpc_error_split_across_chunks() {
        let mut judge = Judge::new(&ChannelProtocol::Mcp, "text/event-stream");
        judge.observe(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"err");
        judge.observe(b"or\":{\"code\":-1,\"message\":\"x\"}}\n\n");
        assert!(!judge.delivered());
    }

    #[test]
    fn judge_passes_an_event_stream_of_results() {
        let mut judge = Judge::new(&ChannelProtocol::Mcp, "text/event-stream");
        judge.observe(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n");
        assert!(judge.delivered());
    }

    #[test]
    fn judge_reads_a_streamed_json_body_at_its_end() {
        let mut failed = Judge::new(&ChannelProtocol::A2a, "application/json");
        failed.observe(b"{\"jsonrpc\":\"2.0\",\"id\":1,");
        failed.observe(b"\"error\":{\"code\":-1}}");
        assert!(!failed.delivered());
        let mut ok = Judge::new(&ChannelProtocol::A2a, "application/json");
        ok.observe(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        assert!(ok.delivered());
    }

    #[test]
    fn judge_ignores_bodies_of_non_json_rpc_protocols() {
        let mut judge = Judge::new(&ChannelProtocol::DIDComm, "text/event-stream");
        judge.observe(b"data: {\"error\":{\"code\":-1}}\n\n");
        assert!(judge.delivered());
    }
}
