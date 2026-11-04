//! Held funds for a response whose body streams: the first byte is not delayed,
//! the funds are captured once a JSON-RPC result (any body bytes, for a protocol
//! without JSON-RPC) is passed on to the client, or once the stream completes
//! without a JSON-RPC error, and voided when the upstream stream fails or the
//! client goes away before either.

use std::sync::Arc;

use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use serde_json::json;

use super::{Authorization, ChannelProtocol, MAX_RECEIPT_BODY_BYTES, Receipt};

/// The event type of the final event an event stream carries the capture
/// receipt in. Clients reading only `message` events skip it.
pub(super) const RECEIPT_EVENT: &str = "payment-receipt";

/// Tells from the bytes of a streamed body whether it carried a JSON-RPC error,
/// and whether it has passed a result on.
struct Judge {
    rpc: bool,
    events: bool,
    pending: Vec<u8>,
    /// More than [`MAX_RECEIPT_BODY_BYTES`] of one event line or JSON body: the
    /// body is judged by its status alone.
    overflowed: bool,
    failed: bool,
    result_relayed: bool,
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
            result_relayed: false,
        }
    }

    fn observe(
        &mut self,
        chunk: &[u8],
    ) {
        if !self.rpc {
            self.result_relayed |= !chunk.is_empty();
            return;
        }
        if self.overflowed || self.failed {
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
                self.result_relayed |= carries_result(&line);
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

/// Whether an event stream line carries a JSON-RPC result.
fn carries_result(line: &[u8]) -> bool {
    let Some(data) = std::str::from_utf8(line)
        .ok()
        .and_then(|line| line.strip_prefix("data:"))
    else {
        return false;
    };
    let is_result = |message: &serde_json::Value| {
        message
            .get("result")
            .is_some_and(|result| !result.is_null())
    };
    match serde_json::from_str::<serde_json::Value>(data.trim()) {
        Ok(serde_json::Value::Array(batch)) => batch.iter().any(is_result),
        Ok(message) => is_result(&message),
        Err(_) => false,
    }
}

/// Voids the held funds when the stream is dropped before it completed, unless
/// a result was already passed on.
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
                let relayed = state.judge.result_relayed;
                state.judge.observe(&chunk);
                if !relayed
                    && state.judge.result_relayed
                    && let Some(authorization) = state.guard.0.as_ref()
                {
                    let action = authorization.decide(true);
                    authorization.spawn_settle(&tokio::runtime::Handle::current(), action);
                }
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
    fn judge_marks_a_result_relayed_only_once_a_whole_result_line_passed() {
        let mut judge = Judge::new(&ChannelProtocol::Mcp, "text/event-stream");
        judge.observe(b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n");
        assert!(!judge.result_relayed, "a notification is not a result");
        judge.observe(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"res");
        assert!(!judge.result_relayed, "half a result is not passed on");
        judge.observe(b"ult\":{}}\n\n");
        assert!(judge.result_relayed);

        let mut errored = Judge::new(&ChannelProtocol::Mcp, "text/event-stream");
        errored.observe(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-1}}\n\n");
        errored.observe(b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n");
        assert!(!errored.result_relayed, "nothing is captured after an error");

        let mut json = Judge::new(&ChannelProtocol::A2a, "application/json");
        json.observe(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        assert!(!json.result_relayed, "a JSON body is judged at its end");
    }

    #[test]
    fn judge_marks_any_body_bytes_relayed_without_json_rpc() {
        let mut judge = Judge::new(&ChannelProtocol::DIDComm, "application/octet-stream");
        judge.observe(b"");
        assert!(!judge.result_relayed);
        judge.observe(b"x");
        assert!(judge.result_relayed);
    }

    #[test]
    fn judge_ignores_bodies_of_non_json_rpc_protocols() {
        let mut judge = Judge::new(&ChannelProtocol::DIDComm, "text/event-stream");
        judge.observe(b"data: {\"error\":{\"code\":-1}}\n\n");
        assert!(judge.delivered());
    }
}
