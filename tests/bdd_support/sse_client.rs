use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

/// Default per-frame read timeout. SSE frames are normally delivered in
/// milliseconds; anything larger than this is a hang we want to surface
/// rather than wait on indefinitely.
const SSE_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Parse a single SSE frame (the bytes up to but not including the
/// terminating `\n\n`) into its `event` name and concatenated `data`
/// payload. Multi-line `data:` values are joined with `\n` per the SSE
/// spec. Frames with neither `event:` nor `data:` (e.g., keep-alive
/// comment lines starting with `:`) yield `("".into(), "".into())`.
pub fn parse_sse_frame(frame: &str) -> (String, String) {
    let mut event_name = String::new();
    let mut data = String::new();
    for line in frame.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_name = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.trim());
        }
    }
    (event_name, data)
}

/// Read the byte stream until a frame whose `event:` line matches
/// `expected_event` is found. Returns the frame's concatenated `data`.
/// Frames that don't match are silently discarded (e.g., keep-alive
/// comments).
pub async fn read_named_event(
    stream: &mut BoxStream<'_, reqwest::Result<Bytes>>,
    buf: &mut String,
    expected_event: &str,
) -> Result<String> {
    loop {
        while let Some(idx) = buf.find("\n\n") {
            let frame = buf[..idx].to_string();
            let remainder = buf[idx + 2..].to_string();
            *buf = remainder;
            let (event_name, data) = parse_sse_frame(&frame);
            if event_name == expected_event {
                return Ok(data);
            }
        }
        let next = timeout(SSE_FRAME_READ_TIMEOUT, stream.next())
            .await
            .with_context(|| format!("timed out waiting for SSE '{expected_event}' event"))?;
        match next {
            Some(Ok(bytes)) => buf.push_str(&String::from_utf8_lossy(&bytes)),
            Some(Err(e)) => return Err(anyhow!("SSE stream error: {e}")),
            None => {
                return Err(anyhow!("SSE stream closed before '{expected_event}' event was received"));
            }
        }
    }
}

/// What a caller observed over one Legacy SSE session. The exchange stops at
/// the first step the gateway does not complete, so later fields stay empty.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LegacySseExchange {
    /// Status of the event stream (`GET {route}/sse`).
    pub stream_status: u16,
    pub stream_headers: HashMap<String, String>,
    /// The session message URL path announced by the `endpoint` event.
    pub endpoint_path: Option<String>,
    /// Status of each session POST, in order.
    pub post_statuses: Vec<u16>,
    /// The `message` event reply to each accepted POST, in order. A reply that
    /// is not JSON is kept as a JSON string.
    pub replies: Vec<Value>,
    /// Why the event stream ended before the expected event, if it did.
    pub stream_error: Option<String>,
}

impl LegacySseExchange {
    /// The status the caller saw: the first refused session POST, otherwise
    /// the event stream's.
    pub fn status(&self) -> u16 {
        self.post_statuses
            .iter()
            .copied()
            .find(|status| *status != reqwest::StatusCode::ACCEPTED.as_u16())
            .unwrap_or(self.stream_status)
    }
}

/// Open one Legacy SSE session (`GET {route}/sse`), then POST each of
/// `bodies` in order to the session URL from the `endpoint` event, reading
/// the `message` event that answers each. Only transport failures are errors;
/// everything the gateway answered is recorded in the exchange.
pub async fn legacy_sse_session(
    gateway_base: &str,
    route: &str,
    bodies: &[Value],
) -> Result<LegacySseExchange> {
    let client = reqwest::Client::new();
    let sse_url = format!("{gateway_base}{route}/sse");
    let sse_resp = client
        .get(&sse_url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .with_context(|| format!("GET {sse_url} failed"))?;
    let mut exchange = LegacySseExchange {
        stream_status: sse_resp.status().as_u16(),
        stream_headers: crate::bdd_support::http::collect_headers(sse_resp.headers()),
        ..LegacySseExchange::default()
    };
    if !sse_resp.status().is_success() {
        return Ok(exchange);
    }
    let mut stream: BoxStream<'static, _> = sse_resp
        .bytes_stream()
        .boxed();
    let mut buf = String::new();
    let endpoint_path = match read_named_event(&mut stream, &mut buf, "endpoint").await {
        Ok(path) => path,
        Err(error) => {
            exchange.stream_error = Some(error.to_string());
            return Ok(exchange);
        }
    };
    let post_url = format!("{gateway_base}{endpoint_path}");
    exchange.endpoint_path = Some(endpoint_path);

    for (i, body) in bodies.iter().enumerate() {
        let post_resp = client
            .post(&post_url)
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {post_url} failed on call {i}"))?;
        let post_status = post_resp.status();
        exchange
            .post_statuses
            .push(post_status.as_u16());
        if post_status != reqwest::StatusCode::ACCEPTED {
            break;
        }
        let message_data = match read_named_event(&mut stream, &mut buf, "message").await {
            Ok(data) => data,
            Err(error) => {
                exchange.stream_error = Some(error.to_string());
                break;
            }
        };
        exchange
            .replies
            .push(serde_json::from_str(&message_data).unwrap_or(Value::String(message_data)));
    }

    Ok(exchange)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::{BoxStream, Bytes, parse_sse_frame, read_named_event};
    #[allow(unused_imports)]
    use futures::StreamExt;

    #[test]
    fn parse_sse_frame_handles_event_and_data() {
        let (event, data) = parse_sse_frame("event: message\ndata: {\"a\":1}");
        assert_eq!(event, "message");
        assert_eq!(data, "{\"a\":1}");
    }

    #[test]
    fn parse_sse_frame_concatenates_multi_line_data() {
        let (event, data) = parse_sse_frame("event: chunk\ndata: line1\ndata: line2");
        assert_eq!(event, "chunk");
        assert_eq!(data, "line1\nline2");
    }

    #[test]
    fn parse_sse_frame_returns_empty_for_keepalive() {
        let (event, data) = parse_sse_frame(": keep-alive");
        assert_eq!(event, "");
        assert_eq!(data, "");
    }

    #[test]
    fn parse_sse_frame_handles_data_only_frame() {
        let (event, data) = parse_sse_frame("data: hello");
        assert_eq!(event, "");
        assert_eq!(data, "hello");
    }

    #[tokio::test]
    async fn read_named_event_skips_unrelated_frames() {
        use futures::stream;

        let chunks: Vec<reqwest::Result<Bytes>> = vec![
            Ok(Bytes::from("event: endpoint\ndata: /mcp/messages/?session_id=abc\n\n")),
            Ok(Bytes::from(": keep-alive\n\n")),
            Ok(Bytes::from("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")),
        ];
        let mut stream: BoxStream<'_, _> = stream::iter(chunks).boxed();
        let mut buf = String::new();

        let endpoint = read_named_event(&mut stream, &mut buf, "endpoint")
            .await
            .unwrap();
        assert_eq!(endpoint, "/mcp/messages/?session_id=abc");

        let message = read_named_event(&mut stream, &mut buf, "message")
            .await
            .unwrap();
        assert_eq!(message, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }

    #[test]
    fn legacy_sse_exchange_status_is_the_stream_status_when_every_post_is_accepted() {
        let exchange = super::LegacySseExchange {
            stream_status: 200,
            post_statuses: vec![202, 202],
            ..Default::default()
        };
        assert_eq!(exchange.status(), 200);
    }

    #[test]
    fn legacy_sse_exchange_status_is_the_first_refused_post() {
        let exchange = super::LegacySseExchange {
            stream_status: 200,
            post_statuses: vec![202, 404],
            ..Default::default()
        };
        assert_eq!(exchange.status(), 404);
    }

    #[test]
    fn legacy_sse_exchange_status_is_a_refused_stream() {
        let exchange = super::LegacySseExchange {
            stream_status: 403,
            ..Default::default()
        };
        assert_eq!(exchange.status(), 403);
    }

    #[tokio::test]
    async fn read_named_event_errors_when_stream_closes_without_match() {
        use futures::stream;

        let chunks: Vec<reqwest::Result<Bytes>> = vec![Ok(Bytes::from(": keep-alive\n\n"))];
        let mut stream: BoxStream<'_, _> = stream::iter(chunks).boxed();
        let mut buf = String::new();

        let err = read_named_event(&mut stream, &mut buf, "message")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("closed before"),
            "got: {err}"
        );
    }
}
