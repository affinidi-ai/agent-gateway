use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use serde_json::Value;
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

/// Open a Legacy-SSE connection to the gateway and return the SSE stream,
/// the per-session POST URL path (from the `endpoint` event), and the
/// response `Content-Type` header value.
///
/// The caller is responsible for driving the stream further (POSTing
/// requests and reading `message` events).
pub async fn open_legacy_sse_connection(
    gateway_base: &str,
    route: &str,
) -> Result<(BoxStream<'static, reqwest::Result<Bytes>>, String, String)> {
    let client = reqwest::Client::new();
    let sse_url = format!("{gateway_base}{route}/sse");
    let sse_resp = client
        .get(&sse_url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .with_context(|| format!("GET {sse_url} failed"))?;
    if !sse_resp.status().is_success() {
        return Err(anyhow!("SSE handshake returned non-2xx: {}", sse_resp.status()));
    }
    let content_type = sse_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut stream: BoxStream<'static, _> = sse_resp
        .bytes_stream()
        .boxed();
    let mut buf = String::new();
    let endpoint_path = read_named_event(&mut stream, &mut buf, "endpoint")
        .await
        .context("waiting for SSE endpoint event")?;
    Ok((stream, endpoint_path, content_type))
}

/// Drive a full Legacy-SSE MCP tool-call exchange against the gateway:
///
/// 1. `GET {gateway_base}{route}/sse` → read the `endpoint` event to
///    discover the per-session POST URL.
/// 2. `POST {gateway_base}{endpoint_path}` with `body` → expect `202`.
/// 3. Wait for the `message` event on the SSE stream and return its
///    parsed JSON-RPC payload.
pub async fn legacy_sse_tool_call(
    gateway_base: &str,
    route: &str,
    body: &Value,
) -> Result<Value> {
    let client = reqwest::Client::new();

    let sse_url = format!("{gateway_base}{route}/sse");
    let sse_resp = client
        .get(&sse_url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .with_context(|| format!("GET {sse_url} failed"))?;
    if !sse_resp.status().is_success() {
        return Err(anyhow!("SSE handshake returned non-2xx: {}", sse_resp.status()));
    }
    let mut stream: BoxStream<'_, _> = sse_resp
        .bytes_stream()
        .boxed();
    let mut buf = String::new();

    let endpoint_path = read_named_event(&mut stream, &mut buf, "endpoint")
        .await
        .context("waiting for SSE endpoint event")?;

    let post_url = format!("{gateway_base}{endpoint_path}");
    let post_resp = client
        .post(&post_url)
        .header("content-type", "application/json")
        .json(body)
        .send()
        .await
        .with_context(|| format!("POST {post_url} failed"))?;
    let post_status = post_resp.status();
    if post_status != reqwest::StatusCode::ACCEPTED {
        return Err(anyhow!("Legacy SSE session POST returned {} (expected 202 Accepted)", post_status));
    }

    let message_data = read_named_event(&mut stream, &mut buf, "message")
        .await
        .context("waiting for SSE message event")?;

    serde_json::from_str(&message_data).with_context(|| format!("SSE message data is not valid JSON: {message_data}"))
}

/// Open one Legacy-SSE session and send `count` identical JSON-RPC requests
/// over it, collecting a parsed `message` event reply for each one.
/// Each POST must return `202 Accepted`.
pub async fn legacy_sse_multi_call(
    gateway_base: &str,
    route: &str,
    body: &Value,
    count: usize,
) -> Result<Vec<Value>> {
    legacy_sse_session_calls(gateway_base, route, &vec![body.clone(); count]).await
}

/// Open one Legacy-SSE session and send each of `bodies` over it in order,
/// collecting a parsed `message` event reply for each one. Each POST must
/// return `202 Accepted`.
pub async fn legacy_sse_session_calls(
    gateway_base: &str,
    route: &str,
    bodies: &[Value],
) -> Result<Vec<Value>> {
    let client = reqwest::Client::new();
    let sse_url = format!("{gateway_base}{route}/sse");
    let sse_resp = client
        .get(&sse_url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .with_context(|| format!("GET {sse_url} failed"))?;
    if !sse_resp.status().is_success() {
        return Err(anyhow!("SSE handshake returned non-2xx: {}", sse_resp.status()));
    }
    let mut stream: BoxStream<'static, _> = sse_resp
        .bytes_stream()
        .boxed();
    let mut buf = String::new();

    let endpoint_path = read_named_event(&mut stream, &mut buf, "endpoint")
        .await
        .context("waiting for SSE endpoint event")?;

    let post_url = format!("{gateway_base}{endpoint_path}");
    let mut results = Vec::with_capacity(bodies.len());

    for (i, body) in bodies.iter().enumerate() {
        let post_resp = client
            .post(&post_url)
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {post_url} failed on call {i}"))?;
        let post_status = post_resp.status();
        if post_status != reqwest::StatusCode::ACCEPTED {
            return Err(anyhow!("Legacy SSE session POST (call {i}) returned {} (expected 202 Accepted)", post_status));
        }
        let message_data = read_named_event(&mut stream, &mut buf, "message")
            .await
            .with_context(|| format!("waiting for SSE message event on call {i}"))?;
        let parsed: Value = serde_json::from_str(&message_data)
            .with_context(|| format!("SSE message data (call {i}) is not valid JSON: {message_data}"))?;
        results.push(parsed);
    }

    Ok(results)
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
