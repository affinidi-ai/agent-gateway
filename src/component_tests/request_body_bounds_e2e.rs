//! Request body bounds on the public inbound port — end-to-end.
//!
//! The harness's inbound and outbound listeners share the `localhost` host
//! name, so the inbound listener forwards `/outbound/*` to the outbound
//! listener. That hop streams the request under `a2a.max_body_size` and
//! streams the response back, so the outbound listener authenticates a caller
//! before reading its body and a stream it allows is not cut at the hop.
//! Transit Points without `mcp_http`, Access Points and DID Auth read under a
//! cap too, and answer 413 past it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::helpers::{self, GatewayHarness, MockServer};
use crate::config::agent_surface::AgentSurface;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: usize = 64 * 1024;
const CHUNK: usize = 1024;
const ANSWER_BUDGET: Duration = Duration::from_secs(15);

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

fn shared_host_url(harness: &GatewayHarness) -> String {
    format!("{}/outbound/smoke/target/rpc", harness.gateway_base)
}

fn outbound_port_url(harness: &GatewayHarness) -> String {
    format!(
        "{}/outbound/smoke/target/rpc",
        harness
            .outbound_url
            .as_ref()
            .unwrap()
    )
}

/// A JSON-RPC request padded to exactly `length` bytes.
fn jsonrpc_of_length(
    method: &str,
    length: usize,
) -> String {
    let envelope =
        json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": {"name": "echo", "pad": ""}}).to_string();
    let padded = envelope.replace(r#""pad":"""#, &format!(r#""pad":"{}""#, "x".repeat(length - envelope.len())));
    assert_eq!(padded.len(), length);
    padded
}

/// An endless body of `CHUNK`-byte chunks that counts every byte handed to the
/// connection.
fn endless_counted_body(sent: Arc<AtomicUsize>) -> reqwest::Body {
    reqwest::Body::wrap_stream(futures::stream::repeat_with(move || {
        sent.fetch_add(CHUNK, Ordering::SeqCst);
        Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b' '; CHUNK]))
    }))
}

/// What loopback socket buffers can hold between the caller and the listener
/// the shared-host hop forwards to, beyond what the gateway reads: two
/// connections, each with a send and a receive buffer at the largest size the
/// kernel autotunes them to. On Linux that is the third field of
/// `net.ipv4.tcp_wmem` and `net.ipv4.tcp_rmem`; elsewhere their Linux
/// defaults, 4 MiB and 6 MiB, which exceed the macOS ones. The gateway's own
/// reads are bounded exactly by the in-process hop and Access Point tests.
fn loopback_buffer_allowance() -> usize {
    let largest = |path: &str, default: usize| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|sizes| {
                sizes
                    .split_whitespace()
                    .nth(2)?
                    .parse()
                    .ok()
            })
            .unwrap_or(default)
    };
    2 * (largest("/proc/sys/net/ipv4/tcp_wmem", 4 * 1024 * 1024)
        + largest("/proc/sys/net/ipv4/tcp_rmem", 6 * 1024 * 1024))
}

/// The bytes the caller handed to its connection once the count stops
/// growing, polled every 200 ms; fails when it still grows after
/// `ANSWER_BUDGET`.
async fn settled(sent: &AtomicUsize) -> usize {
    let deadline = Instant::now() + ANSWER_BUDGET;
    let mut last = sent.load(Ordering::SeqCst);
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let now = sent.load(Ordering::SeqCst);
        if now == last {
            return now;
        }
        assert!(Instant::now() < deadline, "the gateway kept reading the refused body: {now} bytes sent");
        last = now;
    }
}

/// Sends headers declaring a `Content-Length` of `length` and holds the body
/// back, so an answer given before reading it always reaches the caller.
async fn send_declared_length(
    url: &str,
    headers: &[(&str, &str)],
    length: usize,
) -> (reqwest::StatusCode, String) {
    let mut request = client()
        .post(url)
        .header("content-type", "application/json")
        .header("content-length", length);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let held_back = futures::stream::pending::<Result<bytes::Bytes, std::io::Error>>();
    let response = tokio::time::timeout(
        ANSWER_BUDGET,
        request
            .body(reqwest::Body::wrap_stream(held_back))
            .send(),
    )
    .await
    .expect("a declared length over the limit must be answered before the body is sent")
    .expect("the answer must reach the caller");
    let status = response.status();
    (
        status,
        response
            .text()
            .await
            .unwrap_or_default(),
    )
}

/// Sends an endless body and returns the status the gateway answered with, or
/// `None` when it closed the connection instead.
async fn send_endless_body(
    url: &str,
    headers: &[(&str, &str)],
    sent: Arc<AtomicUsize>,
) -> Option<(reqwest::StatusCode, String)> {
    let mut request = client()
        .post(url)
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = tokio::time::timeout(
        ANSWER_BUDGET,
        request
            .body(endless_counted_body(sent))
            .send(),
    )
    .await
    .expect("the gateway must answer or close instead of reading an endless body");
    match response {
        Ok(response) => {
            let status = response.status();
            Some((
                status,
                response
                    .text()
                    .await
                    .unwrap_or_default(),
            ))
        }
        Err(_) => None,
    }
}

/// Writes `request` on a raw connection and returns the status line and body
/// of the answer.
async fn raw_exchange(
    base: &str,
    request: String,
) -> (u16, String) {
    let address = base.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .unwrap();
    stream
        .write_all(request.as_bytes())
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(ANSWER_BUDGET, stream.read_to_end(&mut answer)).await;
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let status = answer
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP answer: {answer:?}"));
    (status, answer)
}

/// A chunked request whose second chunk size is not hexadecimal.
fn malformed_chunked_request(path: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n{{\"a\":\r\nzz\r\n"
    )
}

fn mcp_transit_surface(mcp_http: Option<serde_json::Value>) -> AgentSurface {
    let mut point = json!({
        "alias": "target",
        "target_endpoint": "outbound_target_placeholder",
        "gateway_url": "outbound_gateway_url_placeholder",
        "protocol": "mcp",
        "require_transit_token": false,
        "allow_unauthenticated_callers": true
    });
    if let Some(mcp_http) = mcp_http {
        point["mcp_http"] = mcp_http;
    }
    serde_json::from_value(json!({
        "name": "smoke-mcp-outbound",
        "access_point": {"listen_address": "inbound_port_placeholder", "route": "/smoke", "protocol": "mcp"},
        "target": {"endpoint": "inbound_target_placeholder"},
        "transit": {"outbound_listen_address": "outbound_port_placeholder", "points": [point]}
    }))
    .unwrap()
}

fn tokened_transit_surface() -> AgentSurface {
    let mut surface = helpers::build_minimal_outbound_channel();
    let point = &mut surface
        .transit
        .as_mut()
        .unwrap()
        .points[0];
    point.require_transit_token = true;
    point.allow_unauthenticated_callers = false;
    surface
}

async fn start_with_transit_surface(
    mock: MockServer,
    max_body_size: usize,
    surface: AgentSurface,
) -> GatewayHarness {
    GatewayHarness::start_with_outbound_mock(mock, move |_, config, _| {
        config.a2a.max_body_size = max_body_size;
        config.surfaces = vec![surface];
    })
    .await
}

async fn post(
    url: &str,
    headers: &[(&str, &str)],
    body: String,
) -> (reqwest::StatusCode, Option<String>, String) {
    let mut request = client()
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .to_string()
        });
    (status, content_type, response.text().await.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shared_host_answers_a_transit_point_call_like_the_outbound_port() {
    for (case, surface, method) in [
        ("a2a", helpers::build_minimal_outbound_channel(), "message/send"),
        ("mcp", mcp_transit_surface(None), "tools/call"),
    ] {
        let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#).await;
        let harness = start_with_transit_surface(mock, LIMIT, surface).await;
        let body = jsonrpc_of_length(method, LIMIT / 2);

        let direct = post(&outbound_port_url(&harness), &[], body.clone()).await;
        let hop = post(&shared_host_url(&harness), &[], body).await;

        assert_eq!(direct.0, 200, "{case}: {}", direct.2);
        assert_eq!(hop, direct, "{case}");
        assert_eq!(
            harness
                .mock
                .request_count
                .load(Ordering::SeqCst),
            2,
            "{case}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shared_host_refuses_a_declared_oversize_body_before_the_outbound_listener() {
    let tokened = start_with_transit_surface(MockServer::start().await, LIMIT, tokened_transit_surface()).await;

    let (status, body) = send_declared_length(&shared_host_url(&tokened), &[], LIMIT + 1).await;
    assert_eq!(status, 413, "only the hop answers a caller without a transit token with 413: {body}");
    assert!(body.contains(&format!("Request body too large (max: {LIMIT})")), "{body}");
    let (status, body) = send_declared_length(&shared_host_url(&tokened), &[], LIMIT).await;
    assert_eq!(status, 401, "a declared length at the limit reaches the Transit Point: {body}");
    assert!(body.contains("Transit token missing or invalid"), "{body}");

    let harness =
        start_with_transit_surface(MockServer::start().await, LIMIT, helpers::build_minimal_outbound_channel()).await;
    let (status, body) = send_declared_length(&shared_host_url(&harness), &[], LIMIT + 1).await;
    assert_eq!(status, 413, "{body}");
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let (status, _, body) = post(&shared_host_url(&harness), &[], jsonrpc_of_length("message/send", LIMIT)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        harness
            .mock
            .last_request_rx
            .borrow()
            .as_ref()
            .unwrap()
            .body
            .len(),
        LIMIT
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shared_host_refuses_an_endless_body_from_a_caller_without_a_transit_token() {
    let harness = start_with_transit_surface(
        MockServer::start().await,
        crate::config::A2aConfig::default().max_body_size,
        tokened_transit_surface(),
    )
    .await;
    let sent = Arc::new(AtomicUsize::new(0));

    let answer = send_endless_body(&shared_host_url(&harness), &[], sent.clone()).await;

    // The outbound listener closes on the unread body, and the reset can reach
    // the hop before its 401 does.
    if let Some((status, body)) = answer {
        assert!([401, 502].contains(&status.as_u16()), "{status}: {body}");
    }
    let sent = settled(&sent).await;
    assert!(
        sent <= loopback_buffer_allowance(),
        "sent {sent} bytes, more than the loopback socket buffers on the way to the listener hold"
    );
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let (status, _, body) =
        post(&shared_host_url(&harness), &[("x-transit-token", "not-a-token")], jsonrpc_of_length("message/send", 256))
            .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shared_host_refuses_an_endless_body_past_the_limit() {
    let harness =
        start_with_transit_surface(MockServer::start().await, LIMIT, helpers::build_minimal_outbound_channel()).await;
    let sent = Arc::new(AtomicUsize::new(0));

    let answer = send_endless_body(&shared_host_url(&harness), &[], sent.clone()).await;

    if let Some((status, body)) = answer {
        assert_eq!(status, 413, "{body}");
        assert!(body.contains("Request body too large"), "{body}");
    }
    let sent = settled(&sent).await;
    assert!(
        sent <= LIMIT + crate::proxy::server::SHARED_HOST_HOP_STREAM_MARGIN + loopback_buffer_allowance(),
        "sent {sent} bytes, more than the hop's limit and margin plus what loopback socket buffers hold"
    );
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_the_caller_breaks_is_refused_with_400_and_never_forwarded() {
    let harness =
        start_with_transit_surface(MockServer::start().await, LIMIT, helpers::build_minimal_outbound_channel()).await;

    for base in [
        harness.gateway_base.clone(),
        harness
            .outbound_url
            .clone()
            .unwrap(),
    ] {
        let (status, answer) = raw_exchange(&base, malformed_chunked_request("/outbound/smoke/target/rpc")).await;
        assert_eq!(status, 400, "{base}: {answer}");
        assert!(answer.contains("Failed to read request body"), "{base}: {answer}");
    }
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shared_host_streams_a_transit_point_event_stream_past_the_request_timeout() {
    let progress = |n: u32| {
        let event = json!({"jsonrpc": "2.0", "method": "notifications/progress",
            "params": {"progressToken": "work", "progress": n}});
        format!("event: message\ndata: {event}\n\n")
    };
    let result = json!({"jsonrpc": "2.0", "id": "stream", "result": {"resultType": "complete", "content": []}});
    let mock = MockServer::start_with_finished_stream(
        "text/event-stream",
        vec![
            (Duration::ZERO, progress(1)),
            (Duration::from_millis(1500), progress(2)),
            (Duration::from_millis(1500), progress(3)),
            (Duration::from_millis(1000), format!("event: message\ndata: {result}\n\n")),
        ],
    )
    .await;
    let harness = GatewayHarness::start_with_outbound_mock(mock, |_, config, _| {
        config.a2a.timeout_seconds = 2;
        config.surfaces = vec![mcp_transit_surface(None)];
    })
    .await;
    let body = json!({"jsonrpc": "2.0", "id": "stream", "method": "tools/call", "params": {
        "name": "echo", "arguments": {}, "_meta": {
            "progressToken": "work",
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    }});
    let started = Instant::now();

    let mut response = client()
        .post(shared_host_url(&harness))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
        .header("mcp-method", "tools/call")
        .header("mcp-name", "echo")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut received = String::new();
    let mut first_event_after = None;
    while let Some(chunk) = tokio::time::timeout(ANSWER_BUDGET, response.chunk())
        .await
        .expect("the stream must keep delivering")
        .unwrap()
    {
        received.push_str(&String::from_utf8_lossy(&chunk));
        if first_event_after.is_none() && received.contains("notifications/progress") {
            first_event_after = Some(started.elapsed());
        }
    }

    let first_event_after = first_event_after.expect("no progress event arrived");
    assert!(first_event_after < Duration::from_millis(1500), "first event after {first_event_after:?}");
    assert!(received.contains(r#""progress":3"#), "{received}");
    assert!(received.contains(r#""resultType":"complete""#), "{received}");
    assert!(started.elapsed() > Duration::from_secs(3), "stream ended after {:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_without_mcp_http_answers_413_over_the_limit() {
    let harness =
        start_with_transit_surface(MockServer::start().await, LIMIT, helpers::build_minimal_outbound_channel()).await;
    let sent = Arc::new(AtomicUsize::new(0));

    let answer = send_endless_body(&outbound_port_url(&harness), &[], sent.clone()).await;
    if let Some((status, body)) = answer {
        assert_eq!(status, 413, "{body}");
    }
    let sent = settled(&sent).await;
    assert!(
        sent <= LIMIT + loopback_buffer_allowance(),
        "sent {sent} bytes, more than the limit plus what loopback socket buffers hold"
    );
    let (status, _, body) = post(&outbound_port_url(&harness), &[], jsonrpc_of_length("message/send", LIMIT + 1)).await;
    assert_eq!(status, 413, "{body}");
    assert!(body.contains(&format!("Request body too large (max: {LIMIT})")), "{body}");
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let (status, _, body) = post(&outbound_port_url(&harness), &[], jsonrpc_of_length("message/send", LIMIT)).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_mcp_transit_point_keeps_a_request_limit_above_the_appliance_cap() {
    const MIB: usize = 1024 * 1024;
    let mock = MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#).await;
    let harness = start_with_transit_surface(
        mock,
        crate::config::A2aConfig::default().max_body_size,
        mcp_transit_surface(Some(json!({"max_request_bytes": 12 * MIB}))),
    )
    .await;
    assert_eq!(crate::config::A2aConfig::default().max_body_size, 10 * MIB);

    let (status, _, body) = post(&outbound_port_url(&harness), &[], jsonrpc_of_length("tools/call", 11 * MIB)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        harness
            .mock
            .last_request_rx
            .borrow()
            .as_ref()
            .unwrap()
            .body
            .len(),
        11 * MIB
    );

    let (status, _, body) =
        post(&outbound_port_url(&harness), &[], jsonrpc_of_length("tools/call", 12 * MIB + 1)).await;
    assert_eq!(status, 413, "{body}");

    let (status, body) = send_declared_length(
        &shared_host_url(&harness),
        &[("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)],
        11 * MIB,
    )
    .await;
    assert_eq!(status, 413, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(body.get("id").is_none(), "{body}");
    assert_eq!(body["error"]["message"], "MCP request body exceeds the configured limit");
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        1
    );
}

/// Through the shared host, a 2 MiB body to an MCP Transit Point with the
/// default `mcp_http` (1 MiB), declared or chunked, is refused by the Transit
/// Point and never forwarded. The caller gets its JSON-RPC 413, or a 502 or a
/// closed connection when the reset of the unread body overtakes that answer.
#[tokio::test(flavor = "multi_thread")]
async fn an_mcp_transit_point_with_the_default_limit_refuses_a_larger_body_through_the_shared_host() {
    const BODY: usize = 2 * 1024 * 1024;
    let harness = start_with_transit_surface(
        MockServer::start().await,
        crate::config::A2aConfig::default().max_body_size,
        mcp_transit_surface(None),
    )
    .await;

    for declared in [true, false] {
        let body = jsonrpc_of_length("tools/call", BODY);
        let body = if declared {
            reqwest::Body::from(body)
        } else {
            let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = body
                .into_bytes()
                .chunks(64 * 1024)
                .map(|chunk| Ok(bytes::Bytes::copy_from_slice(chunk)))
                .collect();
            reqwest::Body::wrap_stream(futures::stream::iter(chunks))
        };
        let answer = client()
            .post(shared_host_url(&harness))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
            .body(body)
            .send()
            .await;

        if let Ok(response) = answer {
            let status = response.status();
            let text = response
                .text()
                .await
                .unwrap_or_default();
            match status.as_u16() {
                413 => {
                    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(body["error"]["message"], "MCP request body exceeds the configured limit");
                }
                502 => {}
                other => panic!("declared: {declared}: unexpected {other}: {text}"),
            }
        }
    }
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_access_point_refuses_an_endless_body_from_a_caller_without_a_credential() {
    let harness = GatewayHarness::start(|_, config, _| {
        config.a2a.max_body_size = LIMIT;
        config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;
    let sent = Arc::new(AtomicUsize::new(0));

    let answer = send_endless_body(&harness.gateway_url, &[], sent.clone()).await;

    if let Some((status, body)) = answer {
        assert_eq!(status, 413, "{body}");
    }
    let sent = settled(&sent).await;
    assert!(
        sent <= LIMIT + loopback_buffer_allowance(),
        "sent {sent} bytes, more than the limit plus what loopback socket buffers hold"
    );
    let (status, _, body) = post(&harness.gateway_url, &[], jsonrpc_of_length("message/send", LIMIT + 1)).await;
    assert_eq!(status, 413, "{body}");
    assert!(body.contains(&format!("Request body too large (max: {LIMIT})")), "{body}");
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let (status, _, body) = post(&harness.gateway_url, &[], jsonrpc_of_length("message/send", LIMIT)).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fabric_access_point_refuses_a_body_over_the_limit() {
    let harness = GatewayHarness::start(|_, config, _| {
        config.a2a.max_body_size = LIMIT;
        let mut surface = helpers::build_minimal_channel();
        surface.target.endpoint = "fabric://peer-gateway/peer-surface".to_string();
        config.surfaces = vec![surface];
    })
    .await;

    let (status, _, body) = post(&harness.gateway_url, &[], jsonrpc_of_length("message/send", LIMIT + 1)).await;
    assert_eq!(status, 413, "{body}");
    assert!(body.contains(&format!("Request body too large (max: {LIMIT})")), "{body}");

    let (status, _, body) = post(&harness.gateway_url, &[], jsonrpc_of_length("message/send", LIMIT)).await;
    assert_ne!(status, 413, "{body}");
}

fn did_auth_surface() -> AgentSurface {
    serde_json::from_value(json!({
        "name": "smoke-did-auth",
        "access_point": {
            "listen_address": "inbound_port_placeholder", "route": "/smoke", "protocol": "a2a",
            "caller_authentication": {"methods": [{"type": "did_auth",
                "extraction": {"source": "http_header", "field": "X-DID-Auth-Session"}}]}
        },
        "target": {"endpoint": "inbound_target_placeholder"}
    }))
    .unwrap()
}

fn did_key(signing_key: &ed25519_dalek::SigningKey) -> String {
    let mut multicodec_key = vec![0xed, 0x01];
    multicodec_key.extend_from_slice(
        &signing_key
            .verifying_key()
            .to_bytes(),
    );
    format!("did:key:z{}", bs58::encode(multicodec_key).into_string())
}

fn signed_challenge(
    signing_key: &ed25519_dalek::SigningKey,
    did: &str,
    challenge: &str,
) -> String {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let base64url = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let key_fragment = did
        .strip_prefix("did:key:")
        .unwrap();
    let header = json!({"alg": "EdDSA", "kid": format!("{did}#{key_fragment}")});
    let now = chrono::Utc::now().timestamp();
    let payload = json!({"challenge": challenge, "iat": now, "exp": now + 300});
    let signing_input = format!(
        "{}.{}",
        base64url(&serde_json::to_vec(&header).unwrap()),
        base64url(&serde_json::to_vec(&payload).unwrap())
    );
    let signature = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", base64url(&signature.to_bytes()))
}

#[tokio::test(flavor = "multi_thread")]
async fn did_auth_refuses_an_oversize_body_and_still_completes_a_normal_exchange() {
    let harness = GatewayHarness::start(|_, config, _| {
        config.surfaces = vec![did_auth_surface()];
    })
    .await;
    let challenge_url = format!("{}/smoke/authenticate/challenge", harness.gateway_base);
    let authenticate_url = format!("{}/smoke/authenticate", harness.gateway_base);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[29u8; 32]);
    let did = did_key(&signing_key);

    let oversize = json!({"did": did, "channel": "x".repeat(64 * 1024)}).to_string();
    let (status, _, body) = post(&challenge_url, &[], oversize.clone()).await;
    assert_eq!(status, 413, "{body}");
    assert!(body.contains("Request body too large (max: 65536)"), "{body}");
    let (status, _, body) = post(&authenticate_url, &[], oversize).await;
    assert_eq!(status, 413, "{body}");

    let (status, _, body) = post(&challenge_url, &[], json!({"did": did}).to_string()).await;
    assert_eq!(status, 200, "{body}");
    let challenge = serde_json::from_str::<serde_json::Value>(&body).unwrap()["challenge"]
        .as_str()
        .unwrap()
        .to_string();

    let authenticate = json!({"did": did, "challenge_response": signed_challenge(&signing_key, &did, &challenge)});
    let (status, _, body) = post(&authenticate_url, &[], authenticate.to_string()).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["session_id"]
            .as_str()
            .is_some_and(|session| !session.is_empty()),
        "{body}"
    );
}
