use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::any;
use http_body_util::BodyExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use reqwest::Method as ReqwestMethod;

use std::path::PathBuf;

use crate::bdd_support::debug::log_to_file;

#[derive(Debug, Clone)]
pub struct MockAgentFixture {
    pub key: String,
    pub port: u16,
    pub response: MockResponse,
    pub forwarding_address: Option<String>,
    pub log_path: PathBuf,
    pub debug: bool,
}

#[derive(Debug, Clone)]
pub struct ReceivedRequest {
    pub method: String,
    pub headers: HashMap<String, String>,
    pub raw_body: String,
    pub content_type: Option<String>,
    pub path_and_query: String,
}

impl ReceivedRequest {
    pub fn json_body(&self) -> serde_json::Value {
        serde_json::from_str(&self.raw_body).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseDelay {
    min_ms: u64,
    max_ms: u64,
}

impl ResponseDelay {
    pub fn new(
        min_ms: u64,
        max_ms: u64,
    ) -> Self {
        assert!(min_ms <= max_ms, "response delay min must be <= max");
        Self { min_ms, max_ms }
    }

    fn duration_for(
        self,
        request_body: &serde_json::Value,
        sequence: usize,
    ) -> Duration {
        let span = self
            .max_ms
            .saturating_sub(self.min_ms)
            .saturating_add(1);
        let offset = deterministic_seed(request_body, sequence) % span;
        Duration::from_millis(self.min_ms + offset)
    }
}

/// How the mock frames its configured JSON-RPC response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MockStream {
    /// One JSON body.
    #[default]
    None,
    /// The response as a single SSE `message` event.
    Sse,
    /// A request-scoped progress event, then the response once released.
    ProgressThenRelease,
    /// An open SSE stream that carries only keep-alive comments until the
    /// caller goes away.
    Quiet,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
    pub stream: MockStream,
}

impl MockResponse {
    pub fn json(body: serde_json::Value) -> Self {
        Self {
            status: 200,
            headers: std::collections::HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            body,
            stream: MockStream::None,
        }
    }

    /// The same JSON-RPC response framed as `stream`.
    pub fn streamed(
        body: serde_json::Value,
        stream: MockStream,
    ) -> Self {
        let mut response = Self::json(body);
        if stream != MockStream::None {
            response
                .headers
                .insert("content-type".to_string(), "text/event-stream".to_string());
        }
        response.stream = stream;
        response
    }
}

/// Coordination between a scenario and a streaming response.
#[derive(Debug, Clone, Default)]
struct MockSignals {
    release: Arc<tokio::sync::Notify>,
    completed: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

/// Records that the response body was dropped before it ended.
struct CancelGuard(Arc<std::sync::atomic::AtomicBool>);

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn sse_event(message: &serde_json::Value) -> bytes::Bytes {
    bytes::Bytes::from(format!("event: message\ndata: {message}\n\n"))
}

impl From<serde_json::Value> for MockResponse {
    fn from(body: serde_json::Value) -> Self {
        Self::json(body)
    }
}

#[derive(Debug, Clone)]
enum MockBehavior {
    Static,
    DirectLine { reply_text: Option<String> },
}

struct MockState {
    mock_server_fixture: Option<MockAgentFixture>,
    response: MockResponse,
    requests: Vec<ReceivedRequest>,
    response_delay: Option<ResponseDelay>,
    behavior: MockBehavior,
    signals: MockSignals,
}

pub struct MockServer {
    pub port: u16,
    state: Arc<Mutex<MockState>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Debug for MockServer {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("MockServer")
            .field("port", &self.port)
            .finish()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl MockServer {
    pub async fn start(response: impl Into<MockResponse>) -> Self {
        Self::start_with_extra_headers(response, HashMap::new()).await
    }

    pub async fn start_on_non_loopback_interface(response: impl Into<MockResponse>) -> Self {
        let host = discover_non_loopback_local_ip().to_string();
        Self::start_with_bind_address(response, HashMap::new(), &host).await
    }

    pub async fn start_with_extra_headers(
        response: impl Into<MockResponse>,
        extra_headers: HashMap<String, String>,
    ) -> Self {
        Self::start_with_bind_address(response, extra_headers, "127.0.0.1").await
    }

    async fn start_with_bind_address(
        response: impl Into<MockResponse>,
        extra_headers: HashMap<String, String>,
        bind_address: &str,
    ) -> Self {
        let mut mock_response: MockResponse = response.into();
        for (name, value) in extra_headers {
            mock_response
                .headers
                .insert(name, value);
        }
        let state = Arc::new(Mutex::new(MockState {
            mock_server_fixture: None,
            response: mock_response,
            requests: Vec::new(),
            response_delay: None,
            behavior: MockBehavior::Static,
            signals: MockSignals::default(),
        }));

        let app_state = state.clone();
        let app = Router::new()
            .route("/{*path}", any(handler))
            .route("/", any(handler))
            .with_state(app_state);

        let listener = TcpListener::bind(format!("{bind_address}:0"))
            .await
            .unwrap();
        let port = listener
            .local_addr()
            .unwrap()
            .port();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });

        Self { port, state, handle }
    }

    pub async fn start_server_with_fixture(spec: MockAgentFixture) -> Self {
        let port_number = spec.port;
        let has_forwarding = spec
            .forwarding_address
            .is_some();
        let state = Arc::new(Mutex::new(MockState {
            mock_server_fixture: Some(spec),
            requests: Vec::new(),
            response: MockResponse::json(serde_json::json!({"unintended_response": true})),
            response_delay: None,
            behavior: MockBehavior::Static,
            signals: MockSignals::default(),
        }));

        let app_state = state.clone();

        let app = if has_forwarding {
            Router::new().route("/{*path}", any(forward_handler))
        } else {
            Router::new().route("/{*path}", any(default_handler))
        }
        .with_state(app_state);

        let listener = TcpListener::bind(format!("127.0.0.1:{}", port_number))
            .await
            .expect("Listener must be created");

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });

        Self {
            port: port_number,
            state,
            handle,
        }
    }

    pub async fn start_direct_line(reply_text: impl Into<String>) -> Self {
        let server = Self::start(MockResponse::json(serde_json::json!({"unintended_response": true}))).await;
        let reply_text = reply_text.into();
        server
            .state
            .lock()
            .await
            .behavior = MockBehavior::DirectLine { reply_text: Some(reply_text) };
        server
    }

    pub async fn start_direct_line_without_reply() -> Self {
        let server = Self::start(MockResponse::json(serde_json::json!({"unintended_response": true}))).await;
        server
            .state
            .lock()
            .await
            .behavior = MockBehavior::DirectLine { reply_text: None };
        server
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn non_loopback_url(&self) -> String {
        let host = discover_non_loopback_local_ip();
        format!("http://{}:{}", host, self.port)
    }

    pub async fn requests(&self) -> Vec<ReceivedRequest> {
        self.state
            .lock()
            .await
            .requests
            .clone()
    }

    pub async fn last_request(&self) -> Option<ReceivedRequest> {
        self.requests()
            .await
            .last()
            .cloned()
    }

    pub async fn request_count(&self) -> usize {
        self.state
            .lock()
            .await
            .requests
            .len()
    }

    pub async fn clear_requests(&self) {
        self.state
            .lock()
            .await
            .requests
            .clear();
    }

    pub async fn set_response(
        &self,
        response: impl Into<MockResponse>,
    ) {
        self.state
            .lock()
            .await
            .response = response.into();
    }

    pub async fn set_status(
        &self,
        status: u16,
    ) {
        self.state
            .lock()
            .await
            .response
            .status = status;
    }

    /// Lets a `ProgressThenRelease` response send its final message.
    pub async fn release_stream(&self) {
        self.state
            .lock()
            .await
            .signals
            .release
            .notify_one();
    }

    /// Whether a `ProgressThenRelease` response has sent its final message.
    pub async fn stream_completed(&self) -> bool {
        self.state
            .lock()
            .await
            .signals
            .completed
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether a `Quiet` response was dropped by the gateway.
    pub async fn stream_cancelled(&self) -> bool {
        self.state
            .lock()
            .await
            .signals
            .cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub async fn set_response_delay(
        &self,
        min_ms: u64,
        max_ms: u64,
    ) {
        self.state
            .lock()
            .await
            .response_delay = Some(ResponseDelay::new(min_ms, max_ms));
    }
}

pub fn discover_non_loopback_local_ip() -> std::net::IpAddr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind UDP socket for local IP discovery");
    socket
        .connect("8.8.8.8:80")
        .expect("connect UDP socket for local IP discovery");
    let ip = socket
        .local_addr()
        .expect("read local UDP socket address")
        .ip();
    assert!(!ip.is_loopback(), "local IP discovery returned loopback address {ip}");
    ip
}

async fn handler(
    State(state): State<Arc<Mutex<MockState>>>,
    request: Request<Body>,
) -> Response<Body> {
    let method = request
        .method()
        .as_str()
        .to_string();
    let headers: HashMap<String, String> = request
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    let content_type = headers
        .get("content-type")
        .cloned();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| {
            request
                .uri()
                .path()
                .to_string()
        });

    let body_bytes = request
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let raw_body = String::from_utf8_lossy(&body_bytes).to_string();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);

    let (response, response_delay, signals) = {
        let mut state = state.lock().await;
        let sequence = state.requests.len() + 1;
        state
            .requests
            .push(ReceivedRequest {
                method: method.clone(),
                headers,
                raw_body: raw_body.clone(),
                content_type,
                path_and_query: path_and_query.clone(),
            });
        let response = match &state.behavior {
            MockBehavior::Static => state.response.clone(),
            MockBehavior::DirectLine { reply_text } => {
                direct_line_response(&method, &path_and_query, reply_text.as_deref())
            }
        };
        (
            response,
            state
                .response_delay
                .map(|delay| delay.duration_for(&body, sequence)),
            state.signals.clone(),
        )
    };

    if let Some(delay) = response_delay {
        tokio::time::sleep(delay).await;
    }

    let mut response_body_value = response.body;
    if let Some(response_object) = response_body_value.as_object_mut()
        && response_object.contains_key("id")
        && let Some(request_id) = body.get("id")
    {
        response_object.insert("id".to_string(), request_id.clone());
    }
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }

    let body = match response.stream {
        MockStream::None => Body::from(serde_json::to_vec(&response_body_value).unwrap()),
        MockStream::Sse => Body::from(sse_event(&response_body_value)),
        MockStream::ProgressThenRelease => {
            let progress = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {
                "progressToken": body.pointer("/params/_meta/progressToken").cloned().unwrap_or_default(),
                "progress": 1,
                "total": 2
            }});
            let stream = futures::stream::unfold(0u8, move |step| {
                let signals = signals.clone();
                let progress = progress.clone();
                let complete = response_body_value.clone();
                async move {
                    match step {
                        0 => Some((Ok::<_, std::convert::Infallible>(sse_event(&progress)), 1)),
                        1 => {
                            signals
                                .release
                                .notified()
                                .await;
                            signals
                                .completed
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            Some((Ok(sse_event(&complete)), 2))
                        }
                        _ => None,
                    }
                }
            });
            Body::from_stream(stream)
        }
        MockStream::Quiet => {
            let guard = CancelGuard(signals.cancelled.clone());
            let stream = futures::stream::unfold(guard, |guard| async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Some((Ok::<_, std::convert::Infallible>(bytes::Bytes::from_static(b": keep-alive\n\n")), guard))
            });
            Body::from_stream(stream)
        }
    };
    builder.body(body).unwrap()
}

fn direct_line_response(
    method: &str,
    path_and_query: &str,
    reply_text: Option<&str>,
) -> MockResponse {
    let path = path_and_query
        .split('?')
        .next()
        .unwrap_or(path_and_query);
    let body = if method == "POST" && path == "/v3/directline/conversations" {
        serde_json::json!({ "conversationId": "bdd-conversation" })
    } else if method == "POST" && path == "/v3/directline/conversations/bdd-conversation/activities" {
        serde_json::json!({ "id": "bdd-activity" })
    } else if method == "GET" && path == "/v3/directline/conversations/bdd-conversation/activities" {
        match reply_text {
            Some(reply_text) => serde_json::json!({
                "activities": [{
                    "type": "message",
                    "from": { "id": "bdd-non-a2a-managed-agent" },
                    "text": reply_text,
                }],
                "watermark": "1",
            }),
            None => serde_json::json!({
                "activities": [],
                "watermark": "1",
            }),
        }
    } else {
        serde_json::json!({ "error": format!("unexpected Direct Line request: {method} {path_and_query}") })
    };
    MockResponse::json(body)
}

fn deterministic_seed(
    request_body: &serde_json::Value,
    sequence: usize,
) -> u64 {
    let seed_value = request_body
        .get("id")
        .unwrap_or(request_body)
        .to_string();
    seed_value
        .bytes()
        .fold(sequence as u64, |seed, byte| seed.wrapping_mul(16_777_619) ^ u64::from(byte))
}

async fn forward_handler(
    State(state): State<Arc<Mutex<MockState>>>,
    request: Request<Body>,
) -> Response<Body> {
    let (forwarding_address, log_path, debug) = {
        let state = state.lock().await;
        let spec = state
            .mock_server_fixture
            .as_ref()
            .expect("Agent spec must be present");
        (
            spec.forwarding_address
                .clone()
                .expect("forwarding_address should be set for forward_handler"),
            spec.log_path
                .clone()
                .to_str()
                .expect("log_path should be valid UTF-8")
                .to_string(),
            spec.debug,
        )
    };

    // let request_uri = request.uri().clone();
    let request_headers: HashMap<String, String> = request
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    let content_type = request_headers
        .get("content-type")
        .cloned();
    let request_path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| {
            request
                .uri()
                .path()
                .to_string()
        });
    let method = request.method().clone();

    let request_body_bytes = request
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let request_raw_body = String::from_utf8_lossy(&request_body_bytes).to_string();
    let request_body: serde_json::Value =
        serde_json::from_slice(&request_body_bytes).unwrap_or(serde_json::Value::Null);

    state
        .lock()
        .await
        .requests
        .push(ReceivedRequest {
            headers: request_headers.clone(),
            method: method.as_str().to_string(),
            raw_body: request_raw_body.clone(),
            path_and_query: request_path_and_query.clone(),
            content_type,
        });

    if debug {
        let my_text = format!(
            "request is here:\n  method: {:#?}\n  headers: {:#?}\n  path_and_query: {:#?}\n  body: {:#?}\n",
            method, request_headers, request_path_and_query, request_body
        );
        log_to_file(&log_path, &my_text);
    }

    let client = reqwest::Client::new();
    let mut request_to_next = client
        .request(ReqwestMethod::from_str(method.as_str()).expect("invalid method"), &forwarding_address)
        .json(&request_body);

    for (name, value) in request_headers.clone() {
        if name.to_lowercase() == "host"
            || name.to_lowercase() == "content-length"
            || name.to_lowercase() == "content-type"
        {
            continue;
        }
        request_to_next = request_to_next.header(&name, value);
    }

    if debug {
        let response_trace_info = format!("forwarding request to {}\n{:#?}", forwarding_address, request_to_next);
        log_to_file(&log_path, &response_trace_info);
    }

    let response_from_next = request_to_next
        .send()
        .await
        .unwrap_or_else(|err| {
            log_to_file(&log_path, "failed to send request to forwarding address\n");
            panic!("failed to send request to forwarding address {}: {}", forwarding_address, err);
        });
    // .expect("send request to gateway");

    if debug {
        let response_trace_info = format!("response received from {}\n", forwarding_address);
        log_to_file(&log_path, &response_trace_info);
    }

    let response_status_from_next = response_from_next
        .status()
        .as_u16();
    let response_headers_from_next: HashMap<String, String> = response_from_next
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    let response_body_from_next: serde_json::Value = response_from_next
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);

    if debug {
        let response_trace_info = format!(
            "response from next:\n  status: {:#?}\n  headers: {:#?}\n  body: {:#?}\n",
            response_status_from_next, response_headers_from_next, response_body_from_next
        );
        log_to_file(&log_path, &response_trace_info);
    }

    let mut builder = Response::builder().status(response_status_from_next);
    for (name, value) in response_headers_from_next {
        builder = builder.header(name, value);
    }

    if debug {
        log_to_file(&log_path, "forwarding response to caller\n");
    }

    builder
        .body(Body::from(response_body_from_next.to_string()))
        .unwrap()
}

async fn default_handler(
    State(state): State<Arc<Mutex<MockState>>>,
    request: Request<Body>,
) -> Response<Body> {
    let (log_path, response, debug) = {
        let state = state.lock().await;
        let spec = state
            .mock_server_fixture
            .as_ref()
            .expect("spec should be set for default_handler");
        (
            spec.log_path
                .clone()
                .to_str()
                .expect("log_path should be valid UTF-8")
                .to_string(),
            spec.response.clone(),
            spec.debug,
        )
    };

    let method = request.method().clone();

    let headers: HashMap<String, String> = request
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    let content_type = headers
        .get("content-type")
        .cloned();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| {
            request
                .uri()
                .path()
                .to_string()
        });

    let body_bytes = request
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let raw_body = String::from_utf8_lossy(&body_bytes).to_string();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);

    if debug {
        let my_text = format!(
            "request is here:\n  method: {:#?}\n  headers: {:#?}\n  path_and_query: {:#?}\n  body: {:#?}\n",
            method, headers, path_and_query, body
        );
        log_to_file(&log_path, &my_text);
    }

    state
        .lock()
        .await
        .requests
        .push(ReceivedRequest {
            headers,
            raw_body,
            method: method.as_str().to_string(),
            path_and_query,
            content_type,
        });

    let mut response_body_value = response.body;
    if let Some(response_object) = response_body_value.as_object_mut()
        && response_object.contains_key("id")
        && let Some(request_id) = body.get("id")
    {
        response_object.insert("id".to_string(), request_id.clone());
    }
    let response_body = serde_json::to_vec(&response_body_value).unwrap();

    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }

    builder
        .body(Body::from(response_body))
        .unwrap()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn mock_server_starts_without_requests() {
        let mock = super::MockServer::start(serde_json::json!({"ok": true})).await;

        assert!(
            mock.requests()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn mock_server_records_request_count_and_forwarded_path() {
        let mock = super::MockServer::start(serde_json::json!({"ok": true})).await;

        reqwest::Client::new()
            .post(format!("{}/nested/path?foo=bar&baz=1", mock.url()))
            .header("content-type", "application/json")
            .json(&serde_json::json!({"hello": "world"}))
            .send()
            .await
            .unwrap();

        let requests = mock.requests().await;

        assert_eq!(requests.len(), 1);
        assert_eq!(mock.request_count().await, 1);
        assert_eq!(requests[0].path_and_query, "/nested/path?foo=bar&baz=1");
        assert_eq!(requests[0].json_body(), serde_json::json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn mock_server_records_request_history_and_last_request() {
        let mock = super::MockServer::start(serde_json::json!({"ok": true})).await;
        let client = reqwest::Client::new();

        client
            .post(format!("{}/first", mock.url()))
            .json(&serde_json::json!({"request": 1}))
            .send()
            .await
            .unwrap();
        client
            .post(format!("{}/second", mock.url()))
            .json(&serde_json::json!({"request": 2}))
            .send()
            .await
            .unwrap();

        let requests = mock.requests().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(mock.request_count().await, 2);
        assert_eq!(requests[0].path_and_query, "/first");
        assert_eq!(requests[0].json_body(), serde_json::json!({"request": 1}));
        assert_eq!(requests[1].path_and_query, "/second");
        assert_eq!(requests[1].json_body(), serde_json::json!({"request": 2}));
        assert_eq!(
            mock.last_request()
                .await
                .unwrap()
                .json_body(),
            serde_json::json!({"request": 2})
        );
    }

    #[tokio::test]
    async fn mock_server_clears_request_history() {
        let mock = super::MockServer::start(serde_json::json!({"ok": true})).await;

        reqwest::Client::new()
            .post(format!("{}/first", mock.url()))
            .json(&serde_json::json!({"request": 1}))
            .send()
            .await
            .unwrap();
        assert_eq!(mock.request_count().await, 1);

        mock.clear_requests().await;

        assert_eq!(mock.request_count().await, 0);
        assert!(
            mock.requests()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn mock_server_uses_configured_response_status_and_headers() {
        let response = super::MockResponse {
            status: 503,
            headers: std::collections::HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                ("x-mock-result".to_string(), "unavailable".to_string()),
            ]),
            body: serde_json::json!({"error": "unavailable"}),
            stream: super::MockStream::None,
        };
        let mock = super::MockServer::start(response).await;

        let response = reqwest::Client::new()
            .post(format!("{}/status", mock.url()))
            .json(&serde_json::json!({"hello": "world"}))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["x-mock-result"], "unavailable");
        assert_eq!(
            response
                .json::<serde_json::Value>()
                .await
                .unwrap(),
            serde_json::json!({"error": "unavailable"})
        );
    }

    #[tokio::test]
    async fn mock_server_can_echo_jsonrpc_request_id_in_response() {
        let mock = super::MockServer::start(super::MockResponse::json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "placeholder",
            "result": {"ok": true}
        })))
        .await;

        let response = reqwest::Client::new()
            .post(format!("{}/mcp", mock.url()))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "caller-request-alpha",
                "method": "tools/list"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .json::<serde_json::Value>()
                .await
                .unwrap(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "caller-request-alpha",
                "result": {"ok": true}
            })
        );
    }

    #[tokio::test]
    async fn mock_server_does_not_inject_jsonrpc_id_when_response_has_none() {
        let mock = super::MockServer::start(super::MockResponse::json(serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"ok": true}
        })))
        .await;

        let response = reqwest::Client::new()
            .post(format!("{}/mcp", mock.url()))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "caller-request-alpha",
                "method": "tools/list"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .json::<serde_json::Value>()
                .await
                .unwrap(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"ok": true}
            })
        );
    }

    #[tokio::test]
    async fn mock_server_keeps_configured_jsonrpc_id_when_request_has_none() {
        let mock = super::MockServer::start(super::MockResponse::json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "configured-response-id",
            "result": {"ok": true}
        })))
        .await;

        let response = reqwest::Client::new()
            .post(format!("{}/mcp", mock.url()))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .json::<serde_json::Value>()
                .await
                .unwrap(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "configured-response-id",
                "result": {"ok": true}
            })
        );
    }

    #[tokio::test]
    async fn mock_servers_record_requests_independently() {
        let original = super::MockServer::start(serde_json::json!({"name": "original"})).await;
        let replacement = super::MockServer::start(serde_json::json!({"name": "replacement"})).await;

        reqwest::Client::new()
            .post(format!("{}/foo", replacement.url()))
            .header("content-type", "application/json")
            .json(&serde_json::json!({"hello": "replacement"}))
            .send()
            .await
            .unwrap();

        assert!(
            original
                .requests()
                .await
                .is_empty()
        );

        let replacement_requests = replacement.requests().await;
        assert_eq!(replacement_requests.len(), 1);
        assert_eq!(replacement_requests[0].path_and_query, "/foo");
        assert_eq!(replacement_requests[0].json_body(), serde_json::json!({"hello": "replacement"}));
    }

    #[tokio::test]
    async fn mock_server_delays_responses_without_serializing_requests() {
        let mock = super::MockServer::start(serde_json::json!({"ok": true})).await;
        mock.set_response_delay(200, 200)
            .await;

        let client = reqwest::Client::new();
        let first = client
            .post(format!("{}/first", mock.url()))
            .json(&serde_json::json!({"request": 1}))
            .send();
        let second = client
            .post(format!("{}/second", mock.url()))
            .json(&serde_json::json!({"request": 2}))
            .send();

        let started_at = std::time::Instant::now();
        let (first_response, second_response) = tokio::join!(first, second);
        let elapsed = started_at.elapsed();

        assert_eq!(
            first_response
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(
            second_response
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        assert!(elapsed < std::time::Duration::from_millis(360), "delayed responses were serialized: {elapsed:?}");
        assert_eq!(mock.request_count().await, 2);
    }
}
