use super::helpers::{self, GatewayHarness};
use futures::StreamExt;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

use axum::{
    Router,
    extract::Query,
    response::{
        Sse,
        sse::{Event as SseEvent, KeepAlive},
    },
    routing::get,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;

/// Mock MCP server that returns a tools/list response with available tools.
struct McpSandboxMockServer {
    pub addr: std::net::SocketAddr,
    pub received_bodies: Arc<Mutex<Vec<String>>>,
    _handle: tokio::task::JoinHandle<()>,
}

impl McpSandboxMockServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind SSE mock");
        let addr = listener.local_addr().unwrap();

        let (sse_tx, sse_rx) = mpsc::channel::<Result<SseEvent, Infallible>>(64);
        let sse_tx_for_post = Arc::new(sse_tx);

        let session_id = Arc::new(
            uuid::Uuid::new_v4()
                .to_string()
                .replace('-', ""),
        );
        let session_id_for_get = Arc::clone(&session_id);
        let sse_rx = Arc::new(Mutex::new(Some(sse_rx)));

        let received_bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let received_bodies_clone = Arc::clone(&received_bodies);

        let app = Router::new().route(
            "/{*path}",
            get({
                let session_id = Arc::clone(&session_id_for_get);
                let sse_rx = Arc::clone(&sse_rx);
                move |_uri: axum::http::Uri| {
                    let session_id = Arc::clone(&session_id);
                    let sse_rx = Arc::clone(&sse_rx);
                    async move {
                        let rx = sse_rx
                            .lock()
                            .await
                            .take()
                            .expect("SSE stream already consumed");

                        let messages_path = format!("/mcp/messages/?session_id={}", session_id);
                        let endpoint_event: Result<SseEvent, Infallible> = Ok(SseEvent::default()
                            .event("endpoint")
                            .data(messages_path));
                        let prefix = futures::stream::once(async move { endpoint_event });
                        let combined = prefix.chain(ReceiverStream::new(rx));

                        Sse::new(combined).keep_alive(
                            KeepAlive::new()
                                .interval(Duration::from_secs(5))
                                .text("keepalive"),
                        )
                    }
                }
            })
            .post({
                let sse_tx = Arc::clone(&sse_tx_for_post);
                let received_bodies = Arc::clone(&received_bodies_clone);
                move |Query(params): Query<std::collections::HashMap<String, String>>, body: axum::body::Bytes| {
                    let sse_tx = Arc::clone(&sse_tx);
                    let received_bodies = Arc::clone(&received_bodies);
                    async move {
                        let _session_id = params
                            .get("session_id")
                            .cloned()
                            .unwrap_or_default();
                        let body_str = String::from_utf8_lossy(&body).to_string();

                        received_bodies
                            .lock()
                            .await
                            .push(body_str.clone());

                        let request: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                        let id = request
                            .get("id")
                            .cloned()
                            .unwrap_or(serde_json::json!(null));
                        let method = request
                            .get("method")
                            .and_then(|m| m.as_str())
                            .unwrap_or("");

                        let result = match method {
                            "initialize" => serde_json::json!({
                                "protocolVersion": "2024-11-05",
                                "capabilities": { "tools": { "listChanged": false } },
                                "serverInfo": { "name": "sandbox-mock-server", "version": "1.0.0" }
                            }),
                            "tools/list" => serde_json::json!({
                                "tools": [
                                    {
                                        "name": "echo",
                                        "description": "Echoes the input back",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": {
                                                "message": { "type": "string" }
                                            },
                                            "required": ["message"]
                                        }
                                    },
                                    {
                                        "name": "get_time",
                                        "description": "Returns the current server time",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": {}
                                        }
                                    }
                                ]
                            }),
                            _ => serde_json::json!({
                                "content": [{"type": "text", "text": "unknown method"}]
                            }),
                        };

                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": result
                        });
                        let response_str = serde_json::to_string(&response).unwrap();

                        let event = SseEvent::default()
                            .event("message")
                            .data(&response_str);
                        let _ = sse_tx.send(Ok(event)).await;

                        axum::http::StatusCode::ACCEPTED
                    }
                }
            }),
        );

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        McpSandboxMockServer {
            addr,
            received_bodies,
            _handle: handle,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

fn parse_sse_events(text: &str) -> Vec<(String, String)> {
    let mut events = vec![];
    let mut event_type = String::new();
    let mut data = String::new();

    for line in text.lines() {
        if line.starts_with("event:") {
            event_type = line
                .trim_start_matches("event:")
                .trim()
                .to_string();
        } else if line.starts_with("data:") {
            data = line
                .trim_start_matches("data:")
                .trim()
                .to_string();
        } else if line.is_empty() && (!event_type.is_empty() || !data.is_empty()) {
            events.push((event_type.clone(), data.clone()));
            event_type.clear();
            data.clear();
        }
    }
    if !event_type.is_empty() || !data.is_empty() {
        events.push((event_type, data));
    }
    events
}

/// Helper: connect SSE, extract session messages URL.
async fn connect_sse(
    client: &reqwest::Client,
    gateway_sse_url: &str,
) -> (impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>, String) {
    let resp = client
        .get(gateway_sse_url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("SSE connection failed");
    assert_eq!(resp.status(), 200);

    let mut stream = resp.bytes_stream();
    let mut collected = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            chunk = stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        collected.push_str(&String::from_utf8_lossy(&bytes));
                        if parse_sse_events(&collected).iter().any(|(t, _)| t == "endpoint") {
                            break;
                        }
                    }
                    Some(Err(e)) => panic!("stream error: {e}"),
                    None => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    let events = parse_sse_events(&collected);
    let endpoint_data = events
        .iter()
        .find(|(t, _)| t == "endpoint")
        .expect("no endpoint event")
        .1
        .clone();

    (stream, endpoint_data)
}

/// Helper: wait for a message event on the SSE stream.
async fn wait_for_message(
    stream: &mut (impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin)
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut chunk_data = String::new();

    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            chunk = stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        chunk_data.push_str(&String::from_utf8_lossy(&bytes));
                        if parse_sse_events(&chunk_data).iter().any(|(t, _)| t == "message") {
                            break;
                        }
                    }
                    Some(Err(e)) => panic!("stream error: {e}"),
                    None => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    let events = parse_sse_events(&chunk_data);
    let message_event = events
        .iter()
        .find(|(t, _)| t == "message")
        .expect("no message event received");

    serde_json::from_str(&message_event.1).expect("response is not valid JSON")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// MCP Sandbox: connect as MCP client, run initialize + tools/list,
/// validate correct sandbox URL is used and a list of tools is returned.
/// The deprecated HTTP+SSE endpoint keeps serving `2024-11-05` clients, with
/// the Origin and size checks applied to legacy traffic too.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_sandbox_connect_and_tools_list_succeeds() {
    let mock = McpSandboxMockServer::start().await;
    let mock_url = mock.url();

    let h = GatewayHarness::start(|_, gw_config, _| {
        let mut surface = helpers::build_minimal_mcp_surface();
        surface.target.endpoint = mock_url.clone();
        gw_config.surfaces = vec![surface];
    })
    .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // Step 1: Open MCP Sandbox — connect via SSE
    let gateway_sse_url = h
        .gateway_url
        .replace("/rpc", "/sse");
    let (mut stream, endpoint_data) = connect_sse(&client, &gateway_sse_url).await;

    let port = h
        .gateway_url
        .split(':')
        .nth(2)
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let messages_url = format!("http://127.0.0.1:{}/smoke{}", port, endpoint_data);

    // Step 2: Send initialize (MCP handshake)
    let initialize_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "agent-gateway-sandbox", "version": "1.0.0" }
        }
    });

    let post_resp = client
        .post(&messages_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&initialize_req).unwrap())
        .send()
        .await
        .expect("POST initialize failed");

    assert_eq!(post_resp.status().as_u16(), 202, "initialize should return 202 Accepted (no 4xx/5xx)");

    let init_response = wait_for_message(&mut stream).await;
    assert_eq!(init_response["jsonrpc"], "2.0");
    assert_eq!(init_response["id"], 1);
    assert!(
        init_response
            .get("result")
            .is_some(),
        "initialize should return a result"
    );
    assert_eq!(init_response["result"]["serverInfo"]["name"], "sandbox-mock-server");

    // Step 3: Execute tools/list
    let tools_list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });

    let post_resp = client
        .post(&messages_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&tools_list_req).unwrap())
        .send()
        .await
        .expect("POST tools/list failed");

    assert_eq!(post_resp.status().as_u16(), 202, "tools/list should return 202 Accepted (no 4xx/5xx)");

    let list_response = wait_for_message(&mut stream).await;
    assert_eq!(list_response["jsonrpc"], "2.0");
    assert_eq!(list_response["id"], 2);
    assert!(
        list_response
            .get("result")
            .is_some(),
        "tools/list should return a result, not an error"
    );

    // Validate: response returns a list of available tools
    let tools = list_response["result"]["tools"]
        .as_array()
        .expect("tools should be an array");
    assert!(!tools.is_empty(), "tools list should not be empty");
    assert_eq!(tools[0]["name"], "echo");
    assert_eq!(tools[1]["name"], "get_time");

    // Validate: sandbox used correct URL (mock received both requests)
    let bodies = mock
        .received_bodies
        .lock()
        .await;
    assert_eq!(bodies.len(), 2, "mock should have received exactly 2 requests (initialize + tools/list)");

    let first_req: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(first_req["method"], "initialize");

    let second_req: serde_json::Value = serde_json::from_str(&bodies[1]).unwrap();
    assert_eq!(second_req["method"], "tools/list");
}

/// MCP Sandbox: verify no errors when calling tools/list on a properly configured channel.
/// This validates the complete request/response cycle without 4xx/5xx errors.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_sandbox_tools_list_no_errors() {
    let mock = McpSandboxMockServer::start().await;
    let mock_url = mock.url();

    let h = GatewayHarness::start(|_, gw_config, _| {
        let mut surface = helpers::build_minimal_mcp_surface();
        surface.target.endpoint = mock_url.clone();
        gw_config.surfaces = vec![surface];
    })
    .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let gateway_sse_url = h
        .gateway_url
        .replace("/rpc", "/sse");
    let (mut stream, endpoint_data) = connect_sse(&client, &gateway_sse_url).await;

    let port = h
        .gateway_url
        .split(':')
        .nth(2)
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let messages_url = format!("http://127.0.0.1:{}/smoke{}", port, endpoint_data);

    // Send tools/list directly (without initialize) — should still succeed
    let tools_list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let post_resp = client
        .post(&messages_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&tools_list_req).unwrap())
        .send()
        .await
        .expect("POST tools/list failed");

    // No 4xx/5xx errors
    let status = post_resp.status().as_u16();
    assert!(status < 400, "expected no error status, got {status}");

    let response = wait_for_message(&mut stream).await;

    // Valid JSON-RPC response with no error field
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(
        response
            .get("error")
            .is_none(),
        "response should not contain an error: {:?}",
        response.get("error")
    );
    assert!(
        response
            .get("result")
            .is_some(),
        "response should contain a result"
    );

    // Tools list is present and valid
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools should be an array");
    assert!(!tools.is_empty(), "tools list should contain available tools");

    // Each tool has required fields
    for tool in tools {
        assert!(tool.get("name").is_some(), "each tool should have a name");
        assert!(
            tool.get("inputSchema")
                .is_some(),
            "each tool should have an inputSchema"
        );
    }
}
