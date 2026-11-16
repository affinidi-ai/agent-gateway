//! A Target that answers before reading the request body, and closes the connection, is
//! answered to the caller as the Target sent it, not as a connection failure.

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::variant_routing_tests::router;
use crate::config::agent_surface::AgentSurface;

/// A Target that reads only the request head, answers `401` and closes the connection,
/// leaving the body unread.
pub(crate) async fn target_refusing_before_the_body() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if socket
                    .read(&mut byte)
                    .await
                    .unwrap_or(0)
                    == 0
                {
                    break;
                }
                head.push(byte[0]);
            }
            let body = r#"{"error":"refused"}"#;
            let answer = format!(
                "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket
                .write_all(answer.as_bytes())
                .await;
            let _ = socket.shutdown().await;
        }
    });
    format!("http://{address}")
}

fn surface(endpoint: &str) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "orders", "name": "Orders",
        "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
        "target": {"endpoint": endpoint}
    }))
    .unwrap()
}

async fn send_large_body(router: crate::state::MultiSurfaceProxyState) -> axum::http::StatusCode {
    let text = "x".repeat(4 * 1024 * 1024);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/a2a")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
                "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": text}]
            }}})
            .to_string(),
        ))
        .unwrap();
    Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
        "127.0.0.1:12345"
            .parse()
            .unwrap(),
        router,
        request,
        crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
        None,
    ))
    .await
    .status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "known bug: the gateway answers 502 when its Target answers and closes before reading the body"]
async fn a_target_that_refuses_before_reading_a_large_body_is_answered_as_it_refused() {
    let target = target_refusing_before_the_body().await;
    for attempt in 0..5 {
        assert_eq!(
            send_large_body(router(surface(&target))).await,
            axum::http::StatusCode::UNAUTHORIZED,
            "attempt {attempt}"
        );
    }
}
