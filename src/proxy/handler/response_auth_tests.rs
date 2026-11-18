//! Response authentication on the direct forward: a Target response that fails the check,
//! a stream among them, is refused before anything of it reaches the caller, and a request
//! whose Target cannot be checked is refused before it is sent.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::{HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE};
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::audit::request_events::{RejectionReason, RejectionStage};
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};
use crate::proxy::response_auth::{BRAVO_KEY, REFUSAL_MESSAGE, api_key_bravo, bravo_key_store, pinned_bravo};

const EVENT: &str = "the-targets-event";

/// What the Target answers a POST with.
#[derive(Clone, Copy)]
enum Post {
    /// An event stream without the key.
    EventStream,
    /// `405` with the key, so the MCP forward falls back to Legacy SSE.
    MethodNotAllowedWithKey,
}

/// A Target on 127.0.0.1 that answers every POST as `post` and a GET of `/sse` with a Legacy
/// SSE stream without the key, counting every request.
struct Target {
    url: String,
    requests: Arc<AtomicUsize>,
}

async fn target(post: Post) -> Target {
    let requests = Arc::new(AtomicUsize::new(0));
    let on_post = Arc::clone(&requests);
    let on_sse = Arc::clone(&requests);
    let app = axum::Router::new()
        .route(
            "/sse",
            axum::routing::get(move || {
                on_sse.fetch_add(1, Ordering::SeqCst);
                async {
                    ([(CONTENT_TYPE, "text/event-stream")], "event: endpoint\ndata: /messages\n\n").into_response()
                }
            }),
        )
        .fallback(move || {
            on_post.fetch_add(1, Ordering::SeqCst);
            async move {
                match post {
                    Post::EventStream => (
                        [(CONTENT_TYPE, "text/event-stream")],
                        format!("data: {}\n\n", json!({"jsonrpc": "2.0", "id": 1, "result": EVENT})),
                    )
                        .into_response(),
                    Post::MethodNotAllowedWithKey => (
                        StatusCode::METHOD_NOT_ALLOWED,
                        [(HeaderName::from_static("x-agent-key"), HeaderValue::from_static(BRAVO_KEY))],
                    )
                        .into_response(),
                }
            }
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    Target { url, requests }
}

fn surface(
    protocol: &str,
    endpoint: &str,
    response_auth: Value,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "bravo", "name": "Bravo",
        "access_point": {"listen_address": "https://gateway.example", "route": format!("/{protocol}"),
            "protocol": protocol},
        "target": {"endpoint": endpoint, "response_auth": response_auth}
    }))
    .unwrap()
}

/// A request to the A2A Access Point asking for an event stream.
fn a2a_stream() -> (&'static str, Vec<(&'static str, &'static str)>, Value) {
    (
        "/a2a",
        vec![("content-type", "application/json"), ("accept", "text/event-stream")],
        json!({"jsonrpc": "2.0", "id": 1, "method": "message/stream", "params": {"message": {
            "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hello"}]
        }}}),
    )
}

/// A Streamable HTTP request to the MCP Access Point.
fn mcp_call() -> (&'static str, Vec<(&'static str, &'static str)>, Value) {
    (
        "/mcp",
        vec![
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION),
        ],
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "lookup", "arguments": {}}}),
    )
}

/// Sends `request` through the Access Point of `surface`, whose secrets hold the key of
/// [`api_key_bravo`], and returns the status, the body and every audit record it wrote.
async fn send(
    surface: AgentSurface,
    (path, headers, body): (&str, Vec<(&str, &str)>, Value),
) -> (StatusCode, String, Vec<DelegationAuditEvent>) {
    let (_dir, secrets) = bravo_key_store().await;
    let mut router = super::variant_routing_tests::router(surface);
    router.secrets_store = Some(secrets);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(path);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let (response, events) =
        crate::audit::producer::capture(Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            router,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        )))
        .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned(), events)
}

fn refusals(events: &[DelegationAuditEvent]) -> Vec<(RejectionStage, RejectionReason, Option<u16>)> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected { stage, reason, http_status, .. } => {
                Some((*stage, *reason, *http_status))
            }
            _ => None,
        })
        .collect()
}

fn assert_refused(
    case: &str,
    (status, body, events): &(StatusCode, String, Vec<DelegationAuditEvent>),
) {
    assert_eq!(*status, StatusCode::BAD_GATEWAY, "{case}: {body}");
    assert!(body.contains(REFUSAL_MESSAGE), "{case}: {body}");
    assert!(!body.contains(EVENT), "{case}: an event reached the caller: {body}");
    assert_eq!(
        refusals(events),
        vec![(RejectionStage::Forward, RejectionReason::TargetResponseAuthFailed, Some(502))],
        "{case}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_event_stream_without_the_key_is_refused_before_any_event_is_forwarded() {
    for (case, protocol, request) in
        [("an A2A event stream", "a2a", a2a_stream()), ("an MCP stream", "mcp", mcp_call())]
    {
        let target = target(Post::EventStream).await;
        let answer = send(surface(protocol, &target.url, api_key_bravo()), request).await;
        assert_refused(case, &answer);
        assert_eq!(
            target
                .requests
                .load(Ordering::SeqCst),
            1,
            "{case}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_legacy_sse_fallback_whose_stream_lacks_the_key_is_refused() {
    let target = target(Post::MethodNotAllowedWithKey).await;
    let answer = send(surface("mcp", &target.url, api_key_bravo()), mcp_call()).await;
    assert_refused("a Legacy SSE stream without the key", &answer);
    assert_eq!(
        target
            .requests
            .load(Ordering::SeqCst),
        2,
        "the POST and the stream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn funds_held_for_a_target_response_without_the_key_are_voided_not_captured() {
    use crate::payments_ledger::SettleAction;
    use crate::payments_ledger::settlement::SettlementStatus;
    use crate::payments_ledger::settlement::tests::{Scripted, answer};
    use crate::proxy::handler::agent_pay_gate::{install_test_transport, tests::MockGate};

    let gateway = format!("response-auth-gate-{}", uuid::Uuid::new_v4());
    install_test_transport(
        &gateway,
        MockGate::answering(
            200,
            &[
                ("Payment-Receipt", "authorization-receipt"),
                ("payment-authorization", "auth-response-key"),
                ("payment-capture-deadline", "2099-01-01T00:00:00Z"),
            ],
            json!({}),
        ),
    );
    let settlement = Scripted::settling(vec![answer(SettlementStatus::Voided)]);
    crate::payments_ledger::settlement::install_test_client(&gateway, settlement.clone());
    let target = target(Post::EventStream).await;
    let mut paid = surface("mcp", &target.url, api_key_bravo());
    paid.target.payment_policy = Some(
        serde_json::from_value(json!({"type": "agent_pay", "payment_gateway_id": gateway,
            "payment_surface_id": "pay-1", "mcp_payment_triggers": {"mode": "all"}}))
        .unwrap(),
    );
    let (path, headers, body) = mcp_call();
    let credential = format!("proof-{}", uuid::Uuid::new_v4());
    let mut headers: Vec<(&str, &str)> = headers;
    headers.push(("payment-signature", &credential));

    assert_refused("a paid call", &send(paid, (path, headers, body)).await);

    let mut settled = Vec::new();
    for _ in 0..200 {
        settled = settlement
            .settled
            .lock()
            .unwrap()
            .iter()
            .map(|(_, action, _)| *action)
            .collect();
        if !settled.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(settled, vec![SettleAction::Void]);
    assert_eq!(
        target
            .requests
            .load(Ordering::SeqCst),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_whose_target_cannot_be_checked_is_refused_before_it_is_sent() {
    let target = target(Post::EventStream).await;
    let https = target
        .url
        .replacen("http://", "https://", 1);
    for (case, surface, request) in [
        ("mTLS settings that cannot be built", surface("a2a", &https, pinned_bravo()), a2a_stream()),
        ("mTLS on an http Target", surface("a2a", &target.url, pinned_bravo()), a2a_stream()),
        ("an API key on an MCP Proxy Target", surface("mcp", "proxy://weather", api_key_bravo()), mcp_call()),
    ] {
        assert_refused(case, &send(surface, request).await);
    }
    assert_eq!(
        target
            .requests
            .load(Ordering::SeqCst),
        0,
        "the Target was never sent a request"
    );
}
