//! The Legacy SSE fallback of the direct path posts a request to the session endpoint the
//! Target advertises. A request carrying a delegated credential in `_meta` goes there only when
//! that endpoint is under the Target base path; otherwise it is refused with `400
//! target_path_refused` and nothing is posted to it.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::audit::request_events::{RejectionReason, RejectionStage};
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};

const CALLER_KEY: &str = "caller-key-value";
const DELEGATED_KEY: &str = "maps-delegated-key";

/// A Legacy SSE server whose `{path}/sse`, for any `path`, advertises `endpoint` as its
/// session endpoint. It refuses a plain POST with `404`, answers a session POST on its stream,
/// and records the path and body of every session POST.
pub(crate) struct LegacyServer {
    pub(crate) url: String,
    session_posts: Arc<Mutex<Vec<(String, Value)>>>,
}

impl LegacyServer {
    /// The `tools/call` requests posted to the session endpoint, with the path each went to.
    pub(crate) fn tool_calls(&self) -> Vec<(String, Value)> {
        self.session_posts
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, message)| message["method"] == "tools/call")
            .cloned()
            .collect()
    }
}

pub(crate) async fn legacy_server(endpoint: &'static str) -> LegacyServer {
    use futures::StreamExt;
    let (events, receiver) = tokio::sync::mpsc::unbounded_channel::<String>();
    let receiver = Arc::new(tokio::sync::Mutex::new(Some(receiver)));
    let session_posts = Arc::new(Mutex::new(Vec::new()));
    let recorded = session_posts.clone();
    let app = axum::Router::new().fallback(
        move |method: axum::http::Method, uri: axum::http::Uri, body: axum::body::Bytes| {
            let recorded = recorded.clone();
            let events = events.clone();
            let receiver = receiver.clone();
            async move {
                if method == axum::http::Method::GET && uri.path().ends_with("/sse") {
                    let Some(receiver) = receiver.lock().await.take() else {
                        return StatusCode::CONFLICT.into_response();
                    };
                    let first = futures::stream::once(async move { format!("event: endpoint\ndata: {endpoint}\n\n") });
                    let rest = tokio_stream::wrappers::UnboundedReceiverStream::new(receiver)
                        .map(|message| format!("event: message\ndata: {message}\n\n"));
                    let body = first
                        .chain(rest)
                        .map(Ok::<_, std::convert::Infallible>);
                    return ([("content-type", "text/event-stream")], axum::body::Body::from_stream(body))
                        .into_response();
                }
                if !uri
                    .path()
                    .ends_with("/messages")
                {
                    return StatusCode::NOT_FOUND.into_response();
                }
                let message: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                recorded
                    .lock()
                    .unwrap()
                    .push((uri.path().to_string(), message.clone()));
                let _ =
                    events.send(json!({"jsonrpc": "2.0", "id": message["id"], "result": {"content": []}}).to_string());
                StatusCode::ACCEPTED.into_response()
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    LegacyServer { url, session_posts }
}

/// The Access Point of an MCP surface whose Target is `target`, authenticating its callers by
/// API key and injecting a delegated API key into `_meta.maps`.
async fn router(target: &str) -> (crate::state::MultiSurfaceProxyState, tempfile::TempDir) {
    use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
    let surface = serde_json::from_value(json!({
        "surface_id": "legacy-sse", "name": "Legacy SSE",
        "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp",
            "public": false,
            "caller_authentication": {"methods": [{"type": "api_key",
                "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "caller-key"}]}},
        "target": {"endpoint": target},
        "outbound_credentials": [{"credential_provider_id": "maps", "inject_as": {"type": "meta", "field": "maps"}}]
    }))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let secrets = crate::secrets::FilesystemSecretsStore::new_async(
        directory
            .path()
            .join("secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    for (secret_id, value) in [("caller-key", CALLER_KEY), ("maps-key", DELEGATED_KEY)] {
        crate::secrets::SecretsStore::create(
            &secrets,
            crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: value.into(),
                secret_type: "ApiKey".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
    }
    let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(secrets);
    let providers = FileSystemCredentialProviderStore::new(
        directory
            .path()
            .join("providers"),
    )
    .await
    .unwrap();
    providers
        .create(
            serde_json::from_value(json!({
                "id": "maps", "name": "Maps", "provider_id": "maps",
                "provider_type": "api_key", "api_key_secret_ref": "maps-key",
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let strategies = Arc::new(
        crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(
            directory
                .path()
                .join("strategies"),
        )
        .await
        .unwrap(),
    );
    let mut router = super::variant_routing_tests::router(surface);
    router.source_auth_middleware = Some(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        router
            .didauth_session_store
            .clone(),
        strategies,
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        Some(secrets.clone()),
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )));
    router.secrets_store = Some(secrets);
    router.credential_provider_store = Some(Arc::new(providers));
    router.delegation_vault_store = Some(Arc::new(
        crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap(),
    ));
    (router, directory)
}

/// Sends a legacy MCP tool call with the caller's API key and returns the status, the body
/// and every audit record it wrote.
async fn call(router: crate::state::MultiSurfaceProxyState) -> (StatusCode, String, Vec<DelegationAuditEvent>) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
        .header("x-api-key", CALLER_KEY)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "lookup", "arguments": {}}})
                .to_string(),
        ))
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

fn path_refusals(events: &[DelegationAuditEvent]) -> Vec<(RejectionStage, Option<u16>)> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                stage,
                reason: RejectionReason::TargetPathRefused,
                http_status,
                ..
            } => Some((*stage, *http_status)),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_endpoint_outside_the_target_base_path_gets_no_delegated_credential() {
    let server = legacy_server("/other-app/messages").await;
    let (router, _directory) = router(&format!("{}/base", server.url)).await;
    let (status, body, events) = call(router).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("target_path_refused"), "{body}");
    assert_eq!(path_refusals(&events), vec![(RejectionStage::Forward, Some(400))]);
    assert_eq!(server.tool_calls(), Vec::new(), "the request is not posted to the advertised endpoint");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_endpoint_under_the_target_base_path_gets_the_delegated_credential() {
    let server = legacy_server("/base/messages").await;
    let (router, _directory) = router(&format!("{}/base", server.url)).await;
    let (status, body, events) = call(router).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(path_refusals(&events), Vec::new());
    let calls = server.tool_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].0, "/base/messages");
    assert_eq!(calls[0].1["params"]["_meta"]["maps"], DELEGATED_KEY, "{}", calls[0].1);
}
