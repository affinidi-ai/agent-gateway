use axum::{body::Body, http::StatusCode, response::Response};
use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::egress::{EgressError, EgressPolicy, guarded_send_inner};

use super::types::{A2aProxy, A2aProxyBackend, A2aProxyStatus, CopilotDirectLineBackend, DirectLineCredentialMode};

const JSONRPC_PARSE_ERROR: i32 = -32700;
const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
const JSONRPC_INVALID_PARAMS: i32 = -32602;
const JSONRPC_INTERNAL_ERROR: i32 = -32603;
const JSONRPC_TARGET_UNAVAILABLE: i32 = -32020;
const JSONRPC_TARGET_TIMEOUT: i32 = -32021;

/// True when the request method is the **send** operation, in either protocol era.
///
/// This proxy fronts a non-A2A backend and supports only non-streaming send, so it
/// accepts `SendMessage` and nothing else, also in its v0.3 spelling `message/send`:
/// the surface serves A2A 1.0 only and checks only the JSON-RPC envelope, not the
/// A2A message shape, so a caller using the older spelling under
/// `A2A-Version: 1.0` keeps working. Hence the canonical
/// comparison rather than a raw string match.
///
/// Everything else is correctly refused, including the extended-card method: the
/// synthesized card declares `capabilities.extendedAgentCard = false`, so the
/// runtime must not answer it.
fn is_supported_proxy_method(method: &str) -> bool {
    crate::a2a::canonical_method(method) == "message/send"
}

pub async fn handle_a2a_proxy_request(
    proxy: &A2aProxy,
    body_bytes: &[u8],
    secrets_store: Option<&Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &str,
) -> Response {
    let allow_local = allow_local_a2a_dial();
    let request = match serde_json::from_slice::<Value>(body_bytes) {
        Ok(request) => request,
        Err(e) => {
            warn!(channel = channel_name, proxy_id = %proxy.id, error = %e, "A2A proxy received invalid JSON");
            return jsonrpc_error(None, JSONRPC_PARSE_ERROR, "Parse error");
        }
    };
    let request_id = request.get("id").cloned();

    if proxy.status == A2aProxyStatus::Disabled {
        warn!(channel = channel_name, proxy_id = %proxy.id, proxy_name = %proxy.name, "A2A proxy is disabled");
        return jsonrpc_error(request_id, JSONRPC_TARGET_UNAVAILABLE, "A2A proxy is disabled");
    }

    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_supported_proxy_method(method) {
        warn!(channel = channel_name, proxy_id = %proxy.id, method = ?crate::a2a::clip_for_log(method), "A2A proxy refused an unsupported method");
        return jsonrpc_error(request_id, JSONRPC_METHOD_NOT_FOUND, "Unsupported A2A method");
    }

    let message = match request
        .get("params")
        .and_then(|params| params.get("message"))
    {
        Some(message) => message,
        None => {
            warn!(channel = channel_name, proxy_id = %proxy.id, method = ?crate::a2a::clip_for_log(method), "A2A proxy refused a request without params.message");
            return jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "Missing params.message");
        }
    };
    let context_id = message
        .get("contextId")
        .cloned();
    let text = match extract_text(message) {
        Ok(text) => text,
        Err(message) => {
            warn!(channel = channel_name, proxy_id = %proxy.id, method = ?crate::a2a::clip_for_log(method), reason = message, "A2A proxy refused the message");
            return jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, message);
        }
    };

    match &proxy.backend {
        A2aProxyBackend::CopilotDirectLine(backend) => {
            let started = Instant::now();
            info!(
                channel = channel_name,
                proxy_id = %proxy.id,
                proxy_name = %proxy.name,
                backend_kind = "copilot_direct_line",
                credential_mode = ?backend.credential_mode,
                timeout_secs = backend.timeout_secs,
                operation = "message/send",
                "A2A proxy dispatch started"
            );
            match send_via_direct_line(proxy, backend, &text, secrets_store, channel_name, allow_local).await {
                Ok(parts) => {
                    info!(
                        channel = channel_name,
                        proxy_id = %proxy.id,
                        proxy_name = %proxy.name,
                        backend_kind = "copilot_direct_line",
                        result = "ok",
                        replies = parts.len(),
                        duration_ms = started.elapsed().as_millis(),
                        "A2A proxy dispatch completed"
                    );
                    jsonrpc_success(request_id, context_id, parts)
                }
                Err(A2aProxyRuntimeError::Timeout) => {
                    warn!(
                        channel = channel_name,
                        proxy_id = %proxy.id,
                        proxy_name = %proxy.name,
                        backend_kind = "copilot_direct_line",
                        result = "timeout",
                        duration_ms = started.elapsed().as_millis(),
                        "A2A proxy dispatch failed"
                    );
                    jsonrpc_error(request_id, JSONRPC_TARGET_TIMEOUT, "A2A proxy target timed out")
                }
                Err(A2aProxyRuntimeError::TargetUnavailable(message)) => {
                    warn!(
                        channel = channel_name,
                        proxy_id = %proxy.id,
                        proxy_name = %proxy.name,
                        backend_kind = "copilot_direct_line",
                        result = "target_unavailable",
                        duration_ms = started.elapsed().as_millis(),
                        "A2A proxy dispatch failed"
                    );
                    jsonrpc_error(request_id, JSONRPC_TARGET_UNAVAILABLE, &message)
                }
                Err(A2aProxyRuntimeError::Internal(message)) => {
                    error!(
                        channel = channel_name,
                        proxy_id = %proxy.id,
                        proxy_name = %proxy.name,
                        backend_kind = "copilot_direct_line",
                        result = "internal_error",
                        duration_ms = started.elapsed().as_millis(),
                        error = %message,
                        "A2A proxy dispatch failed"
                    );
                    jsonrpc_error(request_id, JSONRPC_INTERNAL_ERROR, "A2A proxy request failed")
                }
            }
        }
    }
}

#[derive(Debug)]
enum A2aProxyRuntimeError {
    TargetUnavailable(String),
    Timeout,
    Internal(String),
}

/// Dev/test escape hatch: when `AG_ALLOW_LOCAL_A2A_PROXY` is `1`/`true`/`yes`
/// (case-insensitive), the A2A-proxy dial may target a loopback / private
/// `base_url` so BDD and local development can point at a mock Direct Line
/// server. Cloud-metadata endpoints stay blocked and redirects are still
/// re-validated even when the hatch is on. Default off; never set in production.
fn allow_local_a2a_dial() -> bool {
    let enabled = std::env::var("AG_ALLOW_LOCAL_A2A_PROXY")
        .map(|v| {
            matches!(
                v.to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false);
    if enabled {
        warn!(
            "AG_ALLOW_LOCAL_A2A_PROXY is set: A2A-proxy egress permits loopback/private base URLs. \
             This is for dev/test only and must never be set in production."
        );
    }
    enabled
}

/// Dial a Direct Line endpoint through the shared SSRF egress guard.
///
/// `base_url` is attacker-influenceable (an operator or, on a no-auth deploy, an
/// unauthenticated caller sets it) and every request carries the tenant Direct
/// Line credential, so the dial uses [`EgressPolicy::Strict`]: the credential
/// can never reach loopback / RFC 1918 / link-local / cloud-metadata, and a
/// cross-origin redirect strips the `Authorization` header before re-sending.
/// When the local dev hatch is on, the exact URL is allow-listed so loopback is
/// permitted while metadata stays blocked and redirects stay re-validated.
async fn guarded_direct_line_dial(
    method: Method,
    url: String,
    bearer: &str,
    json_body: Option<Value>,
    timeout: Duration,
    allow_local: bool,
) -> Result<reqwest::Response, A2aProxyRuntimeError> {
    let mut headers = HeaderMap::new();
    let auth = HeaderValue::from_str(&format!("Bearer {bearer}"))
        .map_err(|e| A2aProxyRuntimeError::Internal(format!("invalid credential header: {e}")))?;
    headers.insert(AUTHORIZATION, auth);
    let body = match json_body {
        Some(value) => {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            Some(
                serde_json::to_vec(&value)
                    .map_err(|e| A2aProxyRuntimeError::Internal(format!("failed to serialize request body: {e}")))?,
            )
        }
        None => None,
    };
    let allowlist = allow_local.then(|| url.clone());
    match guarded_send_inner(method, &url, headers, body, EgressPolicy::Strict, timeout, allowlist.as_deref()).await {
        Ok(response) => Ok(response),
        Err(EgressError::Blocked(message)) => Err(A2aProxyRuntimeError::TargetUnavailable(format!(
            "A2A proxy target blocked by egress policy: {message}"
        ))),
        Err(EgressError::Dns(message)) => {
            Err(A2aProxyRuntimeError::TargetUnavailable(format!("A2A proxy target DNS resolution failed: {message}")))
        }
        Err(EgressError::Parse(message)) => {
            Err(A2aProxyRuntimeError::TargetUnavailable(format!("A2A proxy target URL is invalid: {message}")))
        }
        Err(EgressError::TooManyRedirects) => {
            Err(A2aProxyRuntimeError::TargetUnavailable("A2A proxy target redirected too many times".to_string()))
        }
        Err(EgressError::Http(e)) if e.is_timeout() => Err(A2aProxyRuntimeError::Timeout),
        Err(EgressError::Http(e)) => {
            Err(A2aProxyRuntimeError::TargetUnavailable(format!("A2A proxy request failed: {e}")))
        }
    }
}

fn extract_text(message: &Value) -> Result<String, &'static str> {
    let parts = message
        .get("parts")
        .and_then(Value::as_array)
        .ok_or("Missing message parts")?;
    if parts.is_empty() {
        return Err("message parts must not be empty");
    }

    let mut text_parts = Vec::with_capacity(parts.len());
    for part in parts {
        // A2A v0.3 tags each part with `kind` (`{"kind":"text","text":"…"}`).
        // v1.0 models `Part` as a `oneof { text | raw | url | data }`, so a
        // compliant 1.0 caller sends `{"text":"…"}` with **no** `kind` at all.
        // A part is text when its `kind` is `text`, or when it has no `kind`
        // and carries `text`.
        let is_text = match part
            .get("kind")
            .and_then(Value::as_str)
        {
            Some(kind) => kind == "text",
            None => part.get("text").is_some(),
        };
        if !is_text {
            return Err("A2A proxy supports text parts only");
        }
        let text = part
            .get("text")
            .and_then(Value::as_str)
            .ok_or("Text part is missing text")?;
        text_parts.push(text.to_string());
    }

    Ok(text_parts.join("\n"))
}

async fn send_via_direct_line(
    proxy: &A2aProxy,
    backend: &CopilotDirectLineBackend,
    text: &str,
    secrets_store: Option<&Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &str,
    allow_local: bool,
) -> Result<Vec<String>, A2aProxyRuntimeError> {
    let credential = resolve_direct_line_credential(proxy, backend, secrets_store, channel_name, allow_local).await?;
    let base_url = backend
        .base_url
        .trim_end_matches('/');
    let dial_timeout = Duration::from_secs(backend.timeout_secs.into());
    let deadline = Instant::now() + dial_timeout;

    let conversation_started = Instant::now();
    info!(channel = channel_name, proxy_id = %proxy.id, proxy_name = %proxy.name, backend_kind = "copilot_direct_line", operation = "conversations.create", timeout_secs = backend.timeout_secs, "Direct Line operation started");
    let conversation: Value = guarded_direct_line_dial(
        Method::POST,
        format!("{base_url}/conversations"),
        &credential,
        Some(serde_json::json!({})),
        dial_timeout,
        allow_local,
    )
    .await?
    .error_for_status()
    .map_err(|e| A2aProxyRuntimeError::TargetUnavailable(format!("Direct Line conversation creation failed: {e}")))?
    .json()
    .await
    .map_err(|e| A2aProxyRuntimeError::Internal(format!("Invalid Direct Line conversation response: {e}")))?;
    let conversation_id = conversation
        .get("conversationId")
        .and_then(Value::as_str)
        .ok_or_else(|| A2aProxyRuntimeError::Internal("Direct Line response omitted conversationId".to_string()))?;
    info!(channel = channel_name, proxy_id = %proxy.id, proxy_name = %proxy.name, backend_kind = "copilot_direct_line", operation = "conversations.create", result = "ok", conversation_id, duration_ms = conversation_started.elapsed().as_millis(), "Direct Line operation completed");

    let post_started = Instant::now();
    debug!(channel = channel_name, proxy_id = %proxy.id, conversation_id, backend_kind = "copilot_direct_line", operation = "activities.post", "Posting Direct Line activity");
    guarded_direct_line_dial(
        Method::POST,
        format!("{base_url}/conversations/{conversation_id}/activities"),
        &credential,
        Some(serde_json::json!({
            "type": "message",
            "from": { "id": "agent-gateway" },
            "text": text,
        })),
        dial_timeout,
        allow_local,
    )
    .await?
    .error_for_status()
    .map_err(|e| A2aProxyRuntimeError::TargetUnavailable(format!("Direct Line activity post failed: {e}")))?;
    info!(channel = channel_name, proxy_id = %proxy.id, proxy_name = %proxy.name, backend_kind = "copilot_direct_line", operation = "activities.post", result = "ok", conversation_id, duration_ms = post_started.elapsed().as_millis(), "Direct Line operation completed");

    let mut watermark: Option<String> = None;
    let poll_interval = Duration::from_millis(
        backend
            .poll_interval_ms
            .into(),
    );
    for attempt in 0..backend.max_poll_attempts {
        if Instant::now() >= deadline {
            return Err(A2aProxyRuntimeError::Timeout);
        }
        let poll_url = if let Some(watermark) = watermark.as_deref() {
            format!("{base_url}/conversations/{conversation_id}/activities?watermark={watermark}")
        } else {
            format!("{base_url}/conversations/{conversation_id}/activities")
        };
        let activities: Value =
            guarded_direct_line_dial(Method::GET, poll_url, &credential, None, dial_timeout, allow_local)
                .await?
                .error_for_status()
                .map_err(|e| A2aProxyRuntimeError::TargetUnavailable(format!("Direct Line activity poll failed: {e}")))?
                .json()
                .await
                .map_err(|e| A2aProxyRuntimeError::Internal(format!("Invalid Direct Line activities response: {e}")))?;

        watermark = activities
            .get("watermark")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or(watermark);

        let texts = collect_bot_texts(&activities);
        if !texts.is_empty() {
            info!(channel = channel_name, proxy_id = %proxy.id, backend_kind = "copilot_direct_line", operation = "activities.poll", result = "ok", conversation_id, attempt, replies = texts.len(), "Direct Line response collected");
            return Ok(texts);
        }

        tokio::time::sleep(poll_interval).await;
    }

    Err(A2aProxyRuntimeError::Timeout)
}

async fn resolve_direct_line_credential(
    proxy: &A2aProxy,
    backend: &CopilotDirectLineBackend,
    secrets_store: Option<&Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &str,
    allow_local: bool,
) -> Result<String, A2aProxyRuntimeError> {
    let store =
        secrets_store.ok_or_else(|| A2aProxyRuntimeError::Internal("Secrets store is not configured".to_string()))?;
    let secret = store
        .get_by_secret_id(&backend.secret_id)
        .await
        .map_err(|e| A2aProxyRuntimeError::Internal(format!("Failed to load Direct Line secret: {e}")))?
        .ok_or_else(|| A2aProxyRuntimeError::TargetUnavailable("Direct Line secret not found".to_string()))?;

    match backend.credential_mode {
        DirectLineCredentialMode::Secret => {
            info!(channel = channel_name, proxy_id = %proxy.id, credential_mode = "secret", "Using configured Direct Line credential for A2A proxy request");
            Ok(secret.value)
        }
        DirectLineCredentialMode::GenerateToken => {
            let base_url = backend
                .base_url
                .trim_end_matches('/');
            let token_started = Instant::now();
            info!(channel = channel_name, proxy_id = %proxy.id, credential_mode = "generate_token", operation = "tokens.generate", "Generating Direct Line token for A2A proxy request");
            let response: Value = guarded_direct_line_dial(
                Method::POST,
                format!("{base_url}/tokens/generate"),
                &secret.value,
                None,
                Duration::from_secs(backend.timeout_secs.into()),
                allow_local,
            )
            .await?
            .error_for_status()
            .map_err(|e| A2aProxyRuntimeError::TargetUnavailable(format!("Direct Line token generation failed: {e}")))?
            .json()
            .await
            .map_err(|e| A2aProxyRuntimeError::Internal(format!("Invalid Direct Line token response: {e}")))?;
            let token = response
                .get("token")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    A2aProxyRuntimeError::Internal("Direct Line token response omitted token".to_string())
                })?;
            info!(channel = channel_name, proxy_id = %proxy.id, credential_mode = "generate_token", operation = "tokens.generate", result = "ok", duration_ms = token_started.elapsed().as_millis(), "Direct Line token generated for A2A proxy request");
            Ok(token)
        }
    }
}

fn collect_bot_texts(activities: &Value) -> Vec<String> {
    activities
        .get("activities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|activity| {
            activity
                .get("type")
                .and_then(Value::as_str)
                == Some("message")
        })
        .filter(|activity| {
            activity
                .get("from")
                .and_then(|from| from.get("id"))
                .and_then(Value::as_str)
                != Some("agent-gateway")
        })
        .filter_map(|activity| {
            activity
                .get("text")
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
        .collect()
}

/// The A2A 1.0 `SendMessageResponse` for the backend's reply: the `message`
/// member of its `oneof payload`, with role `ROLE_AGENT` and one text part per
/// reply, without the 0.3 `kind` discriminators. An A2A-proxy surface serves
/// A2A 1.0 only, so this is the only reply shape it returns.
fn jsonrpc_success(
    id: Option<Value>,
    context_id: Option<Value>,
    texts: Vec<String>,
) -> Response {
    let parts: Vec<Value> = texts
        .into_iter()
        .map(|text| serde_json::json!({ "text": text }))
        .collect();
    let mut message = serde_json::json!({
        "messageId": uuid::Uuid::new_v4().to_string(),
        "role": "ROLE_AGENT",
        "parts": parts,
    });
    if let Some(context_id) = context_id
        && let Some(object) = message.as_object_mut()
    {
        object.insert("contextId".to_string(), context_id);
    }
    json_response(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "result": { "message": message },
    }))
}

fn jsonrpc_error(
    id: Option<Value>,
    code: i32,
    message: &str,
) -> Response {
    json_response(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
        }
    }))
}

fn json_response(value: Value) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .expect("JSON response builder")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_send_method_in_either_era() {
        // v0.3 and v1.0 spellings of the one operation this proxy supports.
        assert!(is_supported_proxy_method("message/send"));
        assert!(
            is_supported_proxy_method("SendMessage"),
            "the synthesized card advertises protocolVersion 1.0, so the v1.0 \
             spelling must be accepted"
        );
    }

    #[test]
    fn rejects_everything_the_proxy_cannot_serve_in_either_era() {
        // Streaming is advertised as unsupported (capabilities.streaming = false).
        assert!(!is_supported_proxy_method("message/stream"));
        assert!(!is_supported_proxy_method("SendStreamingMessage"));
        // Task methods are not implemented by this proxy.
        assert!(!is_supported_proxy_method("tasks/get"));
        assert!(!is_supported_proxy_method("GetTask"));
        assert!(!is_supported_proxy_method("tasks/list"));
        assert!(!is_supported_proxy_method("ListTasks"));
        // Extended card is advertised as unsupported
        // (capabilities.extendedAgentCard = false) — stay consistent with the card.
        assert!(!is_supported_proxy_method("agent/getAuthenticatedExtendedCard"));
        assert!(!is_supported_proxy_method("GetExtendedAgentCard"));
        // Junk and the dropped pre-0.2 alias.
        assert!(!is_supported_proxy_method("tasks/send"));
        assert!(!is_supported_proxy_method(""));
    }

    #[test]
    fn extract_text_joins_multiple_text_parts() {
        let message = serde_json::json!({
            "parts": [
                { "kind": "text", "text": "hello" },
                { "kind": "text", "text": "worker" }
            ]
        });

        assert_eq!(extract_text(&message).unwrap(), "hello\nworker");
    }

    #[test]
    fn extract_text_rejects_non_text_parts() {
        let message = serde_json::json!({
            "parts": [{ "kind": "file", "file": { "name": "a.txt" } }]
        });

        assert_eq!(extract_text(&message).unwrap_err(), "A2A proxy supports text parts only");
    }

    /// A2A v1.0 models `Part` as a `oneof { text | raw | url | data }`, so a
    /// compliant 1.0 caller sends a text part with no `kind` discriminator at
    /// all. The proxy's own synthesized card advertises `protocolVersion: "1.0"`
    /// and accepts the v1.0 `SendMessage` spelling, so refusing the v1.0 message
    /// body left it advertising a version it would not actually serve.
    #[test]
    fn extract_text_accepts_v1_0_parts_without_a_kind_discriminator() {
        let message = serde_json::json!({
            "parts": [{ "text": "hello" }, { "text": "worker" }]
        });

        assert_eq!(extract_text(&message).unwrap(), "hello\nworker");
    }

    /// Both eras can appear while callers migrate, including within one message.
    #[test]
    fn extract_text_accepts_mixed_era_text_parts() {
        let message = serde_json::json!({
            "parts": [{ "kind": "text", "text": "zero-three" }, { "text": "one-oh" }]
        });

        assert_eq!(extract_text(&message).unwrap(), "zero-three\none-oh");
    }

    /// A v1.0 non-text part carries `raw`, `url` or `data` instead of `text`,
    /// and must still be refused rather than silently treated as empty text.
    #[test]
    fn extract_text_rejects_v1_0_non_text_parts_without_a_kind() {
        for part in [
            serde_json::json!({ "url": "https://example.com/a.txt" }),
            serde_json::json!({ "data": { "any": "value" } }),
            serde_json::json!({ "raw": "aGVsbG8=" }),
        ] {
            let message = serde_json::json!({ "parts": [part] });
            assert_eq!(
                extract_text(&message).unwrap_err(),
                "A2A proxy supports text parts only",
                "a v1.0 non-text part must be refused"
            );
        }
    }

    #[tokio::test]
    async fn guarded_dial_blocks_loopback_base_url_without_sending_credential() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                hits_srv.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
            }
        });

        // Hatch OFF: the strict egress policy must block a loopback base_url so the
        // tenant credential never leaves the process.
        let result = guarded_direct_line_dial(
            Method::POST,
            format!("http://{addr}/v3/directline/conversations"),
            "super-secret-credential",
            Some(serde_json::json!({})),
            Duration::from_secs(2),
            false,
        )
        .await;

        assert!(
            matches!(result, Err(A2aProxyRuntimeError::TargetUnavailable(_))),
            "loopback base_url must be blocked, got {result:?}"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "credential-bearing request must never reach the blocked loopback host"
        );
        server.abort();
    }

    #[tokio::test]
    async fn guarded_dial_blocks_public_to_internal_redirect_without_leaking_credential() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Entry server stands in for a legitimate (allow-listed) base_url that
        // 302-redirects the dial to the cloud-metadata IP. The guard must
        // re-validate the redirect hop and block it — the credential-bearing
        // request must never be followed to the internal target.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let captured_srv = captured.clone();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                hits_srv.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let n = sock
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                *captured_srv.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
                let _ = sock.flush().await;
            }
        });

        // Hatch ON allow-lists ONLY the entry URL; the metadata redirect target is
        // never allow-listed and metadata is never relaxed, so the hop is blocked.
        let result = guarded_direct_line_dial(
            Method::POST,
            format!("http://{addr}/v3/directline/conversations"),
            "super-secret-credential",
            Some(serde_json::json!({})),
            Duration::from_secs(2),
            true,
        )
        .await;

        assert!(
            matches!(result, Err(A2aProxyRuntimeError::TargetUnavailable(_))),
            "public->internal redirect on the a2a path must be blocked, got {result:?}"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        // The entry hop is hit exactly once; the redirect to metadata is never
        // followed, so the internal target receives nothing.
        assert_eq!(hits.load(Ordering::SeqCst), 1, "only the entry hop should be contacted");
        let entry_request = captured
            .lock()
            .unwrap()
            .clone();
        assert!(entry_request.contains("super-secret-credential"), "sanity: the entry hop carries the credential");
        server.abort();
    }

    #[test]
    fn collect_bot_texts_ignores_gateway_echo() {
        let activities = serde_json::json!({
            "activities": [
                { "type": "message", "from": { "id": "agent-gateway" }, "text": "hello" },
                { "type": "message", "from": { "id": "bot" }, "text": "hi" },
                { "type": "typing", "from": { "id": "bot" } }
            ]
        });

        assert_eq!(collect_bot_texts(&activities), vec!["hi".to_string()]);
    }

    async fn reply_body(response: Response) -> Value {
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The reply is the A2A 1.0 `SendMessageResponse`: the `message` member of
    /// its payload, `ROLE_AGENT`, and text parts without the 0.3 `kind`.
    #[tokio::test]
    async fn the_reply_is_an_a2a_1_0_send_message_response() {
        let body = reply_body(jsonrpc_success(
            Some(serde_json::json!("req-1")),
            Some(serde_json::json!("ctx-1")),
            vec!["hello".to_string(), "world".to_string()],
        ))
        .await;

        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], "req-1");
        let message = &body["result"]["message"];
        assert_eq!(message["role"], "ROLE_AGENT");
        assert_eq!(message["contextId"], "ctx-1");
        assert!(
            message["messageId"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        assert_eq!(message["parts"], serde_json::json!([{ "text": "hello" }, { "text": "world" }]));
        assert!(
            body["result"]
                .get("kind")
                .is_none(),
            "no 0.3 discriminator on the result"
        );
        assert!(message.get("kind").is_none(), "no 0.3 discriminator on the message");
    }

    #[tokio::test]
    async fn the_reply_omits_a_context_id_the_caller_did_not_send() {
        let body = reply_body(jsonrpc_success(None, None, vec!["hi".to_string()])).await;
        assert_eq!(body["id"], Value::Null);
        assert!(
            body["result"]["message"]
                .get("contextId")
                .is_none()
        );
    }
}
