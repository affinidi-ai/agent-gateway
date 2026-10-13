use std::future::Future;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::config::ContinuationRuntime;
use super::embedded::EmbeddedContinuations;
use super::protected::{ContinuationCipher, ContinuationKey};
use super::service::ContinuationService;
use crate::mcp::error_codes;

/// An embedded runtime whose continuations expire after `ttl_secs`.
pub(crate) fn continuation_runtime(
    now: u64,
    ttl_secs: u64,
) -> Arc<ContinuationRuntime> {
    Arc::new(ContinuationRuntime {
        config: serde_json::from_value(json!({
            "deployment": "deployment", "ttl_secs": ttl_secs, "active_key": "key",
            "keys": [{"id": "key", "secret_id": "key-secret", "not_before": now - 1,
                "seal_until": now + 3600, "open_until": now + 4500}],
            "storage": {"backend": "embedded", "capacity": 32}
        }))
        .unwrap(),
        service: Arc::new(ContinuationService::new(
            ContinuationCipher::new(
                "deployment".into(),
                "key".into(),
                vec![ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap()],
            )
            .unwrap(),
            Arc::new(EmbeddedContinuations::new(32).unwrap()),
        )),
    })
}

/// `state` with its last byte changed, so its seal no longer verifies.
pub(crate) fn tamper(state: &str) -> String {
    let mut bytes = state.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' {
        b'B'
    } else {
        b'A'
    };
    String::from_utf8(bytes).unwrap()
}

/// `pending` re-sent with `id`, resuming `request_state` when given.
pub(crate) fn retry(
    pending: &Value,
    id: &str,
    request_state: Option<&str>,
) -> Value {
    let mut retry = pending.clone();
    retry["id"] = json!(id);
    if let Some(request_state) = request_state {
        retry["params"]["requestState"] = json!(request_state);
    }
    retry
}

/// Sends tampered, cross-user, incapable and expired retries of `pending`, a
/// `tools/call` that requires consent, and asserts each is refused. `send`
/// posts a message as the caller, or with `bearer` when given, against the
/// runtime it is passed. Returns the continuation state issued to the caller,
/// still resumable, for path-specific replays.
pub(crate) async fn assert_rejected_retries<F, Fut>(
    pending: &Value,
    runtime: Arc<ContinuationRuntime>,
    other_principal: String,
    now: u64,
    send: F,
) -> String
where
    F: Fn(Value, Option<String>, Arc<ContinuationRuntime>) -> Fut,
    Fut: Future<Output = (StatusCode, Value)>,
{
    let (_, issued) = send(retry(pending, "negatives", None), None, runtime.clone()).await;
    let issued_state = issued["result"]["requestState"]
        .as_str()
        .expect("a continuation to replay")
        .to_string();

    let tampered = retry(pending, "tampered", Some(&tamper(&issued_state)));
    let (status, body) = send(tampered, None, runtime.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "tampered: {body}");
    assert_eq!(body["error"]["code"], error_codes::INVALID_PARAMS, "tampered: {body}");
    assert_eq!(body["id"], "tampered");

    let cross_user = retry(pending, "cross-user", Some(&issued_state));
    let (status, body) = send(cross_user, Some(other_principal), runtime.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "cross-user: {body}");
    assert_eq!(body["error"]["code"], -32001, "cross-user: {body}");

    let mut incapable = retry(pending, "incapable", None);
    incapable["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
    let (status, body) = send(incapable, None, runtime).await;
    assert_eq!(body["error"]["code"], error_codes::MISSING_REQUIRED_CLIENT_CAPABILITY, "incapable: {status} {body}");
    assert!(body.get("result").is_none(), "incapable: {body}");

    let short = continuation_runtime(now, 1);
    let (_, short_issued) = send(retry(pending, "short", None), None, short.clone()).await;
    let short_state = short_issued["result"]["requestState"]
        .as_str()
        .expect("a short-lived continuation")
        .to_string();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    let (status, body) = send(retry(pending, "expired", Some(&short_state)), None, short).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "expired: {body}");
    assert_eq!(body["error"]["code"], error_codes::INVALID_PARAMS, "expired: {body}");

    issued_state
}
