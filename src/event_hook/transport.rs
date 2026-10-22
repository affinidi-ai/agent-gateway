use std::time::Duration;

use reqwest::StatusCode;

use super::config::{ENV_HOOK_SECRET, ENV_HOOK_URL, HookSecret};

const REJECTION_BODY_LIMIT: usize = 4 * 1024;
const REASON_MAX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    Accepted,
    Rejected { status: u16, reason: Option<String> },
    Retry { reason: String },
}

impl HookOutcome {
    pub fn retry(reason: impl Into<String>) -> Self {
        HookOutcome::Retry { reason: reason.into() }
    }
}

/// POSTs `body` as JSON to the operator-configured endpoint (loopback and
/// private addresses allowed, cloud metadata blocked, redirects not followed).
pub async fn post_json(
    url: &str,
    body: &str,
    timeout: Duration,
    secret: Option<&HookSecret>,
) -> HookOutcome {
    let raw_url = url.to_string();
    let (client, target) =
        match tokio::task::spawn_blocking(move || crate::egress::pinned_forward_client(&raw_url, timeout)).await {
            Ok(Ok(pinned)) => pinned,
            Ok(Err(e)) => return HookOutcome::retry(e.to_string()),
            Err(e) => return HookOutcome::retry(format!("egress task failed: {e}")),
        };
    let request = client
        .post(target.url)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
    let request = match sign_request(request, secret, body.as_bytes()) {
        Ok(request) => request,
        Err(reason) => return HookOutcome::retry(reason),
    };
    match request
        .body(body.to_string())
        .send()
        .await
    {
        // `without_url`: the configured URL is operator input and stays out of logs.
        Err(e) => HookOutcome::retry(format!("request failed: {}", e.without_url())),
        Ok(response) => classify(response, secret.is_some()).await,
    }
}

fn sign_request(
    request: reqwest::RequestBuilder,
    secret: Option<&HookSecret>,
    body: &[u8],
) -> Result<reqwest::RequestBuilder, String> {
    let Some(secret) = secret else {
        return Ok(request);
    };
    let timestamp = chrono::Utc::now()
        .timestamp()
        .to_string();
    let signature = crate::integrations::webhook_signing::sign_timestamped_payload(secret.expose(), &timestamp, body)
        .map_err(|e| format!("cannot sign request: {e:#}"))?;
    Ok(request
        .header("X-Webhook-Timestamp", timestamp)
        .header("X-Webhook-Signature-256", format!("sha256={signature}")))
}

/// GETs `url` through the same pinned client as [`post_json`], signing the
/// empty body when a secret is set, and returns the status and at most
/// `limit` bytes of the body. The URL stays out of every error.
pub async fn get_limited(
    url: &str,
    timeout: Duration,
    secret: Option<&HookSecret>,
    limit: usize,
) -> Result<(StatusCode, Vec<u8>), String> {
    let raw_url = url.to_string();
    let (client, target) = tokio::task::spawn_blocking(move || crate::egress::pinned_forward_client(&raw_url, timeout))
        .await
        .map_err(|e| format!("egress task failed: {e}"))?
        .map_err(|e| e.to_string())?;
    let request = sign_request(client.get(target.url), secret, b"")?;
    let mut response = request
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e.without_url()))?;
    let status = response.status();
    if !status.is_success() {
        return Ok((status, Vec::new()));
    }
    let body = read_limited(&mut response, limit).await?;
    Ok((status, body))
}

async fn classify(
    mut response: reqwest::Response,
    signed: bool,
) -> HookOutcome {
    let status = response.status();
    if status.is_success() {
        return HookOutcome::Accepted;
    }
    if is_auth_failure(status) {
        let hint = if signed {
            format!(
                "the receiver rejected the signature; the key in `{ENV_HOOK_SECRET}` must match the key the receiver verifies with"
            )
        } else {
            format!("the receiver requires a signature; set `{ENV_HOOK_SECRET}` to the key the receiver verifies with")
        };
        return HookOutcome::retry(format!("hook answered {status}: {hint}"));
    }
    if status.is_redirection() {
        return HookOutcome::Rejected {
            status: status.as_u16(),
            reason: Some(format!(
                "the receiver answered with a redirect; redirects are not followed, set `{ENV_HOOK_URL}` to the final URL"
            )),
        };
    }
    if is_retryable(status) {
        return HookOutcome::retry(format!("hook answered {status}"));
    }
    if status.is_client_error() {
        let body = read_limited(&mut response, REJECTION_BODY_LIMIT)
            .await
            .unwrap_or_default();
        let parsed: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
        let field = |name: &str| {
            parsed
                .as_ref()
                .and_then(|value| value.get(name))
                .and_then(|value| value.as_str())
                .map(str::to_string)
        };
        return HookOutcome::Rejected {
            status: status.as_u16(),
            reason: field("reason").and_then(|reason| sanitize_reason(&reason)),
        };
    }
    HookOutcome::retry(format!("hook answered {status}"))
}

/// 401/403 are retried like an outage, so a secret mismatch stays loud.
fn is_auth_failure(status: StatusCode) -> bool {
    matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
}

/// Server errors, timeouts and throttling are transient even though some are
/// 4xx. Every other 4xx is the hook refusing the event.
fn is_retryable(status: StatusCode) -> bool {
    status.is_server_error()
        || matches!(status, StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS)
}

async fn read_limited(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("failed to read response: {}", e.without_url()))?
    {
        if body.len() + chunk.len() > limit {
            return Err(format!("response exceeds {limit} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub fn sanitize_reason(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= REASON_MAX_LEN
        && trimmed
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    valid.then(|| trimmed.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{Router, http::HeaderMap, routing::any};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub(crate) struct Captured {
        pub(crate) method: String,
        pub(crate) headers: HeaderMap,
        pub(crate) body: String,
    }

    pub(crate) async fn serve(
        status: u16,
        response_body: &'static str,
    ) -> (String, Arc<Mutex<Vec<Captured>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = captured.clone();
        let app = Router::new().route(
            "/{*path}",
            any(move |method: axum::http::Method, headers: HeaderMap, body: String| {
                let sink = sink.clone();
                async move {
                    sink.lock()
                        .unwrap()
                        .push(Captured {
                            method: method.to_string(),
                            headers,
                            body,
                        });
                    (axum::http::StatusCode::from_u16(status).unwrap(), response_body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        (format!("http://{addr}/hook"), captured)
    }

    #[tokio::test]
    async fn without_a_secret_the_body_is_posted_unsigned() {
        let (url, captured) = serve(204, "").await;
        let outcome = post_json(&url, r#"{"a":1}"#, Duration::from_secs(5), None).await;
        assert_eq!(outcome, HookOutcome::Accepted);

        let request = captured.lock().unwrap()[0].clone();
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, r#"{"a":1}"#);
        assert_eq!(request.headers["content-type"], "application/json");
        for name in ["x-webhook-signature-256", "x-webhook-timestamp", "authorization"] {
            assert!(
                request
                    .headers
                    .get(name)
                    .is_none(),
                "{name} must not be sent"
            );
        }
    }

    #[tokio::test]
    async fn client_errors_are_rejections_with_sanitized_reason() {
        let (url, _) = serve(422, r#"{"reason":"forbidden","message":"not allowed"}"#).await;
        assert_eq!(
            post_json(&url, "{}", Duration::from_secs(5), None).await,
            HookOutcome::Rejected {
                status: 422,
                reason: Some("forbidden".into()),
            }
        );
    }

    #[tokio::test]
    async fn timeouts_throttling_and_server_errors_are_retryable() {
        for status in [408u16, 425, 429, 500, 502, 503] {
            let (url, _) = serve(status, r#"{"reason":"unavailable"}"#).await;
            assert_eq!(
                post_json(&url, "{}", Duration::from_secs(5), None).await,
                HookOutcome::retry(format!("hook answered {}", StatusCode::from_u16(status).unwrap())),
                "status {status}"
            );
        }
    }

    #[tokio::test]
    async fn other_client_errors_are_permanent_rejections() {
        for status in [400u16, 404, 409, 410, 422] {
            let (url, _) = serve(status, "").await;
            let outcome = post_json(&url, "{}", Duration::from_secs(5), None).await;
            assert!(
                matches!(outcome, HookOutcome::Rejected { status: got, .. } if got == status),
                "status {status}: {outcome:?}"
            );
        }
    }

    #[tokio::test]
    async fn redirects_are_permanent_rejections_with_a_redactor_safe_hint() {
        for status in [301u16, 302, 307, 308] {
            let (url, captured) = serve(status, "").await;
            match post_json(&url, "{}", Duration::from_secs(5), None).await {
                HookOutcome::Rejected { status: got, reason } => {
                    assert_eq!(got, status);
                    let reason = reason.expect("a hint");
                    assert!(reason.contains("redirects are not followed"), "{reason}");
                    assert!(reason.contains("AG_EVENT_HOOK_URL"), "{reason}");
                    let logged = example_redactor()
                        .redact(&reason)
                        .into_owned();
                    assert_eq!(logged, reason, "mangled by the log redactor: {logged}");
                }
                other => panic!("status {status}: {other:?}"),
            }
            assert_eq!(captured.lock().unwrap().len(), 1);
        }
    }

    fn example_redactor() -> Arc<crate::observability::LogRedactor> {
        let example: serde_json::Value =
            serde_json::from_str(include_str!("../../config/examples/gateway.example.json")).unwrap();
        let config: crate::config::types::LogRedactionConfig =
            serde_json::from_value(example["logging"]["redaction"].clone()).unwrap();
        assert!(config.enabled && !config.rules.is_empty());
        crate::observability::LogRedactor::from_config(&config)
    }

    #[test]
    fn the_example_redactor_masks_an_unquoted_secret_variable_name() {
        let unquoted =
            "hook answered 401 Unauthorized: check that AG_EVENT_HOOK_SECRET matches the key the receiver uses";
        assert_ne!(example_redactor().redact(unquoted), unquoted, "the test must be able to detect the problem");
    }

    #[tokio::test]
    async fn auth_failures_are_retryable_and_name_the_secret_in_the_reason() {
        for (secret, hint) in [(Some(test_secret()), "rejected the signature"), (None, "requires a signature")] {
            for status in [401u16, 403] {
                let (url, _) = serve(status, "").await;
                match post_json(&url, "{}", Duration::from_secs(5), secret.as_ref()).await {
                    HookOutcome::Retry { reason } => {
                        assert!(reason.contains(&status.to_string()), "{reason}");
                        assert!(reason.contains(hint), "{reason}");
                        assert!(reason.contains("AG_EVENT_HOOK_SECRET"), "{reason}");
                        assert!(reason.contains("the receiver"), "{reason}");
                        let logged = example_redactor()
                            .redact(&reason)
                            .into_owned();
                        assert_eq!(logged, reason, "mangled by the log redactor: {logged}");
                        assert!(!reason.contains(TEST_SECRET), "the secret appears in the failure reason");
                    }
                    other => panic!("status {status}: {other:?}"),
                }
            }
        }
    }

    const TEST_SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn test_secret() -> HookSecret {
        HookSecret::new(TEST_SECRET).unwrap()
    }

    #[tokio::test]
    async fn with_a_secret_the_signature_verifies_against_the_exact_body_sent() {
        let (url, captured) = serve(204, "").await;
        let body = r#"{"event":"connection_point.created","note":"  spaced \u00e9  "}"#;
        let secret = test_secret();
        assert_eq!(post_json(&url, body, Duration::from_secs(5), Some(&secret)).await, HookOutcome::Accepted);

        let request = captured.lock().unwrap()[0].clone();
        assert_eq!(request.body, body);
        let timestamp = request.headers["x-webhook-timestamp"]
            .to_str()
            .unwrap();
        let sent = request.headers["x-webhook-signature-256"]
            .to_str()
            .unwrap();
        let expected = crate::integrations::webhook_signing::sign_timestamped_payload(
            TEST_SECRET,
            timestamp,
            request.body.as_bytes(),
        )
        .unwrap();
        assert_eq!(sent, format!("sha256={expected}"));
        let now = chrono::Utc::now().timestamp();
        assert!(
            (now - timestamp
                .parse::<i64>()
                .unwrap())
            .abs()
                < 30
        );

        let other =
            crate::integrations::webhook_signing::sign_timestamped_payload(TEST_SECRET, timestamp, b"{}").unwrap();
        assert_ne!(sent, format!("sha256={other}"));
    }

    #[tokio::test]
    async fn loopback_is_allowed_but_cloud_metadata_is_blocked() {
        let outcome = post_json("http://169.254.169.254/latest/meta-data", "{}", Duration::from_secs(2), None).await;
        assert!(matches!(outcome, HookOutcome::Retry { ref reason } if reason.contains("blocked")), "{outcome:?}");

        let (url, captured) = serve(204, "").await;
        assert!(url.starts_with("http://127.0.0.1:"));
        assert_eq!(post_json(&url, "{}", Duration::from_secs(5), None).await, HookOutcome::Accepted);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn connection_refused_is_retryable_and_does_not_echo_the_url() {
        let url = "http://127.0.0.1:1/secret-path".to_string();
        match post_json(&url, "{}", Duration::from_secs(2), None).await {
            HookOutcome::Retry { reason } => {
                assert!(!reason.contains("secret-path"), "the hook URL appears in the failure reason");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reason_sanitization() {
        assert_eq!(sanitize_reason("not_eligible"), Some("not_eligible".into()));
        assert_eq!(sanitize_reason("Not Eligible"), None);
        assert_eq!(sanitize_reason(&"a".repeat(65)), None);
        assert_eq!(sanitize_reason(""), None);
    }
}
