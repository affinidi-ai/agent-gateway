//! Traffic mirroring send path shared by the direct, `fabric://` and owned MCP
//! Proxy forwards.
//!
//! A mirror endpoint gets the same egress guard as the Target: cloud metadata
//! is refused, the connection is pinned to the address vetted at send time and
//! redirects are not followed. Loopback and private addresses stay allowed.

use std::time::Duration;

use bytes::Bytes;
use reqwest::Method;
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};

use crate::config::MirrorConfig;
use crate::egress::{self, EgressError, PinnedTarget};
use crate::http_client::GATEWAY_USER_AGENT;

/// One copy of a live request, addressed to a surface's mirror endpoint.
pub(crate) struct MirrorRequest {
    endpoint: String,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    timeout: Duration,
}

impl MirrorRequest {
    /// Copy of a request with `method` and `body`, aimed at the endpoint of `config`.
    pub(crate) fn new(
        config: &MirrorConfig,
        method: Method,
        body: impl Into<Bytes>,
    ) -> Self {
        Self {
            endpoint: config.endpoint.clone(),
            method,
            headers: HeaderMap::new(),
            body: body.into(),
            timeout: Duration::from_secs(config.timeout_secs),
        }
    }

    /// Add a header. A name or value that is not a valid header is skipped: the
    /// copy is best effort, and callers pass headers already taken from a parsed request.
    pub(crate) fn header(
        mut self,
        name: &str,
        value: impl AsRef<[u8]>,
    ) -> Self {
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_bytes(value.as_ref()))
        {
            self.headers
                .append(name, value);
        }
        self
    }

    /// Copy every header of `source` that `keep` accepts.
    pub(crate) fn headers_from(
        mut self,
        source: &HeaderMap,
        keep: impl Fn(&str) -> bool,
    ) -> Self {
        for (name, value) in source {
            if keep(name.as_str()) {
                self = self.header(name.as_str(), value.as_bytes());
            }
        }
        self
    }

    /// Mark the copy as a mirror, and tie it to the live request's trace when there is one.
    pub(crate) fn mirrored(
        self,
        trace_id: Option<&str>,
    ) -> Self {
        let marked = self.header("X-Mirrored-Request", "true");
        match trace_id {
            Some(trace_id) => marked.header("X-Gateway-Trace-Id", format!("{trace_id}-mirror")),
            None => marked,
        }
    }
}

/// Why a mirror request did not complete. No variant carries the endpoint URL.
#[derive(Debug)]
pub(crate) enum MirrorError {
    /// The egress guard refused the endpoint; nothing was sent.
    Refused(EgressError),
    /// The gateway failed before it could vet the endpoint; nothing was sent.
    Internal(String),
    /// The request was sent and failed.
    Send(reqwest::Error),
}

impl MirrorError {
    /// Short class of the failure, safe to show a caller.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            MirrorError::Refused(EgressError::Dns(_)) => "DNS resolution failed",
            MirrorError::Refused(_) => "blocked by egress policy",
            MirrorError::Internal(_) => "internal error",
            MirrorError::Send(e) if e.is_timeout() => "timeout",
            MirrorError::Send(e) if e.is_connect() => "connection refused",
            MirrorError::Send(e) if e.is_request() => "invalid request",
            MirrorError::Send(_) => "network error",
        }
    }
}

impl std::fmt::Display for MirrorError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            MirrorError::Refused(e) => write!(f, "{e}"),
            MirrorError::Internal(reason) => write!(f, "mirror could not be vetted: {reason}"),
            MirrorError::Send(e) => write!(f, "mirror request failed: {e}"),
        }
    }
}

impl std::error::Error for MirrorError {}

/// Whether a request is mirrored at `percentage` (0 never, 100 and above always).
pub(crate) fn selected(percentage: u8) -> bool {
    use rand::Rng;
    match percentage {
        0 => false,
        100..=u8::MAX => true,
        p => rand::rng().random_range(0..100) < p,
    }
}

/// Send `request` to its endpoint through the egress guard and return the status.
///
/// DNS is resolved once, here, and shares the request's timeout; the response
/// body is discarded.
pub(crate) async fn send(request: MirrorRequest) -> Result<StatusCode, MirrorError> {
    let MirrorRequest {
        endpoint,
        method,
        mut headers,
        body,
        timeout,
    } = request;
    let (client, target) = vet(move || egress::pinned_forward_client(&endpoint, timeout), timeout).await?;
    headers
        .entry(USER_AGENT)
        .or_insert(HeaderValue::from_static(GATEWAY_USER_AGENT));
    let response = client
        .request(method, target.url)
        .headers(headers)
        .body(body)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| MirrorError::Send(e.without_url()))?;
    Ok(response.status())
}

/// Run the blocking vetting step off the async runtime, giving up after `timeout`.
///
/// A resolver that does not answer in time refuses the mirror, as a failed lookup does. The
/// lookup itself cannot be cancelled and holds its blocking thread until the OS resolver returns.
async fn vet(
    vetting: impl FnOnce() -> Result<(reqwest::Client, PinnedTarget), EgressError> + Send + 'static,
    timeout: Duration,
) -> Result<(reqwest::Client, PinnedTarget), MirrorError> {
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(vetting)).await {
        Err(_) => Err(MirrorError::Refused(EgressError::Dns(format!("no answer within {}s", timeout.as_secs())))),
        Ok(Err(e)) => Err(MirrorError::Internal(format!("egress task failed: {e}"))),
        Ok(Ok(Err(EgressError::Http(e)))) => Err(MirrorError::Internal(format!("egress client not built: {e}"))),
        Ok(Ok(Err(refusal))) => Err(MirrorError::Refused(refusal)),
        Ok(Ok(Ok(vetted))) => Ok(vetted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn config(endpoint: &str) -> MirrorConfig {
        serde_json::from_value(serde_json::json!({ "endpoint": endpoint, "timeout_secs": 5 })).expect("mirror config")
    }

    fn request(endpoint: &str) -> MirrorRequest {
        MirrorRequest::new(&config(endpoint), Method::POST, Bytes::from_static(b"payload"))
    }

    async fn serve_once(response: String) -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("addr");
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .expect("accept");
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !String::from_utf8_lossy(&seen).contains("payload") {
                let n = socket
                    .read(&mut buf)
                    .await
                    .expect("read");
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
            }
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write");
            let _ = tx.send(String::from_utf8_lossy(&seen).into_owned());
        });
        (addr, rx)
    }

    #[test]
    fn selected_never_at_zero_and_always_at_100_and_above() {
        assert!((0..200).all(|_| !selected(0)));
        assert!((0..200).all(|_| selected(100)));
        assert!((0..200).all(|_| selected(255)));
    }

    #[test]
    fn selected_at_fifty_percent_yields_both_outcomes() {
        let outcomes: Vec<bool> = (0..400)
            .map(|_| selected(50))
            .collect();
        assert!(outcomes.contains(&true) && outcomes.contains(&false));
    }

    #[tokio::test]
    async fn send_refuses_cloud_metadata_endpoints_without_sending() {
        for endpoint in [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.170.2/v2/credentials",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://[::ffff:169.254.169.254]/",
            "http://[fd00:ec2::254]/",
        ] {
            match send(request(endpoint)).await {
                Err(MirrorError::Refused(EgressError::Blocked(_))) => {}
                other => panic!("expected Refused(Blocked) for {endpoint}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn send_refuses_non_http_unparseable_and_credentialed_endpoints() {
        for endpoint in ["ftp://example.com/mirror", "not a url", "http://user:pass@example.com/mirror"] {
            match send(request(endpoint)).await {
                Err(MirrorError::Refused(EgressError::Blocked(_))) => {}
                other => panic!("expected Refused(Blocked) for {endpoint}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn each_refusal_names_the_rule_that_refused_the_endpoint() {
        for (endpoint, reason) in [
            ("http://169.254.169.254/latest/meta-data/", "cloud-provider metadata"),
            ("http://[fd00:ec2::254]/", "cloud-provider metadata"),
            ("http://user:pass@example.com/mirror", "embedded credentials"),
            ("ftp://example.com/mirror", "scheme"),
        ] {
            let error = send(request(endpoint))
                .await
                .expect_err("refused");
            assert!(
                error
                    .to_string()
                    .contains(reason),
                "{endpoint}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn send_identifies_the_gateway_unless_the_caller_names_a_user_agent() {
        let (addr, seen) = serve_once("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n".into()).await;
        send(request(&format!("http://{addr}/mirror")))
            .await
            .expect("sent");
        let raw = seen
            .await
            .expect("request seen")
            .to_ascii_lowercase();
        assert!(raw.contains("user-agent: affinidi-fabric-agent-gateway/1.0"), "{raw}");

        let (addr, seen) = serve_once("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n".into()).await;
        send(request(&format!("http://{addr}/mirror")).header("User-Agent", "caller-agent/2"))
            .await
            .expect("sent");
        let raw = seen
            .await
            .expect("request seen")
            .to_ascii_lowercase();
        assert!(raw.contains("user-agent: caller-agent/2"), "{raw}");
        assert!(!raw.contains("affinidi-fabric-agent-gateway"), "{raw}");
    }

    #[tokio::test]
    async fn send_reports_an_unresolvable_host_as_dns() {
        match send(request("http://mirror.invalid/")).await {
            Err(MirrorError::Refused(EgressError::Dns(_))) => {}
            other => panic!("expected Refused(Dns), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_reaches_a_loopback_server_with_method_header_and_body() {
        let (addr, seen) = serve_once("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n".into()).await;
        let request = request(&format!("http://{addr}/mirror")).header("X-Mirrored-Request", "true");
        let status = send(request)
            .await
            .expect("loopback mirror is sent");
        assert_eq!(status, StatusCode::NO_CONTENT);
        let raw = seen
            .await
            .expect("server saw the request")
            .to_ascii_lowercase();
        assert!(raw.starts_with("post /mirror "), "{raw}");
        assert!(raw.contains("x-mirrored-request: true"), "{raw}");
        assert!(raw.ends_with("payload"), "{raw}");
    }

    #[tokio::test]
    async fn send_returns_a_redirect_without_following_it() {
        let target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let target_addr = target
            .local_addr()
            .expect("addr");
        let (addr, _) = serve_once(format!(
            "HTTP/1.1 302 Found\r\nlocation: http://{target_addr}/followed\r\ncontent-length: 0\r\n\r\n"
        ))
        .await;
        let status = send(request(&format!("http://{addr}/mirror")))
            .await
            .expect("redirect is returned");
        assert_eq!(status, StatusCode::FOUND);
        let followed = tokio::time::timeout(Duration::from_millis(300), target.accept()).await;
        assert!(followed.is_err(), "the redirect target must not be contacted");
    }

    #[tokio::test]
    async fn refusal_display_and_kind_leave_out_the_endpoint_path() {
        let err = send(request("http://169.254.169.254/latest/secret-path"))
            .await
            .expect_err("metadata refused");
        assert!(
            !err.to_string()
                .contains("secret-path"),
            "{err}"
        );
        assert_eq!(err.kind(), "blocked by egress policy");
        let dns = send(request("http://mirror.invalid/secret-path"))
            .await
            .expect_err("unresolvable");
        assert!(
            !dns.to_string()
                .contains("secret-path"),
            "{dns}"
        );
        assert_eq!(dns.kind(), "DNS resolution failed");
    }

    #[tokio::test]
    async fn send_failure_names_a_connection_refused_kind_without_the_url() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = closed
            .local_addr()
            .expect("addr");
        drop(closed);
        let err = send(request(&format!("http://{addr}/secret-path")))
            .await
            .expect_err("nothing listens");
        assert!(matches!(err, MirrorError::Send(_)), "{err:?}");
        assert_eq!(err.kind(), "connection refused");
    }

    #[test]
    fn an_internal_failure_is_not_called_a_policy_refusal() {
        let error = MirrorError::Internal("egress task failed".into());
        assert_eq!(error.kind(), "internal error");
        assert!(
            error
                .to_string()
                .contains("egress task failed"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_resolver_that_outlives_the_timeout_refuses_the_mirror_as_dns() {
        let slow = || -> Result<(reqwest::Client, PinnedTarget), EgressError> {
            std::thread::sleep(Duration::from_millis(400));
            Err(EgressError::Dns("late".into()))
        };
        match vet(slow, Duration::from_millis(50)).await {
            Err(error @ MirrorError::Refused(EgressError::Dns(_))) => assert_eq!(error.kind(), "DNS resolution failed"),
            other => panic!("expected a DNS refusal, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn a_vetting_task_that_panics_fails_closed_as_internal() {
        let panics = || -> Result<(reqwest::Client, PinnedTarget), EgressError> { panic!("resolver crashed") };
        match vet(panics, Duration::from_secs(5)).await {
            Err(error @ MirrorError::Internal(_)) => assert_eq!(error.kind(), "internal error"),
            other => panic!("expected Internal, got {:?}", other.err()),
        }
    }

    #[test]
    fn headers_from_copies_only_the_headers_the_filter_keeps() {
        let mut source = HeaderMap::new();
        source.insert("x-keep", HeaderValue::from_static("yes"));
        source.insert("authorization", HeaderValue::from_static("Bearer secret"));
        let request = request("http://127.0.0.1:1/").headers_from(&source, |name| name != "authorization");
        assert_eq!(
            request
                .headers
                .get("x-keep")
                .map(HeaderValue::as_bytes),
            Some(&b"yes"[..])
        );
        assert!(
            request
                .headers
                .get("authorization")
                .is_none()
        );
    }

    #[test]
    fn mirrored_marks_the_copy_and_ties_it_to_the_live_trace() {
        let traced = request("http://127.0.0.1:1/").mirrored(Some("trace-1"));
        assert_eq!(
            traced
                .headers
                .get("x-mirrored-request")
                .map(HeaderValue::as_bytes),
            Some(&b"true"[..])
        );
        assert_eq!(
            traced
                .headers
                .get("x-gateway-trace-id")
                .map(HeaderValue::as_bytes),
            Some(&b"trace-1-mirror"[..])
        );
        let untraced = request("http://127.0.0.1:1/").mirrored(None);
        assert!(
            untraced
                .headers
                .get("x-mirrored-request")
                .is_some()
        );
        assert!(
            untraced
                .headers
                .get("x-gateway-trace-id")
                .is_none()
        );
    }
}
