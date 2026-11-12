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
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::config::MirrorConfig;
use crate::egress::{self, EgressError};

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
}

/// Why a mirror request did not complete. Neither variant carries the endpoint URL.
#[derive(Debug)]
pub(crate) enum MirrorError {
    /// The egress guard refused the endpoint; nothing was sent.
    Refused(EgressError),
    /// The request was sent and failed.
    Send(reqwest::Error),
}

impl MirrorError {
    /// Short class of the failure, safe to show a caller.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            MirrorError::Refused(EgressError::Dns(_)) => "DNS resolution failed",
            MirrorError::Refused(_) => "blocked by egress policy",
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
/// DNS is resolved once, here; the response body is discarded.
pub(crate) async fn send(request: MirrorRequest) -> Result<StatusCode, MirrorError> {
    let MirrorRequest {
        endpoint,
        method,
        headers,
        body,
        timeout,
    } = request;
    let (client, target) = tokio::task::spawn_blocking(move || egress::pinned_forward_client(&endpoint, timeout))
        .await
        .map_err(|e| MirrorError::Refused(EgressError::Blocked(format!("egress task failed: {e}"))))?
        .map_err(MirrorError::Refused)?;
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
}
