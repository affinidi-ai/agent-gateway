use std::time::Duration;

use bytes::Bytes;
use url::Url;

use super::{DiscoveryError, DiscoveryFailure, DiscoveryOptions, EgressPosture};
use crate::egress::{EgressError, pinned_forward_client, pinned_strict_client};
use crate::proxy::upstream_body::{UpstreamBodyError, UpstreamBodyLimits, read_bounded};

/// `raw` parsed as an absolute URL with a host and no credentials, whose scheme
/// `posture` accepts: `https` under [`EgressPosture::Strict`], `http` or `https` otherwise.
pub(super) fn parse_fetch_url(
    raw: &str,
    posture: EgressPosture,
) -> Result<Url, DiscoveryError> {
    let url = Url::parse(raw).map_err(|e| DiscoveryError::new(DiscoveryFailure::InvalidUrl, e.to_string()))?;
    let scheme_allowed = match posture {
        EgressPosture::CloudMetadataOnly => matches!(url.scheme(), "http" | "https"),
        EgressPosture::Strict => url.scheme() == "https",
    };
    let acceptable = scheme_allowed
        && url
            .host_str()
            .is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none();
    if acceptable {
        Ok(url)
    } else {
        Err(DiscoveryError::new(
            DiscoveryFailure::InvalidUrl,
            format!("not an absolute URL without credentials with a scheme the {posture:?} posture accepts"),
        ))
    }
}

async fn pinned_client(
    url: &str,
    posture: EgressPosture,
    options: DiscoveryOptions,
) -> Result<reqwest::Client, DiscoveryError> {
    let raw = url.to_string();
    let timeout = options.timeout;
    let pinned = resolve_within(timeout, move || match posture {
        EgressPosture::CloudMetadataOnly => pinned_forward_client(&raw, timeout),
        EgressPosture::Strict => pinned_strict_client(&raw, timeout),
    })
    .await?;
    pinned
        .map(|(client, _target)| client)
        .map_err(egress_failure)
}

async fn resolve_within<T, F>(
    timeout: Duration,
    resolve: F,
) -> Result<T, DiscoveryError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::time::timeout(timeout, tokio::task::spawn_blocking(resolve))
        .await
        .map_err(|_| DiscoveryError::new(DiscoveryFailure::Unreachable, "resolving the host timed out"))?
        .map_err(|e| DiscoveryError::new(DiscoveryFailure::Unreachable, format!("resolve task failed: {e}")))
}

fn egress_failure(error: EgressError) -> DiscoveryError {
    let failure = match error {
        EgressError::Parse(_) => DiscoveryFailure::InvalidUrl,
        EgressError::Blocked(_) | EgressError::Dns(_) | EgressError::TooManyRedirects => DiscoveryFailure::Blocked,
        EgressError::Http(_) => DiscoveryFailure::Unreachable,
    };
    DiscoveryError::new(failure, error.to_string())
}

fn read_deadline_secs(options: DiscoveryOptions) -> u64 {
    u64::try_from(
        options
            .timeout
            .as_millis()
            .div_ceil(1000),
    )
    .unwrap_or(u64::MAX)
    .max(1)
}

/// GET `url` under `posture` and return the body of a 2xx response.
///
/// `url` must be an absolute URL with a host and no credentials; under
/// [`EgressPosture::Strict`] its scheme must be `https`, and under
/// [`EgressPosture::CloudMetadataOnly`] `http` or `https`. Any other URL fails with
/// `invalid_url` before the host is resolved or a request is made.
/// The host is vetted by the egress guard for `posture` and the connection is pinned
/// to the vetted addresses, so DNS cannot rebind between the check and the connect.
/// The egress guard can resolve the name more than once; the connection uses the
/// addresses of the last, vetted resolution. A host that does not resolve fails with
/// `blocked`, as does an IPv6 literal host, which the egress guard cannot pin.
/// Redirects are not followed: a 3xx, like any status outside 2xx, fails with
/// `http_status`. Resolving the host is limited to `options.timeout`, and the HTTP
/// request, from connecting to reading the last byte, to `options.timeout` again, so one
/// call can take up to twice the timeout. The body is bounded by `options.max_bytes`
/// (`too_large`). The request asks for `application/json`.
///
/// Failure codes: `invalid_url`, `blocked`, `unreachable`, `http_status`, `too_large`.
pub async fn get_bounded(
    url: &str,
    posture: EgressPosture,
    options: DiscoveryOptions,
) -> Result<Bytes, DiscoveryError> {
    parse_fetch_url(url, posture)?;
    let client = pinned_client(url, posture, options).await?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| DiscoveryError::new(DiscoveryFailure::Unreachable, e.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(DiscoveryError::new(DiscoveryFailure::HttpStatus, format!("HTTP {status}")));
    }
    let limits = UpstreamBodyLimits::new(options.max_bytes, None, read_deadline_secs(options));
    read_bounded(response, limits)
        .await
        .map_err(|e| match e {
            UpstreamBodyError::TooLarge(limit) => {
                DiscoveryError::new(DiscoveryFailure::TooLarge, format!("response exceeds {limit} bytes"))
            }
            other => DiscoveryError::new(DiscoveryFailure::Unreachable, other.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::authz_metadata::test_server::{Reply, TestServer};

    const OPERATOR: EgressPosture = EgressPosture::CloudMetadataOnly;
    const STRICT: EgressPosture = EgressPosture::Strict;

    fn failure_of(result: Result<Bytes, DiscoveryError>) -> DiscoveryFailure {
        result
            .expect_err("the fetch fails")
            .failure()
    }

    fn short(timeout_ms: u64) -> DiscoveryOptions {
        DiscoveryOptions {
            timeout: Duration::from_millis(timeout_ms),
            ..DiscoveryOptions::default()
        }
    }

    struct RawServer {
        url: String,
        request: Arc<Mutex<String>>,
    }

    async fn raw_server(
        response: Vec<u8>,
        stall_after_writing: bool,
    ) -> RawServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener
            .local_addr()
            .expect("local address");
        let request = Arc::new(Mutex::new(String::new()));
        let seen = request.clone();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head
                .windows(4)
                .any(|w| w == b"\r\n\r\n")
            {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            *seen.lock().unwrap() = String::from_utf8_lossy(&head).into_owned();
            let _ = stream
                .write_all(&response)
                .await;
            let _ = stream.flush().await;
            if stall_after_writing {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        RawServer {
            url: format!("http://{addr}/jwks.json"),
            request,
        }
    }

    fn chunked_response(body_len: usize) -> Vec<u8> {
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_vec();
        let mut remaining = body_len;
        while remaining > 0 {
            let len = remaining.min(4096);
            response.extend_from_slice(format!("{len:x}\r\n").as_bytes());
            response.extend(std::iter::repeat_n(b'x', len));
            response.extend_from_slice(b"\r\n");
            remaining -= len;
        }
        response.extend_from_slice(b"0\r\n\r\n");
        response
    }

    #[test]
    fn the_operator_posture_parses_absolute_http_and_https_urls_without_credentials() {
        assert_eq!(
            parse_fetch_url("https://issuer.example.com/path", OPERATOR)
                .unwrap()
                .host_str(),
            Some("issuer.example.com")
        );
        assert_eq!(
            parse_fetch_url("http://127.0.0.1:4444/", OPERATOR)
                .unwrap()
                .port(),
            Some(4444)
        );
        for raw in [
            "not a url",
            "/relative",
            "file:///etc/passwd",
            "ftp://example.com/",
            "https://user:pw@example.com/",
            "https://user@example.com/",
            "https://:pw@example.com/",
        ] {
            assert_eq!(
                parse_fetch_url(raw, OPERATOR)
                    .unwrap_err()
                    .failure(),
                DiscoveryFailure::InvalidUrl,
                "{raw}"
            );
        }
    }

    #[test]
    fn the_strict_posture_parses_https_urls_only() {
        for raw in ["https://issuer.example.com/path", "HTTPS://issuer.example.com/path"] {
            let url = parse_fetch_url(raw, STRICT).unwrap();
            assert_eq!(url.scheme(), "https", "{raw}");
            assert_eq!(url.host_str(), Some("issuer.example.com"), "{raw}");
        }
        for raw in ["http://issuer.example.com/path", "HTTP://issuer.example.com/path", "ftp://example.com/"] {
            assert_eq!(
                parse_fetch_url(raw, STRICT)
                    .unwrap_err()
                    .failure(),
                DiscoveryFailure::InvalidUrl,
                "{raw}"
            );
        }
    }

    #[test]
    fn the_read_deadline_rounds_up_to_whole_seconds() {
        let with = |timeout| DiscoveryOptions { max_bytes: 1, timeout };
        assert_eq!(read_deadline_secs(with(Duration::from_millis(1))), 1);
        assert_eq!(read_deadline_secs(with(Duration::ZERO)), 1);
        assert_eq!(read_deadline_secs(with(Duration::from_millis(2500))), 3);
        assert_eq!(read_deadline_secs(with(Duration::from_secs(10))), 10);
    }

    #[tokio::test]
    async fn a_resolution_slower_than_the_timeout_is_unreachable() {
        let started = Instant::now();
        let error = resolve_within(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_secs(1));
            7
        })
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
        assert_eq!(error.failure(), DiscoveryFailure::Unreachable);
        assert!(
            error
                .detail()
                .contains("resolving the host timed out"),
            "{}",
            error.detail()
        );
    }

    #[tokio::test]
    async fn a_resolution_within_the_timeout_passes_its_value_through() {
        let value = resolve_within(Duration::from_millis(100), || 7)
            .await
            .unwrap();
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn a_panicking_resolution_is_unreachable() {
        let error = resolve_within(Duration::from_secs(1), || -> u8 { panic!("resolver panicked") })
            .await
            .unwrap_err();
        assert_eq!(error.failure(), DiscoveryFailure::Unreachable);
        assert!(
            error
                .detail()
                .starts_with("resolve task failed"),
            "{}",
            error.detail()
        );
    }

    #[tokio::test]
    async fn the_operator_posture_reaches_a_loopback_server() {
        let server = TestServer::start().await;
        server.reply("/jwks.json", Reply::json(r#"{"keys":[]}"#));
        let body = get_bounded(&server.url("/jwks.json"), OPERATOR, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"keys":[]}"#);
        assert_eq!(server.hits("/jwks.json"), 1);
    }

    #[tokio::test]
    async fn the_strict_posture_refuses_http_before_any_request() {
        let server = TestServer::start().await;
        server.reply("/jwks.json", Reply::json("{}"));
        for url in [server.url("/jwks.json"), "http://203.0.113.7/jwks.json".to_string()] {
            let error = get_bounded(&url, STRICT, DiscoveryOptions::default())
                .await
                .unwrap_err();
            assert_eq!(error.code(), "invalid_url", "{url}");
        }
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn the_strict_posture_blocks_loopback_before_any_request() {
        let server = TestServer::start().await;
        server.reply("/jwks.json", Reply::json("{}"));
        let failure =
            failure_of(get_bounded(&server.https_url("/jwks.json"), STRICT, DiscoveryOptions::default()).await);
        assert_eq!(failure, DiscoveryFailure::Blocked);
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn the_strict_posture_lets_a_public_https_address_through_its_checks() {
        let failure = failure_of(get_bounded("https://203.0.113.7:9/jwks.json", STRICT, short(300)).await);
        assert_eq!(failure, DiscoveryFailure::Unreachable);
    }

    #[tokio::test]
    async fn both_postures_block_cloud_metadata() {
        for (url, posture) in [
            ("http://169.254.169.254/latest/meta-data/", OPERATOR),
            ("https://169.254.169.254/latest/meta-data/", OPERATOR),
            ("https://169.254.169.254/latest/meta-data/", STRICT),
        ] {
            let failure = failure_of(get_bounded(url, posture, DiscoveryOptions::default()).await);
            assert_eq!(failure, DiscoveryFailure::Blocked, "{url} under {posture:?}");
        }
    }

    #[tokio::test]
    async fn the_strict_posture_blocks_private_literals() {
        for url in [
            "https://10.0.0.1/jwks.json",
            "https://172.16.0.1/jwks.json",
            "https://192.168.1.1/jwks.json",
            "https://169.254.10.20/jwks.json",
        ] {
            let failure = failure_of(get_bounded(url, STRICT, DiscoveryOptions::default()).await);
            assert_eq!(failure, DiscoveryFailure::Blocked, "{url}");
        }
    }

    #[tokio::test]
    async fn an_ipv6_literal_host_is_blocked_under_both_postures() {
        for (url, posture) in [("https://[fd00::1]/jwks.json", STRICT), ("http://[::1]:1/jwks.json", OPERATOR)] {
            let failure = failure_of(get_bounded(url, posture, DiscoveryOptions::default()).await);
            assert_eq!(failure, DiscoveryFailure::Blocked, "{url} under {posture:?}");
        }
    }

    #[test]
    fn egress_errors_map_to_their_failures() {
        let cases = [
            (EgressError::Parse("bad".into()), DiscoveryFailure::InvalidUrl),
            (EgressError::Blocked("internal".into()), DiscoveryFailure::Blocked),
            (EgressError::Dns("no such host".into()), DiscoveryFailure::Blocked),
            (EgressError::TooManyRedirects, DiscoveryFailure::Blocked),
        ];
        for (error, expected) in cases {
            let mapped = egress_failure(error);
            assert_eq!(mapped.failure(), expected, "{}", mapped.detail());
        }
    }

    #[tokio::test]
    async fn an_invalid_url_is_refused_before_any_request() {
        let failure = failure_of(get_bounded("ftp://example.com/", OPERATOR, DiscoveryOptions::default()).await);
        assert_eq!(failure, DiscoveryFailure::InvalidUrl);
    }

    #[tokio::test]
    async fn a_url_with_credentials_is_refused_under_both_postures() {
        for url in ["https://user@as.example.com/token", "https://:pw@as.example.com/token"] {
            for posture in [OPERATOR, STRICT] {
                let error = get_bounded(url, posture, DiscoveryOptions::default())
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), "invalid_url", "{url} under {posture:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_non_success_status_fails_with_http_status() {
        let server = TestServer::start().await;
        server.reply("/jwks.json", Reply::status(500));
        let error = get_bounded(&server.url("/jwks.json"), OPERATOR, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "http_status");
        assert!(error.detail().contains("500"));
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let server = TestServer::start().await;
        server.reply("/jwks.json", Reply::redirect(&server.url("/elsewhere")));
        server.reply("/elsewhere", Reply::json("{}"));
        let failure = failure_of(get_bounded(&server.url("/jwks.json"), OPERATOR, DiscoveryOptions::default()).await);
        assert_eq!(failure, DiscoveryFailure::HttpStatus);
        assert_eq!(server.hits("/jwks.json"), 1);
        assert_eq!(server.hits("/elsewhere"), 0);
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_too_large_and_one_at_the_limit_is_accepted() {
        let server = TestServer::start().await;
        server.reply("/big", Reply::json(&"x".repeat(101)));
        server.reply("/exact", Reply::json(&"x".repeat(100)));
        let options = DiscoveryOptions {
            max_bytes: 100,
            ..DiscoveryOptions::default()
        };
        assert_eq!(failure_of(get_bounded(&server.url("/big"), OPERATOR, options).await), DiscoveryFailure::TooLarge);
        assert_eq!(
            get_bounded(&server.url("/exact"), OPERATOR, options)
                .await
                .unwrap()
                .len(),
            100
        );
    }

    #[tokio::test]
    async fn a_chunked_body_over_the_default_limit_is_too_large() {
        let server = raw_server(chunked_response(65_537), false).await;
        let failure = failure_of(get_bounded(&server.url, OPERATOR, DiscoveryOptions::default()).await);
        assert_eq!(failure, DiscoveryFailure::TooLarge);
    }

    #[tokio::test]
    async fn a_chunked_body_at_the_default_limit_is_accepted() {
        let server = raw_server(chunked_response(65_536), false).await;
        let body = get_bounded(&server.url, OPERATOR, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(body.len(), 65_536);
        assert!(
            body.iter()
                .all(|b| *b == b'x')
        );
    }

    #[tokio::test]
    async fn the_request_asks_for_json() {
        let server = raw_server(chunked_response(2), false).await;
        get_bounded(&server.url, OPERATOR, DiscoveryOptions::default())
            .await
            .unwrap();
        let request = server
            .request
            .lock()
            .unwrap()
            .to_ascii_lowercase();
        assert!(request.starts_with("get /jwks.json http/1.1\r\n"), "{request}");
        assert!(request.contains("\r\naccept: application/json\r\n"), "{request}");
    }

    #[tokio::test]
    async fn a_body_that_stalls_is_unreachable() {
        let server = raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{".to_vec(),
            true,
        )
        .await;
        let started = Instant::now();
        let failure = failure_of(get_bounded(&server.url, OPERATOR, short(300)).await);
        assert_eq!(failure, DiscoveryFailure::Unreachable);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_body_cut_short_is_unreachable() {
        let server = raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"a\":".to_vec(),
            false,
        )
        .await;
        let failure = failure_of(get_bounded(&server.url, OPERATOR, DiscoveryOptions::default()).await);
        assert_eq!(failure, DiscoveryFailure::Unreachable);
    }

    #[tokio::test]
    async fn a_slow_server_times_out_as_unreachable() {
        let server = TestServer::start().await;
        server.reply("/slow", Reply::json("{}").delayed(Duration::from_secs(5)));
        let started = Instant::now();
        let failure = failure_of(get_bounded(&server.url("/slow"), OPERATOR, short(200)).await);
        assert_eq!(failure, DiscoveryFailure::Unreachable);
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let failure =
            failure_of(get_bounded("http://127.0.0.1:1/jwks.json", OPERATOR, DiscoveryOptions::default()).await);
        assert_eq!(failure, DiscoveryFailure::Unreachable);
    }
}
