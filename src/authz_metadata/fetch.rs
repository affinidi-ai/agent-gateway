use bytes::Bytes;
use url::Url;

use super::{DiscoveryError, DiscoveryFailure, DiscoveryOptions, EgressPosture};
use crate::egress::{EgressError, pinned_forward_client, pinned_strict_client};
use crate::proxy::upstream_body::{UpstreamBodyError, UpstreamBodyLimits, read_bounded};

/// `raw` parsed as an absolute http(s) URL with a host and no credentials.
pub(super) fn parse_fetch_url(raw: &str) -> Result<Url, DiscoveryError> {
    let url = Url::parse(raw).map_err(|e| DiscoveryError::new(DiscoveryFailure::InvalidUrl, e.to_string()))?;
    let acceptable = matches!(url.scheme(), "http" | "https")
        && url
            .host_str()
            .is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none();
    if acceptable {
        Ok(url)
    } else {
        Err(DiscoveryError::new(DiscoveryFailure::InvalidUrl, "not an absolute http(s) URL without credentials"))
    }
}

async fn pinned_client(
    url: &str,
    posture: EgressPosture,
    options: DiscoveryOptions,
) -> Result<reqwest::Client, DiscoveryError> {
    let raw = url.to_string();
    let timeout = options.timeout;
    let resolve = tokio::task::spawn_blocking(move || match posture {
        EgressPosture::CloudMetadataOnly => pinned_forward_client(&raw, timeout),
        EgressPosture::Strict => pinned_strict_client(&raw, timeout),
    });
    let pinned = tokio::time::timeout(timeout, resolve)
        .await
        .map_err(|_| DiscoveryError::new(DiscoveryFailure::Unreachable, "resolving the host timed out"))?
        .map_err(|e| DiscoveryError::new(DiscoveryFailure::Unreachable, format!("resolve task failed: {e}")))?;
    pinned
        .map(|(client, _target)| client)
        .map_err(egress_failure)
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
    parse_fetch_url(url)?;
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
    use std::time::Duration;

    use super::*;
    use crate::authz_metadata::test_server::{Reply, TestServer};

    const OPERATOR: EgressPosture = EgressPosture::CloudMetadataOnly;

    fn failure_of(result: Result<Bytes, DiscoveryError>) -> DiscoveryFailure {
        result
            .expect_err("the fetch fails")
            .failure()
    }

    #[test]
    fn only_absolute_http_urls_without_credentials_parse() {
        assert_eq!(
            parse_fetch_url("https://issuer.example.com/path")
                .unwrap()
                .host_str(),
            Some("issuer.example.com")
        );
        assert_eq!(
            parse_fetch_url("http://127.0.0.1:4444/")
                .unwrap()
                .port(),
            Some(4444)
        );
        for raw in
            ["not a url", "/relative", "file:///etc/passwd", "ftp://example.com/", "https://user:pw@example.com/"]
        {
            assert_eq!(
                parse_fetch_url(raw)
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
    async fn the_strict_posture_blocks_loopback_before_any_request() {
        let server = TestServer::start().await;
        server.reply("/jwks.json", Reply::json("{}"));
        let failure = failure_of(
            get_bounded(&server.url("/jwks.json"), EgressPosture::Strict, DiscoveryOptions::default()).await,
        );
        assert_eq!(failure, DiscoveryFailure::Blocked);
        assert_eq!(server.hits("/jwks.json"), 0);
    }

    #[tokio::test]
    async fn both_postures_block_cloud_metadata() {
        for posture in [EgressPosture::CloudMetadataOnly, EgressPosture::Strict] {
            let failure = failure_of(
                get_bounded("http://169.254.169.254/latest/meta-data/", posture, DiscoveryOptions::default()).await,
            );
            assert_eq!(failure, DiscoveryFailure::Blocked, "{posture:?}");
        }
    }

    #[tokio::test]
    async fn the_strict_posture_blocks_private_literals() {
        for url in [
            "http://10.0.0.1/jwks.json",
            "http://172.16.0.1/jwks.json",
            "http://192.168.1.1/jwks.json",
            "http://169.254.10.20/jwks.json",
        ] {
            let failure = failure_of(get_bounded(url, EgressPosture::Strict, DiscoveryOptions::default()).await);
            assert_eq!(failure, DiscoveryFailure::Blocked, "{url}");
        }
    }

    #[tokio::test]
    async fn an_ipv6_literal_host_is_blocked_under_both_postures() {
        for (url, posture) in [
            ("http://[fd00::1]/jwks.json", EgressPosture::Strict),
            ("http://[::1]:1/jwks.json", EgressPosture::CloudMetadataOnly),
        ] {
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
    async fn a_slow_server_times_out_as_unreachable() {
        let server = TestServer::start().await;
        server.reply("/slow", Reply::json("{}").delayed(Duration::from_secs(5)));
        let options = DiscoveryOptions {
            timeout: Duration::from_millis(200),
            ..DiscoveryOptions::default()
        };
        let started = std::time::Instant::now();
        let failure = failure_of(get_bounded(&server.url("/slow"), OPERATOR, options).await);
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
