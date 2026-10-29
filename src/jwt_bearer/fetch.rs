//! Bounded, pinned GETs of JWKS documents, and the egress posture of a caller.
//!
//! Every fetch resolves DNS once, pins the connection to the vetted address,
//! refuses redirects, caps the body and the time, and reports failures as a
//! [`FetchFailure`] whose code and message are fixed. The detail, which can
//! name a resolved address, is for logs only.

use std::time::Duration;

use axum::body::Bytes;
use reqwest::header::HeaderMap;
use url::Url;

use crate::authz_metadata::EgressPosture;
use crate::egress::{EgressError, pinned_forward_client, pinned_strict_client};
use crate::http_client::SHORT_TIMEOUT_SECS;
use crate::proxy::upstream_body::{UpstreamBodyError, UpstreamBodyLimits, read_bounded};
use crate::tenancy::PatTenantContext;

/// The egress posture of a caller: a tenant-scoped caller must not reach the appliance's own network.
pub fn posture_for_caller(tenant: Option<&PatTenantContext>) -> EgressPosture {
    match tenant {
        Some(_) => EgressPosture::Strict,
        None => EgressPosture::CloudMetadataOnly,
    }
}

/// Why a fetch failed, as reported to API callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FetchFailure {
    InvalidUrl,
    Blocked,
    Unreachable,
    HttpStatus,
    TooLarge,
    InvalidDocument,
}

impl FetchFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::Blocked => "blocked",
            Self::Unreachable => "unreachable",
            Self::HttpStatus => "http_error",
            Self::TooLarge => "too_large",
            Self::InvalidDocument => "invalid_document",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidUrl => {
                "The URL must be an absolute http or https URL without credentials (https only under the strict posture)"
            }
            Self::Blocked => "The URL is not allowed by the egress policy or its host could not be resolved",
            Self::Unreachable => "The server could not be reached",
            Self::HttpStatus => "The server did not return the document",
            Self::TooLarge => "The response is too large",
            Self::InvalidDocument => "The response is not a valid document",
        }
    }
}

/// A failed fetch: a fixed [`FetchFailure`] plus a detail for logs.
#[derive(Debug, Clone)]
pub struct FetchError {
    failure: FetchFailure,
    detail: String,
}

impl FetchError {
    pub fn new(
        failure: FetchFailure,
        detail: impl Into<String>,
    ) -> Self {
        Self { failure, detail: detail.into() }
    }

    pub fn failure(&self) -> FetchFailure {
        self.failure
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(f, "{}: {}", self.failure.code(), self.detail)
    }
}

impl std::error::Error for FetchError {}

/// `raw` parsed as an absolute URL with a host and no credentials, whose scheme
/// `posture` accepts: `https` under [`EgressPosture::Strict`], `http` or `https` otherwise.
fn parse_fetch_url(
    raw: &str,
    posture: EgressPosture,
) -> Result<Url, FetchError> {
    let url = Url::parse(raw).map_err(|e| FetchError::new(FetchFailure::InvalidUrl, e.to_string()))?;
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
        Err(FetchError::new(
            FetchFailure::InvalidUrl,
            format!("not an absolute URL without credentials with a scheme the {posture:?} posture accepts"),
        ))
    }
}

async fn pinned_client(
    url: &str,
    posture: EgressPosture,
) -> Result<reqwest::Client, FetchError> {
    let raw = url.to_string();
    let timeout = Duration::from_secs(SHORT_TIMEOUT_SECS);
    let resolve = tokio::task::spawn_blocking(move || match posture {
        EgressPosture::CloudMetadataOnly => pinned_forward_client(&raw, timeout),
        EgressPosture::Strict => pinned_strict_client(&raw, timeout),
    });
    tokio::time::timeout(timeout, resolve)
        .await
        .map_err(|_| FetchError::new(FetchFailure::Unreachable, "resolving the host timed out"))?
        .map_err(|e| FetchError::new(FetchFailure::Unreachable, format!("resolve task failed: {e}")))?
        .map(|(client, _target)| client)
        .map_err(egress_failure)
}

fn egress_failure(error: EgressError) -> FetchError {
    let failure = match error {
        EgressError::Parse(_) => FetchFailure::InvalidUrl,
        EgressError::Blocked(_) | EgressError::Dns(_) | EgressError::TooManyRedirects => FetchFailure::Blocked,
        EgressError::Http(_) => FetchFailure::Unreachable,
    };
    FetchError::new(failure, error.to_string())
}

/// GET `url` under `posture`, accepting only a 2xx response whose body fits in `max_bytes`.
///
/// Under [`EgressPosture::Strict`] an `http` URL fails with `invalid_url` before its host
/// is resolved. A host that does not resolve fails with `blocked`, as in
/// [`crate::authz_metadata::get_bounded`].
pub async fn get_bounded(
    url: &str,
    posture: EgressPosture,
    max_bytes: usize,
) -> Result<(Bytes, HeaderMap), FetchError> {
    parse_fetch_url(url, posture)?;
    let client = pinned_client(url, posture).await?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| FetchError::new(FetchFailure::Unreachable, e.without_url().to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(FetchError::new(FetchFailure::HttpStatus, format!("HTTP {status}")));
    }
    let headers = response.headers().clone();
    let limits = UpstreamBodyLimits::new(max_bytes, None, SHORT_TIMEOUT_SECS);
    let body = read_bounded(response, limits)
        .await
        .map_err(|e| match e {
            UpstreamBodyError::TooLarge(limit) => {
                FetchError::new(FetchFailure::TooLarge, format!("response exceeds {limit} bytes"))
            }
            other => FetchError::new(FetchFailure::Unreachable, other.to_string()),
        })?;
    Ok((body, headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::mock_auth_server::{Endpoint, Fault, MockAuthServer};

    const LIMIT: usize = 64 * 1024;

    fn tenant() -> PatTenantContext {
        PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }
    }

    #[test]
    fn a_tenant_caller_gets_the_strict_posture() {
        assert_eq!(posture_for_caller(Some(&tenant())), EgressPosture::Strict);
        assert_eq!(posture_for_caller(None), EgressPosture::CloudMetadataOnly);
    }

    #[test]
    fn the_operator_posture_parses_absolute_http_and_https_urls_without_credentials() {
        let operator = EgressPosture::CloudMetadataOnly;
        assert!(parse_fetch_url("https://issuer.example.com/path", operator).is_ok());
        assert!(parse_fetch_url("http://127.0.0.1:4444/", operator).is_ok());
        for raw in ["not a url", "file:///etc/passwd", "ftp://example.com/", "https://user:pw@example.com/"] {
            assert_eq!(
                parse_fetch_url(raw, operator)
                    .unwrap_err()
                    .failure(),
                FetchFailure::InvalidUrl,
                "{raw}"
            );
        }
    }

    #[test]
    fn the_strict_posture_parses_https_urls_only() {
        assert!(parse_fetch_url("https://as.example.com/jwks.json", EgressPosture::Strict).is_ok());
        for raw in ["http://as.example.com/jwks.json", "HTTP://as.example.com/jwks.json", "ftp://example.com/"] {
            assert_eq!(
                parse_fetch_url(raw, EgressPosture::Strict)
                    .unwrap_err()
                    .failure(),
                FetchFailure::InvalidUrl,
                "{raw}"
            );
        }
    }

    #[test]
    fn egress_errors_map_to_the_failures_discovery_uses() {
        let cases = [
            (EgressError::Parse("bad".into()), FetchFailure::InvalidUrl),
            (EgressError::Blocked("internal".into()), FetchFailure::Blocked),
            (EgressError::Dns("no such host".into()), FetchFailure::Blocked),
            (EgressError::TooManyRedirects, FetchFailure::Blocked),
            (
                EgressError::Http(
                    reqwest::Client::new()
                        .get("not a url")
                        .build()
                        .unwrap_err(),
                ),
                FetchFailure::Unreachable,
            ),
        ];
        for (error, expected) in cases {
            let mapped = egress_failure(error);
            assert_eq!(mapped.failure(), expected, "{mapped}");
        }
    }

    #[tokio::test]
    async fn the_strict_posture_refuses_http_before_any_request() {
        let server = MockAuthServer::start().await;
        for url in [server.jwks_uri(), "http://203.0.113.7/jwks.json".to_string()] {
            let error = get_bounded(&url, EgressPosture::Strict, LIMIT)
                .await
                .unwrap_err();
            assert_eq!(error.failure(), FetchFailure::InvalidUrl, "{url}");
        }
        assert_eq!(server.request_count(Endpoint::Jwks), 0);
    }

    #[tokio::test]
    async fn the_operator_posture_reaches_a_loopback_server() {
        let server = MockAuthServer::start().await;
        let (body, _) = get_bounded(&server.jwks_uri(), EgressPosture::CloudMetadataOnly, LIMIT)
            .await
            .unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            jwks["keys"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
    }

    #[tokio::test]
    async fn the_strict_posture_blocks_loopback_before_any_request() {
        let server = MockAuthServer::start().await;
        let loopback_https = server
            .jwks_uri()
            .replacen("http://", "https://", 1);
        let error = get_bounded(&loopback_https, EgressPosture::Strict, LIMIT)
            .await
            .unwrap_err();
        assert_eq!(error.failure(), FetchFailure::Blocked);
        assert_eq!(server.request_count(Endpoint::Jwks), 0);
    }

    #[tokio::test]
    async fn both_postures_block_cloud_metadata() {
        for (url, posture) in [
            ("http://169.254.169.254/latest/meta-data/", EgressPosture::CloudMetadataOnly),
            ("https://169.254.169.254/latest/meta-data/", EgressPosture::Strict),
        ] {
            let error = get_bounded(url, posture, LIMIT)
                .await
                .unwrap_err();
            assert_eq!(error.failure(), FetchFailure::Blocked, "{url} under {posture:?}");
        }
    }

    #[tokio::test]
    async fn a_non_success_status_and_an_oversized_body_have_their_own_failures() {
        let server = MockAuthServer::start().await;
        server.set_fault(Endpoint::Jwks, Fault::NotFound);
        let missing = get_bounded(&server.jwks_uri(), EgressPosture::CloudMetadataOnly, LIMIT)
            .await
            .unwrap_err();
        assert_eq!(missing.failure(), FetchFailure::HttpStatus);

        server.set_fault(Endpoint::Jwks, Fault::Oversized);
        let oversized = get_bounded(&server.jwks_uri(), EgressPosture::CloudMetadataOnly, LIMIT)
            .await
            .unwrap_err();
        assert_eq!(oversized.failure(), FetchFailure::TooLarge);
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let error = get_bounded("http://127.0.0.1:1/jwks.json", EgressPosture::CloudMetadataOnly, LIMIT)
            .await
            .unwrap_err();
        assert_eq!(error.failure(), FetchFailure::Unreachable);
    }

    #[test]
    fn codes_and_messages_name_no_address() {
        let failures = [
            FetchFailure::InvalidUrl,
            FetchFailure::Blocked,
            FetchFailure::Unreachable,
            FetchFailure::HttpStatus,
            FetchFailure::TooLarge,
            FetchFailure::InvalidDocument,
        ];
        let codes: std::collections::HashSet<_> = failures
            .iter()
            .map(|failure| failure.code())
            .collect();
        assert_eq!(codes.len(), failures.len());
        for failure in failures {
            assert!(
                !failure
                    .message()
                    .chars()
                    .any(|c| c.is_ascii_digit()),
                "{failure:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_body_that_ends_before_its_declared_length_is_unreachable() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}/jwks.json", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"keys\"")
                .await
                .unwrap();
            socket
                .shutdown()
                .await
                .unwrap();
        });

        let error = get_bounded(&url, EgressPosture::CloudMetadataOnly, LIMIT)
            .await
            .unwrap_err();

        assert_eq!(error.failure(), FetchFailure::Unreachable);
    }
}
