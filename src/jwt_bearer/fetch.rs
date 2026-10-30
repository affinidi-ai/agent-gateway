//! Bounded, pinned GETs of JWKS documents, and the egress posture of a caller.
//!
//! Every fetch goes through [`crate::authz_metadata::get_bounded_with_headers`], so a
//! JWKS fetch and a discovery report the same failure with the same code. A failure is
//! a [`FetchFailure`] whose code and message are fixed. The detail, which can name a
//! resolved address, is for logs only.

use axum::body::Bytes;
use reqwest::header::HeaderMap;

use crate::authz_metadata::{
    DiscoveryError, DiscoveryFailure, DiscoveryOptions, EgressPosture, get_bounded_with_headers,
};
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
            Self::HttpStatus => "http_status",
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

impl From<DiscoveryError> for FetchError {
    fn from(error: DiscoveryError) -> Self {
        let failure = match error.failure() {
            DiscoveryFailure::InvalidUrl => FetchFailure::InvalidUrl,
            DiscoveryFailure::Blocked => FetchFailure::Blocked,
            DiscoveryFailure::Unreachable => FetchFailure::Unreachable,
            DiscoveryFailure::HttpStatus => FetchFailure::HttpStatus,
            DiscoveryFailure::TooLarge => FetchFailure::TooLarge,
            DiscoveryFailure::InvalidDocument | DiscoveryFailure::IssuerMismatch => FetchFailure::InvalidDocument,
        };
        Self::new(failure, error.detail())
    }
}

/// GET `url` under `posture`, accepting only a 2xx response whose body fits in `max_bytes`,
/// with the egress checks, pinning and timeouts of [`crate::authz_metadata::get_bounded`].
pub async fn get_bounded(
    url: &str,
    posture: EgressPosture,
    max_bytes: usize,
) -> Result<(Bytes, HeaderMap), FetchError> {
    let options = DiscoveryOptions {
        max_bytes,
        ..DiscoveryOptions::default()
    };
    get_bounded_with_headers(url, posture, options)
        .await
        .map_err(FetchError::from)
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

    #[tokio::test]
    async fn a_url_the_posture_does_not_accept_is_invalid_before_any_request() {
        let cases = [
            ("not a url", EgressPosture::CloudMetadataOnly),
            ("file:///etc/passwd", EgressPosture::CloudMetadataOnly),
            ("https://user:pw@example.com/", EgressPosture::CloudMetadataOnly),
            ("HTTP://as.example.com/jwks.json", EgressPosture::Strict),
            ("ftp://example.com/", EgressPosture::Strict),
        ];
        for (raw, posture) in cases {
            let error = get_bounded(raw, posture, LIMIT)
                .await
                .unwrap_err();
            assert_eq!(error.failure(), FetchFailure::InvalidUrl, "{raw} under {posture:?}");
        }
    }

    #[test]
    fn discovery_failures_keep_their_code_and_detail() {
        let cases = [
            (DiscoveryFailure::InvalidUrl, FetchFailure::InvalidUrl),
            (DiscoveryFailure::Blocked, FetchFailure::Blocked),
            (DiscoveryFailure::Unreachable, FetchFailure::Unreachable),
            (DiscoveryFailure::HttpStatus, FetchFailure::HttpStatus),
            (DiscoveryFailure::TooLarge, FetchFailure::TooLarge),
            (DiscoveryFailure::InvalidDocument, FetchFailure::InvalidDocument),
        ];
        for (discovery, expected) in cases {
            let mapped = FetchError::from(DiscoveryError::new(discovery, "HTTP 503"));
            assert_eq!(mapped.failure(), expected);
            assert_eq!(expected.code(), discovery.code());
            assert_eq!(mapped.to_string(), format!("{}: HTTP 503", discovery.code()));
        }
        assert_eq!(FetchFailure::HttpStatus.code(), "http_status");
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
