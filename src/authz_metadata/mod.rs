#![allow(dead_code)]
//! Authorization server metadata discovery (RFC 8414, then OpenID Connect Discovery).
//!
//! [`discover`] fetches the metadata document of an issuer through a pinned,
//! bounded GET ([`get_bounded`]) and returns the four fields a caller pins:
//! the issuer, the URL the document was read from, the token endpoint and the
//! JWKS URI. [`parse_metadata`] validates a document without any I/O.
//!
//! [`discover_client`] and [`parse_client_metadata`] read the same documents for
//! an OAuth client of the server, the client profile: the JWKS URI is optional,
//! and they also return the authorization, revocation and registration endpoints
//! and the methods the server says it supports.
//!
//! The module records no metrics and writes no audit events: callers record the
//! outcome themselves from [`DiscoveryError::code`].

mod discovery;
mod fetch;

#[cfg(test)]
mod test_server;

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
pub use discovery::{discover, discover_client, metadata_urls, parse_client_metadata, parse_metadata, validate_issuer};
#[allow(unused_imports)]
pub use fetch::get_bounded;

/// Largest metadata document accepted by default, in bytes.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;

/// The authorization server metadata a caller pins after discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzServerMetadata {
    /// The discovered `issuer`, equal byte for byte to the requested issuer.
    pub issuer: String,
    /// The URL the metadata document was read from.
    pub metadata_url: String,
    /// The `token_endpoint` of the document: an absolute http(s) URL.
    pub token_endpoint: String,
    /// The `jwks_uri` of the document: an absolute http(s) URL. Required although
    /// RFC 8414 makes it optional, because the gateway validates JWT access tokens.
    pub jwks_uri: String,
}

/// The authorization server metadata an OAuth client of the server is checked
/// against (the client profile).
///
/// Every endpoint passes the same checks as [`AuthzServerMetadata`]'s. The
/// `jwks_uri` is optional here, since a client that never validates the server's
/// JWTs does not need its keys, and many servers publish none.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAuthzMetadata {
    /// The discovered `issuer`, equal byte for byte to the requested issuer.
    pub issuer: String,
    /// The URL the metadata document was read from.
    pub metadata_url: String,
    /// The `authorization_endpoint` of the document. Required.
    pub authorization_endpoint: String,
    /// The `token_endpoint` of the document. Required.
    pub token_endpoint: String,
    /// The RFC 7009 `revocation_endpoint`, when the document names one.
    pub revocation_endpoint: Option<String>,
    /// The RFC 7591 `registration_endpoint`, when the document names one.
    pub registration_endpoint: Option<String>,
    /// The `jwks_uri`, when the document names one.
    pub jwks_uri: Option<String>,
    /// `code_challenge_methods_supported`, when the document lists it.
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// `token_endpoint_auth_methods_supported`, when the document lists it.
    /// RFC 8414 reads its absence as `client_secret_basic` only.
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// RFC 9207 `authorization_response_iss_parameter_supported`; `false` when absent.
    pub authorization_response_iss_parameter_supported: bool,
}

/// Which schemes and addresses a fetch, and the endpoints of a discovered document, may use.
///
/// Both postures block cloud-metadata addresses and host names, refuse redirects, and
/// connect only to the addresses the egress guard vetted for the request. They differ in
/// the schemes they accept and the address ranges they block. Under either posture a
/// discovered endpoint must not use a weaker scheme than the issuer: an `https` issuer
/// requires `https` endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPosture {
    /// Accepts `http` and `https`, and blocks cloud-metadata addresses only; loopback
    /// and private ranges are allowed. For operator-trusted callers whose authorization server runs on the
    /// same machine or in the same network.
    CloudMetadataOnly,
    /// Accepts `https` only, and also blocks loopback (including the name `localhost`),
    /// RFC 1918, link-local and unique-local addresses. An `http` URL fails with
    /// `invalid_url` before its host is resolved. For callers that must not reach the appliance's own network.
    Strict,
}

/// Limits applied to one discovery or bounded fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryOptions {
    /// Largest response body accepted, in bytes; a larger body fails with `too_large`.
    pub max_bytes: usize,
    /// Time allowed for resolving the host of each request, and again for the request
    /// itself, from connecting to reading the last byte of the body; a step that takes
    /// longer fails with `unreachable`.
    pub timeout: Duration,
}

impl Default for DiscoveryOptions {
    /// [`MAX_METADATA_BYTES`] and the shared short timeout of
    /// [`crate::http_client::SHORT_TIMEOUT_SECS`] seconds.
    fn default() -> Self {
        Self {
            max_bytes: MAX_METADATA_BYTES,
            timeout: Duration::from_secs(crate::http_client::SHORT_TIMEOUT_SECS),
        }
    }
}

/// Why a discovery or fetch failed, ordered from least to most specific.
///
/// [`discover`] returns the most specific failure of its attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiscoveryFailure {
    /// The URL is not an absolute http or https URL with a host and without credentials,
    /// its scheme is `http` under [`EgressPosture::Strict`], which accepts `https` only,
    /// or an issuer has a query, a fragment, or whitespace or a control character.
    /// Code `invalid_url`.
    InvalidUrl,
    /// The egress posture forbids the host or an address it resolves to. The egress
    /// guard resolves a host name while vetting it, so a name that does not resolve,
    /// and an IPv6 literal host, which the guard cannot pin, also fail here. Code `blocked`.
    Blocked,
    /// Resolving the host timed out, the connection failed or timed out, or the body
    /// could not be read in time. Code `unreachable`.
    Unreachable,
    /// The server answered with a status outside 2xx, redirects included. Code `http_status`.
    HttpStatus,
    /// The body exceeds the size limit. Code `too_large`.
    TooLarge,
    /// The body is not a JSON object with acceptable `issuer`, `token_endpoint` and
    /// `jwks_uri` members, or, for the client profile, acceptable `issuer`,
    /// `authorization_endpoint` and `token_endpoint` members and optional members.
    /// Code `invalid_document`.
    InvalidDocument,
    /// The document's `issuer` differs from the requested issuer. Code `issuer_mismatch`.
    IssuerMismatch,
}

impl DiscoveryFailure {
    /// The stable code of the failure: `invalid_url`, `blocked`, `unreachable`,
    /// `http_status`, `too_large`, `invalid_document` or `issuer_mismatch`.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::Blocked => "blocked",
            Self::Unreachable => "unreachable",
            Self::HttpStatus => "http_status",
            Self::TooLarge => "too_large",
            Self::InvalidDocument => "invalid_document",
            Self::IssuerMismatch => "issuer_mismatch",
        }
    }

    /// Fixed text describing the failure, safe for API responses: it never names a
    /// URL, an address or a transport error.
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidUrl => {
                "The URL must be an absolute http or https URL without credentials (https only under the strict posture), and an issuer must have no query or fragment"
            }
            Self::Blocked => "The URL is not allowed by the egress policy or its host could not be resolved",
            Self::Unreachable => "The server could not be reached",
            Self::HttpStatus => "The server did not return the document",
            Self::TooLarge => "The response is too large",
            Self::InvalidDocument => "The response is not a valid authorization server metadata document",
            Self::IssuerMismatch => "The discovered issuer does not match the expected issuer",
        }
    }
}

/// A failed discovery or fetch: a [`DiscoveryFailure`] with fixed code and message,
/// plus a detail for logs.
///
/// The detail can name a resolved address or carry transport error text, so only
/// [`code`](Self::code) and [`message`](Self::message) belong in an API response.
/// The `Display` output includes the detail and is for logs only.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{}: {detail}", .failure.code())]
pub struct DiscoveryError {
    failure: DiscoveryFailure,
    detail: String,
}

impl DiscoveryError {
    pub(crate) fn new(
        failure: DiscoveryFailure,
        detail: impl Into<String>,
    ) -> Self {
        Self { failure, detail: detail.into() }
    }

    /// The kind of failure.
    pub fn failure(&self) -> DiscoveryFailure {
        self.failure
    }

    /// The stable code of the failure: `invalid_url`, `blocked`, `unreachable`,
    /// `http_status`, `too_large`, `invalid_document` or `issuer_mismatch`.
    pub fn code(&self) -> &'static str {
        self.failure.code()
    }

    /// Fixed text describing the failure, safe for API responses: it never names a
    /// URL, an address or a transport error.
    pub fn message(&self) -> &'static str {
        self.failure.message()
    }

    /// What went wrong in detail, for logs only.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [DiscoveryFailure; 7] = [
        DiscoveryFailure::InvalidUrl,
        DiscoveryFailure::Blocked,
        DiscoveryFailure::Unreachable,
        DiscoveryFailure::HttpStatus,
        DiscoveryFailure::TooLarge,
        DiscoveryFailure::InvalidDocument,
        DiscoveryFailure::IssuerMismatch,
    ];

    #[test]
    fn default_options_use_the_metadata_limit_and_the_short_timeout() {
        let options = DiscoveryOptions::default();
        assert_eq!(options.max_bytes, 64 * 1024);
        assert_eq!(options.max_bytes, MAX_METADATA_BYTES);
        assert_eq!(options.timeout, Duration::from_secs(10));
    }

    #[test]
    fn each_failure_has_its_documented_code() {
        let codes: Vec<&str> = ALL
            .iter()
            .map(|failure| DiscoveryError::new(*failure, "detail").code())
            .collect();
        assert_eq!(
            codes,
            [
                "invalid_url",
                "blocked",
                "unreachable",
                "http_status",
                "too_large",
                "invalid_document",
                "issuer_mismatch"
            ]
        );
    }

    #[test]
    fn code_and_message_never_carry_the_detail() {
        let detail = "host 'internal.example' resolves to blocked address '10.1.2.3': connection refused (os error 61)";
        for failure in ALL {
            let error = DiscoveryError::new(failure, detail);
            assert_eq!(error.failure(), failure);
            assert_eq!(error.detail(), detail);
            for text in [error.code(), error.message()] {
                assert!(
                    !text
                        .chars()
                        .any(|c| c.is_ascii_digit()),
                    "{failure:?}: {text}"
                );
                assert!(!text.contains("10.1.2.3"), "{failure:?}: {text}");
                assert!(!text.contains("internal.example"), "{failure:?}: {text}");
                assert!(!text.contains("refused"), "{failure:?}: {text}");
            }
        }
    }

    #[test]
    fn each_failure_has_its_fixed_message() {
        let messages: Vec<&str> = ALL
            .iter()
            .map(|failure| failure.message())
            .collect();
        assert_eq!(
            messages,
            [
                "The URL must be an absolute http or https URL without credentials (https only under the strict posture), and an issuer must have no query or fragment",
                "The URL is not allowed by the egress policy or its host could not be resolved",
                "The server could not be reached",
                "The server did not return the document",
                "The response is too large",
                "The response is not a valid authorization server metadata document",
                "The discovered issuer does not match the expected issuer",
            ]
        );
    }

    #[test]
    fn display_shows_the_code_and_the_detail() {
        let error = DiscoveryError::new(DiscoveryFailure::HttpStatus, "HTTP 404 Not Found");
        assert_eq!(error.to_string(), "http_status: HTTP 404 Not Found");
    }

    #[test]
    fn failures_are_ordered_from_least_to_most_specific() {
        let mut shuffled = ALL;
        shuffled.reverse();
        shuffled.sort();
        assert_eq!(shuffled, ALL);
    }
}
