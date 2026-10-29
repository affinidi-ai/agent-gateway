//! Source authentication error types

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use serde::Serialize;
use thiserror::Error;

use crate::config::agent_surface::SurfaceProtocol;
use crate::jwt_bearer::errors::JwtBearerError;
use crate::source_auth::models::SourceAuthConfig;

/// Errors returned by the source authentication middleware.
#[derive(Debug, Clone, Error)]
pub enum SourceAuthError {
    /// The required credential was not found in the request.
    #[error("Missing credential: {reason}")]
    MissingCredential { reason: String },

    /// The credential was found but validation failed.
    #[error("Invalid credential: {reason}")]
    InvalidCredential { reason: String },

    /// The credential verified but does not grant every required scope.
    #[error("Insufficient scope: missing {}", .missing.join(" "))]
    InsufficientScope { missing: Vec<String> },

    /// The referenced authentication configuration was not found.
    #[error("Auth config not found: {id}")]
    ConfigNotFound { id: String },

    /// An internal error occurred (e.g. unimplemented auth method).
    #[error("Internal source auth error: {reason}")]
    Internal { reason: String },
}

impl From<JwtBearerError> for SourceAuthError {
    fn from(err: JwtBearerError) -> Self {
        match err {
            JwtBearerError::MissingToken => SourceAuthError::MissingCredential {
                reason: "Missing bearer token".to_string(),
            },
            JwtBearerError::StrategyNotFound(id) => SourceAuthError::ConfigNotFound { id },
            JwtBearerError::ExpiredToken => SourceAuthError::InvalidCredential {
                reason: "Token has expired".to_string(),
            },
            JwtBearerError::InvalidIssuer => SourceAuthError::InvalidCredential {
                reason: "Invalid issuer".to_string(),
            },
            JwtBearerError::InvalidAudience => SourceAuthError::InvalidCredential {
                reason: "Invalid audience".to_string(),
            },
            JwtBearerError::InvalidToken(msg) => SourceAuthError::InvalidCredential {
                reason: format!("Invalid token: {msg}"),
            },
            JwtBearerError::KeyNotFound(kid) => SourceAuthError::InvalidCredential {
                reason: format!("Key not found for kid: {kid}"),
            },
            JwtBearerError::JwksFetchFailed(msg) => SourceAuthError::Internal {
                reason: format!("JWKS fetch failed: {msg}"),
            },
            JwtBearerError::Storage(msg) => SourceAuthError::Internal {
                reason: format!("Storage error: {msg}"),
            },
        }
    }
}

/// Why a caller's credential failed, published to policy as `input.source_auth.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthFailureKind {
    Missing,
    Invalid,
    InsufficientScope,
}

impl SourceAuthError {
    /// The failure kind when this failure is attributable to the caller's
    /// credential (missing, invalid or short of scope), `None` for a server-side
    /// problem (config resolution, JWKS fetch, storage).
    pub fn failure_kind(&self) -> Option<SourceAuthFailureKind> {
        match self {
            SourceAuthError::MissingCredential { .. } => Some(SourceAuthFailureKind::Missing),
            SourceAuthError::InvalidCredential { .. } => Some(SourceAuthFailureKind::Invalid),
            SourceAuthError::InsufficientScope { .. } => Some(SourceAuthFailureKind::InsufficientScope),
            SourceAuthError::ConfigNotFound { .. } | SourceAuthError::Internal { .. } => None,
        }
    }

    /// Whether this failure is attributable to the caller's credential rather
    /// than a server-side problem. Caller-attributable failures are handed to
    /// the policy layer instead of being blocked at the source-auth stage.
    pub fn is_caller_attributable(&self) -> bool {
        self.failure_kind().is_some()
    }

    /// HTTP status for a blocking denial. A missing or invalid credential maps
    /// to 401 and a scope shortfall to 403. Server-side failures (config not
    /// found, internal) map to 500, because 401 would misrepresent a
    /// server-side problem as the caller's fault.
    fn http_status(&self) -> StatusCode {
        match self.failure_kind() {
            Some(SourceAuthFailureKind::InsufficientScope) => StatusCode::FORBIDDEN,
            Some(_) => StatusCode::UNAUTHORIZED,
            None => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn problem_title(&self) -> &'static str {
        match self.http_status() {
            StatusCode::FORBIDDEN => "Forbidden",
            StatusCode::UNAUTHORIZED => "Unauthorized",
            _ => "Internal Server Error",
        }
    }
}

/// Result alias for source authentication operations.
pub type SourceAuthResult<T> = Result<T, SourceAuthError>;

/// Build a protocol-appropriate denial response for a source authentication
/// failure. A missing or invalid credential maps to **401 Unauthorized** and a
/// scope shortfall to **403 Forbidden**; server-side failures (config not found, internal) map
/// to **500 Internal Server Error** — a 401 would misrepresent a server-side
/// problem as the caller's fault. Note: caller-attributable failures are
/// normally handed to the policy layer rather than blocked, so in practice this
/// builder is reached for server-side (500) failures.
///
/// - **A2A / AP2**: `application/problem+json` with the A2A `proxy-error` type
///   URI. JWT Bearer 401s include a `WWW-Authenticate: Bearer` header.
/// - **MCP**: JWT Bearer 401s return `application/problem+json` *without*
///   the A2A error URI, plus a `WWW-Authenticate: Bearer` header with `realm`.
///   It names no `resource_metadata`. API key failures use an `about:blank` problem type.
/// - **Other protocols**: fall back to the A2A shape (matches the previous
///   behaviour).
///
/// A `WWW-Authenticate` challenge is only emitted for a genuine 401, and it
/// carries the gateway challenge marker.
pub fn deny_response(
    protocol: &SurfaceProtocol,
    auth_config: &SourceAuthConfig,
    error: &SourceAuthError,
) -> Response {
    let detail = error.to_string();
    let status = error.http_status();
    let title = error.problem_title();
    // Only a genuine 401 warrants a `WWW-Authenticate` challenge; a 403 or 500
    // is not a prompt for the caller to re-authenticate.
    let challenge = status == StatusCode::UNAUTHORIZED;

    match protocol {
        SurfaceProtocol::Mcp => mcp_deny(auth_config, &detail, status, title, challenge),
        _ => a2a_deny(auth_config, &detail, status, title, challenge),
    }
}

fn a2a_deny(
    auth_config: &SourceAuthConfig,
    detail: &str,
    status: StatusCode,
    title: &str,
    challenge: bool,
) -> Response {
    let body = serde_json::json!({
        "type": "https://a2a-protocol.org/errors/proxy-error",
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
    });

    problem_response(
        status,
        &body,
        (challenge && matches!(auth_config, SourceAuthConfig::JwtBearer(_))).then_some("Bearer"),
    )
}

fn mcp_deny(
    auth_config: &SourceAuthConfig,
    detail: &str,
    status: StatusCode,
    title: &str,
    challenge: bool,
) -> Response {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
    });

    problem_response(
        status,
        &body,
        (challenge && matches!(auth_config, SourceAuthConfig::JwtBearer(_)))
            .then_some("Bearer realm=\"agent-gateway\""),
    )
}

fn problem_response(
    status: StatusCode,
    body: &serde_json::Value,
    challenge: Option<&'static str>,
) -> Response {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
    if let Some(challenge) = challenge {
        crate::protocols::protected_resource::mark_gateway_challenge(
            &mut response,
            HeaderValue::from_static(challenge),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt_config() -> SourceAuthConfig {
        SourceAuthConfig::JwtBearer(crate::jwt_bearer::models::JwtBearerAuthConfig::default())
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("parse problem+json")
    }

    #[test]
    fn caller_attributable_classification() {
        assert!(SourceAuthError::MissingCredential { reason: "x".into() }.is_caller_attributable());
        assert!(SourceAuthError::InvalidCredential { reason: "x".into() }.is_caller_attributable());
        assert!(SourceAuthError::InsufficientScope { missing: vec!["x".into()] }.is_caller_attributable());
        assert!(!SourceAuthError::ConfigNotFound { id: "x".into() }.is_caller_attributable());
        assert!(!SourceAuthError::Internal { reason: "x".into() }.is_caller_attributable());
    }

    #[test]
    fn failure_kind_names_each_caller_failure() {
        assert_eq!(
            SourceAuthError::MissingCredential { reason: "x".into() }.failure_kind(),
            Some(SourceAuthFailureKind::Missing)
        );
        assert_eq!(
            SourceAuthError::InvalidCredential { reason: "x".into() }.failure_kind(),
            Some(SourceAuthFailureKind::Invalid)
        );
        assert_eq!(
            SourceAuthError::InsufficientScope { missing: vec!["x".into()] }.failure_kind(),
            Some(SourceAuthFailureKind::InsufficientScope)
        );
        assert_eq!(SourceAuthError::ConfigNotFound { id: "x".into() }.failure_kind(), None);
        assert_eq!(SourceAuthError::Internal { reason: "x".into() }.failure_kind(), None);
        for (kind, value) in [
            (SourceAuthFailureKind::Missing, "missing"),
            (SourceAuthFailureKind::Invalid, "invalid"),
            (SourceAuthFailureKind::InsufficientScope, "insufficient_scope"),
        ] {
            assert_eq!(serde_json::to_value(kind).expect("serialize"), serde_json::json!(value));
        }
    }

    #[test]
    fn insufficient_scope_message_lists_every_missing_scope() {
        let err = SourceAuthError::InsufficientScope {
            missing: vec!["a2a:invoke".into(), "mcp:tools".into()],
        };
        assert_eq!(err.to_string(), "Insufficient scope: missing a2a:invoke mcp:tools");
    }

    #[tokio::test]
    async fn insufficient_scope_is_403_without_challenge() {
        for protocol in [SurfaceProtocol::A2a, SurfaceProtocol::Mcp] {
            let err = SourceAuthError::InsufficientScope {
                missing: vec!["a2a:invoke".into()],
            };
            let resp = deny_response(&protocol, &jwt_config(), &err);
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert!(
                resp.headers()
                    .get("www-authenticate")
                    .is_none()
            );
            let body = body_json(resp).await;
            assert_eq!(body["status"], 403);
            assert_eq!(body["title"], "Forbidden");
        }
    }

    #[tokio::test]
    async fn every_challenge_carries_the_gateway_marker() {
        for protocol in [SurfaceProtocol::A2a, SurfaceProtocol::Mcp] {
            let err = SourceAuthError::MissingCredential { reason: "no token".into() };
            let resp = deny_response(&protocol, &jwt_config(), &err);
            assert!(
                resp.headers()
                    .contains_key("www-authenticate")
            );
            assert!(crate::protocols::protected_resource::is_gateway_challenge(&resp));
        }
        let err = SourceAuthError::Internal { reason: "x".into() };
        let resp = deny_response(&SurfaceProtocol::A2a, &jwt_config(), &err);
        assert!(!crate::protocols::protected_resource::is_gateway_challenge(&resp));
    }

    #[tokio::test]
    async fn problem_body_and_content_type_are_unchanged() {
        let err = SourceAuthError::InvalidCredential { reason: "expired".into() };
        let resp = deny_response(&SurfaceProtocol::A2a, &jwt_config(), &err);
        assert_eq!(resp.headers()["content-type"], "application/problem+json");
        assert_eq!(resp.headers()["www-authenticate"], "Bearer");
        let body = body_json(resp).await;
        assert_eq!(
            body,
            serde_json::json!({
                "type": "https://a2a-protocol.org/errors/proxy-error",
                "title": "Unauthorized",
                "status": 401,
                "detail": "Invalid credential: expired",
            })
        );
    }

    #[tokio::test]
    async fn api_key_failure_carries_no_challenge() {
        let api_key = SourceAuthConfig::ApiKey(crate::source_auth::models::ApiKeyAuthConfig {
            extraction: crate::source_auth::models::CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "s".to_string(),
        });
        let err = SourceAuthError::MissingCredential { reason: "no key".into() };
        let resp = deny_response(&SurfaceProtocol::Mcp, &api_key, &err);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            resp.headers()
                .get("www-authenticate")
                .is_none()
        );
        assert!(!crate::protocols::protected_resource::is_gateway_challenge(&resp));
    }

    #[tokio::test]
    async fn internal_error_detail_is_unchanged() {
        let err = SourceAuthError::Internal {
            reason: "jwks fetch failed".into(),
        };
        let body = body_json(deny_response(&SurfaceProtocol::A2a, &jwt_config(), &err)).await;
        assert_eq!(body["detail"], "Internal source auth error: jwks fetch failed");
    }

    #[tokio::test]
    async fn a2a_invalid_credential_is_401_with_challenge() {
        let err = SourceAuthError::InvalidCredential { reason: "expired".into() };
        let resp = deny_response(&SurfaceProtocol::A2a, &jwt_config(), &err);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            resp.headers()
                .get("www-authenticate")
                .is_some_and(|v| v
                    .to_str()
                    .unwrap()
                    .contains("Bearer"))
        );
        let body = body_json(resp).await;
        assert_eq!(body["status"], 401);
        assert_eq!(body["title"], "Unauthorized");
    }

    #[tokio::test]
    async fn a2a_internal_error_is_500_without_challenge() {
        let err = SourceAuthError::Internal {
            reason: "jwks fetch failed".into(),
        };
        let resp = deny_response(&SurfaceProtocol::A2a, &jwt_config(), &err);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            resp.headers()
                .get("www-authenticate")
                .is_none()
        );
        let body = body_json(resp).await;
        assert_eq!(body["status"], 500);
        assert_eq!(body["title"], "Internal Server Error");
    }

    #[tokio::test]
    async fn mcp_caller_credential_failure_is_401_with_a_challenge_naming_no_metadata() {
        for err in [
            SourceAuthError::MissingCredential { reason: "no token".into() },
            SourceAuthError::InvalidCredential { reason: "expired".into() },
        ] {
            let resp = deny_response(&SurfaceProtocol::Mcp, &jwt_config(), &err);
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(resp.headers()["www-authenticate"], "Bearer realm=\"agent-gateway\"");
            let body = body_json(resp).await;
            assert_eq!(body["status"], 401);
        }
    }

    #[tokio::test]
    async fn mcp_config_not_found_is_500_without_challenge() {
        let err = SourceAuthError::ConfigNotFound { id: "missing".into() };
        let resp = deny_response(&SurfaceProtocol::Mcp, &jwt_config(), &err);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            resp.headers()
                .get("www-authenticate")
                .is_none()
        );
        let body = body_json(resp).await;
        assert_eq!(body["status"], 500);
        assert_eq!(body["title"], "Internal Server Error");
    }
}
