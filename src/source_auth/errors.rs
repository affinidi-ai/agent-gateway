//! Source authentication error types

use axum::{body::Body, http::StatusCode, response::Response};
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

impl SourceAuthError {
    /// Whether this failure is attributable to the caller's credential (missing
    /// or invalid) rather than a server-side problem (config resolution, JWKS
    /// fetch, storage). Caller-attributable failures are handed to the policy
    /// layer instead of being blocked at the source-auth stage.
    pub fn is_caller_attributable(&self) -> bool {
        matches!(self, SourceAuthError::MissingCredential { .. } | SourceAuthError::InvalidCredential { .. })
    }

    /// HTTP status for a blocking denial. Caller-credential failures map to
    /// 401; server-side failures (config not found, internal) map to 500 —
    /// 401 would misrepresent a server-side problem as the caller's fault.
    fn http_status(&self) -> StatusCode {
        if self.is_caller_attributable() {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    fn problem_title(&self) -> &'static str {
        if self.is_caller_attributable() {
            "Unauthorized"
        } else {
            "Internal Server Error"
        }
    }
}

/// Result alias for source authentication operations.
pub type SourceAuthResult<T> = Result<T, SourceAuthError>;

/// Build a protocol-appropriate denial response for a source authentication
/// failure. Caller-attributable failures (missing/invalid credential) map to
/// **401 Unauthorized**; server-side failures (config not found, internal) map
/// to **500 Internal Server Error** — a 401 would misrepresent a server-side
/// problem as the caller's fault. Note: caller-attributable failures are
/// normally handed to the policy layer rather than blocked, so in practice this
/// builder is reached for server-side (500) failures.
///
/// - **A2A / AP2**: `application/problem+json` with the A2A `proxy-error` type
///   URI. JWT Bearer 401s include a `WWW-Authenticate: Bearer` header.
/// - **MCP**: JWT Bearer 401s return `application/problem+json` *without*
///   the A2A error URI, plus a `WWW-Authenticate` header with `realm` and
///   `resource_metadata`. API key failures use an `about:blank` problem type.
/// - **Other protocols**: fall back to the A2A shape (matches the previous
///   behaviour).
///
/// A `WWW-Authenticate` challenge is only emitted for a genuine 401.
pub fn deny_response(
    protocol: &SurfaceProtocol,
    auth_config: &SourceAuthConfig,
    error: &SourceAuthError,
) -> Response {
    let detail = error.to_string();
    let status = error.http_status();
    let title = error.problem_title();
    // Only a genuine 401 warrants a `WWW-Authenticate` challenge; a 500 is a
    // server-side fault, not a prompt for the caller to re-authenticate.
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

    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/problem+json");

    if challenge && matches!(auth_config, SourceAuthConfig::JwtBearer(_)) {
        builder = builder.header("www-authenticate", "Bearer");
    }

    builder
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
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

    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/problem+json");

    if challenge && matches!(auth_config, SourceAuthConfig::JwtBearer(_)) {
        builder = builder.header(
            "www-authenticate",
            "Bearer realm=\"agent-gateway\", resource_metadata=\"/.well-known/oauth-protected-resource\"",
        );
    }

    builder
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
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
        assert!(!SourceAuthError::ConfigNotFound { id: "x".into() }.is_caller_attributable());
        assert!(!SourceAuthError::Internal { reason: "x".into() }.is_caller_attributable());
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
    async fn mcp_missing_credential_is_401_with_challenge() {
        let err = SourceAuthError::MissingCredential { reason: "no token".into() };
        let resp = deny_response(&SurfaceProtocol::Mcp, &jwt_config(), &err);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            resp.headers()
                .get("www-authenticate")
                .is_some_and(|v| v
                    .to_str()
                    .unwrap()
                    .contains("realm"))
        );
        let body = body_json(resp).await;
        assert_eq!(body["status"], 401);
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
