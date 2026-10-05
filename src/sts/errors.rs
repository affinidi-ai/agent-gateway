//! OAuth 2.0 error responses for the Security Token Service.
//!
//! Maps internal failures onto the RFC 6749 §5.2 / RFC 8693 §2.2.2 error codes
//! and renders them as `application/json` with `Cache-Control: no-store`.

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// A token-endpoint error, carrying an OAuth error code and a human-readable
/// description. `error_description` is safe for a client to read; it must not
/// leak secrets or internal state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StsError {
    /// Malformed request: missing/duplicate/unsupported parameters.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    /// Client authentication failed or was absent.
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    /// The presented subject/actor/assertion token is invalid, expired, or unverifiable.
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    /// The requested scope is unknown, malformed, or exceeds what the client may request.
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    /// The authenticated client is not permitted to use this grant / connection.
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),
    /// The `grant_type` is not supported by this endpoint.
    #[error("unsupported_grant_type: {0}")]
    UnsupportedGrantType(String),
    /// The requested `resource`/`audience` is unknown or not allowed (RFC 8693 §2.2.2).
    #[error("invalid_target: {0}")]
    InvalidTarget(String),
    /// A `subject_token_type` / `requested_token_type` we do not support.
    #[error("invalid_request: unsupported token type: {0}")]
    UnsupportedTokenType(String),
    /// Internal failure (signing, storage). Rendered as a generic server error.
    #[error("server_error: {0}")]
    ServerError(String),
}

impl StsError {
    /// The stable OAuth error code (the `error` field).
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) | Self::UnsupportedTokenType(_) => "invalid_request",
            Self::InvalidClient(_) => "invalid_client",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidScope(_) => "invalid_scope",
            Self::UnauthorizedClient(_) => "unauthorized_client",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::InvalidTarget(_) => "invalid_target",
            Self::ServerError(_) => "server_error",
        }
    }

    /// The HTTP status for this error. `invalid_client` is 401 (RFC 6749 §5.2);
    /// `server_error` is 500; everything else is 400.
    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::InvalidClient(_) => StatusCode::UNAUTHORIZED,
            Self::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// The human-readable `error_description`.
    pub fn description(&self) -> String {
        match self {
            Self::InvalidRequest(m)
            | Self::InvalidClient(m)
            | Self::InvalidGrant(m)
            | Self::InvalidScope(m)
            | Self::UnauthorizedClient(m)
            | Self::UnsupportedGrantType(m)
            | Self::InvalidTarget(m)
            | Self::UnsupportedTokenType(m)
            | Self::ServerError(m) => m.clone(),
        }
    }

    /// The `error_description` safe to return to the client. A `server_error`
    /// collapses to a generic message so internal detail (crypto, storage, or
    /// secret-resolution errors) never leaks over the wire; the full detail is
    /// logged server-side instead (see [`IntoResponse`]).
    pub fn client_description(&self) -> String {
        match self {
            Self::ServerError(_) => "the authorization server encountered an internal error".to_string(),
            other => other.description(),
        }
    }
}

/// Serializable OAuth error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OAuthErrorBody {
    pub error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error_description: String,
}

impl From<&StsError> for OAuthErrorBody {
    fn from(e: &StsError) -> Self {
        Self {
            error: e.error_code().to_string(),
            error_description: e.client_description(),
        }
    }
}

impl IntoResponse for StsError {
    fn into_response(self) -> Response {
        // Log the internal detail of a server fault server-side; the client body
        // carries only the generic `client_description`.
        if let StsError::ServerError(detail) = &self {
            tracing::error!(target: "sts_audit", error_detail = %detail, "STS internal error");
        }
        let body = OAuthErrorBody::from(&self);
        let mut response = (self.http_status(), Json(body)).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(StsError::InvalidRequest("x".into()).error_code(), "invalid_request");
        assert_eq!(StsError::UnsupportedTokenType("x".into()).error_code(), "invalid_request");
        assert_eq!(StsError::InvalidClient("x".into()).error_code(), "invalid_client");
        assert_eq!(StsError::InvalidGrant("x".into()).error_code(), "invalid_grant");
        assert_eq!(StsError::InvalidScope("x".into()).error_code(), "invalid_scope");
        assert_eq!(StsError::UnauthorizedClient("x".into()).error_code(), "unauthorized_client");
        assert_eq!(StsError::UnsupportedGrantType("x".into()).error_code(), "unsupported_grant_type");
        assert_eq!(StsError::InvalidTarget("x".into()).error_code(), "invalid_target");
        assert_eq!(StsError::ServerError("x".into()).error_code(), "server_error");
    }

    #[test]
    fn http_status_mapping() {
        assert_eq!(StsError::InvalidClient("x".into()).http_status(), StatusCode::UNAUTHORIZED);
        assert_eq!(StsError::ServerError("x".into()).http_status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(StsError::InvalidRequest("x".into()).http_status(), StatusCode::BAD_REQUEST);
        assert_eq!(StsError::InvalidTarget("x".into()).http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn error_body_carries_code_and_description() {
        let body = OAuthErrorBody::from(&StsError::InvalidTarget("audience not allowed".into()));
        assert_eq!(body.error, "invalid_target");
        assert_eq!(body.error_description, "audience not allowed");
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(json["error"], "invalid_target");
        assert_eq!(json["error_description"], "audience not allowed");
    }

    #[test]
    fn empty_description_is_omitted() {
        let body = OAuthErrorBody {
            error: "invalid_request".to_string(),
            error_description: String::new(),
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert!(
            json.get("error_description")
                .is_none(),
            "empty description must be omitted"
        );
    }

    #[test]
    fn server_error_body_hides_internal_detail() {
        let body = OAuthErrorBody::from(&StsError::ServerError("token signing failed: key file missing".into()));
        assert_eq!(body.error, "server_error");
        assert!(
            !body
                .error_description
                .contains("key file missing"),
            "internal server detail must not leak to the client"
        );
        assert!(
            !body
                .error_description
                .is_empty(),
            "a generic description is still provided"
        );
    }
}
