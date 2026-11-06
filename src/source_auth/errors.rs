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

    /// The request carries credentials for more than one source
    /// authentication method, so none is verified.
    #[error("Ambiguous credentials: the request carries credentials for more than one source authentication method")]
    AmbiguousCredentials,

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
            JwtBearerError::InvalidPrincipalClaim(msg) => SourceAuthError::Internal {
                reason: format!("Invalid principal claim: {msg}"),
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
        matches!(
            self,
            SourceAuthError::MissingCredential { .. }
                | SourceAuthError::InvalidCredential { .. }
                | SourceAuthError::AmbiguousCredentials
        )
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
/// handed to the policy layer unless the Access Point rejects failed callers
/// (see [`caller_refusal`]), so in practice this builder is reached for
/// server-side (500) failures.
///
/// A caller-attributable failure reports [`CALLER_CREDENTIAL_REFUSED`] as its
/// detail, so the reason the credential failed is never sent to the caller.
///
/// - **A2A / AP2**: `application/problem+json` with the A2A `proxy-error` type
///   URI. JWT Bearer 401s include a `WWW-Authenticate: Bearer` header.
/// - **MCP**: JWT Bearer 401s return `application/problem+json` *without*
///   the A2A error URI, plus a `WWW-Authenticate: Bearer` header with `realm`.
///   API key failures use an `about:blank` problem type.
/// - **Other protocols**: fall back to the A2A shape (matches the previous
///   behaviour).
///
/// A `WWW-Authenticate` challenge is only emitted for a genuine 401.
pub fn deny_response(
    protocol: &SurfaceProtocol,
    auth_config: &SourceAuthConfig,
    error: &SourceAuthError,
) -> Response {
    let detail = if error.is_caller_attributable() {
        CALLER_CREDENTIAL_REFUSED.to_string()
    } else {
        error.to_string()
    };
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

/// What a caller refused for a missing or invalid credential is told. Why the
/// credential failed is logged, never sent.
pub const CALLER_CREDENTIAL_REFUSED: &str = "Caller credential missing or invalid";

/// The `WWW-Authenticate` challenge an MCP JWT Bearer refusal carries.
const MCP_BEARER_CHALLENGE: &str = "Bearer realm=\"agent-gateway\"";

/// The `401` for a caller whose credential is missing or invalid, on an Access
/// Point whose caller authentication rejects such callers, or whose inbound
/// identity is `from_jwt_claim`. An MCP caller gets a JSON-RPC error answering
/// `mcp_request_id`; any other caller gets `application/problem+json`. A JWT
/// Bearer refusal carries a `WWW-Authenticate: Bearer` challenge.
pub fn caller_refusal(
    protocol: &SurfaceProtocol,
    auth_config: &SourceAuthConfig,
    mcp_request_id: Option<serde_json::Value>,
) -> Response {
    let status = StatusCode::UNAUTHORIZED;
    match protocol {
        SurfaceProtocol::Mcp => {
            let mut response = crate::mcp::errors::create_mcp_error_response_with_status(
                status,
                mcp_request_id,
                crate::mcp::errors::error_codes::INTERNAL_ERROR,
                CALLER_CREDENTIAL_REFUSED,
                None,
            );
            if matches!(auth_config, SourceAuthConfig::JwtBearer(_)) {
                response.headers_mut().insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static(MCP_BEARER_CHALLENGE),
                );
            }
            response
        }
        _ => a2a_deny(auth_config, CALLER_CREDENTIAL_REFUSED, status, "Unauthorized", true),
    }
}

/// What a caller of an Access Point that is not ready is told. Why it is not
/// ready is logged, never sent.
pub const ACCESS_POINT_UNAVAILABLE: &str = "This Access Point is not available.";

/// The `503` for every request to an Access Point that is not ready: closed
/// (`public: false`) with no source authentication. An MCP caller gets a
/// JSON-RPC error answering `mcp_request_id`; any other caller gets
/// `application/problem+json`, as a Transit Point that can't be served does.
pub fn access_point_unavailable(
    protocol: &SurfaceProtocol,
    mcp_request_id: Option<serde_json::Value>,
) -> Response {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    match protocol {
        SurfaceProtocol::Mcp => crate::mcp::errors::create_mcp_error_response_with_status(
            status,
            mcp_request_id,
            crate::mcp::errors::error_codes::INTERNAL_ERROR,
            ACCESS_POINT_UNAVAILABLE,
            None,
        ),
        _ => crate::a2a::errors::create_error_response(status, ACCESS_POINT_UNAVAILABLE),
    }
}

/// Why an Access Point is not ready: it is closed and authenticates no caller
/// ([`AgentSurface::refuses_every_request`]), or it derives a DID from an API
/// key it may not use ([`crate::identity::provider_key_gate`]).
///
/// [`AgentSurface::refuses_every_request`]: crate::config::agent_surface::AgentSurface::refuses_every_request
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotReadyReason {
    NoSourceAuthentication,
    ProviderKeyTenant,
    ApiKeyStoreUnavailable,
}

impl NotReadyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoSourceAuthentication => "no source authentication",
            Self::ProviderKeyTenant => crate::identity::provider_key_gate::PROVIDER_KEY_TENANT_RULE,
            Self::ApiKeyStoreUnavailable => crate::identity::provider_key_gate::API_KEY_STORE_UNAVAILABLE,
        }
    }

    /// Why a request to `surface`, as served, is refused before source
    /// authentication, on the direct path and over Fabric, if it is.
    pub async fn of(surface: &crate::config::agent_surface::AgentSurface) -> Option<Self> {
        if surface.refuses_every_request() {
            return Some(Self::NoSourceAuthentication);
        }
        crate::identity::provider_key_gate::gate()
            .refuses(surface)
            .await
    }
}

/// Refuses a request to `surface`, whose Access Point is not ready for
/// `reason`, on the direct path and over Fabric: logs why, records
/// `request_rejected` with the reason `access_point_not_ready`, and answers
/// with [`access_point_unavailable`].
pub fn refuse_unavailable_access_point(
    surface: &crate::config::agent_surface::AgentSurface,
    facts: &crate::audit::request_events::RequestFacts<'_>,
    variant_alias: Option<&str>,
    mcp_request_id: Option<serde_json::Value>,
    reason: NotReadyReason,
) -> Response {
    crate::channel_warn!(
        surface.surface_id,
        "Access Point is not ready (variant={:?}, via_fabric={}, reason={}) — refusing with 503",
        variant_alias,
        facts.via_fabric,
        reason.as_str()
    );
    let response = access_point_unavailable(&surface.access_point.protocol, mcp_request_id);
    let rpc_error_code = (surface.access_point.protocol == SurfaceProtocol::Mcp)
        .then_some(i64::from(crate::mcp::errors::error_codes::INTERNAL_ERROR));
    crate::audit::request_events::request_rejected(
        facts,
        crate::audit::request_events::RejectionStage::Admission,
        crate::audit::request_events::RejectionReason::AccessPointNotReady,
        response.status().as_u16(),
        rpc_error_code,
    );
    response
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
        builder = builder.header("www-authenticate", MCP_BEARER_CHALLENGE);
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
        assert_eq!(body["detail"], CALLER_CREDENTIAL_REFUSED);
        assert!(
            !body
                .to_string()
                .contains("expired"),
            "the refusal reason reached the caller: {body}"
        );
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

    fn api_key_config() -> SourceAuthConfig {
        SourceAuthConfig::ApiKey(crate::source_auth::models::ApiKeyAuthConfig {
            extraction: crate::source_auth::models::CredentialExtraction::HttpHeader { field: "x-api-key".to_string() },
            secret_id: "key".to_string(),
        })
    }

    #[tokio::test]
    async fn a_refused_caller_is_told_only_that_its_credential_is_missing_or_invalid() {
        for (protocol, config, challenge) in
            [(SurfaceProtocol::A2a, jwt_config(), Some("Bearer")), (SurfaceProtocol::Ap2, api_key_config(), None)]
        {
            let resp = caller_refusal(&protocol, &config, Some(serde_json::json!(7)));
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(resp.headers()["content-type"], "application/problem+json");
            assert_eq!(
                resp.headers()
                    .get("www-authenticate")
                    .map(|value| value.to_str().unwrap()),
                challenge
            );
            let body = body_json(resp).await;
            assert_eq!(body["detail"], CALLER_CREDENTIAL_REFUSED);
            assert_eq!(body["status"], 401);
            assert!(body.get("id").is_none());
        }
    }

    #[tokio::test]
    async fn a_refused_mcp_caller_gets_a_json_rpc_error_answering_its_request() {
        for (config, id, challenge) in [
            (jwt_config(), Some(serde_json::json!("call-1")), Some("Bearer realm=\"agent-gateway\"")),
            (api_key_config(), None, None),
        ] {
            let resp = caller_refusal(&SurfaceProtocol::Mcp, &config, id.clone());
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                resp.headers()
                    .get("www-authenticate")
                    .map(|value| value.to_str().unwrap()),
                challenge
            );
            let body = body_json(resp).await;
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body.get("id").cloned(), id);
            assert_eq!(body["error"]["code"], crate::mcp::errors::error_codes::INTERNAL_ERROR);
            assert_eq!(body["error"]["message"], CALLER_CREDENTIAL_REFUSED);
        }
    }

    #[tokio::test]
    async fn test_access_point_unavailable_is_503_in_the_callers_protocol_shape() {
        for protocol in [SurfaceProtocol::A2a, SurfaceProtocol::Ap2] {
            let resp = access_point_unavailable(&protocol, Some(serde_json::json!(7)));
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(resp.headers()["content-type"], "application/problem+json");
            assert!(
                resp.headers()
                    .get("www-authenticate")
                    .is_none()
            );
            let body = body_json(resp).await;
            assert_eq!(body["detail"], ACCESS_POINT_UNAVAILABLE);
            assert_eq!(body["status"], 503);
            assert!(body.get("id").is_none());
        }

        let resp = access_point_unavailable(&SurfaceProtocol::Mcp, Some(serde_json::json!("call-1")));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(
            body,
            serde_json::json!({"jsonrpc": "2.0", "id": "call-1", "error": {
                "code": crate::mcp::errors::error_codes::INTERNAL_ERROR, "message": ACCESS_POINT_UNAVAILABLE
            }})
        );
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
