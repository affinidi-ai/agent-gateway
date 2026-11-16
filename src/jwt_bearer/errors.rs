//! JWT Bearer error types

use thiserror::Error;

/// Errors that can occur during JWT Bearer token verification or strategy management.
#[derive(Debug, Clone, Error)]
pub enum JwtBearerError {
    /// The request carries no `Authorization: Bearer` header.
    #[error("Missing bearer token")]
    MissingToken,

    /// The token is structurally or cryptographically invalid.
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// The token's `exp` claim is in the past.
    #[error("Token has expired")]
    ExpiredToken,

    /// The token's `iss` claim does not match the configured issuer.
    #[error("Invalid issuer")]
    InvalidIssuer,

    /// The token's `aud` claim does not match any configured audience.
    #[error("Invalid audience")]
    InvalidAudience,

    /// The referenced JWT verification strategy does not exist (e.g. it was deleted).
    #[error("JWT verification strategy not found: {0}")]
    StrategyNotFound(String),

    /// Failed to fetch or parse the JWKS from the remote endpoint.
    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    /// The JWKS URI is not an http(s) URL or resolves to loopback, an
    /// unspecified address or cloud metadata, so the egress policy refuses to
    /// fetch it.
    #[error("JWKS URI refused by egress policy")]
    JwksUriBlocked,

    /// The `kid` referenced in the token header was not found in the JWKS.
    #[error("Key not found for kid: {0}")]
    KeyNotFound(String),

    /// A storage I/O error occurred.
    #[error("Storage error: {0}")]
    Storage(String),

    /// The strategy's stored `principal_claim` is not one that can name a caller.
    #[error("Invalid principal claim on strategy: {0}")]
    InvalidPrincipalClaim(String),
}

impl From<anyhow::Error> for JwtBearerError {
    fn from(e: anyhow::Error) -> Self {
        JwtBearerError::Storage(e.to_string())
    }
}

/// Result alias for JWT Bearer operations.
pub type JwtBearerResult<T> = Result<T, JwtBearerError>;
