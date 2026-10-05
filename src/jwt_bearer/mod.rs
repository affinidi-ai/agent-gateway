//! JWT Bearer token authentication module
//!
//! Provides JWT bearer token validation for inbound requests on channels.
//! Supports generic OAuth 2.0 / OIDC providers with local JWT verification (RS256/ES256 family).
//!
//! # Module layout
//! - [`models`]    — data types: `JwtVerificationStrategy`, `JwtBearerAuthConfig`, etc.
//! - [`errors`]    — `JwtBearerError` / `JwtBearerResult`
//! - [`storage`]   — `JwtVerificationStrategyStorage` trait + `FileSystemJwtVerificationStrategyStore`
//! - [`jwks`]      — JWKS fetching and in-memory caching
//! - [`validator`] — JWT signature + claims verification (`JwtBearerVerifier`)

pub mod errors;
pub mod handlers;
pub mod jwks;
pub mod models;
pub mod router;
pub mod storage;
pub mod validator;

#[cfg(test)]
pub mod test_utils;

// Primary public API
pub use jwks::JwksClient;
pub use storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
pub use validator::JwtBearerVerifier;
