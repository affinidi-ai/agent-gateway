//! Unified source authentication module
//!
//! Provides a single `SourceAuthMiddleware` that dispatches authentication for
//! all supported source authentication methods: JWT Bearer, API Key, DID Auth,
//! and mTLS (stub).
//!
//! # Module layout
//! - [`models`]      — `SourceAuthConfig`, `AuthenticatedIdentity`, `CredentialExtraction`, etc.
//! - [`errors`]      — `SourceAuthError` / `SourceAuthResult`
//! - [`middleware`]   — `SourceAuthMiddleware` — the unified authentication gate
//! - [`mtls`]         — mTLS verification helpers (pure logic; no I/O)
//! - [`client_ip`]    — the caller's IP for per-client limits, trusting forwarded headers only from trusted proxies

pub mod client_ip;
pub mod errors;
pub mod middleware;
pub mod mtls;

pub mod models;
pub mod peer_cert;

pub use middleware::SourceAuthMiddleware;
pub use models::{AuthenticatedIdentity, ManagedIdentityConfig, SourceAuthConfig};
