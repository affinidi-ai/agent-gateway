// Dashboard authentication module
//
// This module provides the management dashboard's sign-in: WebAuthn passkeys, SAML, or OpenID
// Connect, one mode at a time.

pub mod auth_config;
pub mod cli_login;
pub mod decoy_credential;
pub mod handlers;
pub mod mode_handler;
pub mod oidc;
pub mod saml;
pub mod session;
pub mod session_cleanup;
pub mod session_cookie;
pub mod session_finalizer;
pub mod sign_in_events;
pub mod sign_in_pages;
pub mod state;
pub mod storage;
#[cfg(debug_assertions)]
pub mod test_auth;
pub mod types;

pub use auth_config::{AuthMode, SamlConfig};
pub use session::SessionManager;
pub use session_cleanup::periodic_session_cleanup;
pub use state::AuthState;
pub use types::{UserRole, UserStatus};
