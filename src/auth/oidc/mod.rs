// OpenID Connect sign-in module
//
// Signs dashboard users in with one OpenID provider (`auth_mode = "oidc"`, configured in
// `oidc.json`): authorization code with PKCE, a verified ID token, just-in-time users keyed on the
// provider account, and roles from a claim mapping recomputed at every sign-in.

pub mod config;
pub mod discovery;
pub mod egress;
pub mod handlers;
pub mod pending;
pub mod roles;
#[cfg(test)]
mod sign_in_tests;
#[cfg(test)]
pub(crate) mod test_support;
pub mod throttle;
pub mod tokens;
pub mod user_provisioning;

pub use config::OidcConfig;
pub use handlers::{OidcState, oidc_callback, oidc_login};
