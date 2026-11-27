// OpenID Connect sign-in module
//
// Signs dashboard users in with one OpenID provider (`auth_mode = "oidc"`, configured in
// `oidc.json`): authorization code with PKCE, a verified ID token, just-in-time users keyed on the
// provider account, and roles from a claim mapping recomputed at every sign-in. The provider can
// start a sign-in (third-party-initiated login) and end sessions (back-channel logout), and
// signing out of the dashboard can sign the person out at the provider (RP-initiated logout).

pub mod config;
pub mod discovery;
pub mod egress;
pub mod handlers;
pub mod initiate;
pub mod logout;
#[cfg(test)]
mod logout_tests;
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
pub use initiate::oidc_initiate;
pub use logout::{MAX_BACKCHANNEL_LOGOUT_BYTES, oidc_backchannel_logout, oidc_logout};
