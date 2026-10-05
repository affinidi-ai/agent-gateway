// SAML authentication module
//
// This module provides SAML 2.0 authentication with Azure AD

pub mod graph_api;
pub mod handlers;
pub mod service;
pub mod user_provisioning;

pub use handlers::*;
pub use service::SamlService;
