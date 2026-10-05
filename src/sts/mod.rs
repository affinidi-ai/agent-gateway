//! Security Token Service — RFC 8693 OAuth 2.0 Token Exchange + ID-JAG.
//!
//! Gives the gateway an identity-native STS: it accepts a caller's identity
//! assertion (a JWT / ID-token / ID-JAG, or a decentralized Verifiable
//! Presentation), applies policy, and mints a short-lived, audience-scoped token
//! carrying a verifiable delegation chain (RFC 8693 `act`).
//!
//! Module layout:
//! - [`types`] — grant/token-type URNs and request/response shapes.
//! - [`errors`] — OAuth error responses (RFC 6749 §5.2 / RFC 8693 §2.2.2).
//! - [`token_exchange`] — pure RFC 8693 validation, `act` chain, claim building.
//! - [`id_jag`] — ID-JAG issue + redeem (`draft-ietf-oauth-identity-assertion-authz-grant`).
//! - [`handlers`] — axum token endpoint, discovery, JWKS.

pub mod admin;
pub mod client;
pub mod errors;
pub mod handlers;
pub mod id_jag;
pub mod mcp_profile;
pub mod policy;
pub mod replay;
pub mod resource_owners;
pub mod store;
pub mod throttle;
pub mod token_exchange;
pub mod trust_check;
pub mod types;
