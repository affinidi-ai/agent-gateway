// Identity API module - REST API for agent identity credential issuance
//
// This module provides HTTP endpoints for clients to submit their agent identity
// and receive a verifiable credential and DID.

pub mod credential_identity;
pub mod did_keys;
pub mod filesystem;
pub mod handlers;
pub mod identity_hash;
pub mod identity_selector;
pub mod router;
pub mod ssi;
pub mod state;
pub mod store;
#[cfg(test)]
pub mod test_helpers;
pub mod utils;
pub mod vc_issuer;
pub mod vp_challenge_store;

// did:webvh + UAI modules are behind feature gate until fully integrated
#[cfg(feature = "didwebvh")]
pub mod didwebvh;
#[cfg(feature = "didwebvh")]
pub mod uai;

// Re-export main types for convenience
pub use filesystem::*;
pub use identity_hash::compute_canonical_identity_hash;
pub use identity_selector::*;
pub use router::create_did_router;
pub use router::create_identity_api_router;
pub use router::create_onboarding_router;
pub use state::IdentityApiState;
pub use store::IdentityStore;
pub use vc_issuer::*;
pub use vp_challenge_store::*;
