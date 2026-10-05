// Vault Identity module - Provides identity generation for API keys and certificates
//
// This module provides HTTP endpoints for generating did:web identities that can be
// associated with API keys and certificates for authentication purposes.

pub mod handlers;
pub mod router;

pub use router::create_vault_identity_router;
