//! DID Authentication module for channels
//!
//! Provides DID-based authentication for channels.
//! When a channel has identity_config.mode = "didauth", it exposes:
//! - `{listen_address}/authenticate/challenge` - Returns a challenge for the client
//! - `{listen_address}/authenticate` - Verifies the signed challenge and returns a session token
//!
//! Clients must then include the session token in subsequent requests (via HTTP header or protocol field)

pub mod handlers;
pub mod sessions;
pub mod verify;

pub use sessions::DidAuthSessionStore;
