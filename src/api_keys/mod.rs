//! API Key Provider Module
//!
//! Provides API key management for onboarded agents. External clients can obtain
//! agent-scoped API keys for authenticated access through the gateway.
//!
//! # Features
//! - Per-agent API key creation with client_id scoping
//! - Key rotation and revocation
//! - Storage-agnostic design with filesystem backend
//! - Integration with A2A auth validation
//!
//! # Storage Layout (Filesystem)
//! ```text
//! _storage/
//! └── api_keys/
//!     └── {agent_id}/
//!         ├── {key_id_1}.json
//!         └── ...
//! ```

mod errors;
mod filesystem;
mod generator;
pub mod handlers;
pub mod router;
pub mod store;
mod types;

// Re-exports for public API
pub use errors::ApiKeyResult;
pub use filesystem::FileSystemApiKeyStore;
pub use generator::KEY_ID_PREFIX;
pub use store::ApiKeyValidator;
#[cfg(test)]
pub use types::ApiKeyIssuer;
pub use types::{ApiKeyCreated, ApiKeyMeta, ApiKeyStatus};
