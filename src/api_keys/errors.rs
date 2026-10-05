//! API Key error types

use thiserror::Error;

/// API Key operation errors
#[derive(Debug, Error)]
pub enum ApiKeyError {
    /// Key not found (structured)
    #[error("API key not found: {key_id}")]
    KeyNotFound { key_id: String },

    /// Agent not found
    #[error("Agent not found: {agent_id}")]
    #[allow(unused)]
    AgentNotFound { agent_id: String },

    /// Key already revoked
    #[error("API key already revoked: {key_id}")]
    AlreadyRevoked { key_id: String },

    /// Invalid key status transition
    #[error("Invalid status transition from {from:?} to {to:?}")]
    #[allow(unused)]
    InvalidStatusTransition { from: super::ApiKeyStatus, to: super::ApiKeyStatus },

    /// Validation error
    #[error("Validation error: {message}")]
    Validation { message: String },

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] anyhow::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for API key operations
pub type ApiKeyResult<T> = Result<T, ApiKeyError>;

impl ApiKeyError {
    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation { message: message.into() }
    }

    /// Create a key not found error
    pub fn not_found(key_id: impl Into<String>) -> Self {
        Self::KeyNotFound { key_id: key_id.into() }
    }

    /// Create an agent not found error
    pub fn _agent_not_found(agent_id: impl Into<String>) -> Self {
        Self::AgentNotFound { agent_id: agent_id.into() }
    }
}
