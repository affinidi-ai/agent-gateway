use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("Integration '{0}' not found")]
    NotFound(String),

    #[error("Integration '{0}' is not active (status: {1})")]
    Inactive(String, String),

    #[error("Unknown integration type: {0}")]
    UnknownType(String),

    #[error("Integration '{0}' receives only governance audit records")]
    AuditOnly(String),

    #[error("Invalid configuration: {0}")]
    #[allow(dead_code)]
    InvalidConfig(String),

    #[error("Invalid content template: {0}")]
    #[allow(dead_code)]
    InvalidContent(String),

    #[error("Failed to parse configuration: {0}")]
    #[allow(dead_code)]
    ConfigParseError(String),

    #[error("Publisher error: {0}")]
    PublisherError(#[from] anyhow::Error),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Variable substitution error: {0}")]
    #[allow(dead_code)]
    VariableError(String),

    #[error("Batch operation failed: {successful}/{total} succeeded")]
    #[allow(dead_code)]
    BatchPartialFailure { successful: usize, total: usize },
}

pub type Result<T> = std::result::Result<T, IntegrationError>;
