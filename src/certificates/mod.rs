//! Certificate management module

pub mod filesystem;
pub mod handlers;
pub mod router;
pub mod store;

use serde::{Deserialize, Serialize};

/// What this certificate represents in the gateway.
///
/// Determines whether the cert participates in TLS server termination,
/// mTLS pinned-cert trust, or chain validation as a trust anchor.
/// Existing stored certificates without this field deserialize as
/// [`CertificateKind::ServerLeaf`] to preserve historical behaviour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateKind {
    /// Server certificate + private key bundle used to terminate TLS.
    /// (Historical default.)
    #[default]
    ServerLeaf,
    /// Client leaf certificate used in mTLS [`MtlsTrust::Pinned`] mode.
    ClientLeaf,
    /// Issuer CA certificate used as a trust anchor for mTLS
    /// [`MtlsTrust::Ca`] mode.
    Ca,
}

/// Certificate information returned in list responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateListItem {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub certificate_id: String, // UUID for certificate identifier
    pub description: Option<String>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub kind: CertificateKind,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
}

/// Full certificate data including the PEM content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub certificate_id: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub kind: CertificateKind,
    #[serde(rename = "certificate_pem")]
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
    /// Optional DID associated with this certificate for identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_did: Option<String>,
}

/// Request to create a new certificate
#[derive(Debug, Deserialize)]
pub struct CreateCertificateRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub kind: CertificateKind,
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub active: Option<bool>,
    pub identity_did: Option<String>,
}

/// Request to update an existing certificate
#[derive(Debug, Deserialize)]
pub struct UpdateCertificateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub kind: Option<CertificateKind>,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub active: Option<bool>,
    pub identity_did: Option<String>,
}

pub use filesystem::FilesystemCertificateStore;
pub use store::CertificateStore;
