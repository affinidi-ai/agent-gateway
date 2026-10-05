//! Filesystem-based certificate storage implementation

use super::{Certificate, CertificateListItem, CertificateStore, CreateCertificateRequest, UpdateCertificateRequest};
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

/// Implement StorableEntity for Certificate to use generic filesystem storage
impl StorableEntity for Certificate {
    fn id(&self) -> &str {
        &self.id
    }
}

pub struct FilesystemCertificateStore {
    storage: Box<dyn StorageBackend<Certificate>>,
}

impl FilesystemCertificateStore {
    pub async fn new(storage_path: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_path, "certificate").await?;
        Ok(Self { storage })
    }
}

#[async_trait]
impl CertificateStore for FilesystemCertificateStore {
    async fn list_all(&self) -> Result<Vec<CertificateListItem>, String> {
        self.storage
            .list_all()
            .await
            .map(|certs| {
                certs
                    .into_iter()
                    .map(|cert| CertificateListItem {
                        id: cert.id,
                        tenant_id: cert.tenant_id,
                        name: cert.name,
                        certificate_id: cert.certificate_id,
                        description: cert.description,
                        tags: cert.tags,
                        kind: cert.kind,
                        created_at: cert.created_at,
                        updated_at: cert.updated_at,
                        active: cert.active,
                    })
                    .collect()
            })
            .map_err(|e| format!("Failed to list certificates: {}", e))
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Certificate>, String> {
        self.storage
            .get(id)
            .await
            .map_err(|e| format!("Failed to get certificate: {}", e))
    }

    async fn create_with_ids(
        &self,
        request: CreateCertificateRequest,
        id: String,
        certificate_id: String,
    ) -> Result<Certificate, String> {
        let now = chrono::Utc::now();

        let certificate = Certificate {
            id: id.clone(),
            tenant_id: request.tenant_id,
            name: request.name,
            certificate_id,
            description: request.description,
            tags: request
                .tags
                .unwrap_or_default(),
            kind: request.kind,
            certificate_pem: request.certificate_pem,
            private_key_pem: request.private_key_pem,
            expires_at: request.expires_at,
            created_at: now,
            updated_at: now,
            active: request.active.unwrap_or(true),
            identity_did: request.identity_did,
        };

        self.storage
            .save(&certificate)
            .await
            .map_err(|e| format!("Failed to create certificate: {}", e))?;

        info!("Created certificate: {} ({})", certificate.name, id);
        Ok(certificate)
    }

    async fn update(
        &self,
        id: &str,
        request: UpdateCertificateRequest,
    ) -> Result<Certificate, String> {
        let mut certificate = self
            .get(id)
            .await?
            .ok_or_else(|| format!("Certificate not found: {}", id))?;

        if let Some(name) = request.name {
            certificate.name = name;
        }
        if let Some(description) = request.description {
            certificate.description = Some(description);
        }
        if let Some(tags) = request.tags {
            certificate.tags = tags;
        }
        if let Some(kind) = request.kind {
            certificate.kind = kind;
        }
        if let Some(certificate_pem) = request.certificate_pem {
            certificate.certificate_pem = certificate_pem;
        }
        if let Some(private_key_pem) = request.private_key_pem {
            certificate.private_key_pem = Some(private_key_pem);
        }
        if let Some(expires_at) = request.expires_at {
            certificate.expires_at = Some(expires_at);
        }
        if let Some(active) = request.active {
            certificate.active = active;
        }

        certificate.updated_at = chrono::Utc::now();
        if request.identity_did.is_some() {
            certificate.identity_did = request.identity_did;
        }

        self.storage
            .save(&certificate)
            .await
            .map_err(|e| format!("Failed to update certificate: {}", e))?;

        info!("Updated certificate: {} ({})", certificate.name, id);
        Ok(certificate)
    }

    async fn set_tenant_id(
        &self,
        id: &str,
        tenant_id: Option<String>,
    ) -> Result<Certificate, String> {
        let mut certificate = self
            .get(id)
            .await?
            .ok_or_else(|| format!("Certificate not found: {}", id))?;
        certificate.tenant_id = tenant_id;
        certificate.updated_at = chrono::Utc::now();
        self.storage
            .save(&certificate)
            .await
            .map_err(|error| format!("Failed to update certificate tenant: {}", error))?;
        Ok(certificate)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<(), String> {
        self.storage
            .delete(id)
            .await
            .map_err(|e| format!("Failed to delete certificate: {}", e))?;
        info!("Deleted certificate: {}", id);
        Ok(())
    }
}
