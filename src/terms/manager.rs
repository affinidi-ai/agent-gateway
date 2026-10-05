use anyhow::Result;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use url::Url;
use uuid::Uuid;

use super::acceptance::{AcceptedDocumentVersion, TermsVersionKey, terms_status, validate_acceptance_request};
use super::affinidi_provider::AffinidiTermsProvider;
use super::storage::TermsStorage;
use super::types::*;
use super::validation::{validate_draft, validate_terms_version};

#[derive(Debug, thiserror::Error)]
pub enum TermsError {
    #[error("Terms state is unavailable: {0}")]
    Operational(String),
    #[error("invalid Terms data: {0}")]
    Invalid(String),
    #[error("submitted Terms versions are stale")]
    Stale(Vec<TermsRequirement>),
    #[error("Terms are disabled")]
    Disabled,
    #[error("no Customer Terms draft exists")]
    NoDraft,
}

enum AffinidiTermsSource {
    Static(Option<TermsVersion>),
    Remote(Arc<AffinidiTermsProvider>),
}

impl AffinidiTermsSource {
    async fn current(&self) -> Result<Option<TermsVersion>, TermsError> {
        match self {
            Self::Static(version) => Ok(version.clone()),
            Self::Remote(provider) => provider
                .current()
                .await
                .map(Some),
        }
    }

    async fn status(&self) -> Option<AffinidiProviderStatus> {
        match self {
            Self::Static(_) => None,
            Self::Remote(provider) => Some(provider.status().await),
        }
    }

    async fn cached(&self) -> Option<TermsVersion> {
        match self {
            Self::Static(version) => version.clone(),
            Self::Remote(provider) => provider.current().await.ok(),
        }
    }
}

pub struct TermsManager {
    enabled: bool,
    appliance_id: String,
    affinidi: AffinidiTermsSource,
    storage_path: PathBuf,
    storage: RwLock<Option<Arc<TermsStorage>>>,
    operational_error: RwLock<Option<String>>,
    verification_lock: Mutex<()>,
    write_lock: Mutex<()>,
}

impl TermsManager {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            appliance_id: String::new(),
            affinidi: AffinidiTermsSource::Static(None),
            storage_path: PathBuf::new(),
            storage: RwLock::new(None),
            operational_error: RwLock::new(None),
            verification_lock: Mutex::new(()),
            write_lock: Mutex::new(()),
        }
    }

    pub async fn open(
        enabled: bool,
        appliance_id: String,
        storage_path: PathBuf,
        affinidi: Option<TermsVersion>,
    ) -> Result<Self, TermsError> {
        Self::open_with_source(enabled, appliance_id, storage_path, AffinidiTermsSource::Static(affinidi)).await
    }

    pub async fn open_remote(
        appliance_id: String,
        storage_path: PathBuf,
        endpoint: Url,
    ) -> Result<Self, TermsError> {
        let provider = Arc::new(AffinidiTermsProvider::open(&storage_path.join("affinidi"), endpoint).await?);
        let manager =
            Self::open_with_source(true, appliance_id, storage_path, AffinidiTermsSource::Remote(provider.clone()))
                .await?;
        provider.spawn_refresh();
        Ok(manager)
    }

    async fn open_with_source(
        enabled: bool,
        appliance_id: String,
        storage_path: PathBuf,
        affinidi: AffinidiTermsSource,
    ) -> Result<Self, TermsError> {
        if !enabled {
            return Ok(Self::disabled());
        }

        if appliance_id.trim().is_empty() {
            return Err(TermsError::Invalid("appliance id is required".to_string()));
        }
        let current_affinidi = affinidi.cached().await;
        if let Some(version) = current_affinidi.as_ref() {
            validate_terms_version(version).map_err(|error| TermsError::Invalid(error.to_string()))?;
            if version.terms_type != TermsType::Affinidi || version.document_id != AFFINIDI_TERMS_DOCUMENT_ID {
                return Err(TermsError::Invalid("definition must identify Affinidi Terms".to_string()));
            }
        }
        let (storage, operational_error) = match TermsStorage::open(&storage_path, current_affinidi.as_ref()).await {
            Ok(storage) => (Some(Arc::new(storage)), None),
            Err(error) => {
                let error = error.to_string();
                tracing::error!(error = %error, "Terms storage is unavailable; continuing in operational failure state");
                (None, Some(error))
            }
        };
        Ok(Self {
            enabled,
            appliance_id,
            affinidi,
            storage_path,
            storage: RwLock::new(storage),
            operational_error: RwLock::new(operational_error),
            verification_lock: Mutex::new(()),
            write_lock: Mutex::new(()),
        })
    }

    fn ensure_enabled(&self) -> Result<(), TermsError> {
        if self.enabled {
            Ok(())
        } else {
            Err(TermsError::Disabled)
        }
    }

    async fn storage(&self) -> Result<Arc<TermsStorage>, TermsError> {
        self.ensure_enabled()?;
        let affinidi = self
            .affinidi
            .current()
            .await?;
        self.verified_storage(affinidi)
            .await
    }

    async fn local_storage(&self) -> Result<Arc<TermsStorage>, TermsError> {
        self.ensure_enabled()?;
        self.verified_storage(self.affinidi.cached().await)
            .await
    }

    async fn verified_storage(
        &self,
        affinidi: Option<TermsVersion>,
    ) -> Result<Arc<TermsStorage>, TermsError> {
        let _verification = self
            .verification_lock
            .lock()
            .await;
        let existing = self
            .storage
            .read()
            .await
            .clone();
        let storage = match existing {
            Some(storage) => storage,
            None => match TermsStorage::open(&self.storage_path, affinidi.as_ref()).await {
                Ok(storage) => Arc::new(storage),
                Err(error) => {
                    return Err(self
                        .mark_operational_failure(error.to_string())
                        .await);
                }
            },
        };

        *self.storage.write().await = Some(storage.clone());
        self.operational_error
            .write()
            .await
            .take();
        Ok(storage)
    }

    async fn mark_operational_failure(
        &self,
        error: String,
    ) -> TermsError {
        *self.storage.write().await = None;
        *self
            .operational_error
            .write()
            .await = Some(error.clone());
        TermsError::Operational(error)
    }

    pub async fn applicable(&self) -> Result<Vec<TermsRequirement>, TermsError> {
        self.current_versions()
            .await
            .map(|versions| {
                versions
                    .iter()
                    .map(TermsRequirement::from)
                    .collect()
            })
    }

    pub async fn status(
        &self,
        user_id: &str,
        context: AcceptanceContext,
    ) -> Result<TermsStatus, TermsError> {
        if !self.enabled {
            return Ok(TermsStatus {
                consent_required: false,
                required_terms: Vec::new(),
            });
        }
        let current = self
            .current_versions()
            .await?;
        let accepted = self
            .accepted_versions(user_id)
            .await?;
        Ok(terms_status(&current, &accepted, context))
    }

    pub async fn validate_registration(
        &self,
        request: &AcceptTermsRequest,
    ) -> Result<(), TermsError> {
        let submitted = validate_acceptance_request(request)?;
        let required_terms = self.applicable().await?;
        let required = required_terms
            .iter()
            .map(TermsVersionKey::from_requirement)
            .collect::<HashSet<_>>();
        if submitted != required {
            return Err(TermsError::Stale(required_terms));
        }
        Ok(())
    }

    pub async fn accept(
        &self,
        user_id: &str,
        context: AcceptanceContext,
        request: AcceptTermsRequest,
    ) -> Result<AcceptTermsResponse, TermsError> {
        if user_id.trim().is_empty() {
            return Err(TermsError::Invalid("user id is required".to_string()));
        }
        let submitted = validate_acceptance_request(&request)?;
        if !self.enabled {
            return if submitted.is_empty() {
                Ok(AcceptTermsResponse { accepted: true })
            } else {
                Err(TermsError::Stale(Vec::new()))
            };
        }

        let _guard = self.write_lock.lock().await;
        let current = self
            .current_versions()
            .await?;
        let accepted = self
            .accepted_versions(user_id)
            .await?;
        let status = terms_status(&current, &accepted, context);
        let required = status
            .required_terms
            .iter()
            .map(TermsVersionKey::from_requirement)
            .collect::<HashSet<_>>();
        let current_by_key = current
            .iter()
            .map(|version| (TermsVersionKey::from_version(version), version))
            .collect::<HashMap<_, _>>();

        if required.is_empty() {
            let repeated_submission = submitted.iter().all(|key| {
                current_by_key
                    .get(key)
                    .is_some_and(|version| {
                        accepted.contains(&AcceptedDocumentVersion {
                            document_id: version.document_id.clone(),
                            version_id: key.version_id.clone(),
                        })
                    })
            });
            if submitted.is_empty() || repeated_submission {
                return Ok(AcceptTermsResponse { accepted: true });
            }
        }

        if submitted != required {
            return Err(TermsError::Stale(status.required_terms));
        }

        let now = Utc::now();
        let records = request
            .accepted_terms
            .into_iter()
            .map(|submitted| {
                let version = current_by_key
                    .get(&TermsVersionKey {
                        terms_type: submitted.terms_type,
                        version_id: submitted.version_id,
                    })
                    .expect("submitted set was checked against current requirements");
                AcceptanceRecord {
                    id: Uuid::new_v4().to_string(),
                    user_id: user_id.to_string(),
                    appliance_id: self.appliance_id.clone(),
                    terms_type: version.terms_type,
                    document_id: version.document_id.clone(),
                    version_id: version.version_id.clone(),
                    version: version.version.clone(),
                    title: version.title.clone(),
                    url: version.url.clone(),
                    accepted_at: now,
                    context,
                }
            })
            .collect();
        let batch = AcceptanceBatch {
            id: Uuid::new_v4().to_string(),
            records,
        };
        self.storage()
            .await?
            .acceptances
            .save_atomic(&batch)
            .await
            .map_err(|error| TermsError::Operational(error.to_string()))?;
        Ok(AcceptTermsResponse { accepted: true })
    }

    pub async fn definitions(&self) -> Result<TermsDefinitions, TermsError> {
        self.ensure_enabled()?;
        Ok(TermsDefinitions {
            affinidi: self.affinidi.cached().await,
            affinidi_provider: self.affinidi.status().await,
            customer: self
                .customer_definition()
                .await?,
        })
    }

    pub async fn provider_status(&self) -> Result<AffinidiProviderStatus, TermsError> {
        self.ensure_enabled()?;
        self.affinidi
            .status()
            .await
            .ok_or_else(|| TermsError::Operational("Affinidi Terms provider status is unavailable".to_string()))
    }

    async fn customer_definition(&self) -> Result<CustomerTermsDocument, TermsError> {
        self.local_storage()
            .await?
            .customer_document()
            .await
            .map_err(|error| TermsError::Operational(error.to_string()))
    }

    pub async fn save_draft(
        &self,
        draft: CustomerTermsDraft,
    ) -> Result<CustomerTermsDocument, TermsError> {
        self.ensure_enabled()?;
        validate_draft(&draft).map_err(|error| TermsError::Invalid(error.to_string()))?;
        let _guard = self.write_lock.lock().await;
        let mut document = self
            .customer_definition()
            .await?;
        document.draft = Some(draft);
        self.local_storage()
            .await?
            .customer
            .save_atomic(&document)
            .await
            .map_err(|error| TermsError::Operational(error.to_string()))?;
        Ok(document)
    }

    pub async fn publish(
        &self,
        published_by: String,
    ) -> Result<TermsVersion, TermsError> {
        self.ensure_enabled()?;
        let _guard = self.write_lock.lock().await;
        let mut document = self
            .customer_definition()
            .await?;
        let draft = document
            .draft
            .take()
            .ok_or(TermsError::NoDraft)?;
        validate_draft(&draft).map_err(|error| TermsError::Invalid(error.to_string()))?;
        if document
            .versions
            .iter()
            .any(|version| version.version.trim() == draft.version.trim())
        {
            return Err(TermsError::Invalid("Customer Terms version has already been published".to_string()));
        }
        let version = TermsVersion {
            terms_type: TermsType::Customer,
            document_id: CUSTOMER_TERMS_DOCUMENT_ID.to_string(),
            version_id: Uuid::new_v4().to_string(),
            version: draft.version,
            title: draft.title,
            url: draft.url,
            requires_reconsent: draft.requires_reconsent,
            published_at: Utc::now(),
            published_by: Some(published_by),
        };
        document.current_version_id = Some(version.version_id.clone());
        document
            .versions
            .push(version.clone());
        self.local_storage()
            .await?
            .customer
            .save_atomic(&document)
            .await
            .map_err(|error| TermsError::Operational(error.to_string()))?;
        Ok(version)
    }

    pub async fn deactivate_customer_terms(&self) -> Result<(), TermsError> {
        self.ensure_enabled()?;
        let _guard = self.write_lock.lock().await;
        let mut document = self
            .customer_definition()
            .await?;
        document.current_version_id = None;
        self.local_storage()
            .await?
            .customer
            .save_atomic(&document)
            .await
            .map_err(|error| TermsError::Operational(error.to_string()))
    }

    async fn current_versions(&self) -> Result<Vec<TermsVersion>, TermsError> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        let mut versions = Vec::with_capacity(2);
        if let Some(affinidi) = self
            .affinidi
            .current()
            .await?
        {
            versions.push(affinidi);
        }
        let customer = self
            .customer_definition()
            .await?;
        if let Some(current_id) = customer
            .current_version_id
            .as_deref()
        {
            let current = customer
                .versions
                .iter()
                .find(|version| version.version_id == current_id)
                .ok_or_else(|| TermsError::Operational("current Customer Terms version does not exist".to_string()))?;
            versions.push(current.clone());
        }
        Ok(versions)
    }

    async fn accepted_versions(
        &self,
        user_id: &str,
    ) -> Result<HashSet<AcceptedDocumentVersion>, TermsError> {
        let batches = self
            .storage()
            .await?
            .acceptance_batches()
            .await
            .map_err(|error| TermsError::Operational(error.to_string()))?;
        Ok(batches
            .into_iter()
            .flat_map(|batch| batch.records)
            .filter(|record| record.user_id == user_id && record.appliance_id == self.appliance_id)
            .map(|record| AcceptedDocumentVersion {
                document_id: record.document_id,
                version_id: record.version_id,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn affinidi(
        version_id: &str,
        requires_reconsent: bool,
    ) -> TermsVersion {
        TermsVersion {
            terms_type: TermsType::Affinidi,
            document_id: AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
            version_id: version_id.to_string(),
            version: "3.2".to_string(),
            title: "Affinidi Terms and Conditions".to_string(),
            url: "https://www.affinidi.com/legal/terms.pdf".to_string(),
            requires_reconsent,
            published_at: Utc::now(),
            published_by: None,
        }
    }

    async fn manager(
        directory: &TempDir,
        affinidi: Option<TermsVersion>,
    ) -> TermsManager {
        TermsManager::open(true, "did:web:appliance.example".to_string(), directory.path().to_path_buf(), affinidi)
            .await
            .unwrap()
    }

    fn acceptance(status: &TermsStatus) -> AcceptTermsRequest {
        AcceptTermsRequest {
            accepted_terms: status
                .required_terms
                .iter()
                .map(|requirement| AcceptedTermsVersion {
                    terms_type: requirement.terms_type,
                    version_id: requirement.version_id.clone(),
                    accepted: true,
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn registration_requires_current_affinidi_terms() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, Some(affinidi("affinidi-v1", false))).await;

        let status = manager
            .status("user-1", AcceptanceContext::Registration)
            .await
            .unwrap();

        assert!(status.consent_required);
        assert_eq!(status.required_terms[0].version_id, "affinidi-v1");
    }

    #[tokio::test]
    async fn existing_affinidi_3_2_acceptance_remains_valid() {
        let directory = TempDir::new().unwrap();
        let initial = manager(&directory, Some(affinidi("affinidi:3.2", true))).await;
        let status = initial
            .status("user-1", AcceptanceContext::Registration)
            .await
            .unwrap();
        initial
            .accept("user-1", AcceptanceContext::Registration, acceptance(&status))
            .await
            .unwrap();
        drop(initial);

        let restored = manager(&directory, Some(affinidi("affinidi:3.2", true))).await;
        let status = restored
            .status("user-1", AcceptanceContext::Login)
            .await
            .unwrap();

        assert!(!status.consent_required);
    }

    #[tokio::test]
    async fn acceptance_is_server_snapshotted_and_idempotent() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, Some(affinidi("affinidi-v1", false))).await;
        let status = manager
            .status("user-1", AcceptanceContext::Registration)
            .await
            .unwrap();
        let request = acceptance(&status);

        manager
            .accept("user-1", AcceptanceContext::Registration, request.clone())
            .await
            .unwrap();
        manager
            .accept("user-1", AcceptanceContext::Registration, request)
            .await
            .unwrap();

        let batches = manager
            .storage()
            .await
            .unwrap()
            .acceptance_batches()
            .await
            .unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].records[0].appliance_id, "did:web:appliance.example");
        assert_eq!(batches[0].records[0].context, AcceptanceContext::Registration);
    }

    #[tokio::test]
    async fn stale_registration_returns_current_requirements() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, Some(affinidi("affinidi-v2", true))).await;
        let error = manager
            .validate_registration(&AcceptTermsRequest {
                accepted_terms: vec![AcceptedTermsVersion {
                    terms_type: TermsType::Affinidi,
                    version_id: "affinidi-v1".to_string(),
                    accepted: true,
                }],
            })
            .await
            .unwrap_err();

        let TermsError::Stale(required) = error else {
            panic!("expected stale registration");
        };
        assert_eq!(required[0].version_id, "affinidi-v2");
    }

    #[tokio::test]
    async fn stale_submission_returns_current_requirements() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, Some(affinidi("affinidi-v2", true))).await;
        let error = manager
            .accept(
                "user-1",
                AcceptanceContext::Login,
                AcceptTermsRequest {
                    accepted_terms: vec![AcceptedTermsVersion {
                        terms_type: TermsType::Affinidi,
                        version_id: "affinidi-v1".to_string(),
                        accepted: true,
                    }],
                },
            )
            .await
            .unwrap_err();

        let TermsError::Stale(required) = error else {
            panic!("expected stale submission");
        };
        assert_eq!(required[0].version_id, "affinidi-v2");
    }

    #[tokio::test]
    async fn login_honors_reconsent_setting() {
        let directory = TempDir::new().unwrap();
        let first = manager(&directory, Some(affinidi("affinidi-v1", true))).await;
        let status = first
            .status("user-1", AcceptanceContext::Login)
            .await
            .unwrap();
        first
            .accept("user-1", AcceptanceContext::Login, acceptance(&status))
            .await
            .unwrap();
        drop(first);

        let no_reconsent = manager(&directory, Some(affinidi("affinidi-v2", false))).await;
        assert!(
            !no_reconsent
                .status("user-1", AcceptanceContext::Login)
                .await
                .unwrap()
                .consent_required
        );
        drop(no_reconsent);

        let reconsent = manager(&directory, Some(affinidi("affinidi-v2", true))).await;
        assert!(
            reconsent
                .status("user-1", AcceptanceContext::Login)
                .await
                .unwrap()
                .consent_required
        );
    }

    #[tokio::test]
    async fn customer_publication_preserves_history_and_deactivation() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, None).await;
        manager
            .save_draft(CustomerTermsDraft {
                version: "1".to_string(),
                title: "Customer Terms".to_string(),
                url: "https://customer.example/terms/1".to_string(),
                requires_reconsent: true,
            })
            .await
            .unwrap();
        let first = manager
            .publish("admin-1".to_string())
            .await
            .unwrap();
        manager
            .save_draft(CustomerTermsDraft {
                version: "2".to_string(),
                title: "Customer Terms".to_string(),
                url: "https://customer.example/terms/2".to_string(),
                requires_reconsent: false,
            })
            .await
            .unwrap();
        let second = manager
            .publish("admin-1".to_string())
            .await
            .unwrap();

        let definition = manager
            .definitions()
            .await
            .unwrap()
            .customer;
        assert_eq!(definition.versions.len(), 2);
        assert_eq!(
            definition
                .current_version_id
                .as_deref(),
            Some(second.version_id.as_str())
        );
        assert_ne!(first.version_id, second.version_id);

        manager
            .deactivate_customer_terms()
            .await
            .unwrap();
        assert!(
            manager
                .applicable()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            manager
                .definitions()
                .await
                .unwrap()
                .customer
                .versions
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn rejects_non_https_and_credentialed_urls() {
        for url in
            ["http://example.com/terms", "/terms", "javascript:alert(1)", "https://user:secret@example.com/terms"]
        {
            let directory = TempDir::new().unwrap();
            let manager = manager(&directory, None).await;
            let error = manager
                .save_draft(CustomerTermsDraft {
                    version: "1".to_string(),
                    title: "Terms".to_string(),
                    url: url.to_string(),
                    requires_reconsent: false,
                })
                .await
                .unwrap_err();
            assert!(matches!(error, TermsError::Invalid(_)), "url={url}");
        }
    }

    #[tokio::test]
    async fn rejects_more_than_the_two_supported_terms_types() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, Some(affinidi("affinidi-v1", true))).await;
        let error = manager
            .validate_registration(&AcceptTermsRequest {
                accepted_terms: vec![
                    AcceptedTermsVersion {
                        terms_type: TermsType::Affinidi,
                        version_id: "affinidi-v1".to_string(),
                        accepted: true,
                    },
                    AcceptedTermsVersion {
                        terms_type: TermsType::Customer,
                        version_id: "customer-v1".to_string(),
                        accepted: true,
                    },
                    AcceptedTermsVersion {
                        terms_type: TermsType::Customer,
                        version_id: "customer-v2".to_string(),
                        accepted: true,
                    },
                ],
            })
            .await
            .unwrap_err();
        assert!(matches!(error, TermsError::Invalid(_)));
    }

    #[tokio::test]
    async fn rejects_customer_acceptance_snapshot_mismatch() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, None).await;
        manager
            .save_draft(CustomerTermsDraft {
                version: "1".to_string(),
                title: "Customer Terms".to_string(),
                url: "https://customer.example/terms/1".to_string(),
                requires_reconsent: true,
            })
            .await
            .unwrap();
        manager
            .publish("admin-1".to_string())
            .await
            .unwrap();
        let status = manager
            .status("user-1", AcceptanceContext::Login)
            .await
            .unwrap();
        manager
            .accept("user-1", AcceptanceContext::Login, acceptance(&status))
            .await
            .unwrap();
        let mut batch = manager
            .storage()
            .await
            .unwrap()
            .acceptance_batches()
            .await
            .unwrap()
            .pop()
            .unwrap();
        batch.records[0].title = "Tampered title".to_string();
        tokio::fs::write(
            directory
                .path()
                .join(format!("acceptances/{}.json", batch.id)),
            serde_json::to_vec_pretty(&batch).unwrap(),
        )
        .await
        .unwrap();

        let manager = TermsManager::open(true, "did:web:appliance.example".into(), directory.path().into(), None)
            .await
            .unwrap();
        assert!(matches!(manager.applicable().await, Err(TermsError::Operational(_))));
    }

    #[tokio::test]
    async fn rejects_duplicate_customer_version_labels_in_loaded_state() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, None).await;
        manager
            .save_draft(CustomerTermsDraft {
                version: "1".to_string(),
                title: "Customer Terms".to_string(),
                url: "https://customer.example/terms/1".to_string(),
                requires_reconsent: true,
            })
            .await
            .unwrap();
        manager
            .publish("admin-1".to_string())
            .await
            .unwrap();

        let storage = manager
            .storage()
            .await
            .unwrap();
        let mut document = storage
            .customer_document()
            .await
            .unwrap();
        let mut duplicate = document.versions[0].clone();
        duplicate.version_id = "different-id".to_string();
        document
            .versions
            .push(duplicate);
        storage
            .customer
            .save_atomic(&document)
            .await
            .unwrap();

        let manager = TermsManager::open(true, "did:web:appliance.example".into(), directory.path().into(), None)
            .await
            .unwrap();
        assert!(matches!(manager.applicable().await, Err(TermsError::Operational(_))));
    }

    #[tokio::test]
    async fn rejects_current_affinidi_acceptance_snapshot_mismatch() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, Some(affinidi("affinidi-v1", true))).await;
        let status = manager
            .status("user-1", AcceptanceContext::Login)
            .await
            .unwrap();
        manager
            .accept("user-1", AcceptanceContext::Login, acceptance(&status))
            .await
            .unwrap();

        let storage = manager
            .storage()
            .await
            .unwrap();
        let mut batch = storage
            .acceptance_batches()
            .await
            .unwrap()
            .pop()
            .unwrap();
        batch.records[0].title = "Tampered title".to_string();
        storage
            .acceptances
            .save_atomic(&batch)
            .await
            .unwrap();

        let manager = TermsManager::open(
            true,
            "did:web:appliance.example".into(),
            directory.path().into(),
            Some(affinidi("affinidi-v1", true)),
        )
        .await
        .unwrap();
        assert!(matches!(manager.applicable().await, Err(TermsError::Operational(_))));
    }

    #[tokio::test]
    async fn rejects_orphan_customer_acceptance() {
        let directory = TempDir::new().unwrap();
        let acceptance_dir = directory
            .path()
            .join("acceptances");
        tokio::fs::create_dir_all(&acceptance_dir)
            .await
            .unwrap();
        let batch = AcceptanceBatch {
            id: "batch-1".to_string(),
            records: vec![AcceptanceRecord {
                id: "acceptance-1".to_string(),
                user_id: "user-1".to_string(),
                appliance_id: "did:web:appliance.example".to_string(),
                terms_type: TermsType::Customer,
                document_id: CUSTOMER_TERMS_DOCUMENT_ID.to_string(),
                version_id: "missing-version".to_string(),
                version: "1".to_string(),
                title: "Customer Terms".to_string(),
                url: "https://customer.example/terms/1".to_string(),
                accepted_at: Utc::now(),
                context: AcceptanceContext::Login,
            }],
        };
        tokio::fs::write(acceptance_dir.join("batch-1.json"), serde_json::to_vec_pretty(&batch).unwrap())
            .await
            .unwrap();

        let manager = manager(&directory, None).await;
        assert!(matches!(manager.applicable().await, Err(TermsError::Operational(_))));
    }

    #[tokio::test]
    async fn preserves_acceptance_for_historical_customer_version() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, None).await;
        for version in ["1", "2"] {
            manager
                .save_draft(CustomerTermsDraft {
                    version: version.to_string(),
                    title: "Customer Terms".to_string(),
                    url: format!("https://customer.example/terms/{version}"),
                    requires_reconsent: true,
                })
                .await
                .unwrap();
            manager
                .publish("admin-1".to_string())
                .await
                .unwrap();
            if version == "1" {
                let status = manager
                    .status("user-1", AcceptanceContext::Login)
                    .await
                    .unwrap();
                manager
                    .accept("user-1", AcceptanceContext::Login, acceptance(&status))
                    .await
                    .unwrap();
            }
        }

        let status = manager
            .status("user-1", AcceptanceContext::Login)
            .await
            .unwrap();
        assert!(status.consent_required);
        assert_eq!(status.required_terms[0].version, "2");
    }

    #[tokio::test]
    async fn runtime_reads_use_validated_cache_until_restart() {
        let directory = TempDir::new().unwrap();
        let manager = manager(&directory, None).await;
        let corrupt_path = directory
            .path()
            .join("acceptances/corrupt.json");
        tokio::fs::write(&corrupt_path, b"not json")
            .await
            .unwrap();

        assert!(
            manager
                .applicable()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !manager
                .status("user-1", AcceptanceContext::Login)
                .await
                .unwrap()
                .consent_required
        );
        let restarted =
            TermsManager::open(true, "did:web:appliance.example".to_string(), directory.path().to_path_buf(), None)
                .await
                .unwrap();
        assert!(matches!(restarted.applicable().await, Err(TermsError::Operational(_))));

        tokio::fs::remove_file(corrupt_path)
            .await
            .unwrap();
        assert_eq!(
            manager
                .applicable()
                .await
                .unwrap(),
            Vec::<TermsRequirement>::new()
        );
        assert!(
            manager
                .operational_error
                .read()
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn degraded_startup_recovers_without_restart() {
        let directory = TempDir::new().unwrap();
        let acceptance_dir = directory
            .path()
            .join("acceptances");
        tokio::fs::create_dir_all(&acceptance_dir)
            .await
            .unwrap();
        let corrupt_path = acceptance_dir.join("corrupt.json");
        tokio::fs::write(&corrupt_path, b"not json")
            .await
            .unwrap();

        let manager =
            TermsManager::open(true, "did:web:appliance.example".to_string(), directory.path().to_path_buf(), None)
                .await
                .unwrap();
        assert!(matches!(manager.applicable().await, Err(TermsError::Operational(_))));

        tokio::fs::remove_file(corrupt_path)
            .await
            .unwrap();
        assert!(
            manager
                .applicable()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn definitions_report_unavailable_remote_provider_without_metadata() {
        let directory = TempDir::new().unwrap();
        let manager = TermsManager::open_remote(
            "did:web:appliance.example".to_string(),
            directory.path().to_path_buf(),
            Url::parse("http://127.0.0.1:9/terms.json").unwrap(),
        )
        .await
        .unwrap();

        let definitions = manager
            .definitions()
            .await
            .unwrap();
        assert!(definitions.affinidi.is_none());
        assert_eq!(
            definitions
                .affinidi_provider
                .unwrap()
                .state,
            AffinidiProviderState::Unavailable
        );
    }

    #[tokio::test]
    async fn disabled_terms_bypass_storage_and_reject_management() {
        let directory = TempDir::new().unwrap();
        let storage_path = directory.path().join("terms");
        let manager =
            TermsManager::open(false, String::new(), storage_path.clone(), Some(affinidi("affinidi-v1", true)))
                .await
                .unwrap();

        assert!(
            manager
                .applicable()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !manager
                .status("user-1", AcceptanceContext::Login)
                .await
                .unwrap()
                .consent_required
        );
        assert!(!storage_path.exists());
        assert!(matches!(manager.definitions().await, Err(TermsError::Disabled)));
    }
}
