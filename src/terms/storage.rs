use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage_strict};
use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::types::{
    AcceptanceBatch, CUSTOMER_TERMS_DOCUMENT_ID, CUSTOMER_TERMS_STATE_ID, CustomerTermsDocument, TermsType,
    TermsVersion,
};
use super::{validate_acceptance_record, validate_draft, validate_terms_version};

impl StorableEntity for CustomerTermsDocument {
    fn id(&self) -> &str {
        &self.id
    }
}

impl StorableEntity for AcceptanceBatch {
    fn id(&self) -> &str {
        &self.id
    }
}

pub(crate) struct TermsStorage {
    pub(crate) customer: Box<dyn StorageBackend<CustomerTermsDocument>>,
    pub(crate) acceptances: Box<dyn StorageBackend<AcceptanceBatch>>,
}

impl TermsStorage {
    pub(crate) async fn open(
        base_path: &Path,
        affinidi: Option<&TermsVersion>,
    ) -> Result<Self> {
        let customer = cached_storage_strict(base_path.join("customer"), "customer_terms")
            .await
            .context("failed to load Customer Terms")?;
        let acceptances = cached_storage_strict(base_path.join("acceptances"), "terms_acceptance")
            .await
            .context("failed to load Terms acceptances")?;
        let storage = Self { customer, acceptances };
        storage
            .validate(affinidi)
            .await?;
        Ok(storage)
    }

    async fn validate(
        &self,
        affinidi: Option<&TermsVersion>,
    ) -> Result<()> {
        let customer_documents = self
            .customer
            .list_all()
            .await?;
        if customer_documents.len() > 1 {
            bail!("multiple Customer Terms documents found");
        }
        let mut customer_versions = HashMap::new();
        if let Some(document) = customer_documents.first() {
            if document.id != CUSTOMER_TERMS_STATE_ID {
                bail!("unexpected Customer Terms document id");
            }
            if let Some(draft) = document.draft.as_ref() {
                validate_draft(draft)?;
            }
            let mut version_ids = HashSet::new();
            let mut version_labels = HashSet::new();
            for version in &document.versions {
                validate_terms_version(version)?;
                if version.terms_type != TermsType::Customer || version.document_id != CUSTOMER_TERMS_DOCUMENT_ID {
                    bail!("Customer Terms history contains an unexpected document");
                }
                if version
                    .published_by
                    .as_deref()
                    .is_none_or(|published_by| published_by.trim().is_empty())
                {
                    bail!("Customer Terms publishing user is required");
                }
                if !version_ids.insert(version.version_id.as_str()) {
                    bail!("duplicate Customer Terms version id");
                }
                if !version_labels.insert(version.version.trim()) {
                    bail!("duplicate Customer Terms version");
                }
                customer_versions.insert(version.version_id.as_str(), version);
            }
            if let Some(current) = document
                .current_version_id
                .as_deref()
                && !version_ids.contains(current)
            {
                bail!("current Customer Terms version does not exist");
            }
        }

        let mut acceptance_ids = HashSet::new();
        let mut acceptance_keys = HashSet::new();
        for batch in self
            .acceptances
            .list_all()
            .await?
        {
            if batch.id.trim().is_empty() {
                bail!("Terms acceptance batch id is required");
            }
            if batch.records.is_empty() {
                bail!("empty Terms acceptance batch");
            }
            for record in batch.records {
                validate_acceptance_record(&record)?;
                let authoritative_version = match record.terms_type {
                    TermsType::Customer => Some(
                        *customer_versions
                            .get(record.version_id.as_str())
                            .ok_or_else(|| {
                                anyhow::anyhow!("Customer Terms acceptance references an unknown version")
                            })?,
                    ),
                    TermsType::Affinidi => affinidi.filter(|version| version.version_id == record.version_id),
                };
                if let Some(version) = authoritative_version
                    && (record.terms_type != version.terms_type
                        || record.document_id != version.document_id
                        || record.version != version.version
                        || record.title != version.title
                        || record.url != version.url)
                {
                    bail!("Terms acceptance snapshot does not match its authoritative version");
                }
                if !acceptance_ids.insert(record.id.clone()) {
                    bail!("duplicate Terms acceptance id");
                }
                let key = (record.user_id, record.document_id, record.version_id);
                if !acceptance_keys.insert(key) {
                    bail!("duplicate Terms acceptance record");
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn customer_document(&self) -> Result<CustomerTermsDocument> {
        Ok(self
            .customer
            .get(CUSTOMER_TERMS_STATE_ID)
            .await?
            .unwrap_or_default())
    }

    pub(crate) async fn acceptance_batches(&self) -> Result<Vec<AcceptanceBatch>> {
        self.acceptances
            .list_all()
            .await
    }
}
