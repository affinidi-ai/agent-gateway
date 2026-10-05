use anyhow::{Result, bail};
use url::Url;

use super::types::{
    AFFINIDI_TERMS_DOCUMENT_ID, AcceptanceRecord, CUSTOMER_TERMS_DOCUMENT_ID, CustomerTermsDraft, TermsType,
    TermsVersion,
};

pub(super) const MAX_TERMS_VERSION_ID_LEN: usize = 128;
const MAX_TERMS_TITLE_LEN: usize = 200;
const MAX_TERMS_VERSION_LEN: usize = 100;
const MAX_TERMS_URL_LEN: usize = 2048;

pub(crate) fn validate_terms_version(version: &TermsVersion) -> Result<()> {
    if version
        .version_id
        .trim()
        .is_empty()
        || version
            .version
            .trim()
            .is_empty()
        || version
            .title
            .trim()
            .is_empty()
        || version
            .document_id
            .trim()
            .is_empty()
    {
        bail!("Terms identity, version, and title are required");
    }
    validate_metadata_lengths(&version.version_id, &version.version, &version.title, &version.url)?;
    validate_https_url(&version.url)
}

pub(crate) fn validate_draft(draft: &CustomerTermsDraft) -> Result<()> {
    if draft
        .version
        .trim()
        .is_empty()
        || draft.title.trim().is_empty()
    {
        bail!("Terms version and title are required");
    }
    validate_metadata_lengths("draft", &draft.version, &draft.title, &draft.url)?;
    validate_https_url(&draft.url)
}

pub(crate) fn validate_acceptance_record(record: &AcceptanceRecord) -> Result<()> {
    if record.id.trim().is_empty()
        || record
            .user_id
            .trim()
            .is_empty()
        || record
            .appliance_id
            .trim()
            .is_empty()
        || record
            .document_id
            .trim()
            .is_empty()
        || record
            .version_id
            .trim()
            .is_empty()
        || record
            .version
            .trim()
            .is_empty()
        || record.title.trim().is_empty()
    {
        bail!("Terms acceptance identity and snapshot metadata are required");
    }
    match record.terms_type {
        TermsType::Affinidi if record.document_id != AFFINIDI_TERMS_DOCUMENT_ID => {
            bail!("Affinidi acceptance has an unexpected document id");
        }
        TermsType::Customer if record.document_id != CUSTOMER_TERMS_DOCUMENT_ID => {
            bail!("Customer acceptance has an unexpected document id");
        }
        _ => {}
    }
    validate_metadata_lengths(&record.version_id, &record.version, &record.title, &record.url)?;
    validate_https_url(&record.url)
}

fn validate_metadata_lengths(
    version_id: &str,
    version: &str,
    title: &str,
    url: &str,
) -> Result<()> {
    if version_id.len() > MAX_TERMS_VERSION_ID_LEN
        || version.len() > MAX_TERMS_VERSION_LEN
        || title.len() > MAX_TERMS_TITLE_LEN
        || url.len() > MAX_TERMS_URL_LEN
    {
        bail!("Terms metadata exceeds its size limit");
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<()> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("Terms URL must be an absolute HTTPS URL"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        bail!("Terms URL must be an absolute HTTPS URL");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Terms URL must not contain credentials");
    }
    Ok(())
}
