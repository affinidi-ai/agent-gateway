use std::collections::HashSet;

use super::manager::TermsError;
use super::types::{AcceptTermsRequest, AcceptanceContext, TermsRequirement, TermsStatus, TermsType, TermsVersion};
use super::validation::MAX_TERMS_VERSION_ID_LEN;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct TermsVersionKey {
    pub(super) terms_type: TermsType,
    pub(super) version_id: String,
}

impl TermsVersionKey {
    pub(super) fn from_version(version: &TermsVersion) -> Self {
        Self {
            terms_type: version.terms_type,
            version_id: version.version_id.clone(),
        }
    }

    pub(super) fn from_requirement(requirement: &TermsRequirement) -> Self {
        Self {
            terms_type: requirement.terms_type,
            version_id: requirement.version_id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct AcceptedDocumentVersion {
    pub(super) document_id: String,
    pub(super) version_id: String,
}

pub(super) fn terms_status(
    current: &[TermsVersion],
    accepted: &HashSet<AcceptedDocumentVersion>,
    context: AcceptanceContext,
) -> TermsStatus {
    let required_terms = current
        .iter()
        .filter(|version| match context {
            AcceptanceContext::Registration => !accepted.contains(&AcceptedDocumentVersion {
                document_id: version.document_id.clone(),
                version_id: version.version_id.clone(),
            }),
            AcceptanceContext::Login if version.requires_reconsent => !accepted.contains(&AcceptedDocumentVersion {
                document_id: version.document_id.clone(),
                version_id: version.version_id.clone(),
            }),
            AcceptanceContext::Login => !accepted
                .iter()
                .any(|accepted| accepted.document_id == version.document_id),
        })
        .map(TermsRequirement::from)
        .collect::<Vec<_>>();
    TermsStatus {
        consent_required: !required_terms.is_empty(),
        required_terms,
    }
}

pub(super) fn validate_acceptance_request(
    request: &AcceptTermsRequest
) -> Result<HashSet<TermsVersionKey>, TermsError> {
    if request.accepted_terms.len() > 2 {
        return Err(TermsError::Invalid("at most two Terms versions may be accepted".to_string()));
    }
    if request
        .accepted_terms
        .iter()
        .any(|item| !item.accepted)
    {
        return Err(TermsError::Invalid("every submitted Terms version must be explicitly accepted".to_string()));
    }
    if request
        .accepted_terms
        .iter()
        .any(|item| {
            item.version_id
                .trim()
                .is_empty()
                || item.version_id.len() > MAX_TERMS_VERSION_ID_LEN
        })
    {
        return Err(TermsError::Invalid("submitted Terms version id is invalid".to_string()));
    }
    let submitted = request
        .accepted_terms
        .iter()
        .map(|item| TermsVersionKey {
            terms_type: item.terms_type,
            version_id: item.version_id.clone(),
        })
        .collect::<HashSet<_>>();
    if submitted.len() != request.accepted_terms.len() {
        return Err(TermsError::Invalid("duplicate accepted Terms version".to_string()));
    }
    Ok(submitted)
}
