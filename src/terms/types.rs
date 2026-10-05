use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const AFFINIDI_TERMS_DOCUMENT_ID: &str = "affinidi-terms";
pub const CUSTOMER_TERMS_DOCUMENT_ID: &str = "customer-terms";
pub const CUSTOMER_TERMS_STATE_ID: &str = "customer-terms";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TermsType {
    Affinidi,
    Customer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceContext {
    Registration,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsVersion {
    pub terms_type: TermsType,
    pub document_id: String,
    #[serde(default)]
    pub version_id: String,
    pub version: String,
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub requires_reconsent: bool,
    pub published_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerTermsDraft {
    pub version: String,
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub requires_reconsent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerTermsDocument {
    pub id: String,
    #[serde(default)]
    pub draft: Option<CustomerTermsDraft>,
    #[serde(default)]
    pub current_version_id: Option<String>,
    #[serde(default)]
    pub versions: Vec<TermsVersion>,
}

impl Default for CustomerTermsDocument {
    fn default() -> Self {
        Self {
            id: CUSTOMER_TERMS_STATE_ID.to_string(),
            draft: None,
            current_version_id: None,
            versions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceRecord {
    pub id: String,
    pub user_id: String,
    pub appliance_id: String,
    pub terms_type: TermsType,
    pub document_id: String,
    pub version_id: String,
    pub version: String,
    pub title: String,
    pub url: String,
    pub accepted_at: DateTime<Utc>,
    pub context: AcceptanceContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceBatch {
    pub id: String,
    pub records: Vec<AcceptanceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsRequirement {
    pub terms_type: TermsType,
    pub document_id: String,
    pub version_id: String,
    pub version: String,
    pub title: String,
    pub url: String,
}

impl From<&TermsVersion> for TermsRequirement {
    fn from(value: &TermsVersion) -> Self {
        Self {
            terms_type: value.terms_type,
            document_id: value.document_id.clone(),
            version_id: value.version_id.clone(),
            version: value.version.clone(),
            title: value.title.clone(),
            url: value.url.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffinidiProviderState {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffinidiProviderStatus {
    pub state: AffinidiProviderState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_successful_refresh: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsDefinitions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinidi: Option<TermsVersion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinidi_provider: Option<AffinidiProviderStatus>,
    pub customer: CustomerTermsDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicableTermsResponse {
    pub terms: Vec<TermsRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsStatus {
    pub consent_required: bool,
    pub required_terms: Vec<TermsRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedTermsVersion {
    pub terms_type: TermsType,
    pub version_id: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptTermsRequest {
    pub accepted_terms: Vec<AcceptedTermsVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptTermsResponse {
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsErrorBody {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_terms: Option<Vec<TermsRequirement>>,
}
