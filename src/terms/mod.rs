mod acceptance;
mod affinidi_provider;
pub mod handlers;
mod manager;
mod storage;
pub mod types;
mod validation;

pub use manager::{TermsError, TermsManager};
pub use types::*;
pub(crate) use validation::{validate_acceptance_record, validate_draft, validate_terms_version};
