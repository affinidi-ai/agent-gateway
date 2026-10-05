//! Trust Registry integration for agent authorization

pub mod metadata_gate;
pub mod predefined_queries;
pub mod stage;
pub mod template;
pub mod trqp_adapter;
pub mod trust_check_element;
pub mod trust_check_executor;
pub mod trust_recorder;

pub use stage::{run_caller_trust_check, run_trust_check_stage};
pub use trqp_adapter::TrqpListenerClient;
pub use trust_check_element::{TrustCheckElement, TrustCheckLeg, TrustCheckResult, TrustCheckResultsContext};
pub use trust_check_executor::{
    AGENT_CARD_UNAVAILABLE, IDENTITY_VP_VERIFICATION_FAILED, TARGET_AGENT_IDENTITY_UNAVAILABLE,
    TrustCheckIdentityVerificationFailure, synthesize_failure,
};
pub use trust_recorder::spawn_trust_recorder;
