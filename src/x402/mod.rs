//! x402 (HTTP Native Payments Protocol) records, settlement and wire types.
//!
//! This gateway takes no x402 payment itself and is not an x402 facilitator:
//! an enabled local x402 policy still loads but is refused (see
//! `AgentSurface::payment_policy_unsupported`), and agent-pay takes x402
//! payments for `agent_pay` policies. The x402 transactions recorded before
//! are kept as they are: nothing settles, retries or recovers them, and only a
//! completion their own facilitator gateway reports changes one. What remains
//! serves those records to the admin API and provides the trigger matching and
//! header parsing the agent-pay gate shares.
//!
//! Reference: https://github.com/coinbase/x402

pub mod admin_api;
pub mod config_cache;
pub mod delegate;
pub mod middleware;
pub mod payment;
pub mod transaction_store;
pub mod verification;

pub use admin_api::*;
pub use config_cache::*;
pub use delegate::{PaymentDelegationDecision, map_delegation_response};
pub use payment::*;
pub use verification::*;

// Re-export unified transaction store types
pub use transaction_store::TransactionStore;
