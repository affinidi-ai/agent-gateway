//! x402 (HTTP Native Payments Protocol) records, settlement and wire types.
//!
//! This gateway takes no x402 payment itself and is not an x402 facilitator:
//! an enabled local x402 policy still loads but is refused (see
//! `AgentSurface::payment_policy_unsupported`), and agent-pay takes x402
//! payments for `agent_pay` policies. What remains settles the x402
//! transactions recorded before (the settlement worker and startup recovery),
//! serves those records to the admin API, and provides the trigger matching
//! and header parsing the agent-pay gate shares.
//!
//! Reference: https://github.com/coinbase/x402

pub mod admin_api;
pub mod config_cache;
pub mod delegate;
pub mod embedded_facilitator;
pub mod middleware;
pub mod payment;
pub mod remote_facilitator;
pub mod settlement;
pub mod settlement_worker;
pub mod transaction_store;
pub mod verification;
pub mod x402rs_adapter;

// DIDComm facilitator modules
pub mod didcomm_facilitator_client;
pub mod gateway_facilitator_service;

pub use admin_api::*;
pub use config_cache::*;
pub use delegate::{PaymentDelegationDecision, map_delegation_response};
pub use middleware::*;
pub use payment::*;
pub use settlement::*;
pub use verification::*;

// DIDComm facilitator exports
pub use gateway_facilitator_service::{init_gateway_facilitator_service, set_atm_infrastructure};

// Re-export unified transaction store types
pub use transaction_store::TransactionStore;
