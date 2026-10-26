//! x402 (HTTP Native Payments Protocol) handling
//!
//! This module implements the x402 protocol for blockchain-based HTTP payments.
//! x402 uses HTTP 402 "Payment Required" status code to enable payments for internet resources.
//!
//! Reference: https://github.com/coinbase/x402
//!
//! ## Protocol Flow
//!
//! 1. Client requests resource without payment
//! 2. Server responds with 402 and PAYMENT-REQUIRED header containing payment requirements
//! 3. Client creates payment signature and retries with PAYMENT-SIGNATURE header
//! 4. Server verifies payment (locally or via facilitator)
//! 5. Server settles payment (immediately, deferred, or manual)
//! 6. Server returns resource with 200 and PAYMENT-RESPONSE header

pub mod admin_api;
pub mod config_cache;
pub mod delegate;
pub mod embedded_facilitator;
pub mod errors;
pub mod middleware;
pub mod payment;
pub mod proxy_config;
pub mod proxy_config_cache;
// Only MPP auto-pay signs with it, and nothing calls auto-pay.
#[allow(dead_code)]
pub mod proxy_signer;
pub mod remote_facilitator;
pub mod settlement;
pub mod settlement_worker;
// The x402 test endpoints are not mounted.
#[allow(dead_code)]
pub mod test_handlers;
pub mod transaction_store;
pub mod verification;
pub mod x402rs_adapter;

// DIDComm facilitator modules
pub mod didcomm_facilitator_client;
// The x402 HTTP facilitator is not mounted.
#[allow(dead_code)]
pub mod facilitator_api;
pub mod gateway_facilitator_service;

pub use admin_api::*;
pub use config_cache::*;
pub use delegate::{PaymentDelegationDecision, map_delegation_response};
pub use errors::*;
pub use middleware::*;
pub use payment::*;
pub use settlement::*;
pub use verification::*;

// DIDComm facilitator exports
pub use gateway_facilitator_service::{
    init_gateway_facilitator_service, set_atm_infrastructure, verify_via_facilitator_gateway,
};

// Note: Facilitator API for /verify and /settle endpoints is available as documentation

// Re-export unified transaction store types
pub use transaction_store::TransactionStore;
