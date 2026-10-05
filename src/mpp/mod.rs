//! MPP (Machine Payments Protocol) handling
//!
//! This module implements the MPP protocol for machine-to-machine HTTP payments.
//! MPP uses the HTTP "Payment" authentication scheme with standard WWW-Authenticate
//! and Authorization headers, as defined in the IETF Internet-Draft
//! draft-httpauth-payment-00.
//!
//! Reference: https://paymentauth.org/draft-httpauth-payment-00.html
//!            https://mpp.dev/
//!
//! ## Protocol Flow
//!
//! 1. Client requests resource without payment
//! 2. Server responds with 402 and WWW-Authenticate: Payment challenge header
//! 3. Client fulfills the challenge and retries with Authorization: Payment credential
//! 4. Server verifies the challenge binding (HMAC-SHA256) and payment proof
//! 5. Server returns resource with 200 and Payment-Receipt header

pub mod admin_api;
pub mod auto_pay;
pub mod challenge;
pub mod errors;
pub mod middleware;
pub mod nonce_guard;
pub mod onchain;
pub mod payment_challenge;
pub mod posture;
pub mod secrets;
pub mod stripe;
pub mod transaction_store;
pub mod types;
pub mod verification;

pub use transaction_store::MppTransactionStore;

pub use errors::*;
pub use middleware::*;
pub use types::*;
pub use verification::{extract_mpp_credential, extract_mpp_credential_with_mcp};
