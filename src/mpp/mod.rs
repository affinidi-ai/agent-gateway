//! MPP (Machine Payments Protocol) records and wire types.
//!
//! This gateway takes no MPP payment itself: an enabled local MPP policy still
//! loads but is refused (see `AgentSurface::payment_policy_unsupported`), and
//! agent-pay takes MPP payments for `agent_pay` policies. What remains is the
//! policy configuration a stored surface loads, the MPP transaction records the
//! admin API lists, and the challenge and credential wire formats the agent-pay
//! gate relays.

pub mod admin_api;
pub mod challenge;
pub mod payment_challenge;
pub mod transaction_store;
pub mod types;

pub use transaction_store::MppTransactionStore;

pub use types::*;
