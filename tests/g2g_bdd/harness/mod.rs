//! g2g_bdd-specific harness primitives. Shared harnesses live in
//! [`crate::bdd_support`]:
//! - [`crate::bdd_support::mediator`] — mediator (used by both worlds).
//!
//! Consumers import them directly from `bdd_support`.

pub mod multi_gateway;
