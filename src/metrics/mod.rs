//! Metrics module - refactored from monolithic metrics.rs
//!
//! This module provides metrics tracking for proxy connections and throughput.

pub mod backends;
pub mod hierarchical;
pub mod store;
pub mod types;

// Re-export main types for convenience
pub use hierarchical::{build_hierarchical_metrics, flatten_hierarchical_metrics};
pub use store::MetricsStore;
pub use types::*;
