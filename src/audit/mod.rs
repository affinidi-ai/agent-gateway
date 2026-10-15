//! Governance audit events and the sinks that receive them.
//!
//! Emit sites hand records to the [`producer`], which builds and journals a
//! record only when a sink selects its event. The [`journal`] makes it
//! durable; the [`dispatch`]er delivers it to each sink from that sink's own
//! cursor: the VP Audit Log ([`audit_log_sink`]) and each Governance Audit
//! integration ([`integration_sink`]).

pub mod audit_log_sink;
pub mod catalog;
pub mod context;
pub mod cursors;
pub mod dispatch;
pub mod events;
pub mod integration_sink;
pub mod journal;
pub mod pipeline;
pub mod producer;
pub mod registry;
pub mod request_events;
pub mod sources;
