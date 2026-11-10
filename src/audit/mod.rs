//! Governance audit events and the sinks that receive them.
//!
//! Emit sites hand records to the [`producer`], which builds and journals a
//! record only when a sink selects its event. The [`journal`] makes it
//! durable; the [`dispatch`]er delivers it to each sink from that sink's own
//! cursor: the VP Audit Log ([`audit_log_sink`]) and each Governance Audit
//! integration ([`integration_sink`]). [`log_files`] keeps the VP Audit Log's
//! own file bounded: it rotates the live file and walks the history it leaves
//! behind one line at a time, so a reader never holds a file of it in memory.

pub mod audit_log_sink;
pub mod catalog;
pub mod context;
pub mod cursors;
pub mod dispatch;
pub mod events;
pub mod integration_sink;
pub mod journal;
pub mod log_files;
pub mod pipeline;
pub mod policy_changes;
pub mod policy_refusals;
pub mod producer;
pub mod registry;
pub mod request_events;
pub mod secret_force_deletes;
pub mod sources;
pub mod target_auth_changes;
