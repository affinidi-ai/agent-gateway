//! Utilities for spawning traced background tasks
//!
//! This module provides helpers for spawning tokio tasks with proper
//! OpenTelemetry span propagation

use tracing::{Instrument, info_span};

/// Spawn a background task with a root span
///
/// This creates a new root span for the task with agent_gateway as the target,
/// ensuring it passes through the OpenTelemetry filter and appears in traces.
///
/// # Example
/// ```no_run
/// use crate::observability::tasks::spawn_traced_task;
///
/// spawn_traced_task("process_message", async {
///     // Task work here
/// });
/// ```
pub fn spawn_traced_task<F>(
    task_name: &str,
    future: F,
) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let span = info_span!(
        target: "agent_gateway",
        parent: None,  // Create a new root span
        "background.task",
        otel.name = task_name,
        task.name = task_name,
    );

    tokio::spawn(future.instrument(span))
}

/// Spawn a background task with a custom span name and fields
///
/// This allows more control over the span attributes
pub fn spawn_traced_task_with_fields<F>(
    span_name: &str,
    fields: Vec<(&str, String)>,
    future: F,
) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let span = info_span!(
        target: "agent_gateway",
        parent: None,  // Create a new root span
        "background.task",
        otel.name = span_name,
        task.name = span_name,
    );

    // Record additional fields
    let entered = span.enter();
    for (key, value) in fields {
        tracing::Span::current().record(key, value.as_str());
    }
    drop(entered);

    tokio::spawn(future.instrument(span))
}
