//! Custom span filter for OpenTelemetry export
//!
//! Filters out internal dependency spans (h2, hyper, tower, tokio, etc.)
//! to reduce noise in distributed traces

use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};

/// Filtering span exporter that wraps another exporter
///
/// This exporter filters spans based on their attributes (code.namespace, code.filepath)
/// before passing them to the underlying exporter. This is necessary because
/// dependency crates (h2, hyper, tokio) add these attributes after span creation,
/// so we can't filter them at the subscriber level.
#[derive(Debug)]
pub struct FilteringSpanExporter<E> {
    inner: E,
}

impl<E> FilteringSpanExporter<E> {
    pub fn new(inner: E) -> Self {
        Self { inner }
    }

    /// Check if a span should be filtered based on its attributes
    fn should_filter_span(span: &SpanData) -> bool {
        // Check code.namespace attribute
        for kv in &span.attributes {
            if kv.key.as_str() == "code.namespace" {
                let namespace = kv.value.as_str();
                // Filter out internal dependency crates
                if namespace.starts_with("h2::")
                    || namespace.starts_with("hyper::")
                    || namespace.starts_with("tower::")
                    || namespace.starts_with("tokio::")
                    || namespace.starts_with("reqwest::")
                    || namespace.starts_with("tonic::")
                    || namespace.starts_with("want::")
                    || namespace.starts_with("mio::")
                    || namespace.starts_with("tokio_util::")
                    || namespace.starts_with("axum::")
                    || namespace == "runtime"
                    || namespace == "runtime.spawn"
                {
                    return true; // Filter out
                }
            }

            // Check code.filepath attribute
            if kv.key.as_str() == "code.filepath" {
                let filepath = kv.value.as_str();
                // Filter out spans from .cargo/registry (all external dependencies)
                if filepath.contains("/.cargo/registry/") {
                    return true; // Filter out
                }
            }
        }

        false // Keep the span
    }
}

impl<E> SpanExporter for FilteringSpanExporter<E>
where
    E: SpanExporter,
{
    async fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> std::result::Result<(), opentelemetry_sdk::error::OTelSdkError> {
        // Filter the batch before exporting
        let filtered_batch: Vec<SpanData> = batch
            .into_iter()
            .filter(|span| !Self::should_filter_span(span))
            .collect();

        // Only export if we have any spans left after filtering
        if filtered_batch.is_empty() {
            Ok(())
        } else {
            self.inner
                .export(filtered_batch)
                .await
        }
    }

    fn set_resource(
        &mut self,
        resource: &Resource,
    ) {
        // Propagate resource to inner exporter
        self.inner
            .set_resource(resource);
    }

    fn shutdown(&mut self) -> std::result::Result<(), opentelemetry_sdk::error::OTelSdkError> {
        // Propagate shutdown to inner exporter
        self.inner.shutdown()
    }
}

/// Custom filter for subscriber-level filtering (kept for backwards compatibility)
///
/// Note: This filter is less effective than the exporter-level filter above
/// because it can only check the tracing target, not the span attributes.
use tracing::{Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Filter};

pub struct BusinessLogicFilter {
    /// Allowed crate targets (e.g., "agent_gateway")
    allowed_targets: Vec<String>,
}

impl BusinessLogicFilter {
    /// Create a new filter with allowed crate targets
    pub fn new(allowed_targets: Vec<String>) -> Self {
        Self { allowed_targets }
    }

    /// Check if a span should be filtered based on its metadata
    fn should_filter_metadata(
        &self,
        metadata: &Metadata<'_>,
    ) -> bool {
        let target = metadata.target();

        // Always reject known internal crates
        if target.starts_with("h2::")
            || target.starts_with("hyper::")
            || target.starts_with("tower::")
            || target.starts_with("tokio::")
            || target.starts_with("reqwest::")
            || target.starts_with("tonic::")
            || target.starts_with("want::")
            || target.starts_with("mio::")
            || target == "h2"
            || target == "hyper"
            || target == "tower"
            || target == "tokio"
            || target == "reqwest"
            || target == "tonic"
            || target == "runtime"
            || target == "runtime.spawn"
            || target.starts_with("tokio_util::")
        {
            return true; // Filter out (reject)
        }

        // Allow if target matches any of our allowed crates
        let is_allowed = self
            .allowed_targets
            .iter()
            .any(|allowed| target == allowed || target.starts_with(&format!("{}::", allowed)));

        // Filter out if not allowed
        !is_allowed
    }
}

impl<S> Filter<S> for BusinessLogicFilter
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn enabled(
        &self,
        meta: &Metadata<'_>,
        _cx: &Context<'_, S>,
    ) -> bool {
        // Return true to ENABLE the span, false to filter it out
        !self.should_filter_metadata(meta)
    }

    fn event_enabled(
        &self,
        _event: &tracing::Event<'_>,
        _cx: &Context<'_, S>,
    ) -> bool {
        // Events are always enabled if their parent span is enabled
        true
    }
}
