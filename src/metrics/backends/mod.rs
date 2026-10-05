//! Metrics backend implementations

mod aggregator;
mod cloudwatch;
mod file;
pub mod metric_names;
mod multi;
pub mod opentelemetry_backend;
pub mod prometheus;
mod prometheus_backend;
pub mod types;

// Re-export public types and implementations
pub use cloudwatch::CloudWatchMetricsBackend;
pub use file::FileMetricsBackend;
pub use multi::MultiBackend;
pub use opentelemetry_backend::OpenTelemetryMetricsBackend;
pub use prometheus_backend::PrometheusMetricsBackend;
pub use types::MetricsBackend;
