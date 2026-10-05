//! Observability utilities for monitoring and real-time updates

pub mod caller_names;
pub mod dashboard;
pub mod did_display;
pub mod http_trace;
pub mod identity_binding_audit;
pub mod identity_view;
pub mod log_redact;
pub mod log_watcher;
pub mod metrics_updater;
pub mod opentelemetry;
pub mod otlp_health;
pub mod payload_capture;
pub mod policy_audit;
pub mod simple_format;
pub mod span_filter;
pub mod system_metrics;
pub mod task_monitor;
pub mod tasks;
pub mod trace_registry;
pub mod trust_check_audit;
pub mod websocket_log_layer;

pub use dashboard::*;
pub use http_trace::{
    access_log, record_caller_did_on_current_span, record_caller_identity_on_current_span, set_record_caller_identity,
    trace_http_request,
};
pub use log_redact::{LogRedactor, RedactingMakeWriter};
pub use metrics_updater::periodic_metrics_update;
pub use opentelemetry::{
    BoxedLayer, OtelConfig, build_log_layer_boxed, build_trace_layer_boxed, get_logger_provider, init_logs,
    init_metrics, init_tracer, install_log_reload, install_trace_reload, noop_layer_boxed, reload_otel,
    set_reload_redactor, shutdown as shutdown_otel,
};
pub use payload_capture::broadcast_payload_capture_async;
pub use policy_audit::{PolicyDecisionEvent, PolicyFlow, PolicyScope, record_policy_decision};
pub use simple_format::SimpleFormat;
pub use span_filter::FilteringSpanExporter;
pub use system_metrics::{
    SYSTEM_METRICS_INTERVAL_SECS, SystemMetricsResponse, SystemMetricsStore, periodic_system_metrics_collection,
};
pub use task_monitor::*;
pub use tasks::{spawn_traced_task, spawn_traced_task_with_fields};
pub use trace_registry::{get_trace_info, register_channel_prefix, register_mcp_prefix, should_trace_path};
pub use websocket_log_layer::{WebSocketLogLayer, init_websocket_log_broadcast};
