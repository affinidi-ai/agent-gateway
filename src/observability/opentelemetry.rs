//! OpenTelemetry integration for distributed tracing and metrics export
//!
//! This module provides integration with OpenTelemetry for exporting traces and metrics
//! to OTLP-compatible collectors (Jaeger, Tempo, Prometheus, etc.).
//!
//! # Architecture
//! - Tracer Provider: Exports distributed traces via OTLP gRPC
//! - Meter Provider: Exports metrics via OTLP gRPC with periodic export
//! - Global Providers: Set as global for automatic collection
//!
//! # Usage
//! ```no_run
//! use crate::observability::{OtelConfig, init_tracer, init_metrics, shutdown_otel};
//!
//! let config = OtelConfig::default();
//! let tracer = init_tracer(&config)?;
//! let meter = init_metrics(&config)?;
//!
//! // On shutdown
//! shutdown_otel();
//! ```

use anyhow::{Context, Result};
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::{Resource, trace::Sampler};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{info, warn};
use tracing_subscriber::Layer;

use super::log_redact::{LogRedactor, RedactingSpanExporter};

pub use crate::config::metrics_config::OtlpProtocol;

/// Log processor that stamps `time_unix_nano` on records before delegating.
///
/// `opentelemetry-appender-tracing` only sets `observed_time_unix_nano`,
/// leaving `time_unix_nano = 0` in OTLP exports. This wrapper fills the gap
/// so downstream collectors/backends receive correct event timestamps.
#[derive(Debug)]
struct TimestampFixingLogProcessor<P> {
    inner: P,
}

impl<P: opentelemetry_sdk::logs::LogProcessor> opentelemetry_sdk::logs::LogProcessor
    for TimestampFixingLogProcessor<P>
{
    fn emit(
        &self,
        record: &mut opentelemetry_sdk::logs::SdkLogRecord,
        scope: &opentelemetry::InstrumentationScope,
    ) {
        if record.timestamp().is_none() {
            use opentelemetry::logs::LogRecord as _;
            let ts = record
                .observed_timestamp()
                .unwrap_or_else(std::time::SystemTime::now);
            record.set_timestamp(ts);
        }
        self.inner.emit(record, scope);
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.shutdown()
    }
}

// Global logger provider storage
static LOGGER_PROVIDER: OnceLock<opentelemetry_sdk::logs::SdkLoggerProvider> = OnceLock::new();

// ── Hot-reload state ────────────────────────────────────────────────
//
// The OTEL trace + log layers are wired into the (write-once) global tracing
// subscriber, so they cannot be swapped by re-registering a provider alone.
// Instead they are installed as `reload::Layer`s whose handles live here; a
// config save rebuilds the providers and swaps the layer content in place.

/// Boxed, type-erased layer over the base `Registry` — the reloadable unit.
pub type BoxedLayer = Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>;

/// Reload handle type shared by the trace and log OTEL layers.
pub type OtelReloadHandle = tracing_subscriber::reload::Handle<BoxedLayer, tracing_subscriber::Registry>;

/// Reload handles for the OTEL trace and log layers, set once during startup.
static TRACE_RELOAD: OnceLock<OtelReloadHandle> = OnceLock::new();
static LOG_RELOAD: OnceLock<OtelReloadHandle> = OnceLock::new();

/// Redactor captured at startup, reused when rebuilding the trace exporter on reload.
static RELOAD_REDACTOR: OnceLock<Arc<LogRedactor>> = OnceLock::new();

/// Live providers, kept alive so their batch processors keep exporting and shut
/// down (flushed) when superseded on reload.
static CURRENT_TRACER_PROVIDER: Mutex<Option<opentelemetry_sdk::trace::SdkTracerProvider>> = Mutex::new(None);
static CURRENT_METER_PROVIDER: Mutex<Option<opentelemetry_sdk::metrics::SdkMeterProvider>> = Mutex::new(None);
static CURRENT_LOGGER_PROVIDER: Mutex<Option<opentelemetry_sdk::logs::SdkLoggerProvider>> = Mutex::new(None);

/// Serialises concurrent reloads so two config saves can't race.
static RELOAD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Capture the log redactor for reuse when the trace exporter is rebuilt on a
/// later hot-reload. Call once at startup **regardless** of whether
/// OpenTelemetry is initially enabled: if the process starts with OTEL disabled
/// and an operator enables it via a live config save, the reload must apply the
/// configured redaction rather than falling back to the default (which would
/// export span attributes unredacted until the next restart).
pub fn set_reload_redactor(redactor: Arc<LogRedactor>) {
    let _ = RELOAD_REDACTOR.set(redactor);
}

/// Store the current provider, returning the previous one (for shutdown).
fn store_current<T>(
    slot: &Mutex<Option<T>>,
    provider: T,
) -> Option<T> {
    slot.lock()
        .ok()
        .and_then(|mut g| g.replace(provider))
}

/// OpenTelemetry configuration
///
/// Provides comprehensive configuration for OpenTelemetry tracing and metrics export.
/// All settings can be tuned for production use based on traffic patterns and
/// infrastructure capacity.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Whether OpenTelemetry is enabled
    #[allow(dead_code)]
    pub enabled: bool,
    /// OTLP endpoint (e.g., "http://localhost:4317" for gRPC, ":4318" for HTTP)
    pub otlp_endpoint: String,
    /// OTLP transport protocol (gRPC or HTTP).
    pub protocol: OtlpProtocol,
    /// Optional pre-resolved auth header `(name, value)` attached to every
    /// OTLP export. Resolved from the secrets store at startup.
    pub auth_header: Option<(String, String)>,
    /// Service name for distributed tracing
    pub service_name: String,
    /// Service version (typically from CARGO_PKG_VERSION)
    pub service_version: String,
    /// Deployment environment (development, staging, production)
    pub environment: String,
    /// Trace sampling rate (0.0 = no sampling, 1.0 = 100% sampling)
    pub sample_rate: f64,
    /// Metrics export interval in seconds
    pub export_interval_seconds: u64,
    /// OTLP export timeout in seconds
    pub export_timeout_seconds: u64,
    /// Maximum queue size for batch exporter
    #[allow(dead_code)]
    pub batch_max_queue_size: usize,
    /// Scheduled delay for batch export in milliseconds
    #[allow(dead_code)]
    pub batch_scheduled_delay_ms: u64,
    /// Maximum export batch size
    #[allow(dead_code)]
    pub batch_max_export_size: usize,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: "http://localhost:4317".to_string(),
            protocol: OtlpProtocol::default(),
            auth_header: None,
            service_name: env!("CARGO_PKG_NAME").to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            sample_rate: 1.0,
            export_interval_seconds: 60,
            export_timeout_seconds: 10,
            batch_max_queue_size: 2048,
            batch_scheduled_delay_ms: 5000,
            batch_max_export_size: 512,
        }
    }
}

/// Helper function to create OpenTelemetry resource with service metadata
///
/// Resources are attached to all spans and metrics to provide context about
/// the service generating the telemetry data.
///
/// # Arguments
/// * `config` - Configuration containing service metadata
///
/// # Returns
/// Resource with service name, version, environment, and SDK information
fn create_resource(config: &OtelConfig) -> Resource {
    Resource::builder()
        .with_attributes(vec![
            KeyValue::new("service.name", config.service_name.clone()),
            KeyValue::new("service.version", config.service_version.clone()),
            KeyValue::new("deployment.environment", config.environment.clone()),
            KeyValue::new("telemetry.sdk.name", "opentelemetry"),
            KeyValue::new("telemetry.sdk.language", "rust"),
        ])
        .build()
}

/// Build a gRPC metadata map carrying the optional OTLP auth header.
///
/// Returns an empty map when no auth is configured. Errors if the configured
/// header name or value cannot be represented as valid gRPC metadata.
fn grpc_auth_metadata(auth_header: &Option<(String, String)>) -> Result<tonic::metadata::MetadataMap> {
    let mut map = tonic::metadata::MetadataMap::new();
    if let Some((name, value)) = auth_header {
        let key = tonic::metadata::MetadataKey::from_bytes(
            name.to_ascii_lowercase()
                .as_bytes(),
        )
        .with_context(|| format!("Invalid OTLP auth header name '{name}'"))?;
        let val = tonic::metadata::MetadataValue::try_from(value.as_str())
            .context("OTLP auth header value contains characters invalid for gRPC metadata")?;
        map.insert(key, val);
    }
    Ok(map)
}

/// Build an HTTP header map carrying the optional OTLP auth header.
fn http_auth_headers(auth_header: &Option<(String, String)>) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Some((name, value)) = auth_header {
        map.insert(name.clone(), value.clone());
    }
    map
}

/// Build the per-signal OTLP/HTTP endpoint from a base endpoint.
///
/// The `opentelemetry-otlp` HTTP builder uses the endpoint passed to
/// `with_endpoint` verbatim (it does not append the signal path), while the
/// dashboard/config supplies a base URL like `http://host:4318`. This appends
/// the standard `/v1/{traces,metrics,logs}` path so the export actually reaches
/// the collector's OTLP/HTTP receiver. A base that already ends in the target
/// signal path is left unchanged so a full per-signal endpoint still works.
fn http_signal_endpoint(
    base: &str,
    signal: &str,
) -> String {
    let trimmed = base.trim_end_matches('/');
    let suffix = format!("/v1/{signal}");
    if trimmed.ends_with(&suffix) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{suffix}")
    }
}

/// Build an OTLP span exporter for the configured protocol, attaching the
/// optional auth header.
fn build_span_exporter(config: &OtelConfig) -> Result<opentelemetry_otlp::SpanExporter> {
    let timeout = std::time::Duration::from_secs(config.export_timeout_seconds);
    match config.protocol {
        OtlpProtocol::Grpc => opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&config.otlp_endpoint)
            .with_timeout(timeout)
            .with_metadata(grpc_auth_metadata(&config.auth_header)?)
            .build()
            .context("Failed to build OTLP/gRPC span exporter"),
        OtlpProtocol::Http => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(http_signal_endpoint(&config.otlp_endpoint, "traces"))
            .with_timeout(timeout)
            .with_headers(http_auth_headers(&config.auth_header))
            .build()
            .context("Failed to build OTLP/HTTP span exporter"),
    }
}

/// Build an OTLP metric exporter for the configured protocol, attaching the
/// optional auth header.
fn build_metric_exporter(config: &OtelConfig) -> Result<opentelemetry_otlp::MetricExporter> {
    let timeout = std::time::Duration::from_secs(config.export_timeout_seconds);
    match config.protocol {
        OtlpProtocol::Grpc => opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&config.otlp_endpoint)
            .with_timeout(timeout)
            .with_metadata(grpc_auth_metadata(&config.auth_header)?)
            .build()
            .context("Failed to build OTLP/gRPC metrics exporter"),
        OtlpProtocol::Http => opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(http_signal_endpoint(&config.otlp_endpoint, "metrics"))
            .with_timeout(timeout)
            .with_headers(http_auth_headers(&config.auth_header))
            .build()
            .context("Failed to build OTLP/HTTP metrics exporter"),
    }
}

/// Build an OTLP log exporter for the configured protocol, attaching the
/// optional auth header.
fn build_log_exporter(config: &OtelConfig) -> Result<opentelemetry_otlp::LogExporter> {
    let timeout = std::time::Duration::from_secs(config.export_timeout_seconds);
    match config.protocol {
        OtlpProtocol::Grpc => opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(&config.otlp_endpoint)
            .with_timeout(timeout)
            .with_metadata(grpc_auth_metadata(&config.auth_header)?)
            .build()
            .context("Failed to build OTLP/gRPC logs exporter"),
        OtlpProtocol::Http => opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(http_signal_endpoint(&config.otlp_endpoint, "logs"))
            .with_timeout(timeout)
            .with_headers(http_auth_headers(&config.auth_header))
            .build()
            .context("Failed to build OTLP/HTTP logs exporter"),
    }
}

/// Initialize OpenTelemetry tracer provider with OTLP export
///
/// Creates a tracer provider configured to export spans via OTLP gRPC protocol.
/// The provider is registered globally and will be used for all tracing operations.
///
/// # Arguments
/// * `config` - OpenTelemetry configuration including endpoint, sampling, and batch settings
///
/// # Returns
/// * `Ok(TracerProvider)` - Successfully initialized tracer provider
/// * `Err(anyhow::Error)` - Failed to build exporter or provider
///
/// # Errors
/// - Network connectivity issues to OTLP endpoint
/// - Invalid configuration (malformed endpoint)
/// - Resource exhaustion during initialization
///
/// # Example
/// ```no_run
/// let config = OtelConfig {
///     enabled: true,
///     otlp_endpoint: "http://localhost:4317".into(),
///     service_name: "my-service".into(),
///     sample_rate: 0.1, // 10% sampling
///     ..Default::default()
/// };
/// let provider = init_tracer(&config)?;
/// ```
pub fn init_tracer(
    config: &OtelConfig,
    redactor: Arc<LogRedactor>,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider> {
    info!(
        otel.component = "tracer",
        otel.endpoint = %config.otlp_endpoint,
        otel.service = %config.service_name,
        otel.version = %config.service_version,
        otel.environment = %config.environment,
        otel.sample_rate = %config.sample_rate,
        "Initializing OpenTelemetry tracer"
    );

    // Capture the redactor so the trace exporter can be rebuilt on hot reload.
    let _ = RELOAD_REDACTOR.set(redactor.clone());

    let provider = build_tracer_provider(config, redactor)?;

    // Set as global tracer provider and keep a handle for reload/shutdown.
    global::set_tracer_provider(provider.clone());
    store_current(&CURRENT_TRACER_PROVIDER, provider.clone());

    info!(otel.component = "tracer", "✅ OpenTelemetry tracer initialized successfully");

    Ok(provider)
}

/// Build a tracer provider (backoff → filter → redact → batch export chain)
/// without registering any global. Shared by [`init_tracer`] and [`reload_otel`].
fn build_tracer_provider(
    config: &OtelConfig,
    redactor: Arc<LogRedactor>,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider> {
    let sampler = if config.sample_rate >= 1.0 {
        Sampler::AlwaysOn
    } else if config.sample_rate <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_rate)
    };

    // Create resource with service information
    let resource = create_resource(config);

    // Create OTLP exporter for the configured protocol (gRPC or HTTP) with the
    // optional auth header attached.
    let otlp_exporter = build_span_exporter(config).context(format!("OTLP endpoint: {}", config.otlp_endpoint))?;

    // Gate exports behind bounded exponential backoff (innermost), so a
    // unreachable collector produces one WARN per attempt instead of per-cycle
    // spam, and surfaces its health to the dashboard.
    let gated_exporter = super::otlp_health::BackoffSpanExporter::new(
        otlp_exporter,
        super::otlp_health::controller(super::otlp_health::OtlpSignal::Traces),
    );

    // Wrap with filtering exporter to remove internal dependency spans
    let filtering_exporter = super::FilteringSpanExporter::new(gated_exporter);

    // Wrap with redacting exporter to sanitize sensitive data in span attributes
    let exporter = RedactingSpanExporter::new(filtering_exporter, redactor);

    // Build tracer provider with batch exporter
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(sampler)
        .with_max_events_per_span(128)
        .with_max_attributes_per_span(128)
        .build();

    Ok(provider)
}

// Note: Direct tracing-opentelemetry layer integration is not used due to
// trait compatibility issues with OpenTelemetry 0.27 SDK.
// Spans are still exported via the global tracer provider set in init_tracer().
// Alternative: Use opentelemetry API directly for manual span creation when needed.

/// Initialize OpenTelemetry metrics exporter with periodic export
///
/// Creates a meter provider configured to export metrics via OTLP gRPC protocol
/// on a periodic schedule. The provider is registered globally for automatic collection.
///
/// # Arguments
/// * `config` - OpenTelemetry configuration including endpoint and export interval
///
/// # Returns
/// * `Ok(SdkMeterProvider)` - Successfully initialized meter provider
/// * `Err(anyhow::Error)` - Failed to build exporter or provider
///
/// # Errors
/// - Network connectivity issues to OTLP endpoint
/// - Invalid configuration (malformed endpoint)
/// - Resource exhaustion during initialization
///
/// # Example
/// ```no_run
/// let config = OtelConfig {
///     enabled: true,
///     otlp_endpoint: "http://localhost:4317".into(),
///     export_interval_seconds: 60,
///     ..Default::default()
/// };
/// let provider = init_metrics(&config)?;
/// ```
pub fn init_metrics(config: &OtelConfig) -> Result<opentelemetry_sdk::metrics::SdkMeterProvider> {
    info!(
        otel.component = "metrics",
        otel.endpoint = %config.otlp_endpoint,
        otel.export_interval_s = config.export_interval_seconds,
        "Initializing OpenTelemetry metrics"
    );

    let provider = build_meter_provider(config)?;

    // Set as global meter provider and keep a handle for reload/shutdown.
    global::set_meter_provider(provider.clone());
    store_current(&CURRENT_METER_PROVIDER, provider.clone());

    info!(otel.component = "metrics", "✅ OpenTelemetry metrics initialized successfully");

    Ok(provider)
}

/// Build a meter provider (periodic reader over the backoff-gated exporter)
/// without registering any global. Shared by [`init_metrics`] and [`reload_otel`].
fn build_meter_provider(config: &OtelConfig) -> Result<opentelemetry_sdk::metrics::SdkMeterProvider> {
    // Create resource with service information
    let resource = create_resource(config);

    // Create OTLP metrics exporter for the configured protocol with the
    // optional auth header attached.
    let exporter = build_metric_exporter(config).context(format!("OTLP endpoint: {}", config.otlp_endpoint))?;

    // Gate exports behind bounded exponential backoff and health tracking.
    let exporter = super::otlp_health::BackoffMetricExporter::new(
        exporter,
        super::otlp_health::controller(super::otlp_health::OtlpSignal::Metrics),
    );

    // Build meter provider with periodic reader
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(std::time::Duration::from_secs(config.export_interval_seconds))
        .build();

    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    Ok(provider)
}

/// Initialize OpenTelemetry logs exporter with OTLP export
///
/// Creates a logger provider configured to export logs via OTLP gRPC protocol.
/// The provider is registered globally and will be used for log export operations.
///
/// # Arguments
/// * `config` - OpenTelemetry configuration including endpoint and batch settings
///
/// # Returns
/// * `Ok(LoggerProvider)` - Successfully initialized logger provider
/// * `Err(anyhow::Error)` - Failed to build exporter or provider
///
/// # Errors
/// - Network connectivity issues to OTLP endpoint
/// - Invalid configuration (malformed endpoint)
/// - Resource exhaustion during initialization
pub fn init_logs(config: &OtelConfig) -> Result<opentelemetry_sdk::logs::SdkLoggerProvider> {
    info!(
        otel.component = "logs",
        otel.endpoint = %config.otlp_endpoint,
        otel.service = %config.service_name,
        "Initializing OpenTelemetry logs"
    );

    let provider = build_logger_provider(config)?;

    // Store in global static for retrieval + a reload/shutdown handle.
    let _ = LOGGER_PROVIDER.set(provider.clone());
    store_current(&CURRENT_LOGGER_PROVIDER, provider.clone());

    info!(otel.component = "logs", "✅ OpenTelemetry logs initialized successfully");

    Ok(provider)
}

/// Build a logger provider (timestamp-fixing batch processor over the
/// backoff-gated exporter) without registering any global. Shared by
/// [`init_logs`] and [`reload_otel`].
fn build_logger_provider(config: &OtelConfig) -> Result<opentelemetry_sdk::logs::SdkLoggerProvider> {
    // Create resource with service information
    let resource = create_resource(config);

    // Create OTLP logs exporter for the configured protocol with the optional
    // auth header attached.
    let exporter = build_log_exporter(config).context(format!("OTLP endpoint: {}", config.otlp_endpoint))?;

    // Gate exports behind bounded exponential backoff and health tracking.
    let exporter = super::otlp_health::BackoffLogExporter::new(
        exporter,
        super::otlp_health::controller(super::otlp_health::OtlpSignal::Logs),
    );

    // Build batch processor, wrap with timestamp fix, then build provider
    let batch = opentelemetry_sdk::logs::BatchLogProcessor::builder(exporter).build();
    let processor = TimestampFixingLogProcessor { inner: batch };

    let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_log_processor(processor)
        .build();

    Ok(provider)
}

/// Get the global logger provider if initialized
pub fn get_logger_provider() -> Option<&'static opentelemetry_sdk::logs::SdkLoggerProvider> {
    LOGGER_PROVIDER.get()
}

// ── Reloadable layer construction ───────────────────────────────────

/// Build the boxed (unfiltered) OTEL trace layer for a tracer provider.
///
/// The level + business-logic filters are applied **outside** the reloadable
/// layer by [`install_trace_reload`], never inside it: a per-layer `Filtered`
/// nested in a `reload::Layer` only registers its `FilterId` for the *initial*
/// inner layer, so a hot-swapped filtered layer would panic with
/// "a `Filtered` layer ... had no `FilterId`". Keeping the reloadable content
/// filter-free means only the raw tracer layer is swapped; the surrounding
/// filters are registered once and never move.
pub fn build_trace_layer_boxed(
    provider: &opentelemetry_sdk::trace::SdkTracerProvider,
    service_name: &str,
) -> BoxedLayer {
    use opentelemetry::trace::TracerProvider as _;
    let tracer = provider.tracer(service_name.to_string());
    tracing_opentelemetry::OpenTelemetryLayer::new(tracer).boxed()
}

/// Build the boxed OTEL log-bridge layer for a logger provider.
pub fn build_log_layer_boxed(provider: &opentelemetry_sdk::logs::SdkLoggerProvider) -> BoxedLayer {
    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(provider).boxed()
}

/// A no-op boxed layer, used when a signal is disabled.
pub fn noop_layer_boxed() -> BoxedLayer {
    tracing_subscriber::layer::Identity::new().boxed()
}

/// Wrap `initial` in a reload layer for the OTEL **trace** slot, apply the fixed
/// level + business-logic filters **outside** the reload layer (so their
/// `FilterId` registration survives every hot swap), store the handle globally,
/// and return the boxed layer to insert into the subscriber. Call exactly once
/// during startup. `target_crates` is fixed at startup — changing it needs a
/// restart, unlike the reloadable endpoint/protocol/auth/sampling settings.
pub fn install_trace_reload(
    initial: BoxedLayer,
    target_crates: Vec<String>,
) -> BoxedLayer {
    let (layer, handle) = tracing_subscriber::reload::Layer::new(initial);
    let _ = TRACE_RELOAD.set(handle);
    layer
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO)
        .with_filter(super::span_filter::BusinessLogicFilter::new(target_crates))
        .boxed()
}

/// Wrap `initial` in a reload layer for the OTEL **log** slot, apply a fixed
/// level filter **outside** the reload layer (so its `FilterId` survives every
/// hot swap), store the handle globally, and return the boxed layer to insert
/// into the subscriber. Call exactly once during startup.
///
/// `max_level` mirrors the console/file log level (`config.logging.level`), so
/// the OTLP log export carries the same verbosity as local logs. Only a level
/// filter is applied — not the trace layer's `BusinessLogicFilter` allow-list —
/// because log events use custom targets (e.g. `policy_audit`,
/// `trust_check_audit`) that an allow-list would wrongly drop. This keeps the
/// noisy `TRACE`/`DEBUG` dependency logs (h2, hyper, reqwest, …) out of the OTLP
/// export whenever the configured level excludes them, while preserving every
/// application event at or above the configured level.
pub fn install_log_reload(
    initial: BoxedLayer,
    max_level: tracing::Level,
) -> BoxedLayer {
    let (layer, handle) = tracing_subscriber::reload::Layer::new(initial);
    let _ = LOG_RELOAD.set(handle);
    layer
        .with_filter(tracing_subscriber::filter::LevelFilter::from_level(max_level))
        .boxed()
}

/// Apply a new OpenTelemetry configuration to the running process **without a
/// restart**.
///
/// Rebuilds the trace/metric/log providers from `cfg`, swaps the reloadable
/// trace and log layers in place, re-points the global meter provider, and
/// gracefully shuts down the superseded providers. Enabling or disabling a
/// signal swaps between the real layer and a no-op. Metrics-only changes never
/// touch the subscriber.
///
/// The reloadable layers must have been installed at startup
/// ([`install_trace_reload`] / [`install_log_reload`]); if they were not (the
/// binary started before this support existed) the trace/log swaps are skipped
/// and only metrics reload.
pub async fn reload_otel(
    cfg: &crate::config::metrics_config::OpenTelemetryConfig,
    auth_header: Option<(String, String)>,
) -> Result<()> {
    let _guard = RELOAD_LOCK.lock().await;

    info!(
        otel.component = "reload",
        otel.enabled = cfg.enabled,
        otel.endpoint = %cfg.endpoint,
        "Applying OpenTelemetry configuration without restart"
    );

    // Keep the opt-in caller-identity span toggle in sync.
    super::set_record_caller_identity(
        cfg.traces
            .record_caller_identity,
    );

    let mut otel_config = OtelConfig::from(cfg);
    otel_config.auth_header = auth_header;

    // ── Traces ──
    let tracer_to_flush = if let Some(handle) = TRACE_RELOAD.get() {
        if cfg.enabled {
            let redactor = RELOAD_REDACTOR
                .get()
                .cloned()
                .unwrap_or_else(|| LogRedactor::from_config(&crate::config::types::LogRedactionConfig::default()));
            let provider = build_tracer_provider(&otel_config, redactor)?;
            let layer = build_trace_layer_boxed(&provider, &otel_config.service_name);
            handle
                .reload(layer)
                .map_err(|e| anyhow::anyhow!("Failed to reload OTEL trace layer: {e}"))?;
            global::set_tracer_provider(provider.clone());
            // Clear any stale backoff so a corrected endpoint is retried at once.
            super::otlp_health::reset_backoff(super::otlp_health::OtlpSignal::Traces);
            let to_flush = provider.clone();
            if let Some(old) = store_current(&CURRENT_TRACER_PROVIDER, provider)
                && let Err(e) = old.shutdown()
            {
                warn!("Failed to shut down superseded tracer provider: {e}");
            }
            Some(to_flush)
        } else {
            let _ = handle.reload(noop_layer_boxed());
            shutdown_current(&CURRENT_TRACER_PROVIDER, |p| p.shutdown());
            None
        }
    } else {
        None
    };

    // ── Logs ──
    let logger_to_flush = if let Some(handle) = LOG_RELOAD.get() {
        if cfg.enabled && cfg.logs.enabled {
            let provider = build_logger_provider(&otel_config)?;
            let layer = build_log_layer_boxed(&provider);
            handle
                .reload(layer)
                .map_err(|e| anyhow::anyhow!("Failed to reload OTEL log layer: {e}"))?;
            super::otlp_health::reset_backoff(super::otlp_health::OtlpSignal::Logs);
            let to_flush = provider.clone();
            if let Some(old) = store_current(&CURRENT_LOGGER_PROVIDER, provider)
                && let Err(e) = old.shutdown()
            {
                warn!("Failed to shut down superseded logger provider: {e}");
            }
            Some(to_flush)
        } else {
            let _ = handle.reload(noop_layer_boxed());
            shutdown_current(&CURRENT_LOGGER_PROVIDER, |p| p.shutdown());
            None
        }
    } else {
        None
    };

    // ── Metrics ──
    let meter_to_flush = if cfg.enabled {
        let provider = build_meter_provider(&otel_config)?;
        global::set_meter_provider(provider.clone());
        super::otlp_health::reset_backoff(super::otlp_health::OtlpSignal::Metrics);
        let to_flush = provider.clone();
        if let Some(old) = store_current(&CURRENT_METER_PROVIDER, provider)
            && let Err(e) = old.shutdown()
        {
            warn!("Failed to shut down superseded meter provider: {e}");
        }
        Some(to_flush)
    } else {
        // A meter provider with no readers exports nothing.
        global::set_meter_provider(opentelemetry_sdk::metrics::SdkMeterProvider::builder().build());
        shutdown_current(&CURRENT_METER_PROVIDER, |p| p.shutdown());
        None
    };

    // Trigger an immediate export attempt against the (possibly new) endpoint so
    // a corrected endpoint reconnects right away instead of waiting for the next
    // batch/interval. `force_flush` is blocking, so run it off the async runtime.
    tokio::task::spawn_blocking(move || {
        if let Some(p) = meter_to_flush
            && let Err(e) = p.force_flush()
        {
            tracing::debug!("Immediate OTLP metrics flush after reload failed: {e}");
        }
        if let Some(p) = tracer_to_flush
            && let Err(e) = p.force_flush()
        {
            tracing::debug!("Immediate OTLP trace flush after reload failed: {e}");
        }
        if let Some(p) = logger_to_flush
            && let Err(e) = p.force_flush()
        {
            tracing::debug!("Immediate OTLP log flush after reload failed: {e}");
        }
    });

    info!(otel.component = "reload", "✅ OpenTelemetry configuration applied");
    Ok(())
}

/// Take the current provider out of its slot and shut it down (best effort).
fn shutdown_current<T>(
    slot: &Mutex<Option<T>>,
    shutdown: impl FnOnce(&T) -> opentelemetry_sdk::error::OTelSdkResult,
) {
    let taken = slot
        .lock()
        .ok()
        .and_then(|mut g| g.take());
    if let Some(provider) = taken
        && let Err(e) = shutdown(&provider)
    {
        warn!("Failed to shut down superseded OTEL provider: {e}");
    }
}

/// Shutdown OpenTelemetry gracefully on application exit
///
/// Ensures all pending spans and metrics are flushed to the collector before
/// the application exits. This is critical for data integrity - without proper
/// shutdown, buffered telemetry data may be lost.
///
/// # Important
/// Call this function during application shutdown, typically in a defer block
/// or signal handler.
///
/// # Note
/// OpenTelemetry 0.27 SDK doesn't expose a global meter provider shutdown API.
/// Metrics are flushed when the provider is dropped, but explicit shutdown would
/// be more reliable. Track upstream issue for improvements.
///
/// # Example
/// ```no_run
/// // On SIGTERM or application exit
/// shutdown_otel();
/// ```
pub fn shutdown() {
    info!(otel.component = "shutdown", "Shutting down OpenTelemetry");

    // Shutdown logger provider - flushes pending logs
    if let Some(provider) = LOGGER_PROVIDER.get()
        && let Err(e) = provider.shutdown()
    {
        eprintln!("Failed to shutdown logger provider: {}", e);
    }

    // Tracer and meter providers shutdown automatically on drop in OpenTelemetry 0.31

    info!(otel.component = "shutdown", "✅ OpenTelemetry shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otel_config_default() {
        let config = OtelConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.service_name, env!("CARGO_PKG_NAME"));
        assert_eq!(config.sample_rate, 1.0);
        assert_eq!(config.export_interval_seconds, 60);
        assert_eq!(config.export_timeout_seconds, 10);
        assert_eq!(config.batch_max_queue_size, 2048);
        assert_eq!(config.batch_scheduled_delay_ms, 5000);
        assert_eq!(config.batch_max_export_size, 512);
    }

    #[test]
    fn test_sampler_selection() {
        let config_always = OtelConfig {
            sample_rate: 1.0,
            ..Default::default()
        };

        let config_never = OtelConfig {
            sample_rate: 0.0,
            ..Default::default()
        };

        let config_ratio = OtelConfig {
            sample_rate: 0.5,
            ..Default::default()
        };

        // These should not panic
        assert!(config_always.sample_rate >= 1.0);
        assert!(config_never.sample_rate <= 0.0);
        assert!(config_ratio.sample_rate > 0.0 && config_ratio.sample_rate < 1.0);
    }

    #[test]
    fn test_create_resource() {
        let config = OtelConfig {
            service_name: "test-service".to_string(),
            service_version: "1.0.0".to_string(),
            environment: "testing".to_string(),
            ..Default::default()
        };

        let _resource = create_resource(&config);
        // Resource is created - just verify it doesn't panic
    }

    #[test]
    fn test_batch_config_customization() {
        let config = OtelConfig {
            batch_max_queue_size: 4096,
            batch_scheduled_delay_ms: 10000,
            batch_max_export_size: 1024,
            ..Default::default()
        };

        assert_eq!(config.batch_max_queue_size, 4096);
        assert_eq!(config.batch_scheduled_delay_ms, 10000);
        assert_eq!(config.batch_max_export_size, 1024);
    }

    #[test]
    fn http_signal_endpoint_appends_signal_path() {
        assert_eq!(http_signal_endpoint("http://localhost:4318", "traces"), "http://localhost:4318/v1/traces");
        assert_eq!(http_signal_endpoint("http://localhost:4318", "metrics"), "http://localhost:4318/v1/metrics");
        assert_eq!(http_signal_endpoint("http://localhost:4318", "logs"), "http://localhost:4318/v1/logs");
    }

    #[test]
    fn http_signal_endpoint_trims_trailing_slash() {
        assert_eq!(http_signal_endpoint("http://localhost:4318/", "traces"), "http://localhost:4318/v1/traces");
    }

    #[test]
    fn http_signal_endpoint_preserves_full_per_signal_endpoint() {
        // A base that already targets the signal path is left unchanged.
        assert_eq!(
            http_signal_endpoint("http://localhost:4318/v1/traces", "traces"),
            "http://localhost:4318/v1/traces"
        );
        assert_eq!(
            http_signal_endpoint("http://localhost:4318/v1/traces/", "traces"),
            "http://localhost:4318/v1/traces"
        );
    }

    #[test]
    fn http_signal_endpoint_supports_path_prefix() {
        // A gateway/proxy prefix before the OTLP base is preserved.
        assert_eq!(
            http_signal_endpoint("https://collector.example.com/otlp", "metrics"),
            "https://collector.example.com/otlp/v1/metrics"
        );
    }
}
