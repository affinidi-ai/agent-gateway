//! Metrics configuration loader for metrics.json
//!
//! This module handles loading observability configuration from the metrics.json file,
//! which contains OpenTelemetry and CloudWatch settings.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Root metrics configuration structure matching metrics.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// OpenTelemetry configuration
    pub opentelemetry: OpenTelemetryConfig,

    /// CloudWatch configuration
    pub cloudwatch: CloudWatchMetricConfig,

    /// Retention policies
    #[serde(default)]
    pub retention: RetentionConfig,

    /// Advanced configuration
    #[serde(default)]
    pub advanced: AdvancedConfig,
}

/// OpenTelemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenTelemetryConfig {
    /// Whether OpenTelemetry is enabled
    pub enabled: bool,

    /// OTLP endpoint (host:port or URL, interpreted per `protocol`)
    pub endpoint: String,

    /// OTLP transport protocol used to reach the collector.
    #[serde(default)]
    pub protocol: OtlpProtocol,

    /// Optional authentication for a customer-managed collector. When set, the
    /// resolved header is attached to every OTLP export (traces, metrics, logs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<OtlpAuthConfig>,

    /// Service name for distributed tracing
    pub service_name: String,

    /// Deployment environment
    pub environment: String,

    /// Traces configuration
    pub traces: TracesConfig,

    /// Metrics configuration
    pub metrics: MetricsExportConfig,

    /// Logs configuration
    pub logs: LogsConfig,
}

/// OTLP transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtlpProtocol {
    /// OTLP over gRPC (tonic). Default port 4317.
    #[default]
    Grpc,
    /// OTLP over HTTP with binary protobuf body. Default port 4318.
    Http,
}

/// Authentication for exporting telemetry to a customer-managed OTLP collector.
///
/// The credential value is never stored inline: `secret_id` references a secret
/// held in the internal secrets store (managed via the dashboard Secrets page).
/// The resolved value is interpolated into `header_format` and sent under
/// `header_name`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpAuthConfig {
    /// Header name to send to the collector, e.g. "Authorization" or "X-Api-Key".
    pub header_name: String,

    /// `secret_id` of a secret in the internal secrets store holding the value.
    pub secret_id: String,

    /// Format string for the header value; `{value}` is replaced with the
    /// resolved secret. Defaults to `{value}`. Use `Bearer {value}` for bearer
    /// token auth.
    #[serde(default = "default_header_format")]
    pub header_format: String,
}

fn default_header_format() -> String {
    "{value}".to_string()
}

/// The `{value}` placeholder substituted in `OtlpAuthConfig::header_format`.
const HEADER_VALUE_PLACEHOLDER: &str = "{value}";

/// Resolve an [`OtlpAuthConfig`] into a concrete `(header_name, header_value)`
/// pair by reading the referenced secret and interpolating `header_format`.
///
/// Returns an error if the referenced secret does not exist so startup fails
/// fast rather than silently exporting telemetry unauthenticated.
pub async fn resolve_otel_auth_header(
    auth: &OtlpAuthConfig,
    store: &std::sync::Arc<dyn crate::secrets::SecretsStore>,
) -> Result<(String, String)> {
    let secret = store
        .get_by_secret_id(&auth.secret_id)
        .await
        .with_context(|| format!("Failed to read OTLP auth secret '{}' from the secrets store", auth.secret_id))?
        .ok_or_else(|| anyhow::anyhow!("OTLP auth secret '{}' was not found in the secrets store", auth.secret_id))?;

    let header_value = auth
        .header_format
        .replace(HEADER_VALUE_PLACEHOLDER, &secret.value);

    Ok((auth.header_name.clone(), header_value))
}

/// Traces configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracesConfig {
    /// Whether trace export is enabled
    pub enabled: bool,

    /// Sampling rate (0.0 to 1.0)
    pub sample_rate: f64,

    /// Target crates to include in traces (filters out other crates)
    #[serde(default = "default_target_crates")]
    pub target_crates: Vec<String>,

    /// Whether to stamp the authenticated caller's identity (auth method,
    /// principal, DID) onto the root HTTP span as `caller.*` attributes.
    /// Off by default — operators opt in, since the principal can carry PII
    /// (mitigated by the redacting span exporter).
    #[serde(default)]
    pub record_caller_identity: bool,
}

impl Default for TracesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: default_sample_rate(),
            target_crates: default_target_crates(),
            record_caller_identity: false,
        }
    }
}

#[allow(dead_code)]
fn default_sample_rate() -> f64 {
    1.0
}

#[allow(dead_code)]
fn default_target_crates() -> Vec<String> {
    vec!["agent_gateway".to_string()]
}

/// Metrics export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsExportConfig {
    /// Whether metrics export is enabled
    #[allow(dead_code)]
    pub enabled: bool,

    /// Export interval in seconds
    pub export_interval_seconds: u64,

    /// Maximum queue size before forced flush
    #[allow(dead_code)]
    pub batch_max_queue_size: Option<usize>,

    /// Delay in milliseconds between scheduled exports
    #[allow(dead_code)]
    pub batch_scheduled_delay_ms: Option<u64>,

    /// Maximum batch export size
    #[allow(dead_code)]
    pub batch_max_export_size: Option<usize>,
}

/// Logs configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsConfig {
    /// Whether log export is enabled
    pub enabled: bool,
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// CloudWatch configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudWatchMetricDimensionConfig {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudWatchMetricConfig {
    /// Whether CloudWatch is enabled
    pub enabled: bool,

    /// AWS region
    pub region: Option<String>,

    /// CloudWatch namespace
    pub namespace: String,

    /// Optional dimensions for CloudWatch metrics (list of key-value pairs)
    pub dimensions: Option<Vec<CloudWatchMetricDimensionConfig>>,
}

impl Default for CloudWatchMetricConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            namespace: default_cloudwatch_namespace(),
            region: None,
            dimensions: None,
        }
    }
}

fn default_cloudwatch_namespace() -> String {
    "Fabric/AgentGateway".to_string()
}

/// Retention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Local log retention in hours
    #[serde(default = "default_local_logs_hours")]
    pub local_logs_hours: u64,

    /// Collector log size in MB
    #[serde(default = "default_collector_log_mb")]
    pub collector_log_mb: u64,

    /// Number of collector log backups
    #[serde(default = "default_collector_log_backups")]
    pub collector_log_backups: u32,

    /// Trace retention in days
    #[serde(default = "default_trace_retention_days")]
    pub trace_retention_days: u32,

    /// Metrics retention in days
    #[serde(default = "default_metrics_retention_days")]
    pub metrics_retention_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            local_logs_hours: default_local_logs_hours(),
            collector_log_mb: default_collector_log_mb(),
            collector_log_backups: default_collector_log_backups(),
            trace_retention_days: default_trace_retention_days(),
            metrics_retention_days: default_metrics_retention_days(),
        }
    }
}

/// Advanced configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// Batch queue size
    #[serde(default = "default_batch_queue_size")]
    pub batch_queue_size: usize,

    /// Batch delay in milliseconds
    #[serde(default = "default_batch_delay_ms")]
    pub batch_delay_ms: u64,

    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Export timeout in seconds
    #[serde(default = "default_export_timeout_sec")]
    pub export_timeout_sec: u64,

    /// Host metrics configuration
    #[serde(default)]
    pub host_metrics: HostMetricsConfig,
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            batch_queue_size: default_batch_queue_size(),
            batch_delay_ms: default_batch_delay_ms(),
            batch_size: default_batch_size(),
            export_timeout_sec: default_export_timeout_sec(),
            host_metrics: HostMetricsConfig::default(),
        }
    }
}

/// Host metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMetricsConfig {
    /// Whether host metrics are enabled
    #[serde(default)]
    pub enabled: bool,

    /// Collection interval in seconds
    #[serde(default = "default_collection_interval")]
    pub collection_interval_seconds: u64,

    /// Collectors configuration
    #[serde(default)]
    pub collectors: CollectorsConfig,
}

impl Default for HostMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            collection_interval_seconds: default_collection_interval(),
            collectors: CollectorsConfig::default(),
        }
    }
}

/// Collectors configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorsConfig {
    #[serde(default = "default_true")]
    pub cpu: bool,
    #[serde(default = "default_true")]
    pub memory: bool,
    #[serde(default = "default_true")]
    pub disk: bool,
    #[serde(default = "default_true")]
    pub network: bool,
    #[serde(default = "default_true")]
    pub load: bool,
    #[serde(default = "default_true")]
    pub processes: bool,
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            cpu: true,
            memory: true,
            disk: true,
            network: true,
            load: true,
            processes: true,
        }
    }
}

// Default value functions
fn default_local_logs_hours() -> u64 {
    24
}
fn default_collector_log_mb() -> u64 {
    50
}
fn default_collector_log_backups() -> u32 {
    2
}
fn default_trace_retention_days() -> u32 {
    14
}
fn default_metrics_retention_days() -> u32 {
    30
}
fn default_batch_queue_size() -> usize {
    2048
}
fn default_batch_delay_ms() -> u64 {
    5000
}
fn default_batch_size() -> usize {
    512
}
fn default_export_timeout_sec() -> u64 {
    10
}
fn default_collection_interval() -> u64 {
    10
}
fn default_true() -> bool {
    true
}

/// Load metrics configuration from file
pub fn load_metrics_config<P: AsRef<Path>>(path: P) -> Result<MetricsConfig> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read metrics config from {}", path.display()))?;

    let config: MetricsConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse metrics config from {}", path.display()))?;

    Ok(config)
}

/// Convert MetricsConfig to OtelConfig for compatibility
impl From<&OpenTelemetryConfig> for crate::observability::OtelConfig {
    fn from(config: &OpenTelemetryConfig) -> Self {
        Self {
            enabled: config.enabled,
            otlp_endpoint: config.endpoint.clone(),
            protocol: config.protocol,
            auth_header: None,
            service_name: config.service_name.clone(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: config.environment.clone(),
            sample_rate: config.traces.sample_rate,
            export_interval_seconds: config
                .metrics
                .export_interval_seconds,
            export_timeout_seconds: 10, // Use default for now
            batch_max_queue_size: 2048,
            batch_scheduled_delay_ms: 5000,
            batch_max_export_size: 512,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_metrics_config() {
        let json = r#"{
            "opentelemetry": {
                "enabled": true,
                "endpoint": "http://localhost:4317",
                "service_name": "test-service",
                "environment": "test",
                "traces": {
                    "enabled": true,
                    "sample_rate": 1.0
                },
                "metrics": {
                    "enabled": true,
                    "export_interval_seconds": 60
                },
                "logs": {
                    "enabled": true
                }
            },
            "cloudwatch": {
                "enabled": false,
                "region": "us-east-1",
                "namespace": "Test"
            }
        }"#;

        let config: MetricsConfig = serde_json::from_str(json).unwrap();
        assert!(config.opentelemetry.enabled);
        assert_eq!(
            config
                .opentelemetry
                .service_name,
            "test-service"
        );
    }

    #[test]
    fn protocol_defaults_to_grpc_and_auth_is_optional() {
        let json = r#"{
            "opentelemetry": {
                "enabled": true,
                "endpoint": "http://localhost:4317",
                "service_name": "svc",
                "environment": "test",
                "traces": { "enabled": true, "sample_rate": 1.0 },
                "metrics": { "enabled": true, "export_interval_seconds": 60 },
                "logs": { "enabled": true }
            },
            "cloudwatch": { "enabled": false, "region": "us-east-1", "namespace": "Test" }
        }"#;

        let config: MetricsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.opentelemetry.protocol, OtlpProtocol::Grpc);
        assert!(
            config
                .opentelemetry
                .auth
                .is_none()
        );
    }

    #[test]
    fn parses_http_protocol_and_auth_block() {
        let json = r#"{
            "opentelemetry": {
                "enabled": true,
                "endpoint": "http://collector:4318",
                "protocol": "http",
                "auth": {
                    "header_name": "Authorization",
                    "secret_id": "otel-token",
                    "header_format": "Bearer {value}"
                },
                "service_name": "svc",
                "environment": "test",
                "traces": { "enabled": true, "sample_rate": 1.0 },
                "metrics": { "enabled": true, "export_interval_seconds": 60 },
                "logs": { "enabled": true }
            },
            "cloudwatch": { "enabled": false, "region": "us-east-1", "namespace": "Test" }
        }"#;

        let config: MetricsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.opentelemetry.protocol, OtlpProtocol::Http);
        let auth = config
            .opentelemetry
            .auth
            .expect("auth block should parse");
        assert_eq!(auth.header_name, "Authorization");
        assert_eq!(auth.secret_id, "otel-token");
        assert_eq!(auth.header_format, "Bearer {value}");
    }

    #[test]
    fn header_format_defaults_to_bare_value() {
        let json = r#"{
            "header_name": "X-Api-Key",
            "secret_id": "k"
        }"#;
        let auth: OtlpAuthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(auth.header_format, "{value}");
    }

    #[tokio::test]
    async fn resolve_otel_auth_header_interpolates_stored_secret() {
        let store: std::sync::Arc<dyn crate::secrets::SecretsStore> = std::sync::Arc::new(StubSecretsStore {
            secret_id: "otel-token".to_string(),
            value: "s3cr3t".to_string(),
        });
        let auth = OtlpAuthConfig {
            header_name: "Authorization".to_string(),
            secret_id: "otel-token".to_string(),
            header_format: "Bearer {value}".to_string(),
        };

        let (name, value) = resolve_otel_auth_header(&auth, &store)
            .await
            .expect("resolution should succeed");
        assert_eq!(name, "Authorization");
        assert_eq!(value, "Bearer s3cr3t");
    }

    #[tokio::test]
    async fn resolve_otel_auth_header_errors_when_secret_missing() {
        let store: std::sync::Arc<dyn crate::secrets::SecretsStore> = std::sync::Arc::new(StubSecretsStore {
            secret_id: "present".to_string(),
            value: "v".to_string(),
        });
        let auth = OtlpAuthConfig {
            header_name: "Authorization".to_string(),
            secret_id: "absent".to_string(),
            header_format: "{value}".to_string(),
        };

        let result = resolve_otel_auth_header(&auth, &store).await;
        assert!(result.is_err(), "missing secret should be a hard error");
    }

    /// Minimal secrets store that only answers `get_by_secret_id` for one entry.
    struct StubSecretsStore {
        secret_id: String,
        value: String,
    }

    #[async_trait::async_trait]
    impl crate::secrets::SecretsStore for StubSecretsStore {
        async fn create(
            &self,
            _request: crate::secrets::CreateSecretRequest,
        ) -> Result<crate::secrets::Secret> {
            unimplemented!()
        }

        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<crate::secrets::Secret>> {
            unimplemented!()
        }

        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> Result<Option<crate::secrets::Secret>> {
            if secret_id != self.secret_id {
                return Ok(None);
            }
            let now = chrono::Utc::now();
            Ok(Some(crate::secrets::Secret {
                id: "id".to_string(),
                tenant_id: None,
                name: "name".to_string(),
                secret_id: self.secret_id.clone(),
                description: None,
                value: self.value.clone(),
                secret_type: "General".to_string(),
                tags: vec![],
                created_at: now,
                updated_at: now,
            }))
        }

        async fn list_all(&self) -> Result<Vec<crate::secrets::SecretListItem>> {
            unimplemented!()
        }

        async fn update(
            &self,
            _id: &str,
            _request: crate::secrets::UpdateSecretRequest,
        ) -> Result<crate::secrets::Secret> {
            unimplemented!()
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            unimplemented!()
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<crate::secrets::SecretListItem>> {
            unimplemented!()
        }
    }
}
