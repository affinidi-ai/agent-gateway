//! Handlers for metrics configuration management via API

use axum::{
    Json,
    extract::State,
    http::{HeaderName, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{debug, error, info, warn};

use crate::config::metrics_config::MetricsConfig;
use crate::identity::state::IdentityApiState;

/// Application error type for metrics config handlers
#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    InternalError(String),
    #[allow(dead_code)]
    PermissionDenied(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
            AppError::PermissionDenied(msg) => {
                warn!("API Permission Denied: {}", msg);
                (StatusCode::FORBIDDEN, "Permission Denied", Some(msg.clone()))
            }
        };

        let body = Json(ErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Get current metrics configuration
pub async fn get_metrics_config(State(state): State<IdentityApiState>) -> Result<Json<MetricsConfig>, AppError> {
    info!("Fetching metrics configuration");

    let config_path = &state
        .bootstrap_config
        .config_files
        .metrics;

    // Read the metrics.json file
    let config_str = fs::read_to_string(config_path)
        .map_err(|e| AppError::InternalError(format!("Failed to read metrics config: {}", e)))?;

    // Parse it
    let config: MetricsConfig = serde_json::from_str(&config_str)
        .map_err(|e| AppError::InternalError(format!("Failed to parse metrics config: {}", e)))?;

    debug!("Successfully loaded metrics configuration from {}", config_path);
    Ok(Json(config))
}

/// Update metrics configuration
pub async fn update_metrics_config(
    State(state): State<IdentityApiState>,
    Json(new_config): Json<MetricsConfig>,
) -> Result<Json<UpdateResponse>, AppError> {
    info!("Updating metrics configuration");

    // Validate the configuration
    validate_metrics_config(&new_config)?;

    let config_path = &state
        .bootstrap_config
        .config_files
        .metrics;

    // Serialize with pretty printing
    let config_json = serde_json::to_string_pretty(&new_config)
        .map_err(|e| AppError::InternalError(format!("Failed to serialize metrics config: {}", e)))?;

    // Write to file
    fs::write(config_path, config_json)
        .map_err(|e| AppError::InternalError(format!("Failed to write metrics config: {}", e)))?;

    info!("Successfully updated metrics configuration at {}", config_path);

    // Apply the new OpenTelemetry configuration to the running process without a
    // restart. A live-apply failure is not fatal — the config is already saved
    // and a restart will pick it up — so we surface it in the response message.
    match apply_otel_reload(&state, &new_config).await {
        Ok(()) => Ok(Json(UpdateResponse {
            success: true,
            message: "Metrics configuration updated and applied.".to_string(),
        })),
        Err(e) => {
            warn!("Metrics config saved but live OpenTelemetry apply failed: {}", e);
            Ok(Json(UpdateResponse {
                success: true,
                message: format!(
                    "Metrics configuration saved, but applying it live failed: {e}. A gateway restart will apply it."
                ),
            }))
        }
    }
}

/// Rebuild and swap the live OpenTelemetry pipeline from the saved config,
/// re-resolving the optional collector auth secret so a rotated secret takes
/// effect too.
async fn apply_otel_reload(
    state: &IdentityApiState,
    config: &MetricsConfig,
) -> anyhow::Result<()> {
    let auth_header = match config
        .opentelemetry
        .auth
        .as_ref()
    {
        Some(auth) if config.opentelemetry.enabled => {
            let backend = match state
                .bootstrap_config
                .secrets_backend
                .as_str()
            {
                "aws" => crate::secrets::SecretsBackend::Aws,
                _ => crate::secrets::SecretsBackend::Filesystem,
            };
            let store = crate::secrets::create_secrets_store(
                backend,
                Some(
                    state
                        .bootstrap_config
                        .storage_paths
                        .secrets
                        .clone(),
                ),
            )
            .await?;
            Some(crate::config::metrics_config::resolve_otel_auth_header(auth, &store).await?)
        }
        _ => None,
    };

    crate::observability::reload_otel(&config.opentelemetry, auth_header).await
}

/// Response for update operation
#[derive(Debug, Serialize)]
pub struct UpdateResponse {
    pub success: bool,
    pub message: String,
}

/// Validate metrics configuration before saving
fn validate_metrics_config(config: &MetricsConfig) -> Result<(), AppError> {
    // Validate OpenTelemetry config
    if config.opentelemetry.enabled {
        if config
            .opentelemetry
            .endpoint
            .is_empty()
        {
            return Err(AppError::BadRequest("OpenTelemetry endpoint cannot be empty when enabled".to_string()));
        }

        // Basic URL validation for gRPC endpoint
        if !config
            .opentelemetry
            .endpoint
            .starts_with("http://")
            && !config
                .opentelemetry
                .endpoint
                .starts_with("https://")
        {
            return Err(AppError::BadRequest("OpenTelemetry endpoint must start with http:// or https://".to_string()));
        }

        // Validate service name
        if config
            .opentelemetry
            .service_name
            .is_empty()
        {
            return Err(AppError::BadRequest("Service name cannot be empty when OpenTelemetry is enabled".to_string()));
        }

        // Validate sampling rate
        if config
            .opentelemetry
            .traces
            .sample_rate
            < 0.0
            || config
                .opentelemetry
                .traces
                .sample_rate
                > 1.0
        {
            return Err(AppError::BadRequest("Trace sample rate must be between 0.0 and 1.0".to_string()));
        }

        // Validate export interval
        if config
            .opentelemetry
            .metrics
            .export_interval_seconds
            == 0
        {
            return Err(AppError::BadRequest("Metrics export interval must be greater than 0".to_string()));
        }

        // Validate collector authentication, if configured
        if let Some(auth) = config
            .opentelemetry
            .auth
            .as_ref()
        {
            validate_otel_auth(auth)?;
        }
    }

    // Validate CloudWatch config
    if config.cloudwatch.enabled {
        if config
            .cloudwatch
            .region
            .clone()
            .unwrap_or("".to_string())
            .is_empty()
        {
            return Err(AppError::BadRequest("CloudWatch region cannot be empty when enabled".to_string()));
        }

        if config
            .cloudwatch
            .namespace
            .is_empty()
        {
            return Err(AppError::BadRequest("CloudWatch namespace cannot be empty when enabled".to_string()));
        }
    }

    // Validate retention config
    if config
        .retention
        .local_logs_hours
        == 0
    {
        return Err(AppError::BadRequest("Local logs retention hours must be greater than 0".to_string()));
    }

    if config
        .retention
        .collector_log_mb
        == 0
    {
        return Err(AppError::BadRequest("Collector log size must be greater than 0 MB".to_string()));
    }

    // Validate advanced config
    if config.advanced.batch_size == 0 {
        return Err(AppError::BadRequest("Batch size must be greater than 0".to_string()));
    }

    if config.advanced.batch_delay_ms == 0 {
        return Err(AppError::BadRequest("Batch delay must be greater than 0 ms".to_string()));
    }

    if config
        .advanced
        .batch_queue_size
        == 0
    {
        return Err(AppError::BadRequest("Batch queue size must be greater than 0".to_string()));
    }

    Ok(())
}

/// Validate the optional OTLP collector authentication block.
fn validate_otel_auth(auth: &crate::config::metrics_config::OtlpAuthConfig) -> Result<(), AppError> {
    if auth
        .header_name
        .trim()
        .is_empty()
    {
        return Err(AppError::BadRequest("OpenTelemetry auth header name cannot be empty".to_string()));
    }

    // Reject header names that are not valid HTTP header tokens (e.g. containing
    // spaces or control characters). Both the OTLP/HTTP header builder and the
    // OTLP/gRPC metadata key builder parse this at exporter construction time,
    // so an invalid name would otherwise be persisted and only fail at restart.
    if HeaderName::from_bytes(auth.header_name.as_bytes()).is_err() {
        return Err(AppError::BadRequest(format!(
            "OpenTelemetry auth header name '{}' is not a valid header name (use letters, digits, and -._ only, no spaces)",
            auth.header_name
        )));
    }

    if auth
        .secret_id
        .trim()
        .is_empty()
    {
        return Err(AppError::BadRequest("OpenTelemetry auth secret reference cannot be empty".to_string()));
    }

    if !auth
        .header_format
        .contains("{value}")
    {
        return Err(AppError::BadRequest(
            "OpenTelemetry auth header format must contain the {value} placeholder".to_string(),
        ));
    }

    Ok(())
}

/// Test OpenTelemetry connection
#[derive(Debug, Deserialize)]
pub struct TestConnectionRequest {
    pub endpoint: String,
}

#[derive(Debug, Serialize)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

pub async fn test_otlp_connection(
    Json(request): Json<TestConnectionRequest>
) -> Result<Json<TestConnectionResponse>, AppError> {
    // SSRF guard shared with other caller-supplied endpoints: rejects cloud
    // metadata, loopback and unspecified hosts, non-http(s) schemes and embedded
    // credentials, statically and after DNS resolution. Nothing is dialled on
    // rejection.
    let endpoint_url = crate::url_validation::validate_resolved_url(&request.endpoint)
        .map_err(|e| AppError::BadRequest(format!("OTLP endpoint rejected: {e}")))?;

    info!("Testing OTLP connection to {}", endpoint_url);

    // Determine the host and port
    let host = endpoint_url
        .host_str()
        .unwrap_or("unknown");
    let port = endpoint_url
        .port()
        .unwrap_or(if endpoint_url.scheme() == "https" {
            443
        } else {
            4317
        });

    // Test TCP connection to the endpoint
    let start = std::time::Instant::now();
    let addr = format!("{}:{}", host, port);

    match tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            let latency = start.elapsed().as_millis() as u64;
            info!("Successfully connected to OTLP endpoint {} ({}ms)", request.endpoint, latency);
            Ok(Json(TestConnectionResponse {
                success: true,
                message: format!(
                    "Successfully connected to {} ({}ms). Note: This only tests TCP connectivity, not gRPC protocol compatibility.",
                    addr, latency
                ),
                latency_ms: Some(latency),
            }))
        }
        Ok(Err(e)) => {
            warn!("Failed to connect to OTLP endpoint {}: {}", request.endpoint, e);
            Ok(Json(TestConnectionResponse {
                success: false,
                message: format!(
                    "Connection failed: {}. Ensure the OpenTelemetry Collector is running and accessible.",
                    e
                ),
                latency_ms: None,
            }))
        }
        Err(_) => {
            warn!("Timeout connecting to OTLP endpoint {}", request.endpoint);
            Ok(Json(TestConnectionResponse {
                success: false,
                message: "Connection timeout after 5 seconds. Ensure the endpoint is correct and accessible."
                    .to_string(),
                latency_ms: None,
            }))
        }
    }
}

/// OTLP export health, surfaced to the dashboard OpenTelemetry tab.
#[derive(Debug, Serialize)]
pub struct OtlpStatusResponse {
    /// Whether OpenTelemetry export is enabled in `metrics.json`.
    pub enabled: bool,
    /// Configured transport protocol (`grpc` | `http`).
    pub protocol: String,
    /// Configured base OTLP endpoint.
    pub endpoint: String,
    /// Per-signal export health (traces, metrics, logs).
    pub signals: Vec<crate::observability::otlp_health::OtlpSignalStatus>,
}

/// Report the live OTLP export health (per-signal backoff / failure state).
///
/// Read-only and best-effort: if `metrics.json` cannot be read the endpoint
/// still returns the runtime health snapshot with `enabled = false`.
pub async fn get_otlp_status(State(state): State<IdentityApiState>) -> Json<OtlpStatusResponse> {
    let config_path = &state
        .bootstrap_config
        .config_files
        .metrics;

    let (enabled, protocol, endpoint) = match fs::read_to_string(config_path)
        .ok()
        .and_then(|s| serde_json::from_str::<MetricsConfig>(&s).ok())
    {
        Some(cfg) => {
            let protocol = match cfg.opentelemetry.protocol {
                crate::config::metrics_config::OtlpProtocol::Grpc => "grpc",
                crate::config::metrics_config::OtlpProtocol::Http => "http",
            };
            (
                cfg.opentelemetry.enabled,
                protocol.to_string(),
                cfg.opentelemetry
                    .endpoint
                    .clone(),
            )
        }
        None => (false, "grpc".to_string(), String::new()),
    };

    Json(OtlpStatusResponse {
        enabled,
        protocol,
        endpoint,
        signals: crate::observability::otlp_health::snapshot(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::metrics_config::OtlpAuthConfig;

    fn valid_auth() -> OtlpAuthConfig {
        OtlpAuthConfig {
            header_name: "Authorization".to_string(),
            secret_id: "otel-token".to_string(),
            header_format: "Bearer {value}".to_string(),
        }
    }

    fn bad_request_message(result: Result<(), AppError>) -> String {
        match result {
            Err(AppError::BadRequest(msg)) => msg,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn accepts_valid_auth() {
        assert!(validate_otel_auth(&valid_auth()).is_ok());
    }

    #[test]
    fn accepts_common_header_names() {
        for name in ["Authorization", "X-Api-Key", "x-custom-token"] {
            let auth = OtlpAuthConfig {
                header_name: name.to_string(),
                ..valid_auth()
            };
            assert!(validate_otel_auth(&auth).is_ok(), "expected '{name}' to be accepted");
        }
    }

    #[test]
    fn rejects_empty_header_name() {
        let auth = OtlpAuthConfig {
            header_name: "   ".to_string(),
            ..valid_auth()
        };
        let msg = bad_request_message(validate_otel_auth(&auth));
        assert!(msg.contains("header name cannot be empty"), "got: {msg}");
    }

    #[test]
    fn rejects_header_name_with_space() {
        let auth = OtlpAuthConfig {
            header_name: "Bad Header".to_string(),
            ..valid_auth()
        };
        let msg = bad_request_message(validate_otel_auth(&auth));
        assert!(msg.contains("is not a valid header name"), "got: {msg}");
    }

    #[test]
    fn rejects_header_name_with_trailing_space() {
        let auth = OtlpAuthConfig {
            header_name: "Authorization ".to_string(),
            ..valid_auth()
        };
        assert!(validate_otel_auth(&auth).is_err());
    }

    #[test]
    fn rejects_header_name_with_control_char() {
        let auth = OtlpAuthConfig {
            header_name: "Auth\north".to_string(),
            ..valid_auth()
        };
        assert!(validate_otel_auth(&auth).is_err());
    }

    #[test]
    fn rejects_empty_secret_id() {
        let auth = OtlpAuthConfig {
            secret_id: "  ".to_string(),
            ..valid_auth()
        };
        let msg = bad_request_message(validate_otel_auth(&auth));
        assert!(msg.contains("secret reference cannot be empty"), "got: {msg}");
    }

    #[test]
    fn rejects_header_format_without_placeholder() {
        let auth = OtlpAuthConfig {
            header_format: "Bearer token".to_string(),
            ..valid_auth()
        };
        let msg = bad_request_message(validate_otel_auth(&auth));
        assert!(msg.contains("{value} placeholder"), "got: {msg}");
    }

    /// Every case here is rejected statically (IP literal, `localhost`, or a
    /// metadata hostname), so no DNS lookup and no connection attempt happens.
    #[tokio::test]
    async fn test_otlp_connection_rejects_loopback_unspecified_and_metadata_endpoints() {
        for endpoint in [
            "http://127.0.0.1:4317",
            "http://localhost:4317",
            "http://[::1]:4317",
            "http://0.0.0.0:4317",
            "http://[::ffff:127.0.0.1]:4317",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ] {
            let result = test_otlp_connection(Json(TestConnectionRequest { endpoint: endpoint.to_string() })).await;
            assert!(
                matches!(result, Err(AppError::BadRequest(_))),
                "expected '{endpoint}' to be rejected before any connection attempt, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_otlp_connection_rejects_bad_schemes_and_embedded_credentials() {
        for endpoint in
            ["ftp://collector.example.com:4317", "http://user:secret@collector.example.com:4317", "not a url"]
        {
            let result = test_otlp_connection(Json(TestConnectionRequest { endpoint: endpoint.to_string() })).await;
            assert!(
                matches!(result, Err(AppError::BadRequest(_))),
                "expected '{endpoint}' to be rejected, got {result:?}"
            );
        }
    }
}
