use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

use crate::identity::state::IdentityApiState;

/// Application error type for metrics handlers
#[derive(Debug)]
pub enum AppError {
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
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

/// Truncate old metrics based on retention period
pub async fn truncate_metrics(
    State(state): State<IdentityApiState>
) -> Result<Json<crate::metrics::TruncateMetricsResult>, AppError> {
    let result = state
        .metrics_store
        .truncate_old_metrics()
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to truncate metrics: {}", e)))?;

    info!(
        "Metrics truncated: removed {} connections and {} events, retained {} connections and {} events",
        result.connections_removed, result.events_removed, result.connections_retained, result.events_retained
    );

    Ok(Json(result))
}

/// Verify HTTP Basic Auth credentials against the configured settings.
/// Returns `None` if authentication succeeds (or is not enabled).
/// Returns `Some(response)` with a 401 if authentication fails.
fn check_prometheus_basic_auth(
    settings: &crate::storage::settings_store::DashboardSettings,
    headers: &HeaderMap,
) -> Option<Response> {
    if !settings.prometheus_auth_enabled {
        return None;
    }

    let unauthorized = || {
        (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"metrics\"")], "Unauthorized")
            .into_response()
    };

    let auth_header = match headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => {
            warn!("Prometheus metrics request rejected: missing Authorization header");
            return Some(unauthorized());
        }
    };

    let encoded = match auth_header.strip_prefix("Basic ") {
        Some(e) => e,
        None => {
            warn!("Prometheus metrics request rejected: not Basic auth scheme");
            return Some(unauthorized());
        }
    };

    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => {
            warn!("Prometheus metrics request rejected: invalid Base64");
            return Some(unauthorized());
        }
    };

    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => {
            warn!("Prometheus metrics request rejected: non-UTF-8 credentials");
            return Some(unauthorized());
        }
    };

    let (username, password) = match decoded_str.split_once(':') {
        Some(pair) => pair,
        None => {
            warn!("Prometheus metrics request rejected: malformed credentials (no colon)");
            return Some(unauthorized());
        }
    };

    let user_ok: bool = username
        .as_bytes()
        .ct_eq(
            settings
                .prometheus_auth_username
                .as_bytes(),
        )
        .into();
    if !user_ok {
        warn!("Prometheus metrics request rejected: invalid username");
        return Some(unauthorized());
    }

    match bcrypt::verify(password, &settings.prometheus_auth_password_hash) {
        Ok(true) => None, // Auth succeeded
        Ok(false) => {
            warn!("Prometheus metrics request rejected: invalid password");
            Some(unauthorized())
        }
        Err(e) => {
            warn!("Prometheus metrics request rejected: bcrypt error: {e}");
            Some(unauthorized())
        }
    }
}

/// Prometheus metrics endpoint.
///
/// When Prometheus authentication is enabled in admin settings, this endpoint
/// requires HTTP Basic Authentication. Otherwise it is publicly accessible.
pub async fn prometheus_metrics(
    State(state): State<IdentityApiState>,
    headers: HeaderMap,
) -> Response {
    let settings = state.settings_store.get();
    if let Some(rejection) = check_prometheus_basic_auth(&settings, &headers) {
        return rejection;
    }

    let metrics = crate::metrics::backends::prometheus::get_metrics();
    ([(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")], metrics).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::settings_store::DashboardSettings;
    use axum::http::header;

    fn make_headers(auth: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = auth {
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        }
        headers
    }

    fn encode_basic(
        username: &str,
        password: &str,
    ) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}")))
    }

    fn enabled_settings(
        username: &str,
        password: &str,
    ) -> DashboardSettings {
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();
        DashboardSettings {
            prometheus_auth_enabled: true,
            prometheus_auth_username: username.to_string(),
            prometheus_auth_password_hash: hash,
            ..DashboardSettings::default()
        }
    }

    #[test]
    fn auth_disabled_allows_access() {
        let settings = DashboardSettings::default();
        let headers = make_headers(None);
        assert!(check_prometheus_basic_auth(&settings, &headers).is_none());
    }

    #[test]
    fn correct_credentials_allows_access() {
        let settings = enabled_settings("prom", "s3cret");
        let headers = make_headers(Some(&encode_basic("prom", "s3cret")));
        assert!(check_prometheus_basic_auth(&settings, &headers).is_none());
    }

    #[test]
    fn wrong_password_returns_401() {
        let settings = enabled_settings("prom", "s3cret");
        let headers = make_headers(Some(&encode_basic("prom", "wrong")));
        let resp = check_prometheus_basic_auth(&settings, &headers).unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn wrong_username_returns_401() {
        let settings = enabled_settings("prom", "s3cret");
        let headers = make_headers(Some(&encode_basic("wrong", "s3cret")));
        let resp = check_prometheus_basic_auth(&settings, &headers).unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn missing_header_returns_401() {
        let settings = enabled_settings("prom", "s3cret");
        let headers = make_headers(None);
        let resp = check_prometheus_basic_auth(&settings, &headers).unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn bearer_scheme_returns_401() {
        let settings = enabled_settings("prom", "s3cret");
        let headers = make_headers(Some("Bearer sometoken"));
        let resp = check_prometheus_basic_auth(&settings, &headers).unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn malformed_base64_returns_401() {
        let settings = enabled_settings("prom", "s3cret");
        let headers = make_headers(Some("Basic %%%not-base64%%%"));
        let resp = check_prometheus_basic_auth(&settings, &headers).unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn no_colon_in_decoded_returns_401() {
        let settings = enabled_settings("prom", "s3cret");
        let bad = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("nocolon"));
        let headers = make_headers(Some(&bad));
        let resp = check_prometheus_basic_auth(&settings, &headers).unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
