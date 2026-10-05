use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthCheckResponse {
    status: String,
}

#[derive(Debug, Serialize)]
pub struct AliveCheckResponse {
    status: String,
}

/// Health check endpoint
///
/// GET /api/v1/health
///
/// Response:
/// ```json
/// {
///   "status": "OK"
/// }
/// ```
pub async fn health_check() -> impl IntoResponse {
    if crate::server::mode::is_ready_to_serve() {
        (StatusCode::OK, Json(HealthCheckResponse { status: "OK".to_string() })).into_response()
    } else {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

pub async fn alive_check() -> Json<AliveCheckResponse> {
    Json(AliveCheckResponse { status: "OK".to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::mode::{self, ServerMode};

    #[tokio::test]
    async fn health_check_reports_503_in_standby_and_200_in_active() {
        let _guard = mode::TEST_GUARD.lock().await;
        let previous = mode::is_standby();

        mode::set_server_mode(ServerMode::Standby);
        assert_eq!(status_now().await, StatusCode::SERVICE_UNAVAILABLE);

        // Active but mid-activation (re-derive not yet complete) must still report 503.
        mode::set_server_mode(ServerMode::Active);
        assert_eq!(status_now().await, StatusCode::SERVICE_UNAVAILABLE);

        // Only once activation is marked ready does health report 200.
        mode::mark_activation_ready(mode::current_activation_generation());
        assert_eq!(status_now().await, StatusCode::OK);

        mode::set_server_mode(if previous {
            ServerMode::Standby
        } else {
            ServerMode::Active
        });
        if !previous {
            mode::mark_activation_ready(mode::current_activation_generation());
        }
    }

    async fn status_now() -> StatusCode {
        health_check()
            .await
            .into_response()
            .status()
    }
}
