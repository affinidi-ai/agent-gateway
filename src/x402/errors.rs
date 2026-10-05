//! x402 errors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine;
use serde_json::json;

/// Create a 402 Payment Required response
///
/// # Arguments
/// * `payment_required` - Payment requirements to send to client
/// * `payment_required_header` - Name of the payment-required header from x402.json config
pub fn create_402_response(
    payment_required: super::PaymentRequired,
    payment_required_header: &str,
) -> Response {
    let json = match serde_json::to_string(&payment_required) {
        Ok(j) => j,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize payment requirements: {}", e))
                .into_response();
        }
    };

    let encoded = base64::engine::general_purpose::STANDARD.encode(&json);

    // Per x402 spec: include PaymentRequired JSON in both the payment_required_header (base64)
    // and the response body (plain JSON) for client compatibility
    (
        StatusCode::PAYMENT_REQUIRED,
        [(payment_required_header, encoded.as_str()), ("Content-Type", "application/json")],
        json,
    )
        .into_response()
}

/// Create a 400 Bad Request response for invalid payment
pub fn create_invalid_payment_response(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        json!({
            "error": "invalid_payment",
            "message": message
        })
        .to_string(),
    )
        .into_response()
}
