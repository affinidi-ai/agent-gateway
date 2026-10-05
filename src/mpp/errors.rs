//! MPP error responses and 402 generation
//!
//! Builds HTTP 402 responses following the MPP protocol:
//! - WWW-Authenticate: Payment headers for each payment option
//! - RFC 9457 Problem Details JSON body
//! - Cache-Control: no-store

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::challenge::{format_www_authenticate, generate_challenges};
use super::types::{MppConfig, MppProblemDetails};

/// Create a 402 Payment Required response with MPP WWW-Authenticate challenges.
///
/// Per the spec:
/// - Each payment method gets its own `WWW-Authenticate: Payment` header
/// - Body is RFC 9457 Problem Details JSON
/// - Must include `Cache-Control: no-store`
pub fn create_mpp_402_response(
    config: &MppConfig,
    resource_url: &str,
) -> Response {
    let challenges = match generate_challenges(config, resource_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("[mpp] Failed to generate challenges: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate payment challenges: {}", e))
                .into_response();
        }
    };

    if challenges.is_empty() {
        tracing::error!("[mpp] No payment methods configured");
        return (StatusCode::INTERNAL_SERVER_ERROR, "No payment methods configured").into_response();
    }

    // Build the problem details body
    let first_challenge_id = challenges[0].id.clone();
    let problem = MppProblemDetails {
        problem_type: "https://paymentauth.org/problems/payment-required".to_string(),
        title: "Payment Required".to_string(),
        status: 402,
        detail: "Payment is required.".to_string(),
        challenge_id: Some(first_challenge_id),
    };

    let body = match serde_json::to_string(&problem) {
        Ok(j) => j,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize problem details: {}", e))
                .into_response();
        }
    };

    // Build response with multiple WWW-Authenticate headers
    let mut response = Response::builder()
        .status(StatusCode::PAYMENT_REQUIRED)
        .header("Content-Type", "application/problem+json")
        .header("Cache-Control", "no-store");

    for challenge in &challenges {
        let header_value = format_www_authenticate(challenge);
        response = response.header("WWW-Authenticate", header_value);
    }

    response
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build response: {}", e)).into_response()
        })
}

/// Create a 402 response for a verification failure (fresh challenge + error).
///
/// Per the spec, verification failures return 402 with a fresh challenge and
/// appropriate problem type.
pub fn create_mpp_verification_failed_response(
    config: &MppConfig,
    resource_url: &str,
    detail: &str,
) -> Response {
    let challenges = generate_challenges(config, resource_url).unwrap_or_default();

    let problem = MppProblemDetails {
        problem_type: "https://paymentauth.org/problems/verification-failed".to_string(),
        title: "Payment Verification Failed".to_string(),
        status: 402,
        detail: detail.to_string(),
        challenge_id: challenges
            .first()
            .map(|c| c.id.clone()),
    };

    let body = serde_json::to_string(&problem).unwrap_or_else(|_| {
        json!({"type": "https://paymentauth.org/problems/verification-failed", "status": 402}).to_string()
    });

    let mut response = Response::builder()
        .status(StatusCode::PAYMENT_REQUIRED)
        .header("Content-Type", "application/problem+json")
        .header("Cache-Control", "no-store");

    for challenge in &challenges {
        let header_value = format_www_authenticate(challenge);
        response = response.header("WWW-Authenticate", header_value);
    }

    response
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build response: {}", e)).into_response()
        })
}

/// Create a 500 response for a secret-resolution failure (e.g. a `$SECRET:`
/// reference that can't be resolved). The detail is intentionally omitted
/// from the response body — it may name a secret id — and is expected to
/// have already been logged server-side by the caller.
pub fn secret_resolution_error_response() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "Payment configuration error").into_response()
}

/// Add MPP WWW-Authenticate challenge headers to an existing 402 response.
///
/// Used to create combined x402+MPP 402 responses when both payment protocols
/// are enabled. The x402 body and headers are preserved; MPP challenge headers
/// are appended so clients can choose either protocol.
pub fn add_mpp_challenges_to_response(
    response: Response,
    config: &MppConfig,
    resource_url: &str,
) -> Response {
    let challenges = match generate_challenges(config, resource_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[mpp] Failed to generate combined challenges: {}", e);
            return response;
        }
    };

    if challenges.is_empty() {
        return response;
    }

    let (mut parts, body) = response.into_parts();

    for challenge in &challenges {
        let header_value = format_www_authenticate(challenge);
        if let Ok(hv) = axum::http::HeaderValue::from_str(&header_value) {
            parts
                .headers
                .append("WWW-Authenticate", hv);
        }
    }

    // Ensure Cache-Control: no-store is present (MPP requirement)
    if !parts
        .headers
        .contains_key("Cache-Control")
        && let Ok(hv) = axum::http::HeaderValue::from_str("no-store")
    {
        parts
            .headers
            .insert("Cache-Control", hv);
    }

    Response::from_parts(parts, body)
}

/// Resolve `config`'s `$SECRET:` references, then add MPP WWW-Authenticate
/// challenge headers to an existing 402 response.
///
/// Every combined x402+MPP challenge path must go through this instead of
/// `add_mpp_challenges_to_response` directly: that function signs each
/// challenge's HMAC with `config.secret_key` as given, so an unresolved
/// `$SECRET:<id>` reference is misread as a literal (or `$ENV_VAR`) value and
/// produces a challenge signed with an empty/wrong key that verification can
/// never accept.
pub async fn add_mpp_challenges_to_response_resolved(
    response: Response,
    config: &MppConfig,
    resource_url: &str,
    secrets_store: &Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
) -> Response {
    match super::secrets::resolve_config_secrets(config, secrets_store).await {
        Ok(resolved) => add_mpp_challenges_to_response(response, &resolved, resource_url),
        Err(e) => {
            tracing::error!("[mpp] Failed to resolve config secrets for combined challenge: {}", e);
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{MppPaymentMethod, MppVerificationMode};
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;

    fn test_config() -> MppConfig {
        MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"test-secret-32-bytes-long!!!!!!!",
            ),
            stripe_secret_key: None,
            payment_methods: vec![MppPaymentMethod {
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "0xrecipient".to_string(),
                amount: "1.00".to_string(),
                network: None,
            }],
            challenge_ttl_seconds: 300,
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            verification_timeout_ms: 10000,
            crypto_verification_mode: MppVerificationMode::default(),
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
        }
    }

    #[tokio::test]
    async fn test_create_mpp_402_response() {
        let config = test_config();
        let response = create_mpp_402_response(&config, "/api/resource");

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

        // Check WWW-Authenticate header is present
        let www_auth = response
            .headers()
            .get("WWW-Authenticate");
        assert!(www_auth.is_some(), "Missing WWW-Authenticate header");
        let www_auth_str = www_auth
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth_str.starts_with("Payment id=\""), "Should start with Payment scheme");
        assert!(www_auth_str.contains("realm=\"test.example.com\""));
        assert!(www_auth_str.contains("method=\"tempo\""));
        assert!(www_auth_str.contains("intent=\"charge\""));

        // Check Cache-Control
        let cache_control = response
            .headers()
            .get("Cache-Control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "no-store");

        // Check Content-Type
        let content_type = response
            .headers()
            .get("Content-Type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, "application/problem+json");

        // Check body is valid Problem Details JSON
        let body_bytes = Body::new(response.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let body: MppProblemDetails = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.status, 402);
        assert_eq!(body.problem_type, "https://paymentauth.org/problems/payment-required");
        assert!(body.challenge_id.is_some());
    }

    #[tokio::test]
    async fn test_create_mpp_verification_failed_response() {
        let config = test_config();
        let response = create_mpp_verification_failed_response(&config, "/api/resource", "Invalid payment proof");

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

        let body_bytes = Body::new(response.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let body: MppProblemDetails = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.problem_type, "https://paymentauth.org/problems/verification-failed");
        assert_eq!(body.detail, "Invalid payment proof");
    }

    #[tokio::test]
    async fn test_add_mpp_challenges_to_x402_response() {
        let config = test_config();

        // Simulate an x402 402 response (JSON body + custom header)
        let x402_body = r#"{"x402Version":2,"accepts":[],"resource":{"url":"/test"}}"#;
        let x402_response = axum::response::Response::builder()
            .status(StatusCode::PAYMENT_REQUIRED)
            .header("PAYMENT-REQUIRED", "base64encodedpayload")
            .header("Content-Type", "application/json")
            .body(Body::from(x402_body))
            .unwrap();

        let combined = add_mpp_challenges_to_response(x402_response, &config, "/test");

        // Status should be 402
        assert_eq!(combined.status(), StatusCode::PAYMENT_REQUIRED);

        // x402 header should be preserved
        assert!(
            combined
                .headers()
                .get("PAYMENT-REQUIRED")
                .is_some(),
            "x402 PAYMENT-REQUIRED header should be preserved"
        );

        // MPP WWW-Authenticate header should be added
        let www_auth = combined
            .headers()
            .get("WWW-Authenticate");
        assert!(www_auth.is_some(), "MPP WWW-Authenticate header should be added");
        let www_auth_str = www_auth
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth_str.starts_with("Payment id=\""), "Should have Payment auth scheme");
        assert!(www_auth_str.contains("realm=\"test.example.com\""));

        // Cache-Control: no-store should be added
        let cache = combined
            .headers()
            .get("Cache-Control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache, "no-store");

        // x402 body should be preserved
        let body_bytes = Body::new(combined.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("x402Version"), "x402 JSON body should be preserved");
    }

    #[tokio::test]
    async fn test_add_mpp_challenges_preserves_existing_cache_control() {
        let config = test_config();

        // Response already has Cache-Control
        let response = axum::response::Response::builder()
            .status(StatusCode::PAYMENT_REQUIRED)
            .header("Cache-Control", "max-age=0")
            .body(Body::from("test"))
            .unwrap();

        let combined = add_mpp_challenges_to_response(response, &config, "/test");

        // Existing Cache-Control should be preserved (not overwritten)
        let cache = combined
            .headers()
            .get("Cache-Control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache, "max-age=0", "Existing Cache-Control should be preserved");
    }
}
