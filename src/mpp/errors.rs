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
use super::types::{MppChallenge, MppConfig, MppProblemDetails};

/// Why an MPP payment did not grant the request.
#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    /// No credential was presented: pay one of `challenges`.
    #[error("payment required")]
    Required(Vec<MppChallenge>),
    /// The credential failed verification; `challenges` are fresh ones to
    /// retry with.
    #[error("payment verification failed: {detail}")]
    VerificationFailed { detail: String, challenges: Vec<MppChallenge> },
    /// The surface's MPP configuration cannot issue challenges or verify
    /// credentials, e.g. an unresolvable `$SECRET:` reference. The detail,
    /// which may name a secret id, is logged where it happens and never sent.
    #[error("payment configuration error")]
    Configuration,
}

impl PaymentError {
    /// Fresh challenges for `config`'s payment methods, or `Configuration`
    /// when none can be issued.
    pub fn required(
        config: &MppConfig,
        resource_url: &str,
    ) -> Self {
        match generate_challenges(config, resource_url) {
            Ok(challenges) if !challenges.is_empty() => Self::Required(challenges),
            Ok(_) => {
                tracing::error!("[mpp] No payment methods configured");
                Self::Configuration
            }
            Err(error) => {
                tracing::error!("[mpp] Failed to generate challenges: {}", error);
                Self::Configuration
            }
        }
    }

    /// Per the spec, a verification failure carries fresh challenges.
    pub fn verification_failed(
        config: &MppConfig,
        resource_url: &str,
        detail: &str,
    ) -> Self {
        Self::VerificationFailed {
            detail: detail.to_string(),
            challenges: generate_challenges(config, resource_url).unwrap_or_default(),
        }
    }
}

/// A 402 Payment Required per the spec: a `WWW-Authenticate: Payment` header
/// per challenge, an RFC 9457 Problem Details body and `Cache-Control:
/// no-store`.
impl IntoResponse for PaymentError {
    fn into_response(self) -> Response {
        let (problem_type, title, detail, challenges) = match self {
            Self::Required(challenges) => (
                "https://paymentauth.org/problems/payment-required",
                "Payment Required",
                "Payment is required.".to_string(),
                challenges,
            ),
            Self::VerificationFailed { detail, challenges } => (
                "https://paymentauth.org/problems/verification-failed",
                "Payment Verification Failed",
                detail,
                challenges,
            ),
            Self::Configuration => return configuration_error(),
        };
        let problem = MppProblemDetails {
            problem_type: problem_type.to_string(),
            title: title.to_string(),
            status: 402,
            detail,
            challenge_id: challenges
                .first()
                .map(|challenge| challenge.id.clone()),
        };
        let body = serde_json::to_string(&problem)
            .unwrap_or_else(|_| json!({"type": problem_type, "status": 402}).to_string());

        let mut response = Response::builder()
            .status(StatusCode::PAYMENT_REQUIRED)
            .header("Content-Type", "application/problem+json")
            .header("Cache-Control", "no-store");
        for challenge in &challenges {
            response = response.header("WWW-Authenticate", format_www_authenticate(challenge));
        }
        response
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|error| {
                tracing::error!(%error, "[mpp] Failed to build the payment challenge response");
                configuration_error()
            })
    }
}

fn configuration_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "Payment configuration error").into_response()
}

/// The MPP challenges offered next to x402's in a combined 402.
///
/// `config`'s `$SECRET:` references are resolved first: each challenge's HMAC
/// is signed with `config.secret_key` as given, so an unresolved
/// `$SECRET:<id>` would be misread as a literal (or `$ENV_VAR`) value and
/// produce a challenge verification can never accept. None are offered when
/// the secrets cannot be resolved or the challenges generated.
pub async fn combined_challenges(
    config: &MppConfig,
    resource_url: &str,
    secrets_store: &Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
) -> Vec<MppChallenge> {
    let resolved = match super::secrets::resolve_config_secrets(config, secrets_store).await {
        Ok(resolved) => resolved,
        Err(e) => {
            tracing::error!("[mpp] Failed to resolve config secrets for combined challenge: {}", e);
            return Vec::new();
        }
    };
    generate_challenges(&resolved, resource_url).unwrap_or_else(|e| {
        tracing::warn!("[mpp] Failed to generate combined challenges: {}", e);
        Vec::new()
    })
}

/// Add MPP WWW-Authenticate challenge headers to another protocol's 402.
///
/// Used for combined x402+MPP 402 responses when both payment protocols are
/// enabled. The x402 body and headers are preserved; MPP challenge headers
/// are appended so clients can choose either protocol.
pub fn append_challenges(
    response: Response,
    challenges: &[MppChallenge],
) -> Response {
    if challenges.is_empty() {
        return response;
    }

    let (mut parts, body) = response.into_parts();

    for challenge in challenges {
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
    async fn a_payment_required_renders_a_402_with_a_challenge_per_method() {
        let config = test_config();
        let error = PaymentError::required(&config, "/api/resource");
        assert!(matches!(&error, PaymentError::Required(challenges) if challenges.len() == 1), "{error:?}");
        let response = error.into_response();

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
    async fn a_verification_failure_renders_a_402_with_fresh_challenges() {
        let config = test_config();
        let response =
            PaymentError::verification_failed(&config, "/api/resource", "Invalid payment proof").into_response();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(
            response
                .headers()
                .get("WWW-Authenticate")
                .is_some()
        );

        let body_bytes = Body::new(response.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let body: MppProblemDetails = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.problem_type, "https://paymentauth.org/problems/verification-failed");
        assert_eq!(body.detail, "Invalid payment proof");
        assert!(body.challenge_id.is_some());
    }

    #[tokio::test]
    async fn a_configuration_without_payment_methods_answers_a_generic_500() {
        let mut config = test_config();
        config.payment_methods.clear();
        let error = PaymentError::required(&config, "/api/resource");
        assert!(matches!(error, PaymentError::Configuration), "{error:?}");

        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body_bytes = Body::new(response.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body_bytes[..], b"Payment configuration error");
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

        let combined = append_challenges(x402_response, &combined_challenges(&config, "/test", &None).await);

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

        let combined = append_challenges(response, &combined_challenges(&config, "/test", &None).await);

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
