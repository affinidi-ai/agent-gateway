//! x402 errors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine;
use serde_json::json;

use crate::config::types::{X402Headers, X402PaymentRequirement};

/// What a request must pay for the resource at `resource_url`: one of the
/// requirements in `accepts`.
#[derive(Debug, Clone)]
pub struct PaymentChallenge {
    pub resource_url: String,
    pub accepts: Vec<X402PaymentRequirement>,
}

/// Why an x402 payment did not grant the request.
#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("payment required")]
    Required(PaymentChallenge),
    #[error("invalid payment: {0}")]
    Invalid(String),
}

impl PaymentError {
    /// The HTTP answer. A challenge is sent in the surface's configured
    /// payment-required header as well as in the body.
    pub fn render(
        self,
        x402_headers: &X402Headers,
    ) -> Response {
        match self {
            Self::Required(challenge) => challenge.render(&x402_headers.payment_required),
            Self::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_payment",
                    "message": message
                })
                .to_string(),
            )
                .into_response(),
        }
    }
}

impl PaymentChallenge {
    /// A 402 Payment Required carrying the challenge, per the x402 spec, both
    /// base64-encoded in `payment_required_header` and as the JSON body, for
    /// client compatibility.
    pub fn render(
        self,
        payment_required_header: &str,
    ) -> Response {
        let payment_required = super::PaymentRequired {
            x402_version: 2,
            error: Some("Payment required".to_string()),
            resource: super::ResourceInfo {
                url: self.resource_url,
                description: "Access to this resource requires payment".to_string(),
                mime_type: "application/json".to_string(),
            },
            accepts: self.accepts,
            extensions: None,
        };
        let json = match serde_json::to_string(&payment_required) {
            Ok(json) => json,
            Err(error) => {
                tracing::error!(%error, "[x402] Failed to serialize payment requirements");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Payment configuration error").into_response();
            }
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        (
            StatusCode::PAYMENT_REQUIRED,
            [(payment_required_header, encoded.as_str()), ("Content-Type", "application/json")],
            json,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_of(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn requirement() -> X402PaymentRequirement {
        X402PaymentRequirement {
            scheme: "exact".to_string(),
            network: "eip155:1".to_string(),
            amount: "1000".to_string(),
            asset: "0x123".to_string(),
            recipient_id: String::new(),
            pay_to: "0x456".to_string(),
            max_timeout_seconds: 300,
            extra: None,
        }
    }

    #[tokio::test]
    async fn a_challenge_renders_a_402_in_the_configured_header_and_the_body() {
        let headers = X402Headers {
            payment_required: "X-Pay-Me".to_string(),
            ..X402Headers::default()
        };
        let response = PaymentError::Required(PaymentChallenge {
            resource_url: "/api/resource".to_string(),
            accepts: vec![requirement()],
        })
        .render(&headers);

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(response.headers()["content-type"], "application/json");
        let header = response.headers()["x-pay-me"]
            .to_str()
            .unwrap()
            .to_string();
        let body = body_of(response).await;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(header)
                .unwrap(),
            body.as_bytes()
        );
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            body,
            json!({
                "x402Version": 2,
                "error": "Payment required",
                "resource": {
                    "url": "/api/resource",
                    "description": "Access to this resource requires payment",
                    "mimeType": "application/json",
                },
                "accepts": [serde_json::to_value(requirement()).unwrap()],
            })
        );
    }

    #[tokio::test]
    async fn an_invalid_payment_renders_a_400_with_its_message() {
        let response =
            PaymentError::Invalid("Payment settlement failed: boom".to_string()).render(&X402Headers::default());

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body_of(response).await).unwrap(),
            json!({ "error": "invalid_payment", "message": "Payment settlement failed: boom" })
        );
    }
}
