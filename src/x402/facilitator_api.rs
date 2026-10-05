//! Facilitator API for x402 payment verification and settlement
//!
//! This module provides helper functions for external services to verify and settle payments.
//! This is useful for:
//! - Distributed payment verification
//! - Third-party payment processing
//! - Batch settlement services
//! - Multi-gateway coordination
//!
//! ## Usage
//!
//! The facilitator API can be used programmatically:
//!
//! ```rust,ignore
//! use agent_gateway::x402::{verify_payment, PaymentPayload};
//!
//! async fn verify_external_payment(payment: PaymentPayload, config: &X402Config) -> Result<PaymentPayload, String> {
//!     verify_payment(&payment, config, "channel-name", "channel-id").await
//! }
//! ```
//!
//! ## HTTP Endpoints (Optional)
//!
//! To expose facilitator functionality via HTTP, create a separate service that:
//!
//! ### POST /verify
//! ```json
//! {
//!   "payment": { ... },  // PaymentPayload
//!   "channel_id": "abc123"
//! }
//! ```
//!
//! Response:
//! ```json
//! {
//!   "valid": true,
//!   "payment": { ... }
//! }
//! ```
//!
//! ### POST /settle
//! ```json
//! {
//!   "payment": { ... },  // PaymentPayload
//!   "channel_id": "abc123",
//!   "mode": "immediate"
//! }
//! ```
//!
//! Response:
//! ```json
//! {
//!   "success": true,
//!   "tx_hash": "0x...",
//!   "status": "completed"
//! }
//! ```

use super::{PaymentPayload, verify_payment};
use crate::config::types::X402Config;
use serde::{Deserialize, Serialize};

/// Verify payment request structure
#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyRequest {
    /// Base64-encoded payment signature (x402-v2 PaymentPayload)
    pub payment_signature: String,

    /// Channel ID for verification context
    pub surface_id: String,
}

/// Verify payment response structure
#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyResponse {
    /// Whether payment is valid
    pub valid: bool,

    /// Error message if invalid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Verified payment payload (if valid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<PaymentPayload>,
}

/// Settle payment request structure
#[derive(Debug, Deserialize, Serialize)]
pub struct SettleRequest {
    /// Base64-encoded payment signature (x402-v2 PaymentPayload)
    pub payment_signature: String,

    /// Channel ID for settlement context
    pub surface_id: String,

    /// Settlement mode: "immediate" or "deferred"
    #[serde(default = "default_settlement_mode")]
    pub mode: String,
}

fn default_settlement_mode() -> String {
    "immediate".to_string()
}

/// Settle payment response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct SettleResponse {
    /// Whether settlement was successful
    pub success: bool,

    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Transaction hash if settled on-chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Settlement status: "pending", "processing", "completed", "failed"
    pub status: String,
}

/// Programmatic verification function for facilitators
///
/// This can be called from your own HTTP server or service
pub async fn verify_facilitator_payment(
    payment_signature: String,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
) -> VerifyResponse {
    match verify_payment(
        &payment_signature,
        config,
        channel_name,
        channel_id,
        "/.well-known/facilitator-verify", // Facilitator verification endpoint
        None,                              // Facilitator verification doesn't use listener_manager
        None,                              // Facilitator verification doesn't use transaction_store
        None,                              // No existing correlation_id
    )
    .await
    {
        Ok((verified_payload, _correlation_id)) => VerifyResponse {
            valid: true,
            error: None,
            payment: Some(verified_payload),
        },
        Err(e) => VerifyResponse {
            valid: false,
            error: Some(e),
            payment: None,
        },
    }
}

/// Programmatic settlement function for facilitators
///
/// TODO: Implement actual on-chain settlement execution
pub async fn settle_facilitator_payment(
    _payment_signature: String,
    _mode: String,
) -> SettleResponse {
    // TODO: Implement settlement execution
    // This would involve:
    // 1. Calling transferWithAuthorization on-chain for EIP-3009
    // 2. Calling x402Permit2Proxy.settle for Permit2
    // 3. Managing gas and nonce for facilitator wallet
    // 4. Recording settlement in storage backend

    SettleResponse {
        success: false,
        error: Some("Settlement execution not yet implemented".to_string()),
        tx_hash: None,
        status: "not_implemented".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settlement_mode() {
        assert_eq!(default_settlement_mode(), "immediate");
    }

    #[tokio::test]
    async fn test_settle_not_implemented() {
        let response = settle_facilitator_payment("mock_payment_signature".to_string(), "immediate".to_string()).await;
        assert!(!response.success);
        assert_eq!(response.status, "not_implemented");
    }
}

/// HTTP Facilitator routes and handlers
/// These implement the standard x402 specification facilitator endpoints
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use std::sync::Arc;
use tracing::{error, info};

/// State for HTTP facilitator API
#[derive(Clone)]
pub struct HttpFacilitatorState {
    pub channels: Arc<tokio::sync::RwLock<Vec<crate::state::SurfaceInfo>>>,
}

/// Supported payment schemes response
#[derive(Debug, Serialize)]
pub struct SupportedResponse {
    /// Supported payment schemes (e.g., ["exact"])
    pub schemes: Vec<String>,

    /// Supported networks (e.g., ["eip155:1", "eip155:8453"])
    pub networks: Vec<String>,

    /// Facilitator signer addresses per network
    /// Map of network (CAIP-2) to facilitator wallet address
    pub signers: std::collections::HashMap<String, String>,

    /// Optional extensions supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
}

/// Create HTTP facilitator router (standard x402 spec endpoints)
pub fn create_http_facilitator_router() -> Router<HttpFacilitatorState> {
    Router::new()
        .route("/verify", post(handle_verify_http))
        .route("/settle", post(handle_settle_http))
        .route("/supported", get(handle_supported))
}

/// POST /verify - Verify a payment signature (x402 spec)
async fn handle_verify_http(
    State(state): State<HttpFacilitatorState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    info!("HTTP facilitator verify request for channel: {}", request.surface_id);

    // Find channel by ID
    let channels = state.channels.read().await;
    let channel_info = channels
        .iter()
        .find(|ch| {
            ch.surface
                .config_id()
                .map(|id| id == request.surface_id.as_str())
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            error!("Channel not found: {}", request.surface_id);
            StatusCode::NOT_FOUND
        })?;

    // Get x402 config from channel
    let x402_config = channel_info
        .surface
        .x402_config()
        .ok_or_else(|| {
            error!("Channel {} does not have x402 payment configuration", request.surface_id);
            StatusCode::BAD_REQUEST
        })?;

    // Verify payment
    let response = verify_facilitator_payment(
        request.payment_signature,
        x402_config,
        &channel_info.surface.name,
        &request.surface_id,
    )
    .await;

    Ok(Json(response))
}

/// POST /settle - Settle a verified payment on-chain (x402 spec)
async fn handle_settle_http(
    State(state): State<HttpFacilitatorState>,
    Json(request): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, StatusCode> {
    info!("HTTP facilitator settle request for channel: {}", request.surface_id);

    // Find channel by ID
    let channels = state.channels.read().await;
    let channel_info = channels
        .iter()
        .find(|ch| {
            ch.surface
                .config_id()
                .map(|id| id == request.surface_id.as_str())
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            error!("Channel not found: {}", request.surface_id);
            StatusCode::NOT_FOUND
        })?;

    // Check if payment policy is configured
    if channel_info
        .surface
        .x402_config()
        .is_none()
    {
        error!("Channel {} does not have payment policy configured", request.surface_id);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Execute settlement
    let response = settle_facilitator_payment(request.payment_signature, request.mode).await;

    Ok(Json(response))
}

/// GET /supported - Get supported payment schemes and networks (x402 spec)
async fn handle_supported(State(state): State<HttpFacilitatorState>) -> Result<Json<SupportedResponse>, StatusCode> {
    info!("HTTP facilitator supported query");

    // Aggregate supported schemes and networks from all channels
    let channels = state.channels.read().await;

    let mut schemes = std::collections::HashSet::new();
    let mut networks = std::collections::HashSet::new();
    let mut signers = std::collections::HashMap::new();

    for channel_info in channels.iter() {
        if let Some(x402) = channel_info
            .surface
            .x402_config()
        {
            // Add supported schemes
            schemes.extend(x402.supported_schemes.clone());

            // Add supported networks
            networks.extend(
                x402.supported_networks
                    .clone(),
            );

            // Add payment requirements to get signer addresses
            for req in &x402.payment_requirements {
                // Extract signer address from pay_to field
                signers.insert(req.network.clone(), req.pay_to.clone());
            }
        }
    }

    Ok(Json(SupportedResponse {
        schemes: schemes.into_iter().collect(),
        networks: networks.into_iter().collect(),
        signers,
        extensions: None,
    }))
}
