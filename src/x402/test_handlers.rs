//! x402 E2E test endpoints
//!
//! These endpoints are for testing x402 payment flow conformance with the official
//! x402 protocol. They provide simple protected endpoints that:
//!
//! 1. Return 402 Payment Required with payment requirements when accessed without payment
//! 2. Verify payment signature and return 200 with protected resource when payment is provided
//! 3. Support both EIP-3009 (default) and Permit2 payment methods (EVM)
//! 4. Support Solana payments (mainnet and devnet)
//!
//! Test endpoint configuration is loaded from config/test-endpoints.json

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

use crate::config::types::{EvmTestEndpointConfig, SolanaTestEndpointConfig, X402PaymentRequirement};

/// The payment requirement an EVM test endpoint issues and verifies against
fn evm_payment_requirement(
    evm_config: &EvmTestEndpointConfig,
    payment_method: &str,
) -> X402PaymentRequirement {
    let mut extra = json!({ "assetTransferMethod": payment_method });
    if let Some(name) = &evm_config.token_name {
        extra["name"] = json!(name);
    }
    if let Some(version) = &evm_config.token_version {
        extra["version"] = json!(version);
    }
    X402PaymentRequirement {
        scheme: "exact".to_string(),
        network: evm_config.network.clone(),
        amount: evm_config.amount.clone(),
        asset: evm_config
            .token_address
            .clone(),
        recipient_id: String::new(),
        pay_to: evm_config.recipient.clone(),
        max_timeout_seconds: 300,
        extra: Some(extra),
    }
}

/// The payment requirement a Solana test endpoint issues and verifies against
fn solana_payment_requirement(solana_config: &SolanaTestEndpointConfig) -> X402PaymentRequirement {
    X402PaymentRequirement {
        scheme: "exact".to_string(),
        network: solana_config.network.clone(),
        amount: solana_config.amount.clone(),
        asset: solana_config
            .token_address
            .clone(),
        recipient_id: String::new(),
        pay_to: solana_config
            .recipient
            .clone(),
        max_timeout_seconds: 300,
        extra: Some(json!({ "chain": "solana" })),
    }
}

/// EIP-3009 protected endpoint (default)
pub async fn protected_eip3009(
    State(config): State<Arc<crate::config::TestEndpointsConfig>>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    handle_protected_resource(config, headers, request, "eip3009").await
}

/// Permit2 protected endpoint
pub async fn protected_permit2(
    State(config): State<Arc<crate::config::TestEndpointsConfig>>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    handle_protected_resource(config, headers, request, "permit2").await
}

/// Core handler for protected resources
async fn handle_protected_resource(
    config: Arc<crate::config::TestEndpointsConfig>,
    headers: HeaderMap,
    _request: Request<Body>,
    payment_method: &str,
) -> Response {
    // Load EVM test endpoint configuration
    let evm_config = match &config.evm {
        Some(cfg) => cfg,
        None => {
            error!("[x402] No EVM test endpoint configuration found");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Test endpoint not configured",
                    "details": "EVM test endpoint configuration missing from test-endpoints.json"
                })),
            )
                .into_response();
        }
    };

    let network = &evm_config.network;
    let amount = &evm_config.amount;
    let rpc_endpoint = &evm_config.rpc_endpoint;
    let payment_requirement = evm_payment_requirement(evm_config, payment_method);

    let payment_sig_header = "payment-signature";
    let payment_required_header = "payment-required";

    // Check for payment signature
    if let Some(payment_signature) = headers.get(payment_sig_header) {
        match payment_signature.to_str() {
            Ok(signature_str) => {
                // Create test x402 config for signature verification
                let mut rpc_endpoints = std::collections::HashMap::new();
                rpc_endpoints.insert(network.clone(), rpc_endpoint.clone());

                let test_config = crate::config::types::X402Config {
                    enabled: true,
                    verification_mode: crate::config::types::X402VerificationMode::Signature,
                    verification_async: Some(crate::config::types::X402AsyncMode::Sync),
                    rpc_endpoints,
                    min_confirmations: 0,
                    accept_mempool_tx: true,
                    payment_requirements: vec![payment_requirement.clone()],
                    ..Default::default()
                };

                // Actually verify the payment using our verification logic
                match crate::x402::verify_payment(
                    signature_str,
                    &test_config,
                    payment_method,
                    "test-endpoint",
                    "/.well-known/x402-test", // Test resource URL
                    None,                     // Test handlers don't have listener_manager access
                    None,                     // Test handlers don't have transaction_store access
                    None,                     // No existing correlation_id
                )
                .await
                {
                    Ok((payment_payload, _correlation_id)) => {
                        info!(
                            "[x402] Payment verified for test endpoint (method={}): scheme={} network={}",
                            payment_method,
                            payment_payload.scheme(),
                            payment_payload.network()
                        );

                        // Return protected resource
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "message": "Access granted",
                                "resource": format!("Protected resource ({})", payment_method),
                                "payment_verified": true,
                                "network": network,
                                "amount": amount
                            })),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        error!("[x402] Payment verification failed: {}", e);
                        // Return 400 Bad Request for invalid payment
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error": "Invalid payment",
                                "details": e
                            })),
                        )
                            .into_response();
                    }
                }
            }
            Err(_) => {
                error!("[x402] Invalid payment signature header");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Invalid payment signature header"
                    })),
                )
                    .into_response();
            }
        }
    }

    // No valid payment provided - return 402 with payment requirements
    info!("[x402] No valid payment signature found, returning 402");

    create_402_response(&payment_requirement, payment_required_header)
}

/// Create a 402 Payment Required response
fn create_402_response(
    payment_required: &X402PaymentRequirement,
    header_name: &str,
) -> Response {
    use base64::Engine;
    let payment_json = serde_json::to_string(payment_required).unwrap();
    let payment_b64 = base64::engine::general_purpose::STANDARD.encode(payment_json.as_bytes());

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header_name, payment_b64)],
        Json(json!({
            "error": "Payment required",
            "payment_required": payment_required
        })),
    )
        .into_response()
}

/// Solana protected endpoint (Devnet)
pub async fn protected_solana_devnet(
    State(config): State<Arc<crate::config::TestEndpointsConfig>>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    handle_solana_protected_resource(config, headers, request, "solana_devnet").await
}

/// Solana protected endpoint (Mainnet)
pub async fn protected_solana_mainnet(
    State(config): State<Arc<crate::config::TestEndpointsConfig>>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    handle_solana_protected_resource(config, headers, request, "solana_mainnet").await
}

/// Core handler for Solana protected resources
async fn handle_solana_protected_resource(
    config: Arc<crate::config::TestEndpointsConfig>,
    headers: HeaderMap,
    _request: Request<Body>,
    network_env: &str,
) -> Response {
    // Load Solana test endpoint configuration
    let solana_config = match network_env {
        "solana_devnet" => config.solana_devnet.as_ref(),
        "solana_mainnet" => config.solana_mainnet.as_ref(),
        _ => None,
    };

    let solana_config = match solana_config {
        Some(cfg) => cfg,
        None => {
            error!("[x402] No {} test endpoint configuration found", network_env);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Test endpoint not configured",
                    "details": format!("{} test endpoint configuration missing from test-endpoints.json", network_env)
                })),
            )
                .into_response();
        }
    };

    let network = &solana_config.network;
    let rpc_endpoint = &solana_config.rpc_endpoint;
    let amount = &solana_config.amount;
    let payment_requirement = solana_payment_requirement(solana_config);
    let payment_sig_header = "payment-signature";
    let payment_required_header = "payment-required";

    // Check for payment signature
    if let Some(payment_signature) = headers.get(payment_sig_header) {
        match payment_signature.to_str() {
            Ok(signature_str) => {
                // Create test x402 config for signature verification
                let mut rpc_endpoints = std::collections::HashMap::new();
                rpc_endpoints.insert(network.clone(), rpc_endpoint.clone());

                let test_config = crate::config::types::X402Config {
                    enabled: true,
                    verification_mode: crate::config::types::X402VerificationMode::Signature,
                    verification_async: Some(crate::config::types::X402AsyncMode::Sync),
                    rpc_endpoints,
                    min_confirmations: 0,
                    accept_mempool_tx: true,
                    payment_requirements: vec![payment_requirement.clone()],
                    ..Default::default()
                };

                // Actually verify the payment using our verification logic
                match crate::x402::verify_payment(
                    signature_str,
                    &test_config,
                    network_env,
                    "test-endpoint-solana",
                    "/.well-known/x402-test-solana", // Test resource URL
                    None,                            // Test handlers don't have listener_manager access
                    None,                            // Test handlers don't have transaction_store access
                    None,                            // No existing correlation_id
                )
                .await
                {
                    Ok((payment_payload, _correlation_id)) => {
                        info!(
                            "[x402] Solana payment verified for test endpoint ({}): scheme={} network={}",
                            network_env,
                            payment_payload.scheme(),
                            payment_payload.network()
                        );

                        // Return protected resource
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "message": "Access granted",
                                "resource": format!("Protected Solana resource ({})", network_env),
                                "payment_verified": true,
                                "network": network,
                                "amount": amount
                            })),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        error!("[x402] Solana payment verification failed: {}", e);
                        // Return 400 Bad Request for invalid payment
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error": "Invalid payment",
                                "details": e
                            })),
                        )
                            .into_response();
                    }
                }
            }
            Err(_) => {
                error!("[x402] Invalid payment signature header");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Invalid payment signature header"
                    })),
                )
                    .into_response();
            }
        }
    }

    // No valid payment provided - return 402 with payment requirements
    info!("[x402] No valid Solana payment signature found, returning 402");

    create_402_response(&payment_requirement, payment_required_header)
}

/// Health check endpoint
pub async fn test_health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "agent-gateway",
        "x402_support": {
            "evm": ["eip3009", "permit2"],
            "solana": ["devnet", "mainnet"]
        }
    }))
}

/// Close endpoint (no-op for now, as gateway runs as a service)
pub async fn test_close() -> impl IntoResponse {
    Json(json!({
        "status": "accepted",
        "message": "Gateway runs as a service and cannot be closed via API"
    }))
}
