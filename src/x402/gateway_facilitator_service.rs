//! Gateway Facilitator Service
//!
//! Provides a service layer for sending x402 DIDComm verification and settlement requests
//! to facilitator gateways. Uses event-driven response handling via connection point listener.

use base64::Engine;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, oneshot};
use tracing::{debug, info, warn};
use uuid::Uuid;

use affinidi_messaging_didcomm::Message as DIDCommMessage;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};

use super::PaymentPayload;
use crate::config::types::X402PaymentRequirement;
use crate::gateways::filesystem::GatewayStore;
use crate::messages::message_types::MessageType;

/// Settlement response data structure
#[derive(Debug, Clone)]
pub struct SettlementResponse {
    pub settled: bool,
    pub tx_hash: String,
    pub error: String,
}

/// Global registry for pending settlement responses
/// Maps correlation_id (DIDComm message ID) → oneshot sender for response
#[allow(clippy::type_complexity)]
static PENDING_SETTLEMENT_RESPONSES: Lazy<
    Arc<tokio::sync::Mutex<HashMap<String, oneshot::Sender<SettlementResponse>>>>,
> = Lazy::new(|| Arc::new(tokio::sync::Mutex::new(HashMap::new())));

/// Send a settlement response to a waiting request (called by message processor)
pub async fn signal_settlement_response(
    correlation_id: &str,
    response: SettlementResponse,
) -> bool {
    let mut pending = PENDING_SETTLEMENT_RESPONSES
        .lock()
        .await;
    if let Some(tx) = pending.remove(correlation_id) {
        let _ = tx.send(response);
        true
    } else {
        false
    }
}

/// Body of the `x402/verify-request` a requesting gateway sends its facilitator gateway, carrying
/// the surface payment requirement the payment was resolved to
pub(crate) fn verify_request_body(
    verification_id: &str,
    payment_signature: &str,
    payment_requirement: &X402PaymentRequirement,
    channel_id: &str,
    resource_path: &str,
) -> serde_json::Value {
    serde_json::json!({
        "verification_id": verification_id,
        "payment_signature": payment_signature,
        "payment_requirement": payment_requirement,
        "network": payment_requirement.network,
        "channel_id": channel_id,
        "resource": resource_path,
    })
}

/// Gateway facilitator service state
pub struct GatewayFacilitatorService {
    /// ATM instance (optional - only available when running as gateway)
    pub atm: Option<Arc<ATM>>,

    /// ATM profile (optional - only available when running as gateway)
    pub profile: Option<Arc<ATMProfile>>,

    /// Our gateway DID (optional - only available when running as gateway)
    pub our_did: Option<String>,
}

impl GatewayFacilitatorService {
    /// Create a new gateway facilitator service
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            atm: None,
            profile: None,
            our_did: None,
        }
    }

    /// Set ATM infrastructure (called during gateway initialization)
    pub fn set_atm_infrastructure(
        &mut self,
        atm: Arc<ATM>,
        profile: Arc<ATMProfile>,
        our_did: String,
    ) {
        self.atm = Some(atm);
        self.profile = Some(profile);
        self.our_did = Some(our_did);
        info!("Gateway facilitator service initialized with ATM infrastructure");
    }

    /// Send verification request to facilitator gateway, which verifies the payment against
    /// `payment_requirement`, the surface requirement this gateway resolved for it
    pub async fn verify_via_facilitator(
        &self,
        facilitator_did: &str,
        payment_signature: &str,
        payment_requirement: &X402PaymentRequirement,
        channel_id: String,
        resource_path: String,
    ) -> Result<(), String> {
        // Check if we have ATM infrastructure
        let atm = self
            .atm
            .as_ref()
            .ok_or_else(|| "Gateway facilitator service not initialized with ATM infrastructure".to_string())?;

        let profile = self
            .profile
            .as_ref()
            .ok_or_else(|| "Gateway facilitator service not initialized with ATM profile".to_string())?;

        let our_did = self
            .our_did
            .as_ref()
            .ok_or_else(|| "Gateway facilitator service not initialized with DID".to_string())?;

        // Parse payment signature (still needs PaymentPayload for validation)
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payment_signature)
            .map_err(|e| format!("Invalid payment signature encoding: {:?}", e))?;
        let _payment: PaymentPayload =
            serde_json::from_slice(&decoded).map_err(|e| format!("Invalid payment signature format: {:?}", e))?;

        // Generate a verification ID for correlation
        let verification_id = Uuid::new_v4().to_string();

        info!(
            verification_id = %verification_id,
            facilitator = %facilitator_did,
            "Creating x402 verify-request for facilitator gateway"
        );

        let request_body =
            verify_request_body(&verification_id, payment_signature, payment_requirement, &channel_id, &resource_path);

        // Create DIDComm message
        let message_id = Uuid::new_v4().to_string();
        let verify_request_msg =
            DIDCommMessage::build(message_id.clone(), MessageType::X402VerifyRequest.to_string(), request_body)
                .from(our_did.clone())
                .to(facilitator_did.to_string())
                .finalize();

        debug!("Verify-request message created: {:?}", verify_request_msg);

        // Pack message encrypted
        let packed_message = atm
            .pack_encrypted(&verify_request_msg, facilitator_did, Some(our_did), Some(our_did))
            .await
            .map_err(|e| format!("Failed to pack verify-request message: {:?}", e))?;

        debug!("Verify-request message packed ({} bytes)", packed_message.0.len());

        // Send via ATM and WAIT for response synchronously (like fabric:// forwarding)
        atm.send_message(
            profile,
            &packed_message.0,
            &message_id,
            false, // Don't wait in send_message (we'll use live_stream_get)
            false, // Don't auto-delete
        )
        .await
        .map_err(|e| format!("Failed to send verify-request message: {:?}", e))?;

        info!(
            verification_id = %verification_id,
            message_id = %message_id,
            "Verify-request sent to facilitator gateway, waiting for response..."
        );

        // Wait for response synchronously (like fabric:// forwarding does)

        let timeout_duration = std::time::Duration::from_secs(30); // 30 second timeout

        let response_result = atm
            .message_pickup()
            .live_stream_get(
                profile,
                &message_id,
                timeout_duration,
                true, // auto_delete
            )
            .await;

        match response_result {
            Ok(Some((response_msg, _metadata))) => {
                // Verify it's an X402VerifyResponse message
                if response_msg.typ != MessageType::X402VerifyResponse.as_str() {
                    return Err(format!("Unexpected message type: {}", response_msg.typ));
                }

                // Parse response body
                let valid = response_msg
                    .body
                    .get("valid")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if valid {
                    info!(
                        verification_id = %verification_id,
                        "Payment verified successfully via gateway facilitator"
                    );
                    Ok(())
                } else {
                    // Verification failed
                    let error = response_msg
                        .body
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Verification failed")
                        .to_string();

                    Err(format!("Payment verification failed: {}", error))
                }
            }
            Ok(None) => {
                // Timeout - no response received
                Err("Gateway facilitator did not respond within timeout period".to_string())
            }
            Err(e) => Err(format!("Failed to receive verification response: {:?}", e)),
        }
    }
}

/// Global gateway facilitator service instance
static GATEWAY_FACILITATOR_SERVICE: once_cell::sync::Lazy<Arc<RwLock<Option<GatewayFacilitatorService>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Initialize the global gateway facilitator service
/// Initialize the global gateway facilitator service
pub async fn init_gateway_facilitator_service() {
    let mut service = GATEWAY_FACILITATOR_SERVICE
        .write()
        .await;
    *service = Some(GatewayFacilitatorService::new());
    info!("Global gateway facilitator service initialized");
}

/// Set ATM infrastructure for the global service
pub async fn set_atm_infrastructure(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    our_did: String,
) -> Result<(), String> {
    let mut service_lock = GATEWAY_FACILITATOR_SERVICE
        .write()
        .await;

    if let Some(service) = service_lock.as_mut() {
        service.set_atm_infrastructure(atm, profile, our_did);
        Ok(())
    } else {
        Err("Gateway facilitator service not initialized".to_string())
    }
}

/// Get the global gateway facilitator service
pub async fn get_gateway_facilitator_service() -> Option<Arc<RwLock<Option<GatewayFacilitatorService>>>> {
    let service = GATEWAY_FACILITATOR_SERVICE
        .read()
        .await;
    if service.is_some() {
        Some(Arc::clone(&GATEWAY_FACILITATOR_SERVICE))
    } else {
        None
    }
}

/// Send settlement request to facilitator gateway
///
/// Returns transaction hash if successful
#[tracing::instrument(
    name = "x402.send_settle_request",
    skip(request_body),
    fields(
        facilitator_gateway_id = %facilitator_gateway_id,
        surface_id = %channel_id
    )
)]
pub async fn send_settle_request(
    facilitator_gateway_id: &str,
    request_body: serde_json::Value,
    channel_id: String,
) -> Result<String, String> {
    use tracing::info;

    let service_lock = get_gateway_facilitator_service()
        .await
        .ok_or_else(|| "Gateway facilitator service not initialized".to_string())?;

    let service_option = service_lock.read().await;

    let svc = service_option
        .as_ref()
        .ok_or_else(|| "Gateway facilitator service not initialized".to_string())?;

    // Check if we have ATM infrastructure
    let atm = svc
        .atm
        .as_ref()
        .ok_or_else(|| "Gateway facilitator service not initialized with ATM infrastructure".to_string())?;

    let profile = svc
        .profile
        .as_ref()
        .ok_or_else(|| "Gateway facilitator service not initialized with ATM profile".to_string())?;

    let our_did = svc
        .our_did
        .as_ref()
        .ok_or_else(|| "Gateway facilitator service not initialized with DID".to_string())?;

    // Resolve facilitator gateway DID from ID
    let facilitator_did = {
        // Load gateway from storage
        let gateways_path = crate::storage::get_gateways_storage_path()
            .ok_or_else(|| "Gateways storage path not initialized".to_string())?;

        let gateway_store = crate::gateways::FileSystemGatewayStore::new(std::path::PathBuf::from(gateways_path), None)
            .await
            .map_err(|e| format!("Failed to initialize gateway store: {:?}", e))?;

        let gateway = gateway_store
            .get(facilitator_gateway_id)
            .await
            .map_err(|e| format!("Failed to get gateway: {:?}", e))?
            .ok_or_else(|| format!("Facilitator gateway not found: {}", facilitator_gateway_id))?;

        gateway.did
    };

    info!(
        facilitator_gateway_id = %facilitator_gateway_id,
        facilitator_did = %facilitator_did,
        "Resolved facilitator gateway DID"
    );

    // Create DIDComm message
    let message_id = Uuid::new_v4().to_string();
    let settle_request_msg =
        DIDCommMessage::build(message_id.clone(), MessageType::X402SettleRequest.to_string(), request_body)
            .from(our_did.clone())
            .to(facilitator_did.clone())
            .finalize();

    info!("Settle-request message created: id={}", message_id);

    // Pack message encrypted
    let packed_message = atm
        .pack_encrypted(&settle_request_msg, &facilitator_did, Some(our_did), Some(our_did))
        .await
        .map_err(|e| format!("Failed to pack settle-request message: {:?}", e))?;

    info!("Settle-request message packed ({} bytes)", packed_message.0.len());

    // Send via ATM and wait for response
    atm.send_message(
        profile,
        &packed_message.0,
        &message_id,
        false, // Don't wait in send_message
        false, // Don't auto-delete
    )
    .await
    .map_err(|e| format!("Failed to send settle-request message: {:?}", e))?;

    info!(
        message_id = %message_id,
        "Settle-request sent to settlement gateway, waiting for response..."
    );

    // Get timeout from config (default 60 seconds)
    let timeout_ms = if let Ok(x402_config) = crate::x402::config_cache::get_or_load_x402_config().await {
        x402_config
            .settlement_timeout_ms
            .unwrap_or(60000)
    } else {
        60000
    };
    let timeout_duration = std::time::Duration::from_millis(timeout_ms);

    // Register oneshot channel for response (event-driven, not polling!)
    let (tx, rx) = oneshot::channel();
    {
        let mut pending = PENDING_SETTLEMENT_RESPONSES
            .lock()
            .await;
        pending.insert(message_id.clone(), tx);
    }

    info!(
        message_id = %message_id,
        timeout_ms = %timeout_ms,
        "Waiting for settlement response via connection point listener..."
    );

    // Wait for response from connection point listener (NO POLLING!)
    // The connection point listener will signal us via the oneshot channel
    match tokio::time::timeout(timeout_duration, rx).await {
        Ok(Ok(settlement_response)) => {
            // Response received from connection point listener
            if settlement_response.settled {
                info!(
                    message_id = %message_id,
                    tx_hash = %settlement_response.tx_hash,
                    "Payment settled successfully via gateway facilitator"
                );
                Ok(settlement_response.tx_hash)
            } else {
                warn!(
                    message_id = %message_id,
                    error = %settlement_response.error,
                    "Payment settlement failed via gateway facilitator"
                );
                Err(format!("Payment settlement failed: {}", settlement_response.error))
            }
        }
        Ok(Err(_)) => {
            // Channel closed unexpectedly
            warn!(message_id = %message_id, "Settlement response channel closed unexpectedly");
            Err("Settlement response channel closed".to_string())
        }
        Err(_) => {
            // Timeout - no response received
            warn!(message_id = %message_id, timeout_ms = %timeout_ms, "Settlement timeout");

            // Clean up the pending response
            PENDING_SETTLEMENT_RESPONSES
                .lock()
                .await
                .remove(&message_id);

            Err(format!("Settlement gateway did not respond within {} seconds", timeout_ms / 1000))
        }
    }
}

/// Verify payment via facilitator gateway (convenience function)
pub async fn verify_via_facilitator_gateway(
    facilitator_did: &str,
    payment_signature: &str,
    payment_requirement: &X402PaymentRequirement,
    channel_id: String,
    resource_path: String,
) -> Result<(), String> {
    let service_lock = get_gateway_facilitator_service()
        .await
        .ok_or_else(|| "Gateway facilitator service not initialized".to_string())?;

    let service_option = service_lock.read().await;

    let svc = service_option
        .as_ref()
        .ok_or_else(|| "Gateway facilitator service not initialized".to_string())?;

    svc.verify_via_facilitator(facilitator_did, payment_signature, payment_requirement, channel_id, resource_path)
        .await
}
