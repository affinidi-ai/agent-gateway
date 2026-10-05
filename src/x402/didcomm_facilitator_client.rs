//! DIDComm-based x402 Facilitator Client
//!
//! This module enables gateways to use other gateways as payment facilitators
//! via encrypted DIDComm messages instead of HTTP.

use super::PaymentPayload;
use crate::config::types::X402Config;

/// Settle payment via DIDComm facilitator gateway
#[tracing::instrument(
    name = "x402.settle_via_gateway",
    skip(payment, config),
    fields(
        facilitator_gateway_id = %config.facilitator_gateway_id.as_ref().unwrap_or(&"none".to_string()),
        surface_id = %channel_id,
        asset_transfer_method = %payment.asset_transfer_method(),
        network = %payment.network(),
        amount = %payment.amount()
    )
)]
pub async fn settle_via_gateway_facilitator(
    payment: &PaymentPayload,
    config: &X402Config,
    channel_id: &str,
) -> Result<String, String> {
    use tracing::{error, info};

    let facilitator_gateway_id = config
        .facilitator_gateway_id
        .as_ref()
        .ok_or("No facilitator gateway ID configured")?;

    info!("[x402-settle] Sending settlement request to facilitator gateway: {}", facilitator_gateway_id);

    // Validate payment has signature-based authorization (EIP-3009, Permit2, or SPL)
    let asset_transfer_method = payment.asset_transfer_method();
    if asset_transfer_method != "eip3009"
        && asset_transfer_method != "permit2"
        && asset_transfer_method != "spl_transfer"
    {
        error!(
            "[x402-settle] Invalid asset transfer method: {}. Only eip3009, permit2, and spl_transfer are supported for delegated settlement",
            asset_transfer_method
        );
        return Err(format!(
            "Settlement delegation requires EIP-3009, Permit2, or SPL signatures, got: {}",
            asset_transfer_method
        ));
    }

    info!(
        "[x402-settle] Settlement request - method={} network={} amount={}",
        asset_transfer_method,
        payment.network(),
        payment.amount()
    );

    // Create DIDComm settle-request message body
    let request_body = serde_json::json!({
        "payment": payment,
        "channel_id": channel_id,
        "asset_transfer_method": asset_transfer_method,
        "network": payment.network(),
    });

    // Send settlement request via gateway facilitator service
    match crate::x402::gateway_facilitator_service::send_settle_request(
        facilitator_gateway_id,
        request_body,
        channel_id.to_string(),
    )
    .await
    {
        Ok(tx_hash) => {
            info!("[x402-settle] ✅ Settlement completed: {}", tx_hash);
            Ok(tx_hash)
        }
        Err(e) => {
            error!("[x402-settle] ❌ Settlement failed: {}", e);
            Err(e)
        }
    }
}
