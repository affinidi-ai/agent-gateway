//! Adapter layer between x402-rs types and our internal types
//!
//! This module provides conversion functions and utilities to bridge between
//! the official x402-rs protocol types and our internal gateway types.
//!
//! ## Type Conversions
//!
//! - `to_verify_request()` - Convert PaymentPayload + resolved requirement → x402-rs VerifyRequest
//! - `to_settle_request()` - Convert a bound PaymentPayload → x402-rs SettleRequest
//!
//! ## Response Parsing
//!
//! Helper functions to extract common fields from x402-rs responses:
//! - `extract_payer()` - Get payer address from verification
//! - `is_verification_valid()` - Check if payment is valid
//! - `extract_verify_error()` - Get verification error reason
//! - `extract_transaction()` - Get transaction hash from settlement
//! - `is_settlement_successful()` - Check if settlement succeeded
//! - `extract_settle_error()` - Get settlement error reason

use super::PaymentPayload;
use crate::config::types::X402PaymentRequirement;
use tracing::info;
use x402_types::proto;

/// Convert our internal PaymentPayload to x402-rs VerifyRequest.
///
/// `payment_requirements` is the surface requirement verification resolved for this payment,
/// so the facilitator checks the caller's `accepted` against it.
pub fn to_verify_request(
    payload: &PaymentPayload,
    payment_requirements: &X402PaymentRequirement,
) -> Result<proto::VerifyRequest, String> {
    info!(
        "[x402-adapter] Converting PaymentPayload to VerifyRequest: network={}, scheme={}",
        payload.accepted.network, payload.accepted.scheme
    );

    // Clone payload for SDK
    let mut normalized_payload = payload.clone();

    // IMPORTANT NOTE: Modern Solana wallets (Phantom, Solflare) automatically add ComputeBudgetProgram
    // instructions when signing transactions. These are:
    // - ComputeBudgetProgram.setComputeUnitLimit
    // - ComputeBudgetProgram.setComputeUnitPrice
    //
    // The x402-chain-solana SDK (v1.1.1) currently rejects transactions with these instructions,
    // causing "Invalid compute limit instruction" errors. This is a known limitation.
    //
    // We cannot strip these instructions from the signed transaction because:
    // 1. The wallet's signature commits to the entire transaction message including compute budget instructions
    // 2. Removing instructions invalidates the signature
    // 3. Re-signing would require user interaction again
    //
    // WORKAROUND: Use wallets that don't automatically add compute budget instructions, or wait for
    // x402-chain-solana SDK update to whitelist these standard Solana instructions.

    // Ensure asset field is in payload for SDK (copy from the payment requirement if missing)
    #[allow(clippy::nonminimal_bool)]
    if normalized_payload
        .payload
        .get("asset")
        .is_none()
    {
        let asset = &payment_requirements.asset;
        normalized_payload
            .payload
            .as_object_mut()
            .ok_or("Payload is not an object")?
            .insert("asset".to_string(), serde_json::Value::String(asset.clone()));
        info!("[x402-adapter] Added asset field to payload: {}", asset);
    }

    // Use the x402Version from the incoming payload
    // This allows clients to choose between v1 and v2 protocols
    // Both V1 and V2 Solana/EVM schemes are registered in the facilitator
    let x402_version = normalized_payload.x402_version;

    info!(
        "[x402-adapter] Using x402 version {} for network {}",
        x402_version,
        normalized_payload
            .accepted
            .network
    );

    // Build the correct structure based on protocol version
    let wrapped = if x402_version == 1 {
        // V1 protocol has a different PaymentPayload structure:
        // {
        //   "x402Version": 1,
        //   "scheme": "exact",
        //   "network": "solana:...",
        //   "payload": { ...scheme-specific data only... }
        // }
        serde_json::json!({
            "x402Version": x402_version,
            "paymentPayload": {
                "x402Version": x402_version,
                "scheme": payment_requirements.scheme,
                "network": payment_requirements.network,
                "payload": normalized_payload.payload,
            },
            "paymentRequirements": payment_requirements
        })
    } else {
        // V2 protocol has accepted + payload structure (matches our internal format)
        // {
        //   "x402Version": 2,
        //   "accepted": { ...payment requirements... },
        //   "payload": { ...scheme-specific data... },
        //   "resource": { ... },
        // }
        // NOTE: For SDK scheme resolution, we also include scheme at top level
        serde_json::json!({
            "x402Version": x402_version,
            "paymentPayload": {
                "x402Version": x402_version,
                "scheme": payment_requirements.scheme,  // Add scheme at top level for SDK resolution
                "network": payment_requirements.network,  // Add network at top level for SDK resolution
                "accepted": normalized_payload.accepted,
                "payload": normalized_payload.payload,
                "resource": normalized_payload.resource,
            },
            "paymentRequirements": payment_requirements
        })
    };

    let raw =
        serde_json::value::to_raw_value(&wrapped).map_err(|e| format!("Failed to serialize VerifyRequest: {}", e))?;
    Ok(proto::VerifyRequest::from(raw))
}

/// Convert our internal PaymentPayload to x402-rs SettleRequest.
///
/// `payload` is the one verification returned, whose `accepted` is the surface requirement it
/// was bound to.
pub fn to_settle_request(payload: &PaymentPayload) -> Result<proto::SettleRequest, String> {
    info!("[x402-adapter] Converting PaymentPayload to SettleRequest: network={}", payload.accepted.network);
    to_verify_request(payload, &payload.accepted)
}

/// Extract payer address from VerifyResponse
pub fn extract_payer(response: &proto::VerifyResponse) -> Option<String> {
    // Try to extract payer from the response value
    if let Ok(value) = serde_json::to_value(response) {
        value
            .get("payer")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    }
}

/// Check if verification was valid
pub fn is_verification_valid(response: &proto::VerifyResponse) -> bool {
    // Try to extract isValid field from the response
    if let Ok(value) = serde_json::to_value(response) {
        value
            .get("isValid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    } else {
        false
    }
}

/// Extract error reason from VerifyResponse
pub fn extract_verify_error(response: &proto::VerifyResponse) -> Option<String> {
    if let Ok(value) = serde_json::to_value(response) {
        value
            .get("invalidReason")
            .or_else(|| value.get("errorReason"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    }
}

/// Extract transaction hash from SettleResponse
pub fn extract_transaction(response: &proto::SettleResponse) -> Option<String> {
    if let Ok(value) = serde_json::to_value(response) {
        value
            .get("transaction")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    }
}

/// Check if settlement was successful
pub fn is_settlement_successful(response: &proto::SettleResponse) -> bool {
    if let Ok(value) = serde_json::to_value(response) {
        value
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    } else {
        false
    }
}

/// Extract error reason from SettleResponse
pub fn extract_settle_error(response: &proto::SettleResponse) -> Option<String> {
    if let Ok(value) = serde_json::to_value(response) {
        value
            .get("errorReason")
            .or_else(|| value.get("error_reason"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirement(
        pay_to: &str,
        amount: &str,
    ) -> X402PaymentRequirement {
        X402PaymentRequirement {
            scheme: "exact".to_string(),
            network: "eip155:8453".to_string(),
            amount: amount.to_string(),
            asset: "0xtoken".to_string(),
            recipient_id: String::new(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 300,
            extra: None,
        }
    }

    fn payload(accepted: X402PaymentRequirement) -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted,
            payload: serde_json::json!({"signature": "0xsig"}),
            extensions: None,
        }
    }

    #[test]
    fn verify_request_carries_resolved_requirement_not_caller_accepted() {
        let caller = payload(requirement("0xcaller", "1"));
        let configured = requirement("0xmerchant", "1000000");

        let request = serde_json::to_value(to_verify_request(&caller, &configured).unwrap()).unwrap();

        assert_eq!(request["paymentRequirements"]["payTo"], "0xmerchant");
        assert_eq!(request["paymentRequirements"]["amount"], "1000000");
        assert_eq!(request["paymentPayload"]["accepted"]["payTo"], "0xcaller");
        assert_eq!(request["paymentPayload"]["accepted"]["amount"], "1");
        assert_eq!(request["paymentPayload"]["payload"]["asset"], "0xtoken");
    }

    #[test]
    fn settle_request_uses_bound_accepted_as_requirement() {
        let bound = payload(requirement("0xmerchant", "1000000"));

        let request = serde_json::to_value(to_settle_request(&bound).unwrap()).unwrap();

        assert_eq!(request["paymentRequirements"], request["paymentPayload"]["accepted"]);
        assert_eq!(request["paymentRequirements"]["payTo"], "0xmerchant");
    }
}
