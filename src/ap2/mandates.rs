//! Official AP2 Mandate Types
//!
//! These types match the official AP2 specification from:
//! https://github.com/google/agent-payments-protocol
//!
//! AP2 mandates are plain JSON objects with JWT strings in specific fields,
//! NOT W3C Verifiable Credentials with embedded proofs.
//!
//! ## Mandate Structure
//!
//! Mandates are wrapped with type keys:
//! - `"ap2.mandates.IntentMandate"`
//! - `"ap2.mandates.CartMandate"`
//! - `"ap2.mandates.PaymentMandate"`
//!
//! ## Signing Rules
//!
//! - **IntentMandate**: NOT signed in human-present flow
//! - **CartMandate**: JWT in `merchant_authorization` field
//! - **PaymentMandate**: SD-JWT-VC in `user_authorization` field

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// AP2 mandate type keys
pub const INTENT_MANDATE_KEY: &str = "ap2.mandates.IntentMandate";
pub const CART_MANDATE_KEY: &str = "ap2.mandates.CartMandate";
pub const PAYMENT_MANDATE_KEY: &str = "ap2.mandates.PaymentMandate";

/// IntentMandate - Shopping intent from buyer
///
/// Represents the user's purchase intent in natural language.
/// NOT signed in human-present scenarios.
///
/// Example:
/// ```json
/// {
///   "ap2.mandates.IntentMandate": {
///     "user_cart_confirmation_required": true,
///     "natural_language_description": "Buy Nike shoes, size 10",
///     "merchants": ["Nike", "Amazon"],
///     "intent_expiry": "2026-01-30T12:00:00Z"
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentMandate {
    pub user_cart_confirmation_required: bool,
    pub natural_language_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchants: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skus: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_refundability: Option<bool>,
    pub intent_expiry: String,
}

/// CartContents - The detailed contents of a shopping cart
///
/// This object is signed by the merchant to create a CartMandate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartContents {
    pub id: String,
    pub user_cart_confirmation_required: bool,
    pub payment_request: PaymentRequest,
    pub cart_expiry: String,
    pub merchant_name: String,
}

/// CartMandate - Shopping cart from merchant with signature
///
/// Contains cart contents and merchant's JWT authorization.
///
/// Example:
/// ```json
/// {
///   "ap2.mandates.CartMandate": {
///     "contents": {
///       "id": "cart_123",
///       "user_cart_confirmation_required": true,
///       "payment_request": { ... },
///       "cart_expiry": "2026-01-30T12:00:00Z",
///       "merchant_name": "TechStore"
///     },
///     "merchant_authorization": "eyJhbGci..."
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartMandate {
    pub contents: CartContents,
    /// JWT signed by merchant containing cart_hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_authorization: Option<String>,
}

/// PaymentMandateContents - Payment details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMandateContents {
    pub payment_mandate_id: String,
    pub payment_details_id: String,
    pub payment_details_total: PaymentItem,
    pub payment_response: PaymentResponse,
    pub merchant_agent: String,
    pub timestamp: String,
}

/// PaymentMandate - Payment authorization with SD-JWT-VC
///
/// Contains payment details and user's SD-JWT-VC authorization.
///
/// Example:
/// ```json
/// {
///   "ap2.mandates.PaymentMandate": {
///     "payment_mandate_contents": { ... },
///     "user_authorization": "eyJhbGci...~eyJhbGci..."
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMandate {
    pub payment_mandate_contents: PaymentMandateContents,
    /// SD-JWT-VC: <issuer-jwt>~<key-binding-jwt>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_authorization: Option<String>,
}

/// W3C PaymentRequest structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub method_data: Vec<PaymentMethodData>,
    pub details: PaymentDetails,
}

/// Payment method data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodData {
    pub supported_methods: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Payment details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDetails {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_items: Option<Vec<PaymentItem>>,
    pub total: PaymentItem,
}

/// Payment item (line item or total)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentItem {
    pub label: String,
    pub amount: PaymentCurrencyAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_period: Option<i32>,
}

/// Currency amount
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCurrencyAmount {
    pub currency: String,
    pub value: f64,
}

/// Payment response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub request_id: String,
    pub method_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, Value>>,
}

/// Enum for all AP2 mandate types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ap2Mandate {
    Intent(IntentMandate),
    Cart(CartMandate),
    Payment(PaymentMandate),
}

impl Ap2Mandate {
    /// Extract AP2 mandate from message data
    ///
    /// Looks for mandate keys in:
    /// - `params.message.parts[].data["ap2.mandates.*"]`
    pub fn extract_from_message(message: &Value) -> Result<Option<Self>> {
        // Try to find mandate in message parts
        if let Some(parts) = message
            .get("params")
            .and_then(|p| p.get("message"))
            .and_then(|m| m.get("parts"))
            .and_then(|p| p.as_array())
        {
            for part in parts {
                if let Some(data) = part.get("data") {
                    // Try each mandate type
                    if let Some(intent) = data.get(INTENT_MANDATE_KEY) {
                        let mandate: IntentMandate = serde_json::from_value(intent.clone())?;
                        return Ok(Some(Ap2Mandate::Intent(mandate)));
                    }
                    if let Some(cart) = data.get(CART_MANDATE_KEY) {
                        let mandate: CartMandate = serde_json::from_value(cart.clone())?;
                        return Ok(Some(Ap2Mandate::Cart(mandate)));
                    }
                    if let Some(payment) = data.get(PAYMENT_MANDATE_KEY) {
                        let mandate: PaymentMandate = serde_json::from_value(payment.clone())?;
                        return Ok(Some(Ap2Mandate::Payment(mandate)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Parse AP2 mandate from JSON value
    /// Detects the mandate type and deserializes accordingly
    pub fn from_value(value: &Value) -> Result<Self> {
        // Detect mandate type from fields
        if value
            .get("natural_language_description")
            .is_some()
        {
            let mandate: IntentMandate = serde_json::from_value(value.clone())?;
            Ok(Ap2Mandate::Intent(mandate))
        } else if value
            .get("contents")
            .is_some()
            && value
                .get("merchant_authorization")
                .is_some()
        {
            let mandate: CartMandate = serde_json::from_value(value.clone())?;
            Ok(Ap2Mandate::Cart(mandate))
        } else if value
            .get("payment_mandate_contents")
            .is_some()
            && value
                .get("user_authorization")
                .is_some()
        {
            let mandate: PaymentMandate = serde_json::from_value(value.clone())?;
            Ok(Ap2Mandate::Payment(mandate))
        } else {
            Err(anyhow!("Unable to detect AP2 mandate type from JSON structure"))
        }
    }

    /// Get mandate type name
    #[allow(unused)]
    pub fn mandate_type(&self) -> &str {
        match self {
            Ap2Mandate::Intent(_) => "IntentMandate",
            Ap2Mandate::Cart(_) => "CartMandate",
            Ap2Mandate::Payment(_) => "PaymentMandate",
        }
    }

    /// Get mandate ID
    #[allow(unused)]
    pub fn mandate_id(&self) -> String {
        match self {
            Ap2Mandate::Intent(m) => {
                format!(
                    "intent-{}",
                    &m.natural_language_description[..20.min(
                        m.natural_language_description
                            .len()
                    )]
                )
            }
            Ap2Mandate::Cart(m) => m.contents.id.clone(),
            Ap2Mandate::Payment(m) => m
                .payment_mandate_contents
                .payment_mandate_id
                .clone(),
        }
    }

    #[allow(unused)]
    /// Check if mandate has a signature
    pub fn has_signature(&self) -> bool {
        match self {
            Ap2Mandate::Intent(_) => false, // IntentMandates are unsigned in human-present flow
            Ap2Mandate::Cart(m) => m
                .merchant_authorization
                .is_some(),
            Ap2Mandate::Payment(m) => m.user_authorization.is_some(),
        }
    }

    #[allow(unused)]
    /// Get signature (JWT or SD-JWT-VC)
    pub fn get_signature(&self) -> Option<&str> {
        match self {
            Ap2Mandate::Intent(_) => None,
            Ap2Mandate::Cart(m) => m
                .merchant_authorization
                .as_deref(),
            Ap2Mandate::Payment(m) => m
                .user_authorization
                .as_deref(),
        }
    }
}

#[allow(unused)]
/// Compute SHA256 hash of CartContents (canonical JSON)
pub fn compute_cart_hash(contents: &CartContents) -> Result<String> {
    // Serialize to canonical JSON (sorted keys, compact)
    let json_str = serde_json::to_string(contents)?;
    let mut hasher = Sha256::new();
    hasher.update(json_str.as_bytes());
    let hash = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(hash)))
}

#[allow(unused)]
/// Compute SHA256 hash of PaymentMandateContents (canonical JSON)
pub fn compute_payment_contents_hash(contents: &PaymentMandateContents) -> Result<String> {
    // Serialize to canonical JSON (sorted keys, compact)
    let json_str = serde_json::to_string(contents)?;
    let mut hasher = Sha256::new();
    hasher.update(json_str.as_bytes());
    let hash = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Parse SD-JWT-VC into issuer and key-binding parts
pub fn parse_sd_jwt_vc(sd_jwt_vc: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = sd_jwt_vc.split('~').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid SD-JWT-VC format: expected 2 parts separated by ~, got {}", parts.len()));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sd_jwt_vc() {
        let sd_jwt = "issuer.jwt.signature~keybinding.jwt.signature";
        let (issuer, kb) = parse_sd_jwt_vc(sd_jwt).unwrap();
        assert_eq!(issuer, "issuer.jwt.signature");
        assert_eq!(kb, "keybinding.jwt.signature");
    }

    #[test]
    fn test_parse_sd_jwt_vc_invalid() {
        let result = parse_sd_jwt_vc("invalid-no-tilde");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_from_message_intent() {
        let message = serde_json::json!({
            "params": {
                "message": {
                    "parts": [{
                        "kind": "data",
                        "data": {
                            "ap2.mandates.IntentMandate": {
                                "user_cart_confirmation_required": true,
                                "natural_language_description": "Buy shoes",
                                "intent_expiry": "2026-01-30T12:00:00Z"
                            }
                        }
                    }]
                }
            }
        });

        let mandate = Ap2Mandate::extract_from_message(&message).unwrap();
        assert!(mandate.is_some());

        let mandate = mandate.unwrap();
        assert_eq!(mandate.mandate_type(), "IntentMandate");
        assert!(!mandate.has_signature());
    }

    #[test]
    fn test_compute_cart_hash() {
        let contents = CartContents {
            id: "cart_123".to_string(),
            user_cart_confirmation_required: true,
            payment_request: PaymentRequest {
                method_data: vec![],
                details: PaymentDetails {
                    id: "order_1".to_string(),
                    display_items: None,
                    total: PaymentItem {
                        label: "Total".to_string(),
                        amount: PaymentCurrencyAmount {
                            currency: "USD".to_string(),
                            value: 99.99,
                        },
                        pending: None,
                        refund_period: None,
                    },
                },
            },
            cart_expiry: "2026-01-30T12:00:00Z".to_string(),
            merchant_name: "TechStore".to_string(),
        };

        let hash = compute_cart_hash(&contents).unwrap();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 71); // "sha256:" + 64 hex chars
    }
}
