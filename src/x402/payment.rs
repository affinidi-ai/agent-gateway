//! x402 payment structures and utilities

use serde::{Deserialize, Serialize};

/// Payment payload from x402 client (v2 spec compliant)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    /// x402 version (always 2)
    #[serde(rename = "x402Version")]
    pub x402_version: i32,

    /// Resource information (optional in v2 spec)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,

    /// The chosen payment requirement from the server's accepts array
    pub accepted: crate::config::types::X402PaymentRequirement,

    /// Scheme-specific payment data
    pub payload: serde_json::Value,

    /// Optional extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl PaymentPayload {
    /// Get the payment scheme from the accepted field
    pub fn scheme(&self) -> &str {
        &self.accepted.scheme
    }

    /// Get the network from the accepted field
    pub fn network(&self) -> &str {
        &self.accepted.network
    }

    /// Get the amount from the accepted field
    pub fn amount(&self) -> &str {
        &self.accepted.amount
    }

    /// Get the recipient address from the accepted field
    pub fn pay_to(&self) -> &str {
        &self.accepted.pay_to
    }

    /// Get the asset/token address from the accepted field
    #[allow(dead_code)]
    pub fn asset(&self) -> Option<&str> {
        self.accepted.token_address()
    }

    /// Extract transaction hash from payload (scheme-specific)
    pub fn tx_hash(&self) -> Option<String> {
        self.payload
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract sender address from payload (scheme-specific)
    #[allow(dead_code)]
    #[allow(clippy::collapsible_if)]
    pub fn from(&self) -> Option<String> {
        // Try authorization.from first (EVM style)
        if let Some(from) = self
            .payload
            .get("authorization")
            .and_then(|auth| auth.get("from"))
            .and_then(|v| v.as_str())
        {
            return Some(from.to_string());
        }
        // Fallback to top-level from
        self.payload
            .get("from")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract signature from payload (scheme-specific)
    pub fn signature(&self) -> Option<String> {
        self.payload
            .get("signature")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Get the asset transfer method (eip3009, permit2, or default to transaction)
    pub fn asset_transfer_method(&self) -> String {
        self.accepted
            .asset_transfer_method()
    }

    /// Extract EIP-3009 authorization data
    pub fn eip3009_authorization(&self) -> Option<Eip3009Authorization> {
        self.payload
            .get("authorization")
            .and_then(|auth| serde_json::from_value(auth.clone()).ok())
    }

    /// Extract Permit2 authorization data
    pub fn permit2_authorization(&self) -> Option<Permit2Authorization> {
        self.payload
            .get("permit2Authorization")
            .and_then(|auth| serde_json::from_value(auth.clone()).ok())
    }
}

/// EIP-3009 transferWithAuthorization parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    #[serde(rename = "validAfter")]
    pub valid_after: String,
    #[serde(rename = "validBefore")]
    pub valid_before: String,
    pub nonce: String,
}

/// Permit2 witness data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permit2Witness {
    pub to: String,
    #[serde(rename = "validAfter")]
    pub valid_after: String,
    pub extra: serde_json::Value,
}

/// Permit2 permitted token data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permit2Permitted {
    pub token: String,
    pub amount: String,
}

/// Permit2 permitWitnessTransferFrom parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permit2Authorization {
    pub permitted: Permit2Permitted,
    pub from: String,
    pub spender: String,
    pub nonce: String,
    pub deadline: String,
    pub witness: Permit2Witness,
}

/// Resource information for v2 PaymentRequired response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Resource URL
    pub url: String,

    /// Human-readable description
    pub description: String,

    /// Expected MIME type of response
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

/// Payment required response (v2 spec)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequired {
    /// x402 version (always 2)
    #[serde(rename = "x402Version")]
    pub x402_version: i32,

    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Resource information
    pub resource: ResourceInfo,

    /// Payment requirements (client can choose one)
    pub accepts: Vec<crate::config::types::X402PaymentRequirement>,

    /// Optional extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Payment response after successful verification/settlement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    /// Whether payment was verified
    pub verified: bool,

    /// Whether payment was settled
    pub settled: bool,

    /// Transaction hash (if settled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Settlement network
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Payment receipt or identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
}
