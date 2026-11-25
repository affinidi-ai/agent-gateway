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

    /// Extract transaction hash from payload (scheme-specific)
    pub fn tx_hash(&self) -> Option<String> {
        self.payload
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract sender address from payload (scheme-specific)
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
