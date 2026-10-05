//! Remote facilitator client using x402-rs
//!
//! This module provides a client for interacting with remote x402 facilitators
//! using the official x402-rs protocol implementation.

use super::PaymentPayload;
use super::x402rs_adapter;
use reqwest::Url;
use tracing::{debug, error, info};
use x402_types::proto;

/// Remote facilitator client
pub struct RemoteFacilitator {
    /// Base URL of the facilitator (e.g., "https://facilitator.x402.org")
    base_url: Url,
    /// HTTP client with configured timeouts
    client: reqwest::Client,
}

impl RemoteFacilitator {
    /// Create a new remote facilitator client.
    ///
    /// `base_url` is operator-configured (`settlement_mode = external_facilitator`),
    /// not attacker-influenceable, but it is still vetted and pinned with the same
    /// DNS-aware, fail-closed cloud-metadata policy the generic proxy forward uses:
    /// cloud-metadata addresses (literal or resolved) are rejected, while loopback
    /// and RFC 1918 stay allowed for a legitimate internal facilitator. The stored
    /// client is a redirect-disabled client pinned to the resolved address
    /// (`resolve_to_addrs`, TLS SNI preserved), so the host cannot rebind to an
    /// internal address between vetting and connect. Re-vetted and re-pinned on
    /// every construction, so an already-configured value is covered too. The
    /// blocking DNS resolve runs on `spawn_blocking`, off the async runtime.
    pub async fn new(base_url: &str) -> Result<Self, String> {
        let raw = base_url.to_string();
        let (client, target) = tokio::task::spawn_blocking(move || {
            crate::egress::pinned_forward_client(
                &raw,
                std::time::Duration::from_secs(crate::http_client::EXTERNAL_TIMEOUT_SECS),
            )
        })
        .await
        .map_err(|e| format!("Facilitator pin task failed: {e}"))?
        .map_err(|e| format!("Invalid facilitator URL: {}", e))?;

        Ok(Self { base_url: target.url, client })
    }

    /// Verify a payment via the remote facilitator
    pub async fn verify(
        &self,
        payload: &PaymentPayload,
        channel_name: &str,
    ) -> Result<proto::VerifyResponse, String> {
        // Convert to x402-rs VerifyRequest
        let verify_request = x402rs_adapter::to_verify_request(payload)?;

        // Serialize request for logging
        let request_json = serde_json::to_string(&verify_request).unwrap_or_else(|_| "Failed to serialize".to_string());

        info!(
            channel = channel_name,
            facilitator = %self.base_url,
            "🌐 [X402 VERIFY] Calling external facilitator"
        );
        debug!("📤 [X402 VERIFY] Request: {}", request_json);

        // Call facilitator /verify endpoint
        let response = self
            .client
            .post(
                self.base_url
                    .join("/verify")
                    .map_err(|e| e.to_string())?,
            )
            .header("Content-Type", "application/json")
            .json(&verify_request)
            .send()
            .await
            .map_err(|e| format!("Failed to call facilitator: {}", e))?;

        let status = response.status();
        info!("📥 [X402 VERIFY] Response status: {}", status);

        // Read response body
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        debug!("📥 [X402 VERIFY] Response body: {}", body);

        if !status.is_success() {
            error!(
                channel = channel_name,
                status = %status,
                body = %body,
                facilitator = %self.base_url,
                "❌ Facilitator verification failed"
            );
            return Err(format!("Facilitator rejected payment: {} - {}", status, body));
        }

        // Parse response using x402-rs types
        let verify_response: proto::VerifyResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Invalid facilitator response JSON: {} - Body: {}", e, body))?;

        // Check if verification was valid
        if !x402rs_adapter::is_verification_valid(&verify_response) {
            let reason =
                x402rs_adapter::extract_verify_error(&verify_response).unwrap_or_else(|| "Unknown error".to_string());
            error!(
                channel = channel_name,
                reason = %reason,
                "❌ Payment verification failed"
            );
            return Err(format!("Payment verification failed: {}", reason));
        }

        info!(
            channel = channel_name,
            payer = ?x402rs_adapter::extract_payer(&verify_response),
            "✅ Payment verified successfully"
        );

        Ok(verify_response)
    }

    /// Settle a payment via the remote facilitator
    pub async fn settle(
        &self,
        payload: &PaymentPayload,
        channel_name: &str,
        channel_id: &str,
    ) -> Result<proto::SettleResponse, String> {
        // Convert to x402-rs SettleRequest
        let settle_request = x402rs_adapter::to_settle_request(payload)?;

        // Serialize request for logging
        let request_json = serde_json::to_string(&settle_request).unwrap_or_else(|_| "Failed to serialize".to_string());

        info!(
            channel = channel_name,
            facilitator = %self.base_url,
            network = %payload.network(),
            amount = %payload.amount(),
            "🌐 [X402 SETTLE] Calling external facilitator"
        );
        debug!("📤 [X402 SETTLE] Request: {}", request_json);

        // Call facilitator /settle endpoint
        let response = self
            .client
            .post(
                self.base_url
                    .join("/settle")
                    .map_err(|e| e.to_string())?,
            )
            .header("Content-Type", "application/json")
            .json(&settle_request)
            .send()
            .await
            .map_err(|e| format!("Failed to call facilitator /settle: {}", e))?;

        let status = response.status();
        info!("📥 [X402 SETTLE] Response status: {}", status);

        // Read response body
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        debug!("📥 [X402 SETTLE] Response body: {}", body);

        if !status.is_success() {
            error!(
                channel = channel_name,
                status = %status,
                body = %body,
                facilitator = %self.base_url,
                "❌ Facilitator settlement failed"
            );
            return Err(format!("Facilitator settlement failed: {} - {}", status, body));
        }

        // Parse response using x402-rs types
        let settle_response: proto::SettleResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Invalid facilitator settlement response JSON: {} - Body: {}", e, body))?;

        // Check if settlement was successful
        if !x402rs_adapter::is_settlement_successful(&settle_response) {
            let reason =
                x402rs_adapter::extract_settle_error(&settle_response).unwrap_or_else(|| "Unknown error".to_string());
            error!(
                channel = channel_name,
                reason = %reason,
                "❌ Facilitator settlement failed"
            );
            return Err(format!("Facilitator settlement failed: {}", reason));
        }

        let tx_hash = x402rs_adapter::extract_transaction(&settle_response).unwrap_or_else(|| "unknown".to_string());

        info!("✅ [{}] Payment settled successfully. Transaction: {}", channel_id, tx_hash);

        Ok(settle_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_facilitator_creation() {
        // A real, DNS-resolvable, non-metadata host — construction now validates
        // the URL (parse + resolve + block cloud metadata), so a syntactically
        // valid but unresolvable placeholder domain no longer suffices here.
        let facilitator = RemoteFacilitator::new("https://example.com").await;
        assert!(facilitator.is_ok());

        let bad_facilitator = RemoteFacilitator::new("not a url").await;
        assert!(bad_facilitator.is_err());
    }

    #[tokio::test]
    async fn rejects_cloud_metadata_facilitator_url() {
        let blocked = RemoteFacilitator::new("http://169.254.169.254/latest/meta-data/").await;
        assert!(blocked.is_err(), "metadata-endpoint facilitator URL must be rejected");
    }

    #[tokio::test]
    async fn allows_loopback_facilitator_url() {
        // Operator-configured internal/loopback facilitators remain legitimate.
        let local = RemoteFacilitator::new("http://127.0.0.1:8402").await;
        assert!(local.is_ok(), "loopback facilitator URL should be permitted");
    }
}
