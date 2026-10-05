//! Payment signing for X402 Proxy

use anyhow::{Context, Result, anyhow};
use serde_json::json;
use tracing::{debug, info};

use super::proxy_config::WalletBinding;
use crate::x402::{PaymentPayload, PaymentRequired};

/// Payment signer - handles signing x402 payments
pub struct PaymentSigner {
    /// Private key (loaded from secrets)
    private_key: String,

    /// Wallet binding configuration
    binding: WalletBinding,
}

impl PaymentSigner {
    /// Create a new payment signer
    pub fn new(
        private_key: String,
        binding: WalletBinding,
    ) -> Self {
        Self { private_key, binding }
    }

    /// Sign a payment request
    pub async fn sign_payment(
        &self,
        payment_required: &PaymentRequired,
    ) -> Result<PaymentPayload> {
        info!("Signing payment for network: {}", self.binding.network);

        // Select the best matching payment option from accepts array
        let accepted = self.select_payment_option(payment_required)?;

        // Sign based on network type and payment scheme
        let payload = match accepted.network.as_str() {
            n if self.is_evm_network(n) => {
                self.sign_evm_payment(payment_required, &accepted)
                    .await?
            }
            n if self.is_solana_network(n) => {
                self.sign_solana_payment(payment_required, &accepted)
                    .await?
            }
            network => {
                return Err(anyhow!("Unsupported network: {}", network));
            }
        };

        Ok(PaymentPayload {
            x402_version: 2,
            resource: Some(
                payment_required
                    .resource
                    .clone(),
            ),
            accepted: accepted.clone(),
            payload,
            extensions: None,
        })
    }

    /// Select the best payment option from the accepts array
    fn select_payment_option(
        &self,
        payment_required: &PaymentRequired,
    ) -> Result<crate::config::types::X402PaymentRequirement> {
        debug!("Selecting payment option from {} choices", payment_required.accepts.len());

        // Find options that match our network
        let network_matches: Vec<_> = payment_required
            .accepts
            .iter()
            .filter(|accept| accept.network == self.binding.network)
            .collect();

        if network_matches.is_empty() {
            return Err(anyhow!("No payment options available for network: {}", self.binding.network));
        }

        // Find options that match our supported symbols, prioritizing by our symbol priority
        // For native tokens, asset is empty or "native"
        let mut symbol_matches: Vec<_> = network_matches
            .iter()
            .filter_map(|accept| {
                // Check if this is a native token payment
                let is_native = accept.asset.is_empty() || accept.asset == "native";

                if is_native {
                    // Native token - find matching symbol config with "native" token_address
                    self.binding
                        .symbols
                        .iter()
                        .find(|s| s.token_address.as_deref() == Some("native"))
                        .map(|s| (accept, s.priority))
                } else {
                    // ERC20/SPL token - match by contract address (case-insensitive)
                    self.binding
                        .symbols
                        .iter()
                        .find(|s| {
                            s.token_address
                                .as_ref()
                                .map(|addr| addr.eq_ignore_ascii_case(&accept.asset))
                                .unwrap_or(false)
                        })
                        .map(|s| (accept, s.priority))
                }
            })
            .collect();

        if symbol_matches.is_empty() {
            return Err(anyhow!(
                "No payment options available for supported symbols: {:?}",
                self.binding
                    .symbols
                    .iter()
                    .map(|s| &s.symbol)
                    .collect::<Vec<_>>()
            ));
        }

        // Sort by priority (descending)
        symbol_matches.sort_by_key(|b| std::cmp::Reverse(b.1));

        // Return the highest priority option
        Ok((*symbol_matches[0].0).clone())
    }

    /// Check if network is EVM-based
    fn is_evm_network(
        &self,
        network: &str,
    ) -> bool {
        // Check for CAIP-2 format (eip155:chainId)
        if network.starts_with("eip155:") {
            return true;
        }

        // Legacy format checks (for backward compatibility)
        network.contains("ethereum")
            || network.contains("base")
            || network.contains("polygon")
            || network.contains("arbitrum")
            || network.contains("optimism")
            || network.ends_with("-sepolia")
            || network.ends_with("-goerli")
            || network.ends_with("-holesky")
    }

    /// Check if network is Solana-based
    fn is_solana_network(
        &self,
        network: &str,
    ) -> bool {
        // Check for CAIP-2 format (solana:genesisHash)
        if network.starts_with("solana:") {
            return true;
        }

        // Legacy format check (for backward compatibility)
        network.contains("solana")
    }

    /// Sign EVM payment (EIP-3009 or transaction)
    async fn sign_evm_payment(
        &self,
        payment_required: &PaymentRequired,
        accepted: &crate::config::types::X402PaymentRequirement,
    ) -> Result<serde_json::Value> {
        use alloy_signer_local::PrivateKeySigner;

        info!("Signing EVM payment using EIP-3009");

        // Parse private key
        let signer: PrivateKeySigner = self
            .private_key
            .parse()
            .context("Failed to parse EVM private key")?;

        // Verify address matches
        let derived_address = format!("{}", signer.address());
        if !derived_address.eq_ignore_ascii_case(&self.binding.address) {
            return Err(anyhow!(
                "Private key address mismatch: expected {}, got {}",
                self.binding.address,
                derived_address
            ));
        }

        // Check asset transfer method (default to EIP-3009)
        let asset_transfer_method = accepted
            .extra
            .as_ref()
            .and_then(|e| e.get("assetTransferMethod"))
            .or_else(|| {
                accepted
                    .extra
                    .as_ref()
                    .and_then(|e| e.get("asset_transfer_method"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or("eip3009");

        match asset_transfer_method {
            "eip3009" => {
                self.sign_eip3009(signer, payment_required, accepted)
                    .await
            }
            "transaction" => {
                self.sign_evm_transaction(signer, accepted)
                    .await
            }
            method => Err(anyhow!("Unsupported asset transfer method: {}", method)),
        }
    }

    /// Sign using EIP-3009 (transferWithAuthorization)
    async fn sign_eip3009(
        &self,
        signer: alloy_signer_local::PrivateKeySigner,
        _payment_required: &PaymentRequired,
        accepted: &crate::config::types::X402PaymentRequirement,
    ) -> Result<serde_json::Value> {
        use alloy_signer::Signer;

        // Extract EIP-712 domain from extra
        let extra = accepted
            .extra
            .as_ref()
            .ok_or_else(|| anyhow!("Missing extra field for EIP-3009"))?;

        let token_name = extra
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing token name in extra"))?;

        let token_version = extra
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing token version in extra"))?;

        let chain_id = extra
            .get("chainId")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("Missing chainId in extra"))?;

        let verifying_contract = extra
            .get("verifyingContract")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing verifyingContract in extra"))?;

        // Generate nonce (random 32 bytes as hex)
        let nonce = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));

        // Current timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let valid_after = "0"; // Valid immediately
        let valid_before = format!("{}", now + 3600); // Valid for 1 hour

        // Build authorization structure
        let authorization = json!({
            "from": format!("{}", signer.address()),
            "to": accepted.pay_to,
            "value": accepted.amount,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": nonce,
        });

        // Build EIP-712 domain
        let domain = json!({
            "name": token_name,
            "version": token_version,
            "chainId": chain_id,
            "verifyingContract": verifying_contract,
        });

        // Calculate EIP-712 hash
        // TODO: Implement proper EIP-712 hash calculation

        // Create struct hash (this is simplified - full implementation would use proper EIP-712 encoding)
        info!("Creating EIP-712 signature for EIP-3009 authorization");
        debug!("Domain: {}", serde_json::to_string_pretty(&domain)?);
        debug!("Authorization: {}", serde_json::to_string_pretty(&authorization)?);

        // For now, create a simple signature (TODO: implement proper EIP-712)
        // In production, you'd use proper EIP-712 typed data signing
        let message = format!(
            "TransferWithAuthorization\nfrom: {}\nto: {}\nvalue: {}\nvalidAfter: {}\nvalidBefore: {}\nnonce: {}",
            authorization["from"],
            authorization["to"],
            authorization["value"],
            authorization["validAfter"],
            authorization["validBefore"],
            authorization["nonce"]
        );

        let signature = signer
            .sign_message(message.as_bytes())
            .await?;
        let signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

        Ok(json!({
            "authorization": authorization,
            "signature": signature_hex,
            "domain": domain,
        }))
    }

    /// Sign EVM transaction
    async fn sign_evm_transaction(
        &self,
        signer: alloy_signer_local::PrivateKeySigner,
        accepted: &crate::config::types::X402PaymentRequirement,
    ) -> Result<serde_json::Value> {
        info!("Signing EVM transaction (not yet fully implemented)");

        // TODO: Implement transaction signing
        // For now, return a placeholder
        let address = signer.address();
        Ok(json!({
            "from": format!("{}", address),
            "to": accepted.pay_to,
            "value": accepted.amount,
            "type": "transaction",
        }))
    }

    /// Sign Solana payment
    async fn sign_solana_payment(
        &self,
        _payment_required: &PaymentRequired,
        _accepted: &crate::config::types::X402PaymentRequirement,
    ) -> Result<serde_json::Value> {
        info!("Signing Solana payment (not yet implemented)");

        // TODO: Implement Solana signing
        Err(anyhow!("Solana payment signing not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_detection() {
        let binding = WalletBinding {
            network: "base-sepolia".to_string(),
            address: "0x123".to_string(),
            private_key: "$SECRET:key".to_string(),
            symbols: vec![],
        };

        let signer = PaymentSigner::new("test".to_string(), binding);
        assert!(signer.is_evm_network("base-sepolia"));
        assert!(signer.is_evm_network("ethereum-mainnet"));
        assert!(!signer.is_evm_network("solana-devnet"));
        assert!(signer.is_solana_network("solana-devnet"));
    }
}
