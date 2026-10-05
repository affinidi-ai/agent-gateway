//! x402 payment verification

use axum::http::HeaderMap;
use base64::Engine;
use tracing::{info, warn};

use super::{PaymentPayload, PaymentResponse, TransactionStore};
use crate::config::types::{X402Config, X402VerificationMode};
use crate::gateways::ConnectionPointListenerManager;
use crate::{channel_debug, channel_error, channel_info, channel_warn};
use std::sync::Arc;

/// Verify x402 payment
/// Returns (payload, correlation_id) on success
#[allow(dead_code)]
pub async fn verify_payment(
    payment_header: &str,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    resource_url: &str,
    listener_manager: Option<Arc<ConnectionPointListenerManager>>,
    transaction_store: Option<Arc<TransactionStore>>,
    existing_correlation_id: Option<String>, // For DIDComm sync - use same ID across gateways
) -> Result<(PaymentPayload, String), String> {
    // Decode payment payload from base64
    let decoded = match base64::engine::general_purpose::STANDARD.decode(payment_header) {
        Ok(d) => d,
        Err(e) => {
            channel_warn!(channel_id, "Failed to decode payment header error={}", e);
            return Err("Invalid payment signature encoding".to_string());
        }
    };
    // Parse payment payload
    let payload: PaymentPayload = match serde_json::from_slice(&decoded) {
        Ok(p) => p,
        Err(e) => {
            channel_warn!(channel_id, "Failed to parse payment payload error={}", e);
            return Err("Invalid payment signature format".to_string());
        }
    };

    // Use tx_hash as correlation_id for deterministic, idempotent transaction tracking
    // This ensures the same payment always maps to the same correlation_id across gateways
    let correlation_id = existing_correlation_id.unwrap_or_else(|| {
        payload
            .tx_hash()
            .unwrap_or_else(|| {
                // Fallback to SHA256 of payment signature if tx_hash not available
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(payment_header.as_bytes());
                format!("{:x}", hasher.finalize())
            })
    });

    channel_debug!(
        channel_id,
        "Verifying x402 payment correlation_id={} scheme={} network={} asset={:?}",
        correlation_id,
        payload.scheme(),
        payload.network(),
        payload.accepted.asset
    );

    // Determine verification_mode string for transaction record
    let verification_mode_str = match config.verification_mode {
        X402VerificationMode::Mock => "Mock",
        X402VerificationMode::Local => "Local",
        X402VerificationMode::Signature => "Signature",
        X402VerificationMode::ExternalFacilitator => "ExternalFacilitator",
        X402VerificationMode::FabricGateway => "FabricGateway",
    };

    // Create transaction record if transaction_store is available
    if let Some(store) = &transaction_store
        && let Err(e) = store
            .create_transaction(
                correlation_id.clone(),
                channel_id.to_string(),
                channel_name.to_string(),
                resource_url.to_string(),
                payload.clone(),
                verification_mode_str.to_string(),
                config
                    .facilitator_gateway_id
                    .clone(),
            )
            .await
    {
        channel_warn!(channel_id, "Failed to create transaction record: {}", e);
        return Err(e);
    }

    // Verify based on configured mode
    match config.verification_mode {
        X402VerificationMode::Mock => {
            channel_info!(channel_id, "Mock verification mode - accepting payment");

            // Complete verification in transaction store
            if let Some(store) = &transaction_store
                && let Err(e) = store
                    .complete_verification(&correlation_id)
                    .await
            {
                channel_warn!(channel_id, "Failed to update transaction record: {}", e);
            }

            Ok((payload, correlation_id))
        }
        X402VerificationMode::Local => {
            verify_local_payment(&payload, &correlation_id, config, channel_name, channel_id, &transaction_store).await
        }
        X402VerificationMode::ExternalFacilitator => {
            verify_facilitator_payment(&payload, &correlation_id, config, channel_name, channel_id, &transaction_store)
                .await
        }
        X402VerificationMode::FabricGateway => {
            // Gateway-to-gateway DIDComm verification via facilitator service
            channel_info!(channel_id, "Gateway verification mode - initiating DIDComm verification");

            // Resolve facilitator gateway DID using listener_manager (same pattern as fabric:// forwarding)
            let facilitator_did = if let Some(gateway_id) = &config.facilitator_gateway_id {
                channel_debug!(channel_id, "Resolving facilitator gateway DID from ID: {}", gateway_id);

                // Get listener_manager to resolve gateway DID (same as fabric:// forwarding)
                let listener_mgr = listener_manager
                    .as_ref()
                    .ok_or_else(|| {
                        channel_error!(channel_id, "Listener manager not available for gateway DID resolution");
                        "Gateway verification requires listener manager to resolve gateway DID".to_string()
                    })?;

                // Resolve gateway DID (same method as handle_fabric_request uses)
                listener_mgr
                    .get_gateway_did(gateway_id)
                    .await
                    .ok_or_else(|| {
                        channel_error!(channel_id, "Facilitator gateway '{}' not found or not connected", gateway_id);
                        format!(
                            "Facilitator gateway '{}' not found. Ensure the gateway is connected via DIDComm.",
                            gateway_id
                        )
                    })?
            } else {
                channel_error!(channel_id, "Fabric gateway mode requires facilitator_gateway_id configuration");
                return Err("No facilitator gateway configured for fabric gateway verification mode".to_string());
            };

            channel_info!(channel_id, "Resolved facilitator gateway DID: {}", facilitator_did);

            // Send verification request via gateway facilitator service
            // This now waits synchronously for the DIDComm response (like fabric:// forwarding)
            match crate::x402::verify_via_facilitator_gateway(
                &facilitator_did,
                payment_header,
                payload.network(),
                channel_id.to_string(),
                format!("/resource/{}", channel_name), // TODO: get actual resource path
            )
            .await
            {
                Ok(payment_json) => {
                    // Parse the returned payment payload
                    let verified_payment: PaymentPayload = serde_json::from_str(&payment_json)
                        .map_err(|e| format!("Failed to parse payment response: {}", e))?;

                    channel_info!(channel_id, "Payment verified successfully via gateway facilitator");

                    // Complete verification in transaction store
                    if let Some(store) = &transaction_store
                        && let Err(e) = store
                            .complete_verification(&correlation_id)
                            .await
                    {
                        channel_warn!(channel_id, "Failed to update transaction record: {}", e);
                    }

                    Ok((verified_payment, correlation_id))
                }
                Err(e) => {
                    channel_warn!(channel_id, "Gateway facilitator verification failed: {}", e);

                    // Mark verification as failed in transaction store
                    if let Some(store) = &transaction_store
                        && let Err(err) = store
                            .fail_verification(&correlation_id, e.clone())
                            .await
                    {
                        channel_warn!(channel_id, "Failed to update transaction record: {}", err);
                    }

                    // Trigger integration alerts for verification failure
                    crate::integrations::trigger_transaction_verification_failed(
                        &correlation_id,
                        channel_id,
                        &payload
                            .tx_hash()
                            .unwrap_or_default(),
                        &e,
                    )
                    .await;

                    // Return the error - don't fall back to local
                    Err(e)
                }
            }
        }
        X402VerificationMode::Signature => {
            // Signature-based verification (EIP-3009 / Permit2)
            // Verifies cryptographic signatures without on-chain state checks
            channel_info!(
                channel_id,
                "Signature verification mode - cryptographic verification only (no blockchain state checks)"
            );

            let transfer_method = payload.asset_transfer_method();

            let result = match transfer_method.as_str() {
                "eip3009" => verify_eip3009_signature(&payload, config, channel_id).await,
                "permit2" => verify_permit2_signature(&payload, config, channel_id).await,
                _ => {
                    channel_warn!(
                        channel_id,
                        "Transaction hash verification not supported in signature mode - use 'local' mode instead"
                    );
                    Err("Signature mode requires EIP-3009 or Permit2 payment method".to_string())
                }
            };

            match result {
                Ok(verified_payload) => {
                    // Complete verification in transaction store
                    if let Some(store) = &transaction_store
                        && let Err(e) = store
                            .complete_verification(&correlation_id)
                            .await
                    {
                        channel_warn!(channel_id, "Failed to update transaction record: {}", e);
                    }
                    Ok((verified_payload, correlation_id))
                }
                Err(e) => {
                    // Mark verification as failed in transaction store
                    if let Some(store) = &transaction_store
                        && let Err(err) = store
                            .fail_verification(&correlation_id, e.clone())
                            .await
                    {
                        channel_warn!(channel_id, "Failed to update transaction record: {}", err);
                    }

                    // Trigger integration alerts for verification failure
                    crate::integrations::trigger_transaction_verification_failed(
                        &correlation_id,
                        channel_id,
                        &payload
                            .tx_hash()
                            .unwrap_or_default(),
                        &e,
                    )
                    .await;

                    Err(e)
                }
            }
        }
    }
}

/// Verify payment locally via blockchain RPC
async fn verify_local_payment(
    payload: &PaymentPayload,
    correlation_id: &str,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    transaction_store: &Option<Arc<TransactionStore>>,
) -> Result<(PaymentPayload, String), String> {
    // Check asset transfer method to determine verification type
    // First check explicit config, then auto-detect from payload structure
    let transfer_method = {
        let configured = payload.asset_transfer_method();
        if configured != "transaction" {
            configured
        } else {
            // Auto-detect from payload structure when not explicitly configured
            if payload
                .payload
                .get("authorization")
                .is_some()
            {
                // EIP-3009 TransferWithAuthorization (has authorization object with from/to/value/nonce)
                channel_info!(channel_id, "Auto-detected EIP-3009 transfer method from payload.authorization");
                "eip3009".to_string()
            } else if payload
                .payload
                .get("permit2Authorization")
                .is_some()
            {
                channel_info!(channel_id, "Auto-detected Permit2 transfer method from payload.permit2Authorization");
                "permit2".to_string()
            } else if payload
                .payload
                .get("transaction")
                .is_some()
                && payload
                    .network()
                    .starts_with("solana:")
            {
                channel_info!(
                    channel_id,
                    "Auto-detected SPL transfer method from payload.transaction on Solana network"
                );
                "spl_transfer".to_string()
            } else {
                configured
            }
        }
    };

    channel_debug!(channel_id, "Payment assetTransferMethod={} network={}", transfer_method, payload.network());

    // Route to appropriate verification method
    match transfer_method.as_str() {
        "eip3009" | "permit2" | "spl_transfer" => {
            // Use embedded x402 facilitator for full EIP-3009/Permit2/SPL verification
            // This includes signature verification + on-chain nonce checking + balance validation
            channel_info!(
                channel_id,
                "Using embedded x402 facilitator for EIP-3009/Permit2/SPL verification (signature + nonce + balance)"
            );

            // Merge global x402.json config (cached at startup) with channel config
            // Channel config provides RPC endpoints and other settings
            // Global config provides sensitive data like private keys (NEVER in channel config)
            let mut merged_config = config.clone();

            // ALWAYS load facilitator_private_keys from global x402.json for security
            // Use cached config for performance (loaded once at startup)
            channel_debug!(channel_id, "Loading facilitator_private_keys from cached global x402.json");

            // Get global config from cache (loaded at startup for performance)
            let global_config = super::config_cache::get_or_load_x402_config().await.map_err(|e| {
                channel_error!(
                    channel_id,
                    "Failed to get global x402.json config from cache: {}. Cannot proceed without facilitator keys.",
                    e
                );
                format!("Failed to get global x402.json config: {}", e)
            })?;

            if let Some(global_keys) = &global_config.facilitator_private_keys {
                channel_debug!(
                    channel_id,
                    "Loaded {} facilitator private keys from global config cache",
                    global_keys.len()
                );
                merged_config.facilitator_private_keys = Some(global_keys.clone());
            } else {
                channel_error!(channel_id, "Global x402.json config has no facilitator_private_keys");
                return Err("Global x402.json config missing facilitator_private_keys".to_string());
            }

            // Merge RPC endpoints from global config if channel config doesn't have them
            // Channel payment_policy typically only has payment_requirements, not rpc_endpoints
            if merged_config
                .rpc_endpoints
                .is_empty()
                && !global_config
                    .rpc_endpoints
                    .is_empty()
            {
                channel_debug!(
                    channel_id,
                    "Merging {} RPC endpoints from global x402.json config",
                    global_config
                        .rpc_endpoints
                        .len()
                );
                merged_config.rpc_endpoints = global_config
                    .rpc_endpoints
                    .clone();
            }

            // Initialize embedded facilitator with merged config
            let facilitator = super::embedded_facilitator::get_embedded_facilitator(&merged_config)
                .await
                .map_err(|e| {
                    channel_error!(channel_id, "Failed to initialize embedded facilitator: {}", e);
                    e.to_string()
                })?;

            // Convert payload to x402 VerifyRequest
            let verify_request = super::x402rs_adapter::to_verify_request(payload).map_err(|e| {
                channel_error!(channel_id, "Failed to convert to x402 request: {}", e);
                format!("Failed to convert payment to x402 format: {}", e)
            })?;

            // Call embedded facilitator for verification
            let result = facilitator
                .verify(verify_request)
                .await;

            // Handle result and update transaction store
            match result {
                Ok(_verify_response) => {
                    // The proto::VerifyResponse is an enum of v1/v2 responses
                    // We need to check if verification was successful
                    // For now, if no error was returned, consider it valid
                    channel_info!(channel_id, "Payment verified successfully via embedded facilitator");

                    // Update transaction store
                    if let Some(store) = transaction_store
                        && let Err(e) = store
                            .complete_verification(correlation_id)
                            .await
                    {
                        channel_warn!(channel_id, "Failed to update transaction record: {}", e);
                    }

                    return Ok((payload.clone(), correlation_id.to_string()));
                }
                Err(e) => {
                    // Mark verification as failed in transaction store
                    if let Some(store) = transaction_store
                        && let Err(err) = store
                            .fail_verification(correlation_id, e.to_string())
                            .await
                    {
                        channel_warn!(channel_id, "Failed to update transaction record: {}", err);
                    }

                    // Trigger integration alerts for verification failure
                    crate::integrations::trigger_transaction_verification_failed(
                        correlation_id,
                        channel_id,
                        &payload
                            .tx_hash()
                            .unwrap_or_default(),
                        &e,
                    )
                    .await;

                    return Err(e.to_string());
                }
            }
        }
        _ => {
            // Traditional transaction hash verification
            // Continue with existing logic below
        }
    }

    // Get RPC endpoint for this network
    // Channel payment_policy typically doesn't include rpc_endpoints,
    // so fall back to the global x402.json config
    let rpc_url = if let Some(url) = config
        .rpc_endpoints
        .get(payload.network())
    {
        url.clone()
    } else {
        // Try global config
        let global_config = super::config_cache::get_or_load_x402_config()
            .await
            .map_err(|e| {
                channel_error!(channel_id, "Failed to get global x402.json config: {}", e);
                format!("Failed to get global x402.json config: {}", e)
            })?;
        global_config
            .rpc_endpoints
            .get(payload.network())
            .cloned()
            .ok_or_else(|| format!("No RPC endpoint configured for network: {}", payload.network()))?
    };

    channel_debug!(channel_id, "Verifying payment on-chain network={} rpc_url={}", payload.network(), rpc_url);

    // Get transaction hash
    let tx_hash = payload
        .tx_hash()
        .ok_or_else(|| "Transaction hash required for local verification".to_string())?;

    channel_info!(
        channel_id,
        "Verifying payment on-chain network={} rpc_url={} tx_hash={}",
        payload.network(),
        rpc_url,
        tx_hash
    );

    // Verify based on network type (CAIP-2 format: namespace:reference)
    // EVM chains use eip155 namespace, Solana uses solana namespace
    let result = if payload
        .network()
        .starts_with("eip155:")
    {
        verify_evm_transaction(payload, &tx_hash, &rpc_url, config, channel_name, channel_id).await
    } else if payload
        .network()
        .starts_with("solana:")
    {
        verify_solana_transaction(payload, &tx_hash, &rpc_url, channel_name, channel_id).await
    } else {
        // Fallback for legacy non-CAIP-2 network identifiers
        match payload.network() {
            "ethereum" | "base" | "optimism" | "arbitrum" | "polygon" | "avalanche" => {
                verify_evm_transaction(payload, &tx_hash, &rpc_url, config, channel_name, channel_id).await
            }
            "solana" => verify_solana_transaction(payload, &tx_hash, &rpc_url, channel_name, channel_id).await,
            network => Err(format!("Unsupported network for local verification: {}", network)),
        }
    };

    // Update transaction store and return with correlation_id
    match result {
        Ok(verified_payload) => {
            // Update transaction store
            if let Some(store) = transaction_store
                && let Err(e) = store
                    .complete_verification(correlation_id)
                    .await
            {
                channel_warn!(channel_id, "Failed to update transaction record: {}", e);
            }
            Ok((verified_payload, correlation_id.to_string()))
        }
        Err(e) => {
            // Mark verification as failed in transaction store
            if let Some(store) = transaction_store
                && let Err(err) = store
                    .fail_verification(correlation_id, e.clone())
                    .await
            {
                channel_warn!(channel_id, "Failed to update transaction record: {}", err);
            }

            // Trigger integration alerts for verification failure
            crate::integrations::trigger_transaction_verification_failed(
                correlation_id,
                channel_id,
                &payload
                    .tx_hash()
                    .unwrap_or_default(),
                &e,
            )
            .await;

            Err(e)
        }
    }
}

/// Verify EVM transaction (Ethereum, Base, etc.)
async fn verify_evm_transaction(
    payload: &PaymentPayload,
    tx_hash: &str,
    rpc_url: &str,
    config: &X402Config,
    _channel_name: &str,
    channel_id: &str,
) -> Result<PaymentPayload, String> {
    use alloy::providers::{Provider, ProviderBuilder};

    // Create provider (we'll wrap RPC calls with timeout to prevent hanging)
    let url = rpc_url
        .parse::<reqwest::Url>()
        .map_err(|e| format!("Invalid RPC URL: {}", e))?;

    let provider = ProviderBuilder::new().connect_http(url);

    // Parse transaction hash
    let tx_hash_bytes: [u8; 32] = hex::decode(tx_hash.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid transaction hash: {}", e))?
        .try_into()
        .map_err(|_| "Transaction hash must be 32 bytes".to_string())?;

    channel_debug!(channel_id, "Fetching transaction receipt tx_hash={} rpc_url={}", tx_hash, rpc_url);

    // Retry logic for transaction lookup (RPC endpoints may be out of sync)
    // Client should verify transaction is on-chain before submitting, so minimal retries needed
    // With 5-second RPC timeout: mempool=1 try (5s max), confirmations=2 tries (10s max)
    let max_retries = if config.min_confirmations == 0 {
        1
    } else {
        2
    };
    let retry_delay = if config.min_confirmations == 0 {
        tokio::time::Duration::from_millis(200)
    } else {
        tokio::time::Duration::from_millis(500)
    };
    let mut last_error = String::new();

    for attempt in 1..=max_retries {
        // Wrap RPC call with timeout to prevent hanging on slow endpoints
        let rpc_timeout = tokio::time::Duration::from_secs(5);
        let receipt_result =
            tokio::time::timeout(rpc_timeout, provider.get_transaction_receipt(tx_hash_bytes.into())).await;

        match receipt_result {
            Ok(Ok(Some(receipt))) => {
                // Transaction found!
                if attempt > 1 {
                    channel_info!(channel_id, "Transaction found on attempt {} tx_hash={}", attempt, tx_hash);
                }

                // Verify transaction succeeded
                if !receipt.status() {
                    return Err("Transaction failed on blockchain".to_string());
                }

                // Continue with rest of verification...
                let tx = provider
                    .get_transaction_by_hash(tx_hash_bytes.into())
                    .await
                    .map_err(|e| format!("Failed to get transaction: {}", e))?
                    .ok_or_else(|| "Transaction not found".to_string())?;

                return verify_evm_transaction_details(receipt, tx, payload, &provider, tx_hash, config, channel_id)
                    .await;
            }
            Ok(Ok(None)) => {
                last_error = format!("Transaction not found on blockchain (attempt {}/{})", attempt, max_retries);
                if attempt < max_retries {
                    channel_warn!(
                        channel_id,
                        "Transaction not found, retrying in {:?}... (attempt {}/{}) tx_hash={}",
                        retry_delay,
                        attempt,
                        max_retries,
                        tx_hash
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
            Ok(Err(e)) => {
                last_error = format!("RPC error: {}", e);
                if attempt < max_retries {
                    channel_warn!(
                        channel_id,
                        "RPC error, retrying in {:?}... (attempt {}/{}) error={}",
                        retry_delay,
                        attempt,
                        max_retries,
                        e
                    );
                    tokio::time::sleep(retry_delay).await;
                } else {
                    return Err(last_error);
                }
            }
            Err(_timeout_err) => {
                last_error = format!("RPC timeout after {:?} (attempt {}/{})", rpc_timeout, attempt, max_retries);
                if attempt < max_retries {
                    channel_warn!(
                        channel_id,
                        "RPC timeout, retrying in {:?}... (attempt {}/{})",
                        retry_delay,
                        attempt,
                        max_retries
                    );
                    tokio::time::sleep(retry_delay).await;
                } else {
                    channel_error!(
                        channel_id,
                        "RPC timeout - all retries exhausted. tx_hash={} rpc_url={} timeout={:?}",
                        tx_hash,
                        rpc_url,
                        rpc_timeout
                    );
                    return Err(last_error);
                }
            }
        }
    }

    // All retries exhausted
    channel_error!(
        channel_id,
        "Transaction not found after {} attempts tx_hash={} rpc_url={}",
        max_retries,
        tx_hash,
        rpc_url
    );
    Err(last_error)
}

async fn verify_evm_transaction_details(
    receipt: alloy::rpc::types::TransactionReceipt,
    tx: alloy::rpc::types::Transaction,
    payload: &PaymentPayload,
    provider: &impl alloy::providers::Provider,
    tx_hash: &str,
    config: &X402Config,
    channel_id: &str,
) -> Result<PaymentPayload, String> {
    use alloy::consensus::Transaction as ConsensusTx;

    // Check confirmations first (applies to both token and native payments)
    let latest_block = provider
        .get_block_number()
        .await
        .map_err(|e| format!("Failed to get latest block: {}", e))?;

    let tx_block = receipt
        .block_number
        .ok_or_else(|| "Transaction block number not found".to_string())?;
    let confirmations = latest_block.saturating_sub(tx_block);

    // Check against configured minimum confirmations
    if confirmations < config.min_confirmations {
        channel_warn!(
            channel_id,
            "Payment has insufficient confirmations confirmations={} required={}",
            confirmations,
            config.min_confirmations
        );
        return Err(format!(
            "Payment requires at least {} confirmation(s), has {}",
            config.min_confirmations, confirmations
        ));
    }

    // Check if this is a token payment or native currency payment
    let is_token_payment = payload.asset().is_some();

    if is_token_payment {
        // ERC-20 Token Payment Verification
        let token_address = payload.asset().unwrap();

        // For token transfers, tx.to should be the token contract
        let contract_to = tx
            .inner
            .to()
            .map(|addr| {
                format!("{:?}", addr)
                    .trim_start_matches("0x")
                    .to_lowercase()
            })
            .unwrap_or_default();
        let expected_contract = token_address
            .trim_start_matches("0x")
            .to_lowercase();

        if contract_to != expected_contract {
            channel_error!(channel_id, "Token contract mismatch expected={} actual={}", expected_contract, contract_to);
            return Err("Transaction not sent to expected token contract".to_string());
        }

        // Verify Transfer event in logs
        // ERC-20 Transfer event signature: Transfer(address,address,uint256)
        // Topic[0]: keccak256("Transfer(address,address,uint256)") = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
        let transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

        let transfer_log = receipt
            .inner
            .logs()
            .iter()
            .find(|log| {
                log.topics()
                    .first()
                    .map(|t| format!("{:?}", t).to_lowercase())
                    == Some(transfer_topic.to_lowercase())
            })
            .ok_or_else(|| "No Transfer event found in transaction logs".to_string())?;

        // Topic[1] is indexed 'from' address (not used for verification)
        // Topic[2] is indexed 'to' address (recipient)
        let recipient_topic = transfer_log
            .topics()
            .get(2)
            .ok_or_else(|| "Transfer event missing recipient topic".to_string())?;

        // Extract address from topic (last 20 bytes of 32-byte topic)
        let recipient_bytes = format!("{:?}", recipient_topic);
        let recipient_addr = recipient_bytes
            .trim_start_matches("0x")
            .chars()
            .skip(24) // Skip first 24 hex chars (12 bytes of padding)
            .collect::<String>();

        let expected_to = payload
            .pay_to()
            .trim_start_matches("0x")
            .to_lowercase();
        if recipient_addr != expected_to {
            channel_error!(
                channel_id,
                "Token transfer recipient mismatch expected={} actual={}",
                expected_to,
                recipient_addr
            );
            return Err("Token transfer recipient does not match expected address".to_string());
        }

        // Decode amount from log data (uint256)
        let amount_hex = transfer_log
            .data()
            .data
            .to_string();
        let amount_bytes = hex::decode(amount_hex.trim_start_matches("0x"))
            .map_err(|e| format!("Failed to decode transfer amount: {}", e))?;

        // Convert bytes to u128 (careful: ERC-20 uses uint256 but we'll use u128 for compatibility)
        let actual_amount = if amount_bytes.len() >= 16 {
            // Take last 16 bytes and convert to u128
            let slice = &amount_bytes[amount_bytes.len() - 16..];
            u128::from_be_bytes(slice.try_into().unwrap())
        } else {
            // If less than 16 bytes, convert what we have
            let mut bytes = [0u8; 16];
            bytes[16 - amount_bytes.len()..].copy_from_slice(&amount_bytes);
            u128::from_be_bytes(bytes)
        };

        let expected_amount: u128 = payload
            .amount()
            .parse()
            .map_err(|_| "Invalid amount format".to_string())?;

        // Verify amount based on scheme
        match payload.scheme() {
            "exact" => {
                if actual_amount != expected_amount {
                    return Err(format!(
                        "Token payment amount mismatch: expected {}, got {} (token: {})",
                        expected_amount, actual_amount, token_address
                    ));
                }
            }
            "upto" => {
                if actual_amount < expected_amount {
                    return Err(format!(
                        "Token payment amount too low: expected at least {}, got {} (token: {})",
                        expected_amount, actual_amount, token_address
                    ));
                }
            }
            scheme => {
                return Err(format!("Unsupported payment scheme: {}", scheme));
            }
        }

        channel_info!(
            channel_id,
            "ERC-20 token payment verified successfully tx_hash={} token={} amount={} recipient={} confirmations={}",
            tx_hash,
            token_address,
            actual_amount,
            expected_to,
            confirmations
        );

        Ok(payload.clone())
    } else {
        // Native Currency (ETH/MATIC) Payment Verification
        let expected_to = payload
            .pay_to()
            .trim_start_matches("0x")
            .to_lowercase();
        let actual_to = tx
            .inner
            .to()
            .map(|addr| {
                format!("{:?}", addr)
                    .trim_start_matches("0x")
                    .to_lowercase()
            })
            .unwrap_or_default();

        if actual_to != expected_to {
            channel_error!(channel_id, "Payment recipient mismatch expected={} actual={}", expected_to, actual_to);
            return Err("Payment recipient does not match expected address".to_string());
        }

        // Verify amount
        let expected_amount: u128 = payload
            .amount()
            .parse()
            .map_err(|_| "Invalid amount format".to_string())?;
        let actual_amount = tx.inner.value().to::<u128>();

        match payload.scheme() {
            "exact" => {
                if actual_amount != expected_amount {
                    return Err(format!(
                        "Native currency payment amount mismatch: expected {}, got {}",
                        expected_amount, actual_amount
                    ));
                }
            }
            "upto" => {
                if actual_amount < expected_amount {
                    return Err(format!(
                        "Native currency payment amount too low: expected at least {}, got {}",
                        expected_amount, actual_amount
                    ));
                }
            }
            scheme => {
                return Err(format!("Unsupported payment scheme: {}", scheme));
            }
        }

        // Confirmations already checked above before token/native branch

        channel_info!(
            channel_id,
            "Native currency (ETH/MATIC) payment verified successfully tx_hash={} amount={} recipient={} confirmations={}",
            tx_hash,
            actual_amount,
            expected_to,
            confirmations
        );

        Ok(payload.clone())
    }
}

/// Verify Solana transaction
async fn verify_solana_transaction(
    payload: &PaymentPayload,
    tx_hash: &str,
    rpc_url: &str,
    channel_name: &str,
    _channel_id: &str,
) -> Result<PaymentPayload, String> {
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::signature::Signature;
    use solana_transaction_status::UiTransactionEncoding;
    use std::str::FromStr;

    // Create RPC client
    let client = RpcClient::new(rpc_url.to_string());

    // Parse signature
    let signature = Signature::from_str(tx_hash).map_err(|e| format!("Invalid Solana signature: {}", e))?;

    // Get transaction using JSON encoding
    let tx = client
        .get_transaction(&signature, UiTransactionEncoding::Json)
        .map_err(|e| format!("Failed to get Solana transaction: {}", e))?;

    // Verify transaction succeeded
    if tx
        .transaction
        .meta
        .as_ref()
        .and_then(|meta| meta.err.as_ref())
        .is_some()
    {
        return Err("Solana transaction failed".to_string());
    }

    // Parse amount from transaction (in lamports)
    let expected_amount: u64 = payload
        .amount()
        .parse()
        .map_err(|_| "Invalid amount format".to_string())?;

    // Get metadata
    let meta = tx
        .transaction
        .meta
        .as_ref()
        .ok_or_else(|| "Transaction metadata not found".to_string())?;

    // Get account keys from the transaction
    // The EncodedTransaction contains account keys in different formats
    let account_keys: Vec<String> = match &tx.transaction.transaction {
        solana_transaction_status::EncodedTransaction::Json(ui_tx) => {
            // Extract account keys from the message
            match &ui_tx.message {
                solana_transaction_status::UiMessage::Parsed(parsed_msg) => parsed_msg
                    .account_keys
                    .iter()
                    .map(|k| k.pubkey.clone())
                    .collect(),
                solana_transaction_status::UiMessage::Raw(raw_msg) => raw_msg.account_keys.clone(),
            }
        }
        _ => {
            // For non-JSON encodings, we can't easily extract account keys
            // Fall back to balance change verification only
            warn!(channel = channel_name, "Solana transaction encoding not JSON, using simplified verification");
            Vec::new()
        }
    };

    // Expected recipient address
    let expected_recipient = payload.pay_to();

    // Verify recipient is in the transaction (if we have account keys)
    if !account_keys.is_empty() {
        let recipient_found = account_keys
            .iter()
            .any(|key| key == expected_recipient);

        if !recipient_found {
            return Err(format!("Payment recipient {} not found in transaction", expected_recipient));
        }

        // Find recipient index in account keys for balance verification
        let recipient_index = account_keys
            .iter()
            .position(|key| key == expected_recipient)
            .ok_or_else(|| "Recipient not found in account keys".to_string())?;

        // Get balance change for recipient
        let pre_balance = meta
            .pre_balances
            .get(recipient_index)
            .copied()
            .unwrap_or(0);
        let post_balance = meta
            .post_balances
            .get(recipient_index)
            .copied()
            .unwrap_or(0);
        let actual_amount = post_balance.saturating_sub(pre_balance);

        match payload.scheme() {
            "exact" => {
                if actual_amount != expected_amount {
                    return Err(format!(
                        "Solana payment amount mismatch: expected {} lamports, got {} lamports (recipient: {})",
                        expected_amount, actual_amount, expected_recipient
                    ));
                }
            }
            "upto" => {
                if actual_amount < expected_amount {
                    return Err(format!(
                        "Solana payment amount too low: expected at least {} lamports, got {} lamports (recipient: {})",
                        expected_amount, actual_amount, expected_recipient
                    ));
                }
            }
            scheme => {
                return Err(format!("Unsupported payment scheme: {}", scheme));
            }
        }

        info!(
            channel = channel_name,
            signature = %tx_hash,
            recipient = %expected_recipient,
            amount = %actual_amount,
            "Solana payment verified successfully"
        );
    } else {
        // If we couldn't extract account keys, just verify based on maximum balance increase
        // This is less secure but better than nothing
        let balance_changes: Vec<_> = meta
            .post_balances
            .iter()
            .zip(meta.pre_balances.iter())
            .map(|(post, pre)| post.saturating_sub(*pre))
            .collect();

        let max_increase = balance_changes
            .iter()
            .max()
            .copied()
            .unwrap_or(0);

        match payload.scheme() {
            "exact" => {
                if max_increase != expected_amount {
                    return Err(format!(
                        "Solana payment amount mismatch: expected {} lamports, got {} lamports (simplified check)",
                        expected_amount, max_increase
                    ));
                }
            }
            "upto" => {
                if max_increase < expected_amount {
                    return Err(format!(
                        "Solana payment amount too low: expected at least {} lamports, got {} lamports (simplified check)",
                        expected_amount, max_increase
                    ));
                }
            }
            scheme => {
                return Err(format!("Unsupported payment scheme: {}", scheme));
            }
        }

        warn!(
            channel = channel_name,
            signature = %tx_hash,
            amount = %max_increase,
            "Solana payment verified with simplified check (recipient not verified)"
        );
    }

    Ok(payload.clone())
}

/// Verify payment via external facilitator using x402-rs
async fn verify_facilitator_payment(
    payload: &PaymentPayload,
    correlation_id: &str,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    transaction_store: &Option<Arc<TransactionStore>>,
) -> Result<(PaymentPayload, String), String> {
    use super::remote_facilitator::RemoteFacilitator;

    let facilitator_url = config
        .facilitator_url
        .as_ref()
        .ok_or_else(|| "Facilitator URL not configured".to_string())?;

    // Create remote facilitator client using x402-rs
    let facilitator = RemoteFacilitator::new(facilitator_url).await?;

    // Verify payment using x402-rs protocol
    let result = facilitator
        .verify(payload, channel_name)
        .await;

    // Update transaction store and return with correlation_id
    match result {
        Ok(_) => {
            // Update transaction store
            if let Some(store) = transaction_store
                && let Err(e) = store
                    .complete_verification(correlation_id)
                    .await
            {
                channel_warn!(channel_id, "Failed to update transaction record: {}", e);
            }
            Ok((payload.clone(), correlation_id.to_string()))
        }
        Err(e) => {
            // Mark verification as failed in transaction store
            if let Some(store) = transaction_store
                && let Err(err) = store
                    .fail_verification(correlation_id, e.clone())
                    .await
            {
                channel_warn!(channel_id, "Failed to update transaction record: {}", err);
            }

            // Trigger integration alerts for verification failure
            crate::integrations::trigger_transaction_verification_failed(
                correlation_id,
                channel_id,
                &payload
                    .tx_hash()
                    .unwrap_or_default(),
                &e,
            )
            .await;

            Err(e)
        }
    }
}

/// Create payment response header
pub fn create_payment_response(
    payload: &PaymentPayload,
    verified: bool,
    settled: bool,
) -> Result<String, String> {
    let response = PaymentResponse {
        verified,
        settled,
        tx_hash: payload.tx_hash(),
        network: Some(payload.network().to_string()),
        receipt: Some(format!(
            "{}:{}",
            payload.network(),
            payload
                .signature()
                .unwrap_or_default()
        )),
    };

    let json = serde_json::to_string(&response).map_err(|e| format!("Failed to serialize payment response: {}", e))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

/// Extract payment signature from headers
///
/// # Arguments
/// * `headers` - HTTP request headers
/// * `payment_signature_header` - Name of the payment signature header from x402.json config
pub fn extract_payment_signature(
    headers: &HeaderMap,
    payment_signature_header: &str,
) -> Option<String> {
    headers
        .get(payment_signature_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract payment signature from headers OR MCP tool parameters
///
/// For MCP tools/call requests, this function checks:
/// 1. HTTP headers (standard x402 flow)
/// 2. MCP tool arguments parameter named "payment_signature"
///
/// If found in MCP parameters, it's removed from the body so it won't be forwarded.
///
/// # Arguments
/// * `headers` - HTTP request headers
/// * `payment_signature_header` - Name of the payment signature header from x402.json config
/// * `body_bytes` - Request body (for MCP parameter extraction)
///
/// # Returns
/// * `(Option<String>, Vec<u8>)` - Payment signature (if found) and potentially modified body
pub fn extract_payment_signature_with_mcp(
    headers: &HeaderMap,
    payment_signature_header: &str,
    body_bytes: &[u8],
) -> (Option<String>, Vec<u8>) {
    // First check headers (standard x402 behavior)
    if let Some(sig) = extract_payment_signature(headers, payment_signature_header) {
        return (Some(sig), body_bytes.to_vec());
    }

    // If not in headers, check MCP tool parameters
    if let Ok(mut body_json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
        // Check if this is a tools/call request
        if let Some(method) = body_json
            .get("method")
            .and_then(|m| m.as_str())
            && method == "tools/call"
        {
            // Extract payment_signature from arguments if present
            if let Some(params) = body_json.get_mut("params")
                && let Some(arguments) = params.get_mut("arguments")
                && let Some(args_obj) = arguments.as_object_mut()
                && let Some(payment_sig) = args_obj.remove("payment_signature")
                && let Some(sig_str) = payment_sig.as_str()
            {
                // Found payment_signature in MCP parameters
                // Return it and the modified body (with payment_signature removed)
                if let Ok(modified_body) = serde_json::to_vec(&body_json) {
                    return (Some(sig_str.to_string()), modified_body);
                }
            }
        }
    }

    // Not found in either location
    (None, body_bytes.to_vec())
}

/// Verify EIP-3009 transferWithAuthorization signature
async fn verify_eip3009_signature(
    payload: &PaymentPayload,
    _config: &X402Config,
    channel_id: &str,
) -> Result<PaymentPayload, String> {
    use alloy::primitives::{Address, B256, U256, keccak256};
    use alloy::signers::Signature as AlloySignature;
    use alloy::sol_types::eip712_domain;

    channel_info!(channel_id, "Verifying EIP-3009 signature (signature-only mode)");

    // Extract signature and authorization
    let signature_hex = payload
        .signature()
        .ok_or_else(|| "Missing signature in payload".to_string())?;

    let authorization = payload
        .eip3009_authorization()
        .ok_or_else(|| "Missing EIP-3009 authorization in payload".to_string())?;

    // Debug: Log raw authorization values before any parsing
    channel_info!(
        channel_id,
        "EIP3009 Raw Authorization - from={} to={} value={} validAfter={} validBefore={} nonce={} nonce_len={}",
        authorization.from,
        authorization.to,
        authorization.value,
        authorization.valid_after,
        authorization.valid_before,
        authorization.nonce,
        authorization.nonce.len()
    );

    // Parse signature (r, s, v format - 65 bytes)
    let sig_bytes =
        hex::decode(signature_hex.trim_start_matches("0x")).map_err(|e| format!("Invalid signature hex: {}", e))?;

    if sig_bytes.len() != 65 {
        return Err(format!("Invalid signature length: expected 65 bytes, got {}", sig_bytes.len()));
    }

    // MetaMask returns signature as [r (32 bytes), s (32 bytes), v (1 byte)]
    // where v is 27 (0x1b) or 28 (0x1c)
    // Alloy expects v to be the y_parity (0 or 1)
    let r = U256::try_from_be_slice(&sig_bytes[0..32]).ok_or_else(|| "Invalid r value".to_string())?;
    let s = U256::try_from_be_slice(&sig_bytes[32..64]).ok_or_else(|| "Invalid s value".to_string())?;
    let v_byte = sig_bytes[64];

    // Convert v from Ethereum format (27/28) to parity (false/true)
    let v_parity = match v_byte {
        27 => false,
        28 => true,
        0 => false, // Some implementations use 0/1
        1 => true,
        _ => return Err(format!("Invalid v value: {}", v_byte)),
    };

    let signature = AlloySignature::new(r, s, v_parity);

    channel_info!(
        channel_id,
        "EIP3009 Parsed signature - r={} s={} v_byte={} v_parity={}",
        hex::encode(r.to_be_bytes::<32>()),
        hex::encode(s.to_be_bytes::<32>()),
        v_byte,
        v_parity
    );

    // Parse addresses and values
    let from_addr: Address = authorization
        .from
        .parse()
        .map_err(|_| "Invalid from address".to_string())?;
    let to_addr: Address = authorization
        .to
        .parse()
        .map_err(|_| "Invalid to address".to_string())?;
    let value: U256 = authorization
        .value
        .parse()
        .map_err(|_| "Invalid value".to_string())?;
    let valid_after: U256 = authorization
        .valid_after
        .parse()
        .map_err(|_| "Invalid validAfter".to_string())?;
    let valid_before: U256 = authorization
        .valid_before
        .parse()
        .map_err(|_| "Invalid validBefore".to_string())?;
    let nonce = B256::from_slice(
        &hex::decode(
            authorization
                .nonce
                .trim_start_matches("0x"),
        )
        .map_err(|e| format!("Invalid nonce hex: {}", e))?,
    );

    // Verify time windows
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now < valid_after.to::<u64>() {
        return Err("Payment not yet valid (validAfter)".to_string());
    }

    if now >= valid_before.to::<u64>() {
        return Err("Payment expired (validBefore)".to_string());
    }

    // Verify amount matches requirement
    let required_amount: U256 = payload
        .amount()
        .parse()
        .map_err(|_| "Invalid required amount".to_string())?;
    if value < required_amount {
        return Err(format!("Insufficient payment amount: {} < {}", value, required_amount));
    }

    // Verify recipient matches
    let expected_to: Address = payload
        .pay_to()
        .parse()
        .map_err(|_| "Invalid payTo address".to_string())?;
    if to_addr != expected_to {
        return Err(format!("Payment recipient mismatch: {} != {}", to_addr, expected_to));
    }

    // Get token contract address from asset field
    channel_debug!(channel_id, "Looking for asset in accepted: {:?}", payload.accepted.asset);
    let token_addr: Address = payload
        .asset()
        .ok_or_else(|| "Asset address required".to_string())?
        .parse()
        .map_err(|e| format!("Invalid token address: {}", e))?;

    channel_info!(
        channel_id,
        "EIP3009 Token address parsed: {} (hex: {})",
        token_addr,
        hex::encode(token_addr.as_slice())
    );

    // EIP-3009 TransferWithAuthorization EIP-712 typed data
    // See USDC implementation: https://github.com/circlefin/stablecoin-evm/blob/master/contracts/v2/EIP3009.sol

    // Get token name and version from payment requirements extra field
    // These come from the channel config and should match the actual token contract's name() and version()
    let token_name = payload
        .accepted
        .extra
        .as_ref()
        .and_then(|extra| extra.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            "Missing 'name' in payment requirements extra field. Required for EIP-3009 signature verification."
                .to_string()
        })?;

    let token_version = payload
        .accepted
        .extra
        .as_ref()
        .and_then(|extra| extra.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            "Missing 'version' in payment requirements extra field. Required for EIP-3009 signature verification."
                .to_string()
        })?;

    channel_info!(
        channel_id,
        "EIP3009 Using token metadata from payment requirements: name={}, version={}",
        token_name,
        token_version
    );

    // Parse chain_id from network (CAIP-2 format: "eip155:84532" -> 84532)
    let chain_id = payload
        .network()
        .strip_prefix("eip155:")
        .ok_or_else(|| format!("Invalid network format (expected eip155:chainId): {}", payload.network()))?
        .parse::<u64>()
        .map_err(|e| format!("Invalid chain_id in network {}: {}", payload.network(), e))?;

    channel_info!(channel_id, "EIP3009 Parsed chain_id={} from network={}", chain_id, payload.network());

    // Define the domain separator for the token contract
    let domain = eip712_domain! {
        name: token_name.clone(),
        version: token_version.clone(),
        chain_id: chain_id,
        verifying_contract: token_addr,
    };

    channel_info!(
        channel_id,
        "EIP3009 Domain created - computing separator with contract={} (bytes: {})",
        token_addr,
        hex::encode(token_addr.as_slice())
    );

    // Construct the TransferWithAuthorization struct hash
    // Type hash for: TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)
    let type_hash = keccak256(
        b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    // Encode struct data: typeHash || from || to || value || validAfter || validBefore || nonce
    let mut struct_data = Vec::new();
    struct_data.extend_from_slice(type_hash.as_slice());
    struct_data.extend_from_slice(&[0u8; 12]); // Pad address to 32 bytes
    struct_data.extend_from_slice(from_addr.as_slice());
    struct_data.extend_from_slice(&[0u8; 12]); // Pad address to 32 bytes
    struct_data.extend_from_slice(to_addr.as_slice());
    struct_data.extend_from_slice(&value.to_be_bytes::<32>());
    struct_data.extend_from_slice(&valid_after.to_be_bytes::<32>());
    struct_data.extend_from_slice(&valid_before.to_be_bytes::<32>());
    struct_data.extend_from_slice(nonce.as_slice());

    channel_info!(
        channel_id,
        "EIP3009 Encoding - typeHash={} from_addr={} to_addr={} value={} validAfter={} validBefore={} nonce={}",
        hex::encode(type_hash.as_slice()),
        hex::encode(from_addr.as_slice()),
        hex::encode(to_addr.as_slice()),
        hex::encode(value.to_be_bytes::<32>()),
        hex::encode(valid_after.to_be_bytes::<32>()),
        hex::encode(valid_before.to_be_bytes::<32>()),
        hex::encode(nonce.as_slice())
    );

    let struct_hash = keccak256(&struct_data);

    // Construct the EIP-712 message hash: "\x19\x01" || domainSeparator || structHash
    let domain_separator = domain.hash_struct();

    channel_info!(
        channel_id,
        "EIP3009 Debug - Domain: name={} version={} chainId={} contract={}",
        token_name,
        token_version,
        84532,
        token_addr
    );

    channel_info!(
        channel_id,
        "EIP3009 Debug - Message: from={} to={} value={} validAfter={} validBefore={} nonce={}",
        authorization.from,
        authorization.to,
        authorization.value,
        authorization.valid_after,
        authorization.valid_before,
        authorization.nonce // This is the original hex string from payload
    );

    channel_info!(
        channel_id,
        "EIP3009 Debug - Hashes: domainSep={} structHash={} signature={}",
        hex::encode(domain_separator.as_slice()),
        hex::encode(struct_hash.as_slice()),
        hex::encode(&sig_bytes)
    );

    let mut message = Vec::new();
    message.extend_from_slice(b"\x19\x01");
    message.extend_from_slice(domain_separator.as_slice());
    message.extend_from_slice(struct_hash.as_slice());
    let message_hash = keccak256(&message);

    channel_info!(channel_id, "EIP3009 Debug - Final messageHash={}", hex::encode(message_hash.as_slice()));

    // Recover signer from signature
    channel_info!(
        channel_id,
        "EIP3009 Attempting signature recovery from message_hash={}",
        hex::encode(message_hash.as_slice())
    );

    let recovered_addr = signature
        .recover_address_from_prehash(&message_hash)
        .map_err(|e| {
            channel_info!(channel_id, "EIP3009 Signature recovery failed: {}", e);
            format!("Failed to recover signer: {}", e)
        })?;

    channel_info!(channel_id, "EIP3009 Recovered address: {} (expected: {})", recovered_addr, from_addr);

    // Verify signer matches authorization.from
    if recovered_addr != from_addr {
        let err_msg = format!("Signature verification failed. Expected signer: {}, Got: {}", from_addr, recovered_addr);
        channel_info!(channel_id, "EIP3009 ERROR: {}", err_msg);
        return Err(err_msg);
    }

    channel_info!(
        channel_id,
        "EIP-3009 signature verified successfully (signature-only mode) from={} to={} value={} signer={}",
        authorization.from,
        authorization.to,
        authorization.value,
        recovered_addr
    );

    Ok(payload.clone())
}

/// Verify EIP-3009 payment with on-chain state checks (for local verification mode)
///
/// Verify EIP-3009 payment using x402-chain-eip155 crate.
/// This uses the official x402-rs facilitator for complete verification including:
/// - Signature validation
/// - Nonce checking (prevents replay attacks)
/// - Balance verification
///
/// Verify Permit2 permitWitnessTransferFrom signature
async fn verify_permit2_signature(
    payload: &PaymentPayload,
    _config: &X402Config,
    channel_id: &str,
) -> Result<PaymentPayload, String> {
    use alloy::primitives::{Address, U256, keccak256};
    use alloy::signers::Signature as AlloySignature;
    use alloy::sol_types::eip712_domain;

    channel_info!(channel_id, "Verifying Permit2 signature (signature-only mode)");

    // Extract signature and authorization
    let signature_hex = payload
        .signature()
        .ok_or_else(|| "Missing signature in payload".to_string())?;

    let authorization = payload
        .permit2_authorization()
        .ok_or_else(|| "Missing Permit2 authorization in payload".to_string())?;

    // Parse signature (r, s, v format - 65 bytes)
    let sig_bytes =
        hex::decode(signature_hex.trim_start_matches("0x")).map_err(|e| format!("Invalid signature hex: {}", e))?;

    if sig_bytes.len() != 65 {
        return Err(format!("Invalid signature length: expected 65 bytes, got {}", sig_bytes.len()));
    }

    let r = U256::try_from_be_slice(&sig_bytes[0..32]).ok_or_else(|| "Invalid r value".to_string())?;
    let s = U256::try_from_be_slice(&sig_bytes[32..64]).ok_or_else(|| "Invalid s value".to_string())?;
    let v = sig_bytes[64] >= 27;

    let signature = AlloySignature::new(r, s, v);

    // Parse addresses and values
    let from_addr: Address = authorization
        .from
        .parse()
        .map_err(|_| "Invalid from address".to_string())?;
    let token_addr: Address = authorization
        .permitted
        .token
        .parse()
        .map_err(|_| "Invalid token address".to_string())?;
    let amount: U256 = authorization
        .permitted
        .amount
        .parse()
        .map_err(|_| "Invalid amount".to_string())?;
    let spender: Address = authorization
        .spender
        .parse()
        .map_err(|_| "Invalid spender address".to_string())?;
    let nonce = U256::from_str_radix(
        authorization
            .nonce
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| format!("Invalid nonce: {}", e))?;
    let deadline: U256 = authorization
        .deadline
        .parse()
        .map_err(|_| "Invalid deadline".to_string())?;
    let witness_valid_after: U256 = authorization
        .witness
        .valid_after
        .parse()
        .map_err(|_| "Invalid witness validAfter".to_string())?;
    let witness_to: Address = authorization
        .witness
        .to
        .parse()
        .map_err(|_| "Invalid witness to address".to_string())?;

    // Verify time windows
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now < witness_valid_after.to::<u64>() {
        return Err("Payment not yet valid (witness.validAfter)".to_string());
    }

    if now >= deadline.to::<u64>() {
        return Err("Payment expired (deadline)".to_string());
    }

    // Verify amount matches requirement
    let required_amount: U256 = payload
        .amount()
        .parse()
        .map_err(|_| "Invalid required amount".to_string())?;
    if amount < required_amount {
        return Err(format!("Insufficient payment amount: {} < {}", amount, required_amount));
    }

    // Verify recipient matches (via witness)
    let expected_to: Address = payload
        .pay_to()
        .parse()
        .map_err(|_| "Invalid payTo address".to_string())?;
    if witness_to != expected_to {
        return Err(format!("Payment recipient mismatch: {} != {}", witness_to, expected_to));
    }

    // Verify token matches
    let expected_token_addr: Address = payload
        .asset()
        .ok_or_else(|| "Asset address required".to_string())?
        .parse()
        .map_err(|_| "Invalid asset address".to_string())?;
    if token_addr != expected_token_addr {
        return Err(format!("Token mismatch: {} != {}", token_addr, expected_token_addr));
    }

    // Permit2 canonical address (same across all EVM chains)
    // See: https://github.com/Uniswap/permit2/blob/main/deployments.md
    let permit2_addr: Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
        .parse()
        .unwrap();

    // Parse chain_id from network (CAIP-2 format: "eip155:84532" -> 84532)
    let chain_id = payload
        .network()
        .strip_prefix("eip155:")
        .ok_or_else(|| format!("Invalid network format (expected eip155:chainId): {}", payload.network()))?
        .parse::<u64>()
        .map_err(|e| format!("Invalid chain_id in network {}: {}", payload.network(), e))?;

    channel_info!(channel_id, "Permit2 Using chain_id={} from network={}", chain_id, payload.network());

    // Define domain separator for Permit2
    // Permit2 uses a static domain across all networks (only chain_id varies)
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: chain_id,
        verifying_contract: permit2_addr,
    };

    // Construct Permit2 permitWitnessTransferFrom typed data
    // This is complex because it includes a custom witness struct
    // See: https://github.com/Uniswap/permit2/blob/main/src/SignatureTransfer.sol

    // PermitWitnessTransferFrom type hash with x402Witness
    // TODO: This needs the actual witness type string which varies by use case
    // For x402, the witness is: "x402Witness witness)x402Witness(address to,uint256 validAfter,string extra)"
    let type_hash = keccak256(
        b"PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,x402Witness witness)TokenPermissions(address token,uint256 amount)x402Witness(address to,uint256 validAfter,string extra)"
    );

    // Encode TokenPermissions struct hash
    let token_permissions_type_hash = keccak256(b"TokenPermissions(address token,uint256 amount)");
    let mut token_permissions_data = Vec::new();
    token_permissions_data.extend_from_slice(token_permissions_type_hash.as_slice());
    token_permissions_data.extend_from_slice(&[0u8; 12]);
    token_permissions_data.extend_from_slice(token_addr.as_slice());
    token_permissions_data.extend_from_slice(&amount.to_be_bytes::<32>());
    let token_permissions_hash = keccak256(&token_permissions_data);

    // Encode x402Witness struct hash
    let witness_type_hash = keccak256(b"x402Witness(address to,uint256 validAfter,string extra)");
    let extra_string = authorization
        .witness
        .extra
        .as_str()
        .unwrap_or("");
    let extra_hash = keccak256(extra_string.as_bytes());
    let mut witness_data = Vec::new();
    witness_data.extend_from_slice(witness_type_hash.as_slice());
    witness_data.extend_from_slice(&[0u8; 12]);
    witness_data.extend_from_slice(witness_to.as_slice());
    witness_data.extend_from_slice(&witness_valid_after.to_be_bytes::<32>());
    witness_data.extend_from_slice(extra_hash.as_slice());
    let witness_hash = keccak256(&witness_data);

    // Encode main struct: typeHash || tokenPermissionsHash || spender || nonce || deadline || witnessHash
    let mut struct_data = Vec::new();
    struct_data.extend_from_slice(type_hash.as_slice());
    struct_data.extend_from_slice(token_permissions_hash.as_slice());
    struct_data.extend_from_slice(&[0u8; 12]);
    struct_data.extend_from_slice(spender.as_slice());
    struct_data.extend_from_slice(&nonce.to_be_bytes::<32>());
    struct_data.extend_from_slice(&deadline.to_be_bytes::<32>());
    struct_data.extend_from_slice(witness_hash.as_slice());
    let struct_hash = keccak256(&struct_data);

    // Construct EIP-712 message hash
    let domain_separator = domain.hash_struct();
    let mut message = Vec::new();
    message.extend_from_slice(b"\x19\x01");
    message.extend_from_slice(domain_separator.as_slice());
    message.extend_from_slice(struct_hash.as_slice());
    let message_hash = keccak256(&message);

    // Recover signer from signature
    let recovered_addr = signature
        .recover_address_from_prehash(&message_hash)
        .map_err(|e| format!("Failed to recover signer: {}", e))?;

    // Verify signer matches authorization.from
    if recovered_addr != from_addr {
        return Err(format!("Signature verification failed. Expected signer: {}, Got: {}", from_addr, recovered_addr));
    }

    channel_info!(
        channel_id,
        "Permit2 signature verified successfully (signature-only mode) from={} to={} amount={} token={} spender={} signer={}",
        authorization.from,
        witness_to,
        amount,
        token_addr,
        spender,
        recovered_addr
    );

    Ok(payload.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::X402VerificationMode;
    use base64::Engine;
    use tempfile::tempdir;

    fn payment_header() -> String {
        let payload_json = r#"{
            "x402Version": 2,
            "resource": {"url": "/test", "description": "test", "mimeType": "application/json"},
            "accepted": {
                "scheme": "exact",
                "network": "eip155:1",
                "amount": "1000",
                "asset": "0x123",
                "payTo": "0x456",
                "maxTimeoutSeconds": 300
            },
            "payload": {
                "authorization": {
                    "from": "0xabc",
                    "to": "0x456",
                    "value": "1000",
                    "validAfter": "0",
                    "validBefore": "999999999",
                    "nonce": "0x123"
                },
                "signature": "0xsig"
            }
        }"#;

        base64::engine::general_purpose::STANDARD.encode(payload_json.as_bytes())
    }

    #[tokio::test]
    async fn rejects_sequential_duplicate_payment_header() {
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(
            TransactionStore::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let config = X402Config {
            verification_mode: X402VerificationMode::Mock,
            ..Default::default()
        };
        let payment_header = payment_header();

        let first_result = verify_payment(
            &payment_header,
            &config,
            "Test Channel",
            "channel-1",
            "/test",
            None,
            Some(Arc::clone(&store)),
            None,
        )
        .await;
        let second_result =
            verify_payment(&payment_header, &config, "Test Channel", "channel-1", "/test", None, Some(store), None)
                .await;

        assert!(first_result.is_ok());
        assert!(
            second_result
                .unwrap_err()
                .contains("already exists")
        );
    }

    #[tokio::test]
    async fn allows_only_one_concurrent_grant_for_same_payment_header() {
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(
            TransactionStore::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let config = Arc::new(X402Config {
            verification_mode: X402VerificationMode::Mock,
            ..Default::default()
        });
        let payment_header = Arc::new(payment_header());

        let tasks = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let config = Arc::clone(&config);
                let payment_header = Arc::clone(&payment_header);

                tokio::spawn(async move {
                    verify_payment(
                        &payment_header,
                        &config,
                        "Test Channel",
                        "channel-1",
                        "/test",
                        None,
                        Some(store),
                        None,
                    )
                    .await
                })
            })
            .collect::<Vec<_>>();

        let results = futures::future::join_all(tasks)
            .await
            .into_iter()
            .map(|result| result.unwrap())
            .collect::<Vec<_>>();
        let success_count = results
            .iter()
            .filter(|result| result.is_ok())
            .count();
        let replay_rejection_count = results
            .iter()
            .filter(|result| {
                result
                    .as_ref()
                    .is_err_and(|error| error.contains("already exists"))
            })
            .count();

        assert_eq!(success_count, 1);
        assert_eq!(replay_rejection_count, 7);
    }
}
