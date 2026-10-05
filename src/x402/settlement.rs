//! x402 payment settlement

use std::sync::Arc;

use super::{PaymentPayload, TransactionStore};
use crate::config::types::{X402Config, X402SettlementMode, X402VerificationMode};
use crate::{channel_error, channel_info, channel_warn};
use tracing::{info, warn};

/// Settle x402 payment with storage backend
/// Settlement method is determined by both settlement_mode and verification_mode:
/// - settlement_mode determines WHEN (none, immediate, deferred)
/// - verification_mode determines HOW/WHERE (local, fabric_gateway, external_facilitator)
///
/// DURABILITY GUARANTEE: All settlement attempts are written to disk BEFORE execution
/// to ensure recovery on restart
#[tracing::instrument(
    name = "x402.settle_payment",
    skip(payload, config, transaction_store),
    fields(
        settlement_mode = ?config.settlement_mode,
        verification_mode = ?config.verification_mode,
        surface_id = %channel_id,
        network = %payload.network(),
        amount = %payload.amount()
    )
)]
pub async fn settle_payment(
    payload: &PaymentPayload,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    transaction_store: Option<&Arc<TransactionStore>>,
    confirmations: Option<u64>,
    correlation_id: Option<String>,
) -> Result<(), String> {
    match config.settlement_mode {
        X402SettlementMode::None => {
            channel_info!(channel_id, "Settlement disabled - skipping");
            Ok(())
        }
        X402SettlementMode::Deferred => {
            // Deferred settlement uses verification_mode to determine WHERE to record
            settle_deferred(payload, config, channel_name, channel_id, transaction_store, confirmations, correlation_id)
                .await
        }
        X402SettlementMode::Immediate => {
            // Immediate settlement uses verification_mode to determine HOW to settle
            // IMPORTANT: Write pending record FIRST before attempting settlement
            settle_immediate_with_mode(
                payload,
                config,
                channel_name,
                channel_id,
                transaction_store,
                confirmations,
                correlation_id,
            )
            .await
        }
    }
}

/// Record payment for deferred settlement (batch processing)
/// Storage location depends on verification_mode:
/// - Local: Store locally on this gateway
/// - FabricGateway: Store on both this gateway and facilitator gateway
/// - ExternalFacilitator: Delegate to external service for storage
async fn settle_deferred(
    payload: &PaymentPayload,
    config: &X402Config,
    _channel_name: &str,
    channel_id: &str,
    transaction_store: Option<&Arc<TransactionStore>>,
    confirmations: Option<u64>,
    correlation_id: Option<String>,
) -> Result<(), String> {
    // Initialize settlement stage if correlation_id is available and transaction_store exists
    if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
        let settlement_method = match config.verification_mode {
            X402VerificationMode::Local | X402VerificationMode::Signature | X402VerificationMode::Mock => "local",
            X402VerificationMode::FabricGateway => "fabric_gateway",
            X402VerificationMode::ExternalFacilitator => "external_facilitator",
        };

        if let Err(e) = txn_store
            .init_settlement(
                corr_id,
                "deferred".to_string(),
                settlement_method.to_string(),
                payload.tx_hash(),
                confirmations,
            )
            .await
        {
            channel_warn!(channel_id, "Failed to initialize settlement in transaction store: {}", e);
        }
    }

    use crate::config::types::X402VerificationMode;

    match config.verification_mode {
        X402VerificationMode::Local | X402VerificationMode::Signature | X402VerificationMode::Mock => {
            // Local deferred settlement - store on this gateway
            channel_info!(
                channel_id,
                "Recording payment for local deferred settlement network={} amount={} tx_hash={:?}",
                payload.network(),
                payload.amount(),
                payload.tx_hash()
            );

            // Transaction already initialized with settlement stage via init_settlement() earlier
            channel_info!(channel_id, "Payment recorded for deferred settlement via TransactionStore");

            Ok(())
        }
        X402VerificationMode::FabricGateway => {
            // Deferred settlement via fabric gateway - GW2 will settle and notify us
            channel_info!(
                channel_id,
                "Recording payment for deferred settlement via fabric gateway network={} amount={}",
                payload.network(),
                payload.amount()
            );

            // DO NOT mark as pending sync - the facilitator (GW2) will settle and send us settlement-complete
            // GW1's transaction just waits for notification from GW2

            channel_info!(
                channel_id,
                "Deferred settlement delegated to facilitator gateway '{:?}' - waiting for settlement notification",
                config.facilitator_gateway_id
            );

            Ok(())
        }
        X402VerificationMode::ExternalFacilitator => {
            // Deferred settlement via external facilitator
            channel_info!(
                channel_id,
                "Delegating deferred settlement recording to external facilitator network={} amount={}",
                payload.network(),
                payload.amount()
            );

            // Delegate to external facilitator for storage
            // TODO: Call external facilitator API to record deferred payment
            channel_info!(channel_id, "TODO: Delegate deferred settlement recording to external facilitator");

            Ok(())
        }
    }
}

/// Execute immediate settlement
/// Settlement method depends on verification_mode:
/// - Local: Execute on-chain via embedded facilitator (this gateway executes transferWithAuthorization)
/// - FabricGateway: Delegate to other gateway which settles immediately
/// - ExternalFacilitator: Delegate to external service which settles immediately
async fn settle_immediate_with_mode(
    payload: &PaymentPayload,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    transaction_store: Option<&Arc<TransactionStore>>,
    confirmations: Option<u64>,
    correlation_id: Option<String>,
) -> Result<(), String> {
    // Initialize settlement stage if correlation_id is available and transaction_store exists
    if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
        let settlement_method = match config.verification_mode {
            X402VerificationMode::Local | X402VerificationMode::Signature | X402VerificationMode::Mock => "local",
            X402VerificationMode::FabricGateway => "fabric_gateway",
            X402VerificationMode::ExternalFacilitator => "external_facilitator",
        };

        if let Err(e) = txn_store
            .init_settlement(
                corr_id,
                "immediate".to_string(),
                settlement_method.to_string(),
                payload.tx_hash(),
                confirmations,
            )
            .await
        {
            channel_warn!(channel_id, "Failed to initialize settlement in transaction store: {}", e);
        }
    }

    use crate::config::types::X402VerificationMode;

    match config.verification_mode {
        X402VerificationMode::Local | X402VerificationMode::Signature | X402VerificationMode::Mock => {
            // Immediate local settlement - execute on-chain via embedded facilitator
            channel_info!(
                channel_id,
                "Executing immediate settlement via embedded facilitator network={} amount={}",
                payload.network(),
                payload.amount()
            );

            // Load facilitator_private_keys from global x402.json (required for security)
            let merged_config = if let Ok(global_config) = crate::x402::config_cache::get_or_load_x402_config().await {
                let mut merged = config.clone();
                if let Some(global_keys) = &global_config.facilitator_private_keys {
                    merged.facilitator_private_keys = Some(global_keys.clone());
                    channel_info!(
                        channel_id,
                        "Loaded {} facilitator_private_keys from global x402.json for settlement",
                        global_keys.len()
                    );
                } else {
                    channel_error!(channel_id, "Global x402.json config has no facilitator_private_keys");
                    return Err("Global x402.json config missing facilitator_private_keys".to_string());
                }
                // Merge RPC endpoints from global config if channel config doesn't have them
                if merged
                    .rpc_endpoints
                    .is_empty()
                    && !global_config
                        .rpc_endpoints
                        .is_empty()
                {
                    channel_info!(
                        channel_id,
                        "Merging {} RPC endpoints from global x402.json for settlement",
                        global_config
                            .rpc_endpoints
                            .len()
                    );
                    merged.rpc_endpoints = global_config
                        .rpc_endpoints
                        .clone();
                }
                merged
            } else {
                channel_error!(channel_id, "Failed to load global x402.json config for settlement");
                return Err("Failed to load global x402.json config".to_string());
            };

            // Initialize embedded facilitator with merged config
            let facilitator = super::embedded_facilitator::get_embedded_facilitator(&merged_config)
                .await
                .map_err(|e| {
                    channel_error!(channel_id, "Failed to initialize embedded facilitator for settlement: {}", e);
                    e.to_string()
                })?;

            // Convert payload to x402 SettleRequest
            let settle_request = super::x402rs_adapter::to_settle_request(payload).map_err(|e| {
                channel_error!(channel_id, "Failed to convert to x402 settle request: {}", e);
                format!("Failed to convert payment to x402 format: {}", e)
            })?;

            // Get facilitator address for this network for error reporting
            let network = payload.network();
            let facilitator_address = merged_config
                .facilitator_private_keys
                .as_ref()
                .and_then(|keys| keys.get(network))
                .map(|key_config| key_config.address.as_str())
                .unwrap_or("unknown");

            // Execute on-chain settlement via embedded facilitator
            channel_info!(
                channel_id,
                "Calling embedded facilitator to execute transferWithAuthorization network={} facilitator={}",
                network,
                facilitator_address
            );

            // PHASE 1: WRITE-AHEAD LOGGING - Record settlement attempt BEFORE execution
            // This ensures crash recovery if server restarts during settlement
            if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
                if let Err(e) = txn_store
                    .increment_settlement_attempt(corr_id)
                    .await
                {
                    channel_error!(channel_id, "CRITICAL: Failed to persist settlement attempt - aborting: {}", e);
                    return Err(format!("Cannot proceed with settlement: failed to persist record: {}", e));
                }
                channel_info!(channel_id, "Settlement attempt recorded correlation_id={}", corr_id);
            }

            // PHASE 2: Execute on-chain settlement via embedded facilitator
            channel_info!(
                channel_id,
                "Executing settlement via embedded facilitator correlation_id={:?}",
                correlation_id
            );

            let settle_response = facilitator
                .settle(settle_request)
                .await
                .map_err(|e| {
                    channel_error!(
                        channel_id,
                        "Settlement execution failed: {} [network={}, facilitator={}]",
                        e,
                        network,
                        facilitator_address
                    );
                    format!(
                        "Settlement execution failed: {} [network={}, facilitator={}]",
                        e, network, facilitator_address
                    )
                })?;

            // Check if settlement was successful and extract transaction hash
            let is_successful = super::x402rs_adapter::is_settlement_successful(&settle_response);
            let tx_hash = super::x402rs_adapter::extract_transaction(&settle_response);

            // PHASE 3: Update payment record with settlement result
            if !is_successful {
                let error_msg = super::x402rs_adapter::extract_settle_error(&settle_response)
                    .unwrap_or_else(|| "Unknown settlement error".to_string());

                // Update record with failure
                if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store)
                    && let Err(e) = txn_store
                        .fail_settlement(corr_id, error_msg.clone())
                        .await
                {
                    channel_warn!(channel_id, "Failed to update payment record with error: {}", e);
                }

                channel_error!(
                    channel_id,
                    "Settlement failed: {} [network={}, facilitator={}]",
                    error_msg,
                    network,
                    facilitator_address
                );

                // Trigger integration alerts for settlement failure
                if let Some(corr_id) = &correlation_id {
                    crate::integrations::trigger_transaction_settlement_failed(
                        corr_id,
                        channel_id,
                        &payload
                            .tx_hash()
                            .unwrap_or_default(),
                        "local",
                        &error_msg,
                    )
                    .await;
                }

                return Err(format!(
                    "Settlement execution failed: {} [network={}, facilitator={}]",
                    error_msg, network, facilitator_address
                ));
            }

            let tx_hash_str = tx_hash.ok_or_else(|| {
                channel_error!(channel_id, "Settlement succeeded but no transaction hash returned");
                "No transaction hash in settlement response".to_string()
            })?;

            channel_info!(channel_id, "Settlement executed successfully tx_hash={}", tx_hash_str);

            // Update transaction store with settlement tx_hash
            if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store)
                && let Err(e) = txn_store
                    .set_settlement_tx_hash(corr_id, tx_hash_str.clone())
                    .await
            {
                channel_warn!(channel_id, "Failed to update transaction with tx_hash: {}", e);
            }

            // PHASE 4: Complete settlement in TransactionStore
            if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
                if let Err(e) = txn_store
                    .complete_settlement(corr_id)
                    .await
                {
                    channel_warn!(channel_id, "Failed to complete settlement in transaction store: {}", e);
                } else {
                    channel_info!(
                        channel_id,
                        "Transaction store updated: settlement completed correlation_id={}",
                        corr_id
                    );
                }
            }

            Ok(())
        }
        X402VerificationMode::FabricGateway => {
            // Immediate settlement via fabric gateway - delegate to other gateway
            settle_via_gateway(
                payload,
                config,
                channel_name,
                channel_id,
                transaction_store,
                confirmations,
                correlation_id.clone(),
            )
            .await
        }
        X402VerificationMode::ExternalFacilitator => {
            // Immediate settlement via external facilitator
            settle_via_external_facilitator(
                payload,
                config,
                channel_name,
                channel_id,
                transaction_store,
                confirmations,
                correlation_id,
            )
            .await
        }
    }
}

/// Delegate settlement to another gateway via DIDComm
async fn settle_via_gateway(
    payload: &PaymentPayload,
    config: &X402Config,
    _channel_name: &str,
    channel_id: &str,
    transaction_store: Option<&Arc<TransactionStore>>,
    _confirmations: Option<u64>,
    correlation_id: Option<String>,
) -> Result<(), String> {
    channel_info!(
        channel_id,
        "Delegating settlement to gateway network={} amount={}",
        payload.network(),
        payload.amount()
    );

    // Get facilitator gateway ID from config (facilitator handles settlement)
    let facilitator_gateway_id = config
        .facilitator_gateway_id
        .as_ref()
        .ok_or_else(|| {
            channel_error!(
                channel_id,
                "settlement_mode is gateway_delegated but facilitator_gateway_id not configured"
            );
            "Facilitator gateway ID not configured".to_string()
        })?;

    // PHASE 1: WRITE-AHEAD LOGGING - Record settlement attempt BEFORE sending DIDComm message
    // This ensures crash recovery and proper tracking of delegated settlements
    // Mark transaction as awaiting remote gateway
    if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
        if let Err(e) = txn_store
            .increment_settlement_attempt(corr_id)
            .await
        {
            channel_error!(channel_id, "CRITICAL: Failed to persist settlement attempt - aborting: {}", e);
            return Err(format!("Cannot proceed with delegated settlement: failed to persist record: {}", e));
        }
        channel_info!(
            channel_id,
            "Settlement marked as AwaitingRemote correlation_id={} facilitator={}",
            corr_id,
            facilitator_gateway_id
        );
    }

    channel_info!(channel_id, "Sending settlement request to facilitator gateway: {}", facilitator_gateway_id);

    // PHASE 2: Send DIDComm settle-request to remote gateway
    // NOTE: This is currently blocking (waits for response), but should be converted to
    // non-blocking with the listener updating the payment record when the response arrives
    // TODO: Refactor didcomm_facilitator_client to support non-blocking mode
    match crate::x402::didcomm_facilitator_client::settle_via_gateway_facilitator(payload, config, channel_id).await {
        Ok(tx_hash) => {
            channel_info!(channel_id, "✅ Gateway settlement completed tx_hash={}", tx_hash);

            // PHASE 3: Update TransactionStore with tx_hash
            if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
                if let Err(e) = txn_store
                    .set_settlement_tx_hash(corr_id, tx_hash.clone())
                    .await
                {
                    channel_warn!(channel_id, "Failed to update transaction with tx_hash: {}", e);
                } else {
                    channel_info!(channel_id, "Transaction updated with settlement tx_hash correlation_id={}", corr_id);
                }
            }

            // PHASE 4: Complete settlement in TransactionStore
            if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
                if let Err(e) = txn_store
                    .complete_settlement(corr_id)
                    .await
                {
                    channel_warn!(channel_id, "Failed to complete settlement in transaction store: {}", e);
                } else {
                    channel_info!(
                        channel_id,
                        "Transaction store updated: settlement completed correlation_id={}",
                        corr_id
                    );

                    // Trigger integration alerts for successful transaction completion
                    crate::integrations::trigger_transaction_completed(
                        corr_id,
                        channel_id,
                        &tx_hash,
                        payload.amount(),
                        payload.network(),
                        "fabric_gateway",
                    )
                    .await;
                }
            }

            Ok(())
        }
        Err(e) => {
            channel_error!(channel_id, "❌ Gateway settlement failed: {}", e);

            // Update record with failure status
            if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store)
                && let Err(update_err) = txn_store
                    .fail_settlement(corr_id, e.clone())
                    .await
            {
                channel_warn!(channel_id, "Failed to update transaction with error: {}", update_err);
            }

            // Trigger integration alerts for settlement failure
            if let Some(corr_id) = &correlation_id {
                crate::integrations::trigger_transaction_settlement_failed(
                    corr_id,
                    channel_id,
                    &payload
                        .tx_hash()
                        .unwrap_or_default(),
                    "fabric_gateway",
                    &e,
                )
                .await;
            }

            Err(format!("Gateway settlement failed: {}", e))
        }
    }
}

/// Delegate settlement to external HTTP facilitator (x402 v2 spec)
async fn settle_via_external_facilitator(
    payload: &PaymentPayload,
    config: &X402Config,
    channel_name: &str,
    channel_id: &str,
    transaction_store: Option<&Arc<TransactionStore>>,
    confirmations: Option<u64>,
    correlation_id: Option<String>,
) -> Result<(), String> {
    use super::remote_facilitator::RemoteFacilitator;

    let facilitator_url = config
        .facilitator_url
        .as_ref()
        .ok_or_else(|| {
            channel_error!(channel_id, "settlement_mode is external_facilitator but facilitator_url not configured");
            "Facilitator URL not configured".to_string()
        })?;

    // PHASE 0: Initialize settlement in TransactionStore
    if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store)
        && let Err(e) = txn_store
            .init_settlement(
                corr_id,
                "immediate".to_string(),
                "external_facilitator".to_string(),
                payload.tx_hash(),
                confirmations,
            )
            .await
    {
        channel_warn!(channel_id, "Failed to initialize settlement in transaction store: {}", e);
    }

    // PHASE 1: WRITE-AHEAD LOGGING - Record settlement attempt BEFORE calling external facilitator
    if let (Some(corr_id), Some(txn_store)) = (&correlation_id, &transaction_store) {
        if let Err(e) = txn_store
            .mark_awaiting_external(corr_id)
            .await
        {
            channel_error!(
                channel_id,
                "CRITICAL: Failed to persist settlement state before external call - aborting: {}",
                e
            );
            return Err(format!("Cannot proceed with external settlement: failed to persist record: {}", e));
        }
        channel_info!(
            channel_id,
            "Settlement marked as AwaitingExternal correlation_id={} facilitator={}",
            corr_id,
            facilitator_url
        );
    }

    channel_info!(
        channel_id,
        "Delegating settlement to external facilitator: {} network={} amount={}",
        facilitator_url,
        payload.network(),
        payload.amount()
    );

    // PHASE 2: Call external facilitator via HTTP
    // Create remote facilitator client using x402-rs
    let facilitator = RemoteFacilitator::new(facilitator_url).await?;

    // Settle payment using x402-rs protocol
    let _response = facilitator
        .settle(payload, channel_name, channel_id)
        .await?;

    // Settlement succeeded
    // TODO: Extract tx_hash from response and update payment record
    Ok(())
}

/// Recover unsettled payments on startup
///
/// Queries the transaction store for verified payments with incomplete settlements
/// and retries them. This ensures crash recovery and handles cases where:
/// - Gateway crashed before completing settlement
/// - Remote gateway response was lost
/// - RPC timeout occurred but settlement may have succeeded
///
/// # Arguments
/// * `transaction_store` - Transaction store to query
/// * `settlement_backend` - Settlement backend for legacy compatibility
/// * `is_fabric_facilitator` - True if this gateway acts as facilitator (GW2), false if originating (GW1)
///
/// # Recovery Logic
/// - If `is_fabric_facilitator=false` (GW1): Retries \"local\" settlements only
/// - If `is_fabric_facilitator=true` (GW2): Retries \"fabric_gateway\" settlements only
/// - External facilitator settlements are not retried (delegated to external service)
pub async fn recover_unsettled_on_startup(
    transaction_store: Arc<TransactionStore>,
    _settlement_backend: Option<()>, // No longer used - kept for API compatibility
    is_fabric_facilitator: bool,
) {
    info!("[x402-recovery] Checking for unsettled verified payments on startup...");

    // Determine which settlement_method this gateway is responsible for
    let settlement_method_filter = if is_fabric_facilitator {
        "fabric_gateway" // GW2 handles fabric gateway settlements
    } else {
        "local" // GW1 handles local settlements
    };

    let unsettled = transaction_store
        .list_unsettled_verified(Some(settlement_method_filter))
        .await;

    if unsettled.is_empty() {
        info!("[x402-recovery] No unsettled payments found");
        return;
    }

    info!(
        "[x402-recovery] Found {} verified but unsettled payment(s) with settlement_method={}",
        unsettled.len(),
        settlement_method_filter
    );

    // Load x402 config for settlement retry
    let config = match crate::x402::config_cache::get_or_load_x402_config().await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("[x402-recovery] Failed to load x402 config, cannot retry settlements: {}", e);
            return;
        }
    };

    let mut recovered = 0;
    let mut failed = 0;

    for transaction in unsettled {
        let correlation_id = transaction.id.clone();
        let channel_id = transaction.surface_id.clone();
        let channel_name = transaction
            .channel_name
            .clone();

        info!(
            "[x402-recovery] Retrying settlement: correlation_id={} channel_id={} channel_name={}",
            correlation_id, channel_id, channel_name
        );

        // Get settlement details
        let Some(settlement) = &transaction.settlement else {
            warn!("[x402-recovery] Transaction missing settlement stage (unexpected): {}", correlation_id);
            continue;
        };

        let _tx_hash = if settlement.tx_hash.is_empty() {
            None
        } else {
            Some(settlement.tx_hash.clone())
        };

        // Reconstruct payment payload
        let payload = transaction
            .payment_payload
            .clone();

        // Build temporary config with settlement mode from transaction
        // Clone the inner X402Config from the Arc so we can modify it
        let mut temp_config = (*config).clone();
        temp_config.settlement_mode = if settlement.settlement_mode == "immediate" {
            X402SettlementMode::Immediate
        } else {
            X402SettlementMode::Deferred
        };

        // Set verification mode based on settlement method
        temp_config.verification_mode = match settlement
            .settlement_method
            .as_str()
        {
            "local" => X402VerificationMode::Local,
            "fabric_gateway" => X402VerificationMode::FabricGateway,
            "external_facilitator" => X402VerificationMode::ExternalFacilitator,
            _ => X402VerificationMode::Local,
        };

        // Retry settlement
        match settle_payment(
            &payload,
            &temp_config,
            &channel_name,
            &channel_id,
            Some(&transaction_store),
            settlement.confirmations,
            Some(correlation_id.clone()),
        )
        .await
        {
            Ok(_) => {
                info!("[x402-recovery] ✅ Successfully retried settlement: {}", correlation_id);
                recovered += 1;
            }
            Err(e) => {
                // Check if error indicates already settled
                let error_lower = e.to_lowercase();
                if error_lower.contains("already used")
                    || error_lower.contains("already spent")
                    || error_lower.contains("already settled")
                    || error_lower.contains("nonce too low")
                {
                    info!("[x402-recovery] ✅ Payment already settled (signature reused): {}", correlation_id);

                    // Mark as completed
                    if let Err(e) = transaction_store
                        .complete_settlement(&correlation_id)
                        .await
                    {
                        warn!("[x402-recovery] Failed to mark already-settled payment as complete: {}", e);
                    }
                    recovered += 1;
                } else {
                    warn!("[x402-recovery] ❌ Failed to retry settlement {}: {}", correlation_id, e);
                    failed += 1;
                }
            }
        }
    }

    info!("[x402-recovery] Startup recovery complete: {} recovered, {} failed", recovered, failed);
}
