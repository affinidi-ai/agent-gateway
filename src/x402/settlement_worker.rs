//! Background settlement worker for processing deferred payments
//!
//! This worker runs in a separate tokio task and periodically:
//! 1. Queries TransactionStore for pending deferred settlements
//! 2. Executes settlements using existing settlement functions
//! 3. Triggers integration events for lifecycle changes
//! 4. Handles retries with exponential backoff

use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

use super::{PaymentPayload, TransactionStore};
use crate::config::types::X402Config;

/// Background worker configuration
pub struct SettlementWorkerConfig {
    /// TransactionStore for querying pending settlements
    pub transaction_store: Arc<TransactionStore>,

    /// X402 configuration (global)
    pub x402_config: Arc<X402Config>,

    /// Bootstrap config for loading channel configurations
    pub bootstrap_config: Arc<crate::config::BootstrapConfig>,

    /// Local gateway ID (for filtering delegated settlements)
    pub local_gateway_id: Option<String>,

    /// Batch size for processing
    pub batch_size: usize,

    /// Interval between settlement runs (seconds)
    pub interval_seconds: u64,

    /// Maximum retry attempts
    pub max_retries: u32,
}

/// Start the background settlement worker task
///
/// Returns a JoinHandle that can be used to wait for or cancel the worker
pub fn start_settlement_worker(config: SettlementWorkerConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            "🚀 Deferred settlement worker started (batch_size={}, interval={}s, max_retries={})",
            config.batch_size, config.interval_seconds, config.max_retries
        );

        loop {
            // Sleep first to give the gateway time to accumulate some pending payments
            sleep(Duration::from_secs(config.interval_seconds)).await;

            if let Err(e) = process_pending_settlements(&config).await {
                error!("Settlement worker error: {}", e);
            }
        }
    })
}

/// Process a batch of pending settlements
async fn process_pending_settlements(config: &SettlementWorkerConfig) -> Result<(), Box<dyn std::error::Error>> {
    use crate::x402::transaction_store::SettlementStatus;

    debug!("⏰ Settlement worker tick - checking for pending deferred settlements...");

    // Query TransactionStore for all pending deferred settlements
    let pending_transactions = config
        .transaction_store
        .list_by_settlement_status(SettlementStatus::Pending)
        .await;

    // Filter for deferred settlement mode only
    let deferred_pending: Vec<_> = pending_transactions
        .into_iter()
        .filter(|txn| {
            txn.settlement
                .as_ref()
                .map(|s| s.settlement_mode == "deferred")
                .unwrap_or(false)
        })
        .collect();

    // Filter out settlements delegated to other gateways
    let local_settlements: Vec<_> = deferred_pending
        .into_iter()
        .filter(|txn| {
            let _settlement = match &txn.settlement {
                Some(s) => s,
                None => return false,
            };

            // Check if this gateway should settle based on facilitator_gateway_id
            // - No facilitator = local transaction, we settle it
            // - Has facilitator = delegated transaction, only the facilitator settles it
            match (&txn.verification.facilitator_gateway_id, &config.local_gateway_id) {
                // No facilitator - local transaction, process it
                (None, _) => true,
                // Has facilitator - only process if we ARE the facilitator
                (Some(facilitator_gw_id), Some(local_gw_id)) => {
                    if facilitator_gw_id == local_gw_id {
                        true
                    } else {
                        debug!(
                            "Skipping settlement for correlation_id={}: delegated to facilitator gateway {} (local gateway is {})",
                            txn.id, facilitator_gw_id, local_gw_id
                        );
                        false
                    }
                }
                // Has facilitator but we don't know our local ID - skip to be safe
                (Some(facilitator_gw_id), None) => {
                    warn!(
                        "Skipping settlement for correlation_id={}: delegated to facilitator gateway {} but local gateway ID unknown",
                        txn.id, facilitator_gw_id
                    );
                    false
                }
            }
        })
        .collect();

    if local_settlements.is_empty() {
        debug!("⏰ Settlement worker: No pending local settlements to process");
        return Ok(());
    }

    info!("Processing {} pending local settlement(s)", local_settlements.len());

    let mut processed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for txn in local_settlements
        .into_iter()
        .take(config.batch_size)
    {
        let correlation_id = &txn.id;
        let channel_id = &txn.surface_id;

        let settlement = match &txn.settlement {
            Some(s) => s,
            None => {
                warn!("Transaction {} has no settlement stage, skipping", correlation_id);
                skipped += 1;
                continue;
            }
        };

        // Check if we've exceeded max retries
        if settlement.settlement_attempts >= config.max_retries {
            warn!("Transaction {} exceeded max retries ({}), marking as failed", correlation_id, config.max_retries);

            if let Err(e) = config
                .transaction_store
                .fail_settlement(correlation_id, "Exceeded maximum retry attempts".to_string())
                .await
            {
                error!("Failed to update transaction {} to Failed status: {}", correlation_id, e);
            }

            // Trigger integration alert for settlement failure
            crate::integrations::trigger_transaction_settlement_failed(
                correlation_id,
                channel_id,
                &settlement.tx_hash,
                &settlement.settlement_method,
                "Exceeded maximum retry attempts",
            )
            .await;

            failed += 1;
            continue;
        }

        // Increment attempt counter (write-ahead logging)
        if let Err(e) = config
            .transaction_store
            .increment_settlement_attempt(correlation_id)
            .await
        {
            error!("Failed to increment settlement attempt for {}: {}", correlation_id, e);
            continue;
        }

        debug!(
            "Executing deferred settlement correlation_id={} channel_id={} attempt={}",
            correlation_id,
            channel_id,
            settlement.settlement_attempts + 1
        );

        // Load channel-specific payment_policy from storage
        let payment_policy = load_channel_payment_policy(channel_id, &config.bootstrap_config).await;

        let x402_config_to_use = payment_policy
            .as_ref()
            .unwrap_or(&config.x402_config);

        let settlement_result = match crate::x402::settleable_payload(&txn, payment_policy.as_ref()).await {
            Ok(payload) => execute_settlement(&txn, &payload, x402_config_to_use, &config.transaction_store).await,
            Err(e) => Err(e),
        };

        // Execute settlement based on settlement_method
        match settlement_result {
            Ok(tx_hash) => {
                info!("✅ Deferred settlement completed correlation_id={} tx_hash={}", correlation_id, tx_hash);

                // Trigger integration alert for successful transaction completion
                crate::integrations::trigger_transaction_completed(
                    correlation_id,
                    channel_id,
                    &tx_hash,
                    &settlement.amount,
                    &settlement.network,
                    &settlement.settlement_method,
                )
                .await;

                processed += 1;
            }
            Err(e) => {
                error!("❌ Deferred settlement failed correlation_id={}: {}", correlation_id, e);

                // Update transaction with error
                if let Err(update_err) = config
                    .transaction_store
                    .fail_settlement(correlation_id, e.clone())
                    .await
                {
                    error!("Failed to update transaction {} with error: {}", correlation_id, update_err);
                }

                // Trigger integration alert for settlement failure
                crate::integrations::trigger_transaction_settlement_failed(
                    correlation_id,
                    channel_id,
                    &settlement.tx_hash,
                    &settlement.settlement_method,
                    &e,
                )
                .await;

                failed += 1;
            }
        }
    }

    info!("Settlement batch complete: {} processed, {} failed, {} skipped", processed, failed, skipped);

    Ok(())
}

/// Execute settlement for a transaction using existing settlement functions
/// Routes to appropriate execution based on settlement_method
async fn execute_settlement(
    txn: &crate::x402::transaction_store::X402Transaction,
    payload: &PaymentPayload,
    x402_config: &X402Config,
    transaction_store: &Arc<TransactionStore>,
) -> Result<String, String> {
    let settlement = txn
        .settlement
        .as_ref()
        .ok_or_else(|| "No settlement stage".to_string())?;

    let correlation_id = &txn.id;
    let channel_id = &txn.surface_id;
    let channel_name = &txn.channel_name;

    debug!("Executing settlement method={} correlation_id={}", settlement.settlement_method, correlation_id);

    match settlement
        .settlement_method
        .as_str()
    {
        "local" => {
            // Local settlement via embedded facilitator
            execute_local_settlement(
                payload,
                x402_config,
                channel_name,
                channel_id,
                transaction_store,
                settlement.confirmations,
                correlation_id.clone(),
            )
            .await
        }
        "fabric_gateway" => {
            // Settlement via DIDComm to another gateway
            execute_fabric_gateway_settlement(
                payload,
                x402_config,
                channel_name,
                channel_id,
                transaction_store,
                settlement.confirmations,
                correlation_id.clone(),
            )
            .await
        }
        "external_facilitator" => {
            // Settlement via external facilitator
            Err("External facilitator settlement not yet implemented".to_string())
        }
        unknown => Err(format!("Unknown settlement method: {}", unknown)),
    }
}

/// Execute local settlement via embedded facilitator
/// This reuses the existing local settlement logic from settlement.rs
async fn execute_local_settlement(
    payload: &PaymentPayload,
    config: &X402Config,
    _channel_name: &str,
    channel_id: &str,
    transaction_store: &Arc<TransactionStore>,
    _confirmations: Option<u64>,
    correlation_id: String,
) -> Result<String, String> {
    use crate::channel_error;
    use crate::channel_info;

    // Load facilitator_private_keys from global x402.json (required for security)
    let merged_config = if let Ok(global_config) = crate::x402::config_cache::get_or_load_x402_config().await {
        let mut merged = config.clone();
        if let Some(global_keys) = &global_config.facilitator_private_keys {
            merged.facilitator_private_keys = Some(global_keys.clone());
            channel_info!(
                channel_id,
                "Loaded {} facilitator_private_keys from global x402.json for deferred settlement",
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
                "Merging {} RPC endpoints from global x402.json for deferred settlement",
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
    let facilitator = crate::x402::embedded_facilitator::get_embedded_facilitator(&merged_config)
        .await
        .map_err(|e| {
            channel_error!(channel_id, "Failed to initialize embedded facilitator for settlement: {}", e);
            e.to_string()
        })?;

    // Validate authorization hasn't expired (EIP-3009 only)
    if let Some(authorization) = payload.eip3009_authorization() {
        use alloy::primitives::U256;

        // Parse validBefore timestamp
        let valid_before: U256 = authorization
            .valid_before
            .parse()
            .map_err(|_| {
                channel_error!(channel_id, "Invalid validBefore in authorization");
                "Invalid validBefore timestamp".to_string()
            })?;

        // Check if authorization has expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now >= valid_before.to::<u64>() {
            channel_error!(
                channel_id,
                "Payment authorization expired: validBefore={} now={} [network={}]",
                valid_before,
                now,
                payload.network()
            );
            return Err(format!("Payment authorization is expired (validBefore={}, now={})", valid_before, now));
        }

        channel_info!(
            channel_id,
            "Authorization time window validated: validBefore={} now={} remaining={}s",
            valid_before,
            now,
            valid_before.to::<u64>() - now
        );
    }

    // Convert payload to x402 SettleRequest
    let settle_request = crate::x402::x402rs_adapter::to_settle_request(payload).map_err(|e| {
        channel_error!(channel_id, "Failed to convert to x402 settle request: {}", e);
        format!("Failed to convert payment to x402 format: {}", e)
    })?;

    channel_info!(
        channel_id,
        "Executing deferred settlement via embedded facilitator network={} amount={}",
        payload.network(),
        payload.amount()
    );

    // Execute on-chain settlement
    let settle_response = facilitator
        .settle(settle_request)
        .await
        .map_err(|e| {
            channel_error!(channel_id, "Settlement execution failed: {} [network={}]", e, payload.network());
            format!("Settlement execution failed: {}", e)
        })?;

    // Check if settlement was successful and extract transaction hash
    let is_successful = crate::x402::x402rs_adapter::is_settlement_successful(&settle_response);
    let tx_hash = crate::x402::x402rs_adapter::extract_transaction(&settle_response);

    if !is_successful {
        let error_msg = crate::x402::x402rs_adapter::extract_settle_error(&settle_response)
            .unwrap_or_else(|| "Unknown settlement error".to_string());

        channel_error!(channel_id, "Settlement failed: {}", error_msg);
        return Err(error_msg);
    }

    let tx_hash_str = tx_hash.ok_or_else(|| {
        channel_error!(channel_id, "Settlement succeeded but no transaction hash returned");
        "No transaction hash in settlement response".to_string()
    })?;

    channel_info!(channel_id, "Settlement executed successfully tx_hash={}", tx_hash_str);

    // Update transaction store with settlement tx_hash
    if let Err(e) = transaction_store
        .set_settlement_tx_hash(&correlation_id, tx_hash_str.clone())
        .await
    {
        channel_error!(channel_id, "Failed to update transaction with tx_hash: {}", e);
    }

    // Complete settlement in TransactionStore
    if let Err(e) = transaction_store
        .complete_settlement(&correlation_id)
        .await
    {
        channel_error!(channel_id, "Failed to complete settlement in transaction store: {}", e);
    } else {
        channel_info!(channel_id, "Transaction store updated: settlement completed correlation_id={}", correlation_id);
    }

    // Check if this transaction was delegated from another gateway (via FabricGateway verification)
    // If so, mark it as pending sync so the sync worker can send settlement completion notification
    if let Some(txn) = transaction_store
        .get(&correlation_id)
        .await
        && let Some(ref facilitator_gw_id) = txn
            .verification
            .facilitator_gateway_id
    {
        channel_info!(
            channel_id,
            "Transaction was delegated from gateway {}, marking for settlement completion sync",
            facilitator_gw_id
        );

        // Mark transaction as pending sync
        // The settlement sync worker will poll for these and send DIDComm notifications
        if let Err(e) = transaction_store
            .mark_pending_sync(&correlation_id)
            .await
        {
            channel_error!(channel_id, "Failed to mark transaction as pending sync: {}", e);
        } else {
            channel_info!(
                channel_id,
                "✅ Transaction marked as pending sync: correlation_id={} tx_hash={} → gateway={}",
                correlation_id,
                tx_hash_str,
                facilitator_gw_id
            );
        }
    }

    Ok(tx_hash_str)
}

/// Execute settlement via fabric gateway (DIDComm delegation)
/// This reuses the existing fabric gateway settlement logic
async fn execute_fabric_gateway_settlement(
    payload: &PaymentPayload,
    config: &X402Config,
    _channel_name: &str,
    channel_id: &str,
    transaction_store: &Arc<TransactionStore>,
    _confirmations: Option<u64>,
    correlation_id: String,
) -> Result<String, String> {
    use crate::channel_error;
    use crate::channel_info;

    // Get facilitator gateway ID from config (facilitator handles both verification AND settlement)
    let facilitator_gateway_id = config
        .facilitator_gateway_id
        .as_ref()
        .ok_or_else(|| {
            channel_error!(
                channel_id,
                "settlement_mode is deferred with fabric_gateway but facilitator_gateway_id not configured"
            );
            "Facilitator gateway ID not configured".to_string()
        })?;

    channel_info!(channel_id, "Sending deferred settlement request to facilitator gateway: {}", facilitator_gateway_id);

    // Send DIDComm settle-request to remote gateway
    match crate::x402::didcomm_facilitator_client::settle_via_gateway_facilitator(payload, config, channel_id).await {
        Ok(tx_hash) => {
            channel_info!(channel_id, "✅ Gateway settlement completed tx_hash={}", tx_hash);

            // Update TransactionStore with tx_hash
            if let Err(e) = transaction_store
                .set_settlement_tx_hash(&correlation_id, tx_hash.clone())
                .await
            {
                channel_error!(channel_id, "Failed to update transaction with tx_hash: {}", e);
            }

            // Complete settlement in TransactionStore
            if let Err(e) = transaction_store
                .complete_settlement(&correlation_id)
                .await
            {
                channel_error!(channel_id, "Failed to complete settlement in transaction store: {}", e);
            } else {
                channel_info!(
                    channel_id,
                    "Transaction store updated: settlement completed correlation_id={}",
                    correlation_id
                );
            }

            Ok(tx_hash)
        }
        Err(e) => {
            channel_error!(channel_id, "❌ Gateway settlement failed: {} facilitator={}", e, facilitator_gateway_id);
            Err(e)
        }
    }
}

/// Get settlement worker configuration from global x402 config
/// Returns None if settlement worker should not run (e.g., no storage configured)
pub async fn get_worker_config_from_x402_config(
    transaction_store: Arc<TransactionStore>,
    x402_config: Arc<X402Config>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    gateway_store: Option<Arc<dyn crate::gateways::filesystem::GatewayStore>>,
) -> Option<SettlementWorkerConfig> {
    // Check if settlement storage is configured
    let storage_config = x402_config
        .settlement_storage
        .as_ref()?;

    let batch_size = storage_config.batch_size;
    let interval_seconds = storage_config.settlement_interval_seconds;
    let max_retries = storage_config.max_retries;

    // Get local gateway ID from storage if available
    let local_gateway_id = if let Some(ref store) = gateway_store {
        crate::gateways::filesystem::get_local_gateway_id(store).await
    } else {
        None
    };

    info!(
        "Initializing settlement worker: batch_size={}, interval={}s, max_retries={}, local_gateway_id={:?}",
        batch_size, interval_seconds, max_retries, local_gateway_id
    );

    Some(SettlementWorkerConfig {
        transaction_store,
        local_gateway_id,
        x402_config,
        bootstrap_config,
        batch_size,
        interval_seconds,
        max_retries,
    })
}

/// Start settlement sync worker
/// Polls for transactions with pending sync status and sends settlement completion notifications
pub fn start_settlement_sync_worker(
    transaction_store: Arc<TransactionStore>,
    listener_manager: Option<Arc<crate::gateways::ConnectionPointListenerManager>>,
    gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    interval_seconds: u64,
) -> tokio::task::JoinHandle<()> {
    info!("Starting settlement sync worker (polls every {}s for pending sync transactions)", interval_seconds);

    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(interval_seconds));
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 5;

        loop {
            interval.tick().await;

            match process_pending_sync(&transaction_store, &listener_manager, &gateway_store).await {
                Ok(processed) => {
                    if processed > 0 {
                        info!("Settlement sync worker processed {} pending notifications", processed);
                    }
                    consecutive_errors = 0;
                }
                Err(e) => {
                    consecutive_errors += 1;
                    error!(
                        "Settlement sync worker error (attempt {}/{}): {}",
                        consecutive_errors, MAX_CONSECUTIVE_ERRORS, e
                    );

                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        error!("Settlement sync worker stopping after {} consecutive errors", MAX_CONSECUTIVE_ERRORS);
                        break;
                    }
                }
            }
        }

        warn!("Settlement sync worker stopped");
    })
}

/// Process transactions with pending sync status
async fn process_pending_sync(
    transaction_store: &TransactionStore,
    listener_manager: &Option<Arc<crate::gateways::ConnectionPointListenerManager>>,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
) -> Result<usize, String> {
    // Get all transactions that need settlement completion notifications sent
    let pending_txns = transaction_store
        .list_pending_sync()
        .await;

    if pending_txns.is_empty() {
        return Ok(0);
    }

    debug!("Found {} transactions with pending settlement completion sync", pending_txns.len());

    // Check if we have the necessary infrastructure to send messages
    let can_send = listener_manager.is_some() && gateway_store.is_some();

    if !can_send {
        debug!("Listener manager or gateway store not available yet, will retry later");
        return Ok(0);
    }

    let manager = listener_manager
        .as_ref()
        .unwrap();
    let mut processed = 0;

    for txn in pending_txns {
        // Get target gateway ID (the gateway that requested verification)
        let target_gateway_id = match &txn
            .verification
            .facilitator_gateway_id
        {
            Some(id) => id,
            None => {
                warn!("Transaction {} has pending sync but no facilitator_gateway_id, marking as synced", txn.id);
                // Mark as synced since there's no one to notify
                let _ = transaction_store
                    .mark_synced(&txn.id)
                    .await;
                continue;
            }
        };

        // Get settlement details
        let settlement = match &txn.settlement {
            Some(s) => s,
            None => {
                warn!("Transaction {} has pending sync but no settlement stage, marking as synced", txn.id);
                let _ = transaction_store
                    .mark_synced(&txn.id)
                    .await;
                continue;
            }
        };

        // Send settlement completion notification via DIDComm
        info!(
            "📨 Sending settlement completion notification: correlation_id={} tx_hash={} → gateway={}",
            txn.id, settlement.tx_hash, target_gateway_id
        );

        match manager
            .send_settlement_complete(target_gateway_id, &txn.id, &settlement.tx_hash)
            .await
        {
            Ok(_) => {
                info!("✅ Settlement completion message sent successfully");

                // Mark as synced after successful send
                if let Err(e) = transaction_store
                    .mark_synced(&txn.id)
                    .await
                {
                    warn!("Failed to mark transaction {} as synced: {}", txn.id, e);
                } else {
                    info!("✅ Transaction {} marked as synced", txn.id);
                    processed += 1;
                }
            }
            Err(e) => {
                warn!("Failed to send settlement completion for transaction {}: {}", txn.id, e);
                // Don't mark as synced, will retry on next poll
            }
        }
    }

    Ok(processed)
}

/// Load channel configuration and extract payment_policy
pub(crate) async fn load_channel_payment_policy(
    channel_id: &str,
    bootstrap_config: &Arc<crate::config::BootstrapConfig>,
) -> Option<X402Config> {
    #[allow(unused_imports)]
    use crate::surfaces::AgentSurfaceStore;

    // Only support local/filesystem surface storage for now
    // DynamoDB surface storage would need different implementation
    if bootstrap_config.channel_config_source != "local" && bootstrap_config.channel_config_source != "filesystem" {
        warn!(
            "Settlement worker only supports local/filesystem surface storage, got: {}",
            bootstrap_config.channel_config_source
        );
        return None;
    }

    let path = std::path::PathBuf::from(
        &bootstrap_config
            .storage_paths
            .agent_surfaces,
    );

    let storage = match crate::surfaces::FileSystemAgentSurfaceStore::new(path).await {
        Ok(store) => store,
        Err(e) => {
            error!("Failed to create FileSystemAgentSurfaceStore: {}", e);
            return None;
        }
    };

    match storage.get(channel_id).await {
        Ok(Some(surface)) => {
            // Try default variant (which falls back to the base surface when no
            // variants are configured). `resolve_variant(None)` returns either
            // the resolved default variant overlay or the base surface itself.
            match surface.resolve_variant(None) {
                Ok(resolved) => {
                    if let Some(policy) = resolved
                        .x402_config()
                        .cloned()
                    {
                        debug!("✓ Loaded payment_policy for channel_id={}", channel_id);
                        return Some(policy);
                    }
                }
                Err(e) => {
                    debug!("resolve_variant(None) failed for channel_id={}: {}", channel_id, e);
                }
            }

            warn!("Channel {} found but has no payment_policy", channel_id);
            None
        }
        Ok(None) => {
            warn!("Channel {} not found in storage", channel_id);
            None
        }
        Err(e) => {
            error!("Failed to load channel {}: {}", channel_id, e);
            None
        }
    }
}
