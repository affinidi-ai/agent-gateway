//! Admin API endpoints for x402 settlement management
//!
//! Provides administrative endpoints for querying and managing settlements

use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::rbac::Feature;
use crate::x402::config_cache::get_x402_metadata;

/// Admin API state containing transaction store
#[derive(Clone)]
pub struct AdminApiState {
    pub transaction_store: Option<Arc<crate::x402::TransactionStore>>,
}

/// Query parameters for listing payments
#[derive(Deserialize)]
pub struct ListPaymentsQuery {
    /// Filter by settlement status
    pub status: Option<String>,

    /// Filter by channel ID
    pub surface_id: Option<String>,

    /// Maximum number of results
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

/// Query parameters for unified payments endpoint
#[derive(Deserialize)]
pub struct AllPaymentsQuery {
    /// Filter by channel ID
    pub surface_id: Option<String>,

    /// Maximum number of results
    #[serde(default = "default_limit")]
    pub limit: usize,

    /// Time bucket size in seconds for chart data
    #[serde(default = "default_bucket_seconds")]
    pub bucket_seconds: u64,
}

fn default_bucket_seconds() -> u64 {
    30
}

/// Build explorer URL for a transaction
async fn build_tx_explorer_url(
    network: &str,
    tx_hash: &str,
) -> Option<String> {
    // Get network metadata from cache
    let metadata = get_x402_metadata()
        .await
        .or_else(|| {
            error!("x402 metadata cache not initialized - cannot build explorer URL");
            None
        })?;

    // Find the network by ID
    let network_config = metadata
        .networks
        .iter()
        .find(|n| n.id == network)
        .or_else(|| {
            error!(
                "Network '{}' not found in x402 metadata. Available networks: {:?}",
                network,
                metadata
                    .networks
                    .iter()
                    .map(|n| &n.id)
                    .collect::<Vec<_>>()
            );
            None
        })?;

    // Check if block_explorer contains a template variable ${TX_HASH}
    let explorer_url = &network_config.block_explorer;

    // Replace template variable with actual TX hash
    Some(explorer_url.replace("${TX_HASH}", tx_hash))
}

/// Build explorer URL for an address
async fn build_address_explorer_url(
    network: &str,
    address: &str,
) -> Option<String> {
    // Get network metadata from cache
    let metadata = get_x402_metadata().await?;

    // Find the network by ID
    let network_config = metadata
        .networks
        .iter()
        .find(|n| n.id == network)?;

    // Check if block_explorer contains a template variable ${ADDRESS}
    let explorer_url = &network_config.block_explorer;

    // Replace template variable with actual address
    Some(explorer_url.replace("${ADDRESS}", address))
}

/// Look up recipient name from address using x402 metadata
async fn get_recipient_name(
    network: &str,
    address: &str,
) -> Option<String> {
    // Get network metadata from cache
    let metadata = get_x402_metadata().await?;

    // Search through recipient_addresses to find a match
    for recipient in &metadata.recipient_addresses {
        if let Some(recipient_addr) = recipient
            .addresses
            .get(network)
        {
            // Case-insensitive comparison for addresses
            if recipient_addr.eq_ignore_ascii_case(address) {
                return Some(recipient.name.clone());
            }
        }
    }

    None
}

/// Extract token decimals from x402 metadata
async fn get_token_decimals(
    network: &str,
    asset: &str,
) -> Option<u32> {
    // Get network metadata from cache
    let metadata = get_x402_metadata().await?;

    // Find the network by ID
    let network_config = metadata
        .networks
        .iter()
        .find(|n| n.id == network)?;

    // If asset is "native", return native currency decimals (typically 18 for ETH chains)
    // Native denomination is usually in wei, gwei, etc.
    if asset == "native" {
        // Most EVM chains use 18 decimals for native currency
        // TODO: This could be configured per-network in x402.json
        return Some(18);
    }

    // Find the token by contract address or symbol
    let token = network_config
        .x402_tokens
        .iter()
        .find(|t| {
            // Match by contract address (case-insensitive)
            t.contract_address.eq_ignore_ascii_case(asset) ||
            // Or match by symbol (case-insensitive)
            t.symbol.eq_ignore_ascii_case(asset)
        })?;

    Some(token.decimals as u32)
}

/// Get network name from x402 metadata by network ID
async fn get_network_name(network_id: &str) -> Option<String> {
    // Get network metadata from cache
    let metadata = get_x402_metadata().await?;

    // Find network by ID
    metadata
        .networks
        .iter()
        .find(|n| n.id == network_id)
        .map(|n| n.name.clone())
}

/// Response for payment listing
#[derive(Serialize)]
pub struct ListPaymentsResponse {
    pub payments: Vec<PaymentSummary>,
    pub total: usize,
}

/// Summary of a payment for API responses
#[derive(Serialize)]
pub struct PaymentSummary {
    pub payment_id: String,
    pub surface_id: String,
    pub tx_hash: String,
    pub chain_id: String,
    pub amount: String,
    pub denomination: String,
    pub status: String,
    pub timestamp: i64,
    pub verified_at: Option<i64>,
    pub settled_at: Option<i64>,
    pub settlement_attempts: u32,
    pub last_error: Option<String>,
}

/// Error response for admin API
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

/// Create admin API router. The caller gates the whole router on `payments.view`;
/// the delete routes additionally require `payments.delete` and deny when `guard` is `None`.
pub fn create_admin_router(guard: Option<RbacGuard>) -> Router<AdminApiState> {
    let gate_delete = |mr| maybe_gate(guard.as_ref(), mr, Feature::PaymentsDelete);
    Router::new()
        .route("/x402/payments/all", get(list_all_payments))
        .route("/x402/payments/{payment_id}", get(get_payment))
        .route("/x402/payments", get(list_payments))
        .route("/x402/stats", get(get_stats))
        .route("/x402/sync-status", get(get_sync_status))
        .route(
            "/x402/transactions/{transaction_id}",
            get(get_transaction).merge(gate_delete(delete(delete_transaction))),
        )
        .route("/x402/transactions", get(list_transactions))
        // Legacy endpoints (deprecated - use /transactions instead)
        .route("/x402/verifications/{verification_id}", gate_delete(delete(delete_transaction)))
        .route("/x402/verifications", get(list_transactions))
        .route("/x402/settlements/{settlement_id}", gate_delete(delete(delete_transaction)))
        .route("/x402/settlements", get(list_transactions))
}

/// List payments with optional filtering
async fn list_payments(
    State(state): State<AdminApiState>,
    Query(query): Query<ListPaymentsQuery>,
) -> Result<Json<ListPaymentsResponse>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    // Get all transactions and filter
    let all_transactions = transaction_store
        .list_all()
        .await;

    // Filter to only those with settlement stage
    let mut transactions_with_settlement: Vec<_> = all_transactions
        .into_iter()
        .filter(|t| t.settlement.is_some())
        .collect();

    // Filter by channel if provided
    if let Some(ref channel_id) = query.surface_id {
        transactions_with_settlement.retain(|t| &t.surface_id == channel_id);
    }

    // Filter by status if provided
    if let Some(ref status_str) = query.status {
        transactions_with_settlement.retain(|t| {
            if let Some(ref settlement) = t.settlement {
                format!("{:?}", settlement.status).to_lowercase() == status_str.to_lowercase()
            } else {
                false
            }
        });
    }

    // Sort by timestamp (newest first)
    transactions_with_settlement.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
    });

    // Limit results
    let limited: Vec<_> = transactions_with_settlement
        .into_iter()
        .take(query.limit)
        .collect();
    let total = limited.len();

    // Convert to PaymentSummary
    let summaries: Vec<PaymentSummary> = limited
        .into_iter()
        .filter_map(|t| {
            t.settlement
                .map(|settlement| PaymentSummary {
                    payment_id: t.id.clone(),
                    surface_id: t.surface_id.clone(),
                    tx_hash: settlement.tx_hash.clone(),
                    chain_id: settlement.network.clone(),
                    amount: settlement.amount.clone(),
                    denomination: format!("{} on {}", settlement.scheme, settlement.network),
                    status: format!("{:?}", settlement.status),
                    timestamp: t.created_at.timestamp(),
                    verified_at: Some(
                        t.verification
                            .completed_at
                            .unwrap_or(t.created_at)
                            .timestamp(),
                    ),
                    settled_at: settlement
                        .settlement_completed_at
                        .map(|dt| dt.timestamp()),
                    settlement_attempts: settlement.settlement_attempts,
                    last_error: settlement.error.clone(),
                })
        })
        .collect();

    Ok(Json(ListPaymentsResponse { payments: summaries, total }))
}

/// Get a specific payment by ID
async fn get_payment(
    State(state): State<AdminApiState>,
    Path(payment_id): Path<String>,
) -> Result<Json<PaymentSummary>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    let transaction = transaction_store
        .get(&payment_id)
        .await
        .ok_or_else(|| ErrorResponse {
            error: format!("Payment not found: {}", payment_id),
        })?;

    let settlement = transaction
        .settlement
        .ok_or_else(|| ErrorResponse {
            error: format!("Transaction {} has no settlement stage", payment_id),
        })?;

    Ok(Json(PaymentSummary {
        payment_id: transaction.id.clone(),
        surface_id: transaction.surface_id.clone(),
        tx_hash: settlement.tx_hash.clone(),
        chain_id: settlement.network.clone(),
        amount: settlement.amount.clone(),
        denomination: format!("{} on {}", settlement.scheme, settlement.network),
        status: format!("{:?}", settlement.status),
        timestamp: transaction
            .created_at
            .timestamp(),
        verified_at: Some(
            transaction
                .verification
                .completed_at
                .unwrap_or(transaction.created_at)
                .timestamp(),
        ),
        settled_at: settlement
            .settlement_completed_at
            .map(|dt| dt.timestamp()),
        settlement_attempts: settlement.settlement_attempts,
        last_error: settlement.error.clone(),
    }))
}

/// Get settlement statistics
async fn get_stats(State(state): State<AdminApiState>) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    let all_transactions = transaction_store
        .list_all()
        .await;
    let transactions_with_settlement: Vec<_> = all_transactions
        .into_iter()
        .filter(|t| t.settlement.is_some())
        .collect();

    let total_payments = transactions_with_settlement.len();
    let pending_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.status),
                Some(crate::x402::transaction_store::SettlementStatus::Pending)
            )
        })
        .count();
    let processing_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.status),
                Some(crate::x402::transaction_store::SettlementStatus::Processing)
            )
        })
        .count();
    let completed_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.status),
                Some(crate::x402::transaction_store::SettlementStatus::Completed)
            )
        })
        .count();
    let failed_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.status),
                Some(crate::x402::transaction_store::SettlementStatus::Failed)
            )
        })
        .count();

    Ok(Json(serde_json::json!({
        "total_payments": total_payments,
        "pending_count": pending_count,
        "processing_count": processing_count,
        "completed_count": completed_count,
        "failed_count": failed_count,
    })))
}

/// Get cross-gateway synchronization health status
async fn get_sync_status(State(state): State<AdminApiState>) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    let all_transactions = transaction_store
        .list_all()
        .await;
    let transactions_with_settlement: Vec<_> = all_transactions
        .into_iter()
        .filter(|t| t.settlement.is_some())
        .collect();

    let total = transactions_with_settlement.len();
    let local_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.sync_status),
                Some(crate::x402::transaction_store::SyncStatus::Local)
            )
        })
        .count();
    let pending_sync_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.sync_status),
                Some(crate::x402::transaction_store::SyncStatus::PendingSync)
            )
        })
        .count();
    let synced_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.sync_status),
                Some(crate::x402::transaction_store::SyncStatus::Synced)
            )
        })
        .count();
    let sync_failed_count = transactions_with_settlement
        .iter()
        .filter(|t| {
            matches!(
                t.settlement
                    .as_ref()
                    .map(|s| &s.sync_status),
                Some(crate::x402::transaction_store::SyncStatus::SyncFailed)
            )
        })
        .count();

    let sync_health = if total == 0 {
        "healthy"
    } else if sync_failed_count > total / 10 {
        "critical"
    } else if pending_sync_count > total / 4 {
        "degraded"
    } else {
        "healthy"
    };

    Ok(Json(serde_json::json!({
        "total_records": total,
        "local_count": local_count,
        "pending_sync_count": pending_sync_count,
        "synced_count": synced_count,
        "sync_failed_count": sync_failed_count,
        "health": sync_health,
    })))
}

/// Response for verification listing
#[derive(Serialize)]
pub struct ListVerificationsResponse {
    pub verifications: Vec<VerificationSummary>,
    pub total: usize,
}

/// Unified payment record type (either verification or settlement)
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UnifiedPayment {
    Verification(VerificationSummary),
    Settlement(SettlementSummary),
}

/// Chart data point for time-bucketed payments
#[derive(Serialize, Clone, Debug)]
pub struct ChartDataPoint {
    pub timestamp: i64,
    pub label: String,
    pub count: u32,
    pub verifications: u32,
    pub settlements: u32,
}

/// Response for unified payments listing with chart data
#[derive(Serialize)]
pub struct AllPaymentsResponse {
    pub payments: Vec<UnifiedPayment>,
    pub total: usize,
    pub chart_data: Vec<ChartDataPoint>,
}

/// Summary of a verification for API responses
#[derive(Serialize, Clone, Debug)]
pub struct VerificationSummary {
    pub id: String,
    pub status: String,
    pub surface_id: String,
    pub channel_name: String,
    pub resource_path: String,
    pub tx_hash: Option<String>,
    pub network: Option<String>,
    pub network_name: Option<String>,
    pub amount: Option<String>,
    pub decimals: Option<u32>,
    pub asset: Option<String>,
    pub recipient: Option<String>,
    pub recipient_name: Option<String>,
    pub tx_explorer_url: Option<String>,
    pub address_explorer_url: Option<String>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub error: Option<String>,
    pub settlement_status: Option<String>,
    pub settlement_mode: Option<String>,
    pub settlement_method: Option<String>,
    pub settlement_completed_at: Option<i64>,
    pub correlation_id: Option<String>,
    pub verification_mode: Option<String>,
    pub sync_status: Option<String>,
}

/// List all transactions (unified view of verifications and settlements)
async fn list_transactions(
    State(state): State<AdminApiState>,
    Query(query): Query<ListPaymentsQuery>,
) -> Result<Json<ListVerificationsResponse>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    // Get all transactions
    let mut all_transactions = transaction_store
        .list_all()
        .await;

    // Filter by verification status if provided
    if let Some(ref status_str) = query.status {
        all_transactions.retain(|t| format!("{:?}", t.verification.status).to_lowercase() == status_str.to_lowercase());
    }

    // Filter by channel if provided
    if let Some(ref channel_id) = query.surface_id {
        all_transactions.retain(|t| &t.surface_id == channel_id);
    }

    // Sort by timestamp (newest first)
    all_transactions.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
    });

    // Limit results
    let limited: Vec<_> = all_transactions
        .into_iter()
        .take(query.limit)
        .collect();
    let total = limited.len();

    // Build summaries
    let mut summaries = Vec::new();
    for t in &limited {
        // Get tx_hash from payment payload
        let tx_hash = t.payment_payload.tx_hash();
        let network_str = t.payment_payload.network();
        let amount = t.payment_payload.amount();
        let asset = if t
            .payment_payload
            .accepted
            .asset
            .is_empty()
            || t.payment_payload
                .accepted
                .asset
                == "native"
        {
            None
        } else {
            Some(
                t.payment_payload
                    .accepted
                    .asset
                    .clone(),
            )
        };
        let recipient = t
            .payment_payload
            .accepted
            .pay_to
            .clone();

        // Build explorer URLs
        let tx_explorer_url = if let Some(ref hash) = tx_hash {
            build_tx_explorer_url(network_str, hash).await
        } else {
            None
        };
        let address_explorer_url = build_address_explorer_url(network_str, &recipient).await;

        // Get decimals and network name
        let decimals = get_token_decimals(
            network_str,
            asset
                .as_deref()
                .unwrap_or("native"),
        )
        .await;
        let network_name = get_network_name(network_str).await;

        // Get settlement info if settlement stage exists
        let settlement_status = t
            .settlement
            .as_ref()
            .map(|s| format!("{:?}", s.status));
        let settlement_mode = t
            .settlement
            .as_ref()
            .map(|s| s.settlement_mode.clone());
        let settlement_method = t
            .settlement
            .as_ref()
            .map(|s| s.settlement_method.clone());
        let settlement_completed_at = t
            .settlement
            .as_ref()
            .and_then(|s| {
                s.settlement_completed_at
                    .map(|dt| dt.timestamp())
            });
        let sync_status = t
            .settlement
            .as_ref()
            .map(|s| format!("{:?}", s.sync_status));

        // Look up recipient name from x402 configuration
        let recipient_name = get_recipient_name(network_str, &recipient).await;

        summaries.push(VerificationSummary {
            id: t.id.clone(),
            status: format!("{:?}", t.verification.status),
            surface_id: t.surface_id.clone(),
            channel_name: t.channel_name.clone(),
            resource_path: t.resource_path.clone(),
            tx_hash,
            network: Some(network_str.to_string()),
            network_name,
            amount: Some(amount.to_string()),
            decimals,
            asset,
            recipient: Some(recipient),
            recipient_name,
            tx_explorer_url,
            address_explorer_url,
            created_at: t.created_at.timestamp(),
            completed_at: t
                .verification
                .completed_at
                .map(|dt| dt.timestamp()),
            error: t.verification.error.clone(),
            settlement_status,
            settlement_mode,
            settlement_method,
            settlement_completed_at,
            correlation_id: Some(t.id.clone()),
            verification_mode: Some(
                t.verification
                    .verification_mode
                    .clone(),
            ),
            sync_status,
        });
    }

    Ok(Json(ListVerificationsResponse {
        verifications: summaries,
        total,
    }))
}

/// Summary of a settlement for API responses  
#[derive(Serialize, Clone, Debug)]
pub struct SettlementSummary {
    pub id: String,
    pub tx_hash: String,
    pub network: String,
    pub network_name: Option<String>,
    pub amount: String,
    pub decimals: Option<u32>,
    pub asset: Option<String>,
    pub recipient: Option<String>,
    pub recipient_name: Option<String>,
    pub tx_explorer_url: Option<String>,
    pub address_explorer_url: Option<String>,
    pub surface_id: String,
    pub channel_name: String,
    pub status: String,
    pub verified_at: i64,
    pub settlement_completed_at: Option<i64>,
    pub settlement_attempts: u32,
    pub error: Option<String>,
    pub sync_status: Option<String>,
    pub synced_at: Option<i64>,
    pub correlation_id: Option<String>,
    pub settlement_mode: Option<String>,
    pub settlement_method: Option<String>,
    pub verification_mode: Option<String>,
    pub created_at: i64,
}

/// Get a specific transaction by ID (returns full transaction JSON)
async fn get_transaction(
    State(state): State<AdminApiState>,
    Path(transaction_id): Path<String>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    let transaction = transaction_store
        .get(&transaction_id)
        .await
        .ok_or_else(|| ErrorResponse {
            error: format!("Transaction not found: {}", transaction_id),
        })?;

    // Return the full transaction as JSON
    Ok(Json(serde_json::to_value(&transaction).unwrap_or_else(|_| {
        serde_json::json!({
            "error": "Failed to serialize transaction"
        })
    })))
}

/// List all payments from unified transaction store (new architecture)
async fn list_all_payments_from_transaction_store(
    _state: AdminApiState,
    query: AllPaymentsQuery,
    transaction_store: Arc<crate::x402::TransactionStore>,
) -> Result<Json<AllPaymentsResponse>, ErrorResponse> {
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;

    // Get all transactions
    let all_transactions = transaction_store
        .list_all()
        .await;

    // Filter by channel if requested
    let filtered_transactions: Vec<_> = if let Some(ref channel_id) = query.surface_id {
        all_transactions
            .into_iter()
            .filter(|t| &t.surface_id == channel_id)
            .take(query.limit)
            .collect()
    } else {
        all_transactions
            .into_iter()
            .take(query.limit)
            .collect()
    };

    // Convert transactions to verification and settlement summaries
    let mut verification_summaries = Vec::new();
    let mut settlement_summaries = Vec::new();

    for tx in &filtered_transactions {
        let payment_ref = &tx.payment_payload;

        // Extract common fields
        let network_str = payment_ref.network();
        let tx_hash = payment_ref.tx_hash();
        let asset = if payment_ref
            .accepted
            .asset
            .is_empty()
            || payment_ref.accepted.asset == "native"
        {
            None
        } else {
            Some(
                payment_ref
                    .accepted
                    .asset
                    .clone(),
            )
        };
        let recipient = payment_ref
            .accepted
            .pay_to
            .clone();
        let decimals = get_token_decimals(
            network_str,
            asset
                .as_deref()
                .unwrap_or("native"),
        )
        .await;
        let network_name = get_network_name(network_str).await;
        let tx_explorer_url = if let Some(ref hash) = tx_hash {
            build_tx_explorer_url(network_str, hash).await
        } else {
            None
        };
        let address_explorer_url = build_address_explorer_url(network_str, &recipient).await;

        // Create verification summary (always present)
        let settlement_status = tx
            .settlement
            .as_ref()
            .map(|s| format!("{:?}", s.status));
        let settlement_mode = tx
            .settlement
            .as_ref()
            .map(|s| s.settlement_mode.clone());
        let settlement_method = tx
            .settlement
            .as_ref()
            .map(|s| s.settlement_method.clone());
        let settlement_completed_at = tx
            .settlement
            .as_ref()
            .and_then(|s| {
                s.settlement_completed_at
                    .map(|dt| dt.timestamp())
            });
        let sync_status = tx
            .settlement
            .as_ref()
            .map(|s| format!("{:?}", s.sync_status));

        // Look up recipient name from x402 configuration
        let recipient_name = get_recipient_name(network_str, &recipient).await;

        verification_summaries.push(VerificationSummary {
            id: format!("{}_verification", tx.id), // Unique ID for verification part
            status: format!("{:?}", tx.verification.status),
            surface_id: tx.surface_id.clone(),
            channel_name: tx.channel_name.clone(),
            resource_path: tx.resource_path.clone(),
            tx_hash,
            network: Some(network_str.to_string()),
            network_name: network_name.clone(),
            amount: Some(
                payment_ref
                    .amount()
                    .to_string(),
            ),
            decimals,
            asset: asset.clone(),
            recipient: Some(recipient.clone()),
            recipient_name: recipient_name.clone(),
            tx_explorer_url: tx_explorer_url.clone(),
            address_explorer_url: address_explorer_url.clone(),
            created_at: tx.created_at.timestamp(),
            completed_at: tx
                .verification
                .completed_at
                .map(|dt| dt.timestamp()),
            error: tx.verification.error.clone(),
            settlement_status,
            settlement_mode: settlement_mode.clone(),
            settlement_method: settlement_method.clone(),
            settlement_completed_at,
            correlation_id: Some(tx.id.clone()),
            verification_mode: Some(
                tx.verification
                    .verification_mode
                    .clone(),
            ),
            sync_status: sync_status.clone(),
        });

        // Create settlement summary if settlement exists
        if let Some(ref settlement) = tx.settlement {
            // Build explorer URL for settlement's tx_hash
            let settlement_tx_explorer_url = build_tx_explorer_url(&settlement.network, &settlement.tx_hash).await;
            let settlement_address_explorer_url =
                build_address_explorer_url(&settlement.network, &settlement.pay_to).await;

            settlement_summaries.push(SettlementSummary {
                id: format!("{}_settlement", tx.id), // Unique ID for settlement part
                tx_hash: settlement.tx_hash.clone(),
                network: settlement.network.clone(),
                network_name,
                amount: settlement.amount.clone(),
                decimals,
                asset: settlement.asset.clone(),
                recipient: Some(settlement.pay_to.clone()),
                recipient_name,
                tx_explorer_url: settlement_tx_explorer_url,
                address_explorer_url: settlement_address_explorer_url,
                surface_id: tx.surface_id.clone(),
                channel_name: tx.channel_name.clone(),
                status: format!("{:?}", settlement.status),
                verified_at: tx
                    .verification
                    .completed_at
                    .unwrap_or(tx.created_at)
                    .timestamp(),
                settlement_completed_at: settlement
                    .settlement_completed_at
                    .map(|dt| dt.timestamp()),
                settlement_attempts: settlement.settlement_attempts,
                error: settlement.error.clone(),
                sync_status: Some(format!("{:?}", settlement.sync_status).to_lowercase()),
                synced_at: settlement
                    .synced_at
                    .map(|dt| dt.timestamp()),
                correlation_id: Some(tx.id.clone()),
                settlement_mode: Some(
                    settlement
                        .settlement_mode
                        .clone(),
                ),
                settlement_method: Some(
                    settlement
                        .settlement_method
                        .clone(),
                ),
                verification_mode: Some(
                    tx.verification
                        .verification_mode
                        .clone(),
                ),
                created_at: tx.created_at.timestamp(),
            });
        }
    }

    // Combine and sort by timestamp (most recent first)
    let mut all_payments: Vec<UnifiedPayment> = verification_summaries
        .into_iter()
        .map(UnifiedPayment::Verification)
        .chain(
            settlement_summaries
                .into_iter()
                .map(UnifiedPayment::Settlement),
        )
        .collect();

    all_payments.sort_by(|a, b| {
        let a_time = match a {
            UnifiedPayment::Verification(v) => v.created_at,
            UnifiedPayment::Settlement(s) => s.verified_at,
        };
        let b_time = match b {
            UnifiedPayment::Verification(v) => v.created_at,
            UnifiedPayment::Settlement(s) => s.verified_at,
        };
        b_time.cmp(&a_time) // Most recent first
    });

    // Generate chart data - bucket payments by time
    let bucket_seconds = query.bucket_seconds as i64;
    let mut buckets: HashMap<i64, (u32, u32)> = HashMap::new(); // bucket_timestamp -> (verifications, settlements)

    // Determine time range. Cap the number of pre-seeded empty buckets so a
    // single very old pending payment can't expand the chart to thousands of
    // empty bars (which makes the chart unreadable and bloats the response).
    const MAX_BUCKETS: i64 = 96;
    let now = Utc::now().timestamp();
    let oldest_payment_time = all_payments
        .iter()
        .map(|p| match p {
            UnifiedPayment::Verification(v) => v.created_at,
            UnifiedPayment::Settlement(s) => s.verified_at,
        })
        .min()
        .unwrap_or(now);

    let window_start = now - bucket_seconds * (MAX_BUCKETS - 1);
    let oldest_time = oldest_payment_time.max(window_start);

    // Create buckets from oldest (within window) to now
    let start_bucket = (oldest_time / bucket_seconds) * bucket_seconds;
    let end_bucket = (now / bucket_seconds) * bucket_seconds;

    for bucket_start in (start_bucket..=end_bucket).step_by(bucket_seconds as usize) {
        buckets.insert(bucket_start, (0, 0));
    }

    // Fill buckets with payment counts
    for payment in &all_payments {
        let timestamp = match payment {
            UnifiedPayment::Verification(v) => v.created_at,
            UnifiedPayment::Settlement(s) => s.verified_at,
        };
        // Skip payments outside the chart window so old pending verifications
        // don't re-expand the bucket range.
        if timestamp < start_bucket {
            continue;
        }
        let bucket_start = (timestamp / bucket_seconds) * bucket_seconds;

        let counts = buckets
            .entry(bucket_start)
            .or_insert((0, 0));
        match payment {
            UnifiedPayment::Verification(_) => counts.0 += 1,
            UnifiedPayment::Settlement(_) => counts.1 += 1,
        }
    }

    // Convert buckets to chart data points
    let mut chart_data: Vec<ChartDataPoint> = buckets
        .into_iter()
        .map(|(timestamp, (verifications, settlements))| {
            let dt = DateTime::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
            let label = dt
                .format("%H:%M:%S")
                .to_string();

            ChartDataPoint {
                timestamp,
                label,
                count: verifications + settlements,
                verifications,
                settlements,
            }
        })
        .collect();

    // Sort chart data by timestamp
    chart_data.sort_by_key(|d| d.timestamp);

    let total = all_payments.len();

    Ok(Json(AllPaymentsResponse {
        payments: all_payments,
        total,
        chart_data,
    }))
}

/// List all payments (verifications + settlements) with chart data
async fn list_all_payments(
    State(state): State<AdminApiState>,
    Query(query): Query<AllPaymentsQuery>,
) -> Result<Json<AllPaymentsResponse>, ErrorResponse> {
    // Require unified transaction store (no legacy fallback)
    let transaction_store = state
        .transaction_store
        .clone()
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    list_all_payments_from_transaction_store(state, query, transaction_store).await
}

/// Delete a transaction (payment record)
/// Only allows deletion if transaction is finalized (not in pending/processing state)
async fn delete_transaction(
    State(state): State<AdminApiState>,
    Path(transaction_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse {
            error: "Transaction store not configured".to_string(),
        })?;

    // Get the transaction to check if it's finalized
    let transaction = transaction_store
        .get(&transaction_id)
        .await
        .ok_or_else(|| ErrorResponse {
            error: "Transaction not found".to_string(),
        })?;

    // Check if verification stage is pending
    if transaction
        .verification
        .status
        == crate::x402::transaction_store::VerificationStatus::Pending
    {
        return Err(ErrorResponse {
            error: "Cannot delete transaction with pending verification".to_string(),
        });
    }

    // Check if settlement stage exists and is pending/processing
    if let Some(ref settlement) = transaction.settlement {
        match settlement.status {
            crate::x402::transaction_store::SettlementStatus::Pending
            | crate::x402::transaction_store::SettlementStatus::Processing
            | crate::x402::transaction_store::SettlementStatus::AwaitingRemote
            | crate::x402::transaction_store::SettlementStatus::AwaitingExternal => {
                return Err(ErrorResponse {
                    error: "Cannot delete transaction with pending/processing settlement".to_string(),
                });
            }
            _ => {} // Completed, Failed, Refunded - OK to delete
        }
    }

    // Transaction is finalized - safe to delete
    transaction_store
        .delete(&transaction_id)
        .await
        .map_err(|e| {
            error!("Failed to delete transaction: {}", e);
            ErrorResponse {
                error: format!("Failed to delete transaction: {}", e),
            }
        })?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::{AuthGuardOk, require_feature};
    use crate::rbac::RbacConfig;
    use axum::{Extension, body::Body, http::Request};
    use chrono::Utc;
    use tower::ServiceExt;

    async fn storage_with_users(users: &[(&str, UserRole)]) -> (Arc<PasskeyStorage>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = PasskeyStorage::new(
            dir.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            dir.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let now = Utc::now();
        for (user_id, role) in users {
            storage
                .save_user(&UserData {
                    user_id: user_id.to_string(),
                    username: user_id.to_string(),
                    passkeys: Vec::new(),
                    role: role.clone(),
                    status: UserStatus::Approved,
                    is_primary: false,
                    first_name: None,
                    last_name: None,
                    email: None,
                    department: None,
                    job_title: None,
                    avatar_path: None,
                    created_at: now,
                    updated_at: now,
                    last_logged_in: None,
                    saml_id: None,
                })
                .await
                .unwrap();
        }
        (Arc::new(storage), dir)
    }

    fn gated_app(
        storage: Arc<PasskeyStorage>,
        user_id: &str,
    ) -> Router {
        let rbac_config = Arc::new(RbacConfig::default());
        let guard = RbacGuard::new(storage.clone(), rbac_config.clone());
        create_admin_router(Some(guard))
            .with_state(AdminApiState { transaction_store: None })
            .layer(require_feature(storage, rbac_config, Feature::PaymentsView))
            .layer(Extension(AuthGuardOk(user_id.to_string())))
    }

    async fn status_of(
        app: Router,
        method: &str,
        uri: &str,
    ) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        app.oneshot(req)
            .await
            .unwrap()
            .status()
    }

    const DELETE_ROUTES: [&str; 3] = ["/x402/transactions/t1", "/x402/verifications/t1", "/x402/settlements/t1"];

    #[tokio::test]
    async fn base_user_is_forbidden_from_reads_and_deletes() {
        let (storage, _dir) = storage_with_users(&[("user-1", UserRole::User)]).await;
        assert_eq!(
            status_of(gated_app(storage.clone(), "user-1"), "GET", "/x402/payments/all").await,
            StatusCode::FORBIDDEN
        );
        for uri in DELETE_ROUTES {
            assert_eq!(
                status_of(gated_app(storage.clone(), "user-1"), "DELETE", uri).await,
                StatusCode::FORBIDDEN,
                "DELETE {uri}"
            );
        }
    }

    #[tokio::test]
    async fn poweruser_reads_payments_but_cannot_delete_them() {
        let (storage, _dir) = storage_with_users(&[("power-1", UserRole::PowerUser)]).await;
        assert_eq!(
            status_of(gated_app(storage.clone(), "power-1"), "GET", "/x402/transactions/t1").await,
            StatusCode::INTERNAL_SERVER_ERROR,
            "GET must reach the handler, which reports the missing store"
        );
        for uri in DELETE_ROUTES {
            assert_eq!(
                status_of(gated_app(storage.clone(), "power-1"), "DELETE", uri).await,
                StatusCode::FORBIDDEN,
                "DELETE {uri}"
            );
        }
    }

    #[tokio::test]
    async fn administrator_delete_reaches_the_handler() {
        let (storage, _dir) = storage_with_users(&[("admin-1", UserRole::Administrator)]).await;
        for uri in DELETE_ROUTES {
            assert_eq!(
                status_of(gated_app(storage.clone(), "admin-1"), "DELETE", uri).await,
                StatusCode::INTERNAL_SERVER_ERROR,
                "DELETE {uri} must reach the handler, which reports the missing store"
            );
        }
    }

    #[tokio::test]
    async fn deletes_deny_without_a_guard_while_reads_still_route() {
        let app = create_admin_router(None).with_state(AdminApiState { transaction_store: None });
        assert_eq!(status_of(app.clone(), "GET", "/x402/transactions/t1").await, StatusCode::INTERNAL_SERVER_ERROR);
        for uri in DELETE_ROUTES {
            assert_eq!(status_of(app.clone(), "DELETE", uri).await, StatusCode::FORBIDDEN, "DELETE {uri}");
        }
    }
}
