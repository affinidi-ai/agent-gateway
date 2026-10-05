//! Unified x402 Transaction Store
//!
//! Single source of truth for x402 verification → settlement lifecycle
//! Each transaction is stored as a single JSON file named by correlation_id

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

use super::PaymentPayload;
use crate::delegation_vault::audit::PaymentStage;
use crate::storage::filesystem::{StorableEntity, StorageBackend, uncached_storage};

/// Emit a protocol-independent payment audit event for an x402 transaction.
/// `vc_jwt`, when present, is a dispute-evidence credential minted for this
/// stage (see `payment_credentials`) and is stamped onto the same event.
fn emit_payment_audit(
    txn: &X402Transaction,
    stage: PaymentStage,
    error: Option<String>,
    vc_jwt: Option<&str>,
) {
    use crate::delegation_vault::audit::{PaymentEventDetails, PaymentRail, record_payment_event};
    let payload = &txn.payment_payload;
    let amount = payload.amount();
    let network = payload.network();
    let scheme = payload.scheme();
    record_payment_event(
        PaymentEventDetails {
            rail: PaymentRail::X402,
            stage,
            transaction_id: txn.id.clone(),
            amount: (!amount.is_empty()).then(|| amount.to_string()),
            currency: (!network.is_empty()).then(|| network.to_string()),
            method: (!scheme.is_empty()).then(|| scheme.to_string()),
            payer: payload.from(),
            error,
            delegated: false,
            payment_gateway_id: None,
            payment_surface_id: None,
            remote_status: None,
        },
        Some(&txn.surface_id),
        Some(&txn.channel_name),
        txn.trace_id.as_deref(),
        false,
        vc_jwt,
    );
}

/// Build a [`crate::payment_credentials::PaymentReceiptInput`] from an x402
/// transaction's own fields.
fn receipt_input_from_transaction(
    txn: &X402Transaction,
    settled: bool,
    settlement: Option<crate::payment_credentials::SettlementEvidence>,
) -> crate::payment_credentials::PaymentReceiptInput {
    let payload = &txn.payment_payload;
    let amount = payload.amount();
    let network = payload.network();
    let scheme = payload.scheme();
    crate::payment_credentials::PaymentReceiptInput {
        rail: "x402",
        payment_id: txn.id.clone(),
        trace_id: txn.trace_id.clone(),
        amount: (!amount.is_empty()).then(|| amount.to_string()),
        currency: (!network.is_empty()).then(|| network.to_string()),
        method: (!scheme.is_empty()).then(|| scheme.to_string()),
        payer: payload.from(),
        resource: Some(txn.resource_path.clone()),
        settled,
        settlement,
        payer_signature: payload.signature(),
    }
}

/// Build a [`crate::payment_credentials::PaymentRejectionInput`] from an
/// x402 transaction's own fields.
fn rejection_input_from_transaction(
    txn: &X402Transaction,
    reason: String,
) -> crate::payment_credentials::PaymentRejectionInput {
    let payload = &txn.payment_payload;
    let scheme = payload.scheme();
    crate::payment_credentials::PaymentRejectionInput {
        rail: "x402",
        payment_id: txn.id.clone(),
        trace_id: txn.trace_id.clone(),
        method: (!scheme.is_empty()).then(|| scheme.to_string()),
        payer: payload.from(),
        reason,
    }
}

/// Verification status enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    /// Verification request sent, awaiting response
    Pending,
    /// Verification completed successfully
    Verified,
    /// Verification failed
    Failed,
    /// Verification timed out
    Timeout,
}

/// Settlement status enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettlementStatus {
    /// Payment verified, awaiting settlement
    Pending,
    /// Settlement in progress (local execution)
    Processing,
    /// Sent to remote gateway, awaiting response
    AwaitingRemote,
    /// Sent to external facilitator, awaiting response
    AwaitingExternal,
    /// Settlement completed successfully
    Completed,
    /// Settlement failed (after retries)
    Failed,
    /// Payment refunded
    Refunded,
}

/// Cross-gateway synchronization status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncStatus {
    /// Record only exists on originating gateway (no sync needed)
    Local,
    /// Notification sent to facilitator gateway, awaiting ACK
    PendingSync,
    /// ACK received from facilitator gateway (safe to delete after retention)
    Synced,
    /// Synchronization failed after retries
    SyncFailed,
}

/// Verification stage of transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStage {
    /// Verification status
    pub status: VerificationStatus,

    /// Verification mode used
    pub verification_mode: String,

    /// When verification started
    pub created_at: DateTime<Utc>,

    /// When verification completed (if any)
    pub completed_at: Option<DateTime<Utc>>,

    /// Error message if verification failed
    pub error: Option<String>,

    /// Facilitator gateway ID (for remote verification via fabric)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facilitator_gateway_id: Option<String>,

    /// DIDComm thread ID (for remote verification tracking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub didcomm_thread_id: Option<String>,

    /// One-time access token (for async verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

/// Settlement stage of transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementStage {
    /// Settlement status
    pub status: SettlementStatus,

    /// Settlement mode (immediate, deferred)
    pub settlement_mode: String,

    /// Settlement method (local, fabric_gateway, external_facilitator)
    pub settlement_method: String,

    /// Blockchain transaction hash
    pub tx_hash: String,

    /// Network identifier (CAIP-2 format)
    pub network: String,

    /// Payment amount in smallest unit
    pub amount: String,

    /// Payment scheme (exact, upto)
    pub scheme: String,

    /// Recipient address
    pub pay_to: String,

    /// Asset/token address (None for native currency)
    pub asset: Option<String>,

    /// Sender address (if available)
    pub from_address: Option<String>,

    /// Number of confirmations at verification
    pub confirmations: Option<u64>,

    /// Number of settlement attempts
    pub settlement_attempts: u32,

    /// Timestamp of last settlement attempt
    pub last_settlement_attempt: Option<DateTime<Utc>>,

    /// Timestamp when settlement completed
    pub settlement_completed_at: Option<DateTime<Utc>>,

    /// Last error message
    pub error: Option<String>,

    /// Cross-gateway synchronization status
    pub sync_status: SyncStatus,

    /// When synchronization was confirmed (ACK received)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced_at: Option<DateTime<Utc>>,
}

/// Unified x402 Transaction Record
/// Single source of truth for verification → settlement lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Transaction {
    /// Correlation ID (deterministic filename: /x402-transactions/{id}.json)
    /// Generated at verification start, used throughout lifecycle
    pub id: String,

    /// Channel ID
    pub surface_id: String,

    /// Channel name
    pub channel_name: String,

    /// Resource path being protected
    pub resource_path: String,

    /// Original payment payload from client
    pub payment_payload: PaymentPayload,

    /// Verification stage (always present)
    pub verification: VerificationStage,

    /// Settlement stage (optional - might be verify-only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement: Option<SettlementStage>,

    /// When transaction was created
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub last_updated: DateTime<Utc>,

    /// Best-effort request trace id captured at creation, so every later
    /// lifecycle audit event (verify, settle) — including ones emitted from a
    /// background settlement task with no request context — correlates back to
    /// the originating request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Signed `PaymentReceiptCredential` JWT (see `payment_credentials`),
    /// minted on `verified` and re-issued on `settled`. Absent when the
    /// `payment_receipt_vc` feature flag is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_vc_jwt: Option<String>,
    /// `sha256:<hex>` fingerprint of `receipt_vc_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_vc_fingerprint: Option<String>,
    /// Signed `PaymentRejectionCredential` JWT, minted on `failed` /
    /// `settlement_failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_vc_jwt: Option<String>,
    /// `sha256:<hex>` fingerprint of `rejection_vc_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_vc_fingerprint: Option<String>,
}

impl X402Transaction {
    /// Create new transaction with verification stage
    pub fn new(
        correlation_id: String,
        surface_id: String,
        channel_name: String,
        resource_path: String,
        payment_payload: PaymentPayload,
        verification_mode: String,
        facilitator_gateway_id: Option<String>,
    ) -> Self {
        let now = Utc::now();

        Self {
            id: correlation_id,
            surface_id,
            channel_name,
            resource_path,
            payment_payload,
            verification: VerificationStage {
                status: VerificationStatus::Pending,
                verification_mode,
                created_at: now,
                completed_at: None,
                error: None,
                facilitator_gateway_id,
                didcomm_thread_id: None,
                access_token: None,
            },
            settlement: None,
            created_at: now,
            last_updated: now,
            trace_id: crate::observability::policy_audit::current_span_trace_id(),
            receipt_vc_jwt: None,
            receipt_vc_fingerprint: None,
            rejection_vc_jwt: None,
            rejection_vc_fingerprint: None,
        }
    }

    /// Mark verification as completed successfully
    pub fn complete_verification(&mut self) {
        self.verification.status = VerificationStatus::Verified;
        self.verification.completed_at = Some(Utc::now());
        self.verification.error = None;
        self.last_updated = Utc::now();
    }

    /// Mark verification as failed
    pub fn fail_verification(
        &mut self,
        error: String,
    ) {
        self.verification.status = VerificationStatus::Failed;
        self.verification.completed_at = Some(Utc::now());
        self.verification.error = Some(error);
        self.last_updated = Utc::now();
    }

    /// Initialize settlement stage
    pub fn init_settlement(
        &mut self,
        settlement_mode: String,
        settlement_method: String,
        tx_hash: Option<String>,
        confirmations: Option<u64>,
    ) {
        let payload = &self.payment_payload;
        let tx_hash = tx_hash
            .or_else(|| payload.tx_hash())
            .unwrap_or_default();

        // Determine sync_status based on facilitator_gateway_id
        // If there's a facilitator, they settle and need to sync back to us
        let sync_status = if self
            .verification
            .facilitator_gateway_id
            .is_some()
        {
            SyncStatus::PendingSync
        } else {
            SyncStatus::Local
        };

        self.settlement = Some(SettlementStage {
            status: SettlementStatus::Pending,
            settlement_mode,
            settlement_method,
            tx_hash,
            network: payload.network().to_string(),
            amount: payload.amount().to_string(),
            scheme: payload.scheme().to_string(),
            pay_to: payload.pay_to().to_string(),
            asset: payload
                .asset()
                .map(|s| s.to_string()),
            from_address: payload.from(),
            confirmations,
            settlement_attempts: 0,
            last_settlement_attempt: None,
            settlement_completed_at: None,
            error: None,
            sync_status,
            synced_at: None,
        });
        self.last_updated = Utc::now();
    }

    /// Update settlement tx_hash (set when remote gateway responds)
    pub fn set_settlement_tx_hash(
        &mut self,
        tx_hash: String,
    ) {
        if let Some(settlement) = &mut self.settlement {
            settlement.tx_hash = tx_hash;
            self.last_updated = Utc::now();
        }
    }

    /// Mark settlement as completed
    pub fn complete_settlement(&mut self) {
        if let Some(settlement) = &mut self.settlement {
            settlement.status = SettlementStatus::Completed;
            settlement.settlement_completed_at = Some(Utc::now());
            settlement.error = None;
            self.last_updated = Utc::now();
        }
    }

    /// Mark settlement as failed
    pub fn fail_settlement(
        &mut self,
        error: String,
    ) {
        if let Some(settlement) = &mut self.settlement {
            settlement.status = SettlementStatus::Failed;
            settlement.error = Some(error);
            self.last_updated = Utc::now();
        }
    }

    /// Increment settlement attempt counter
    pub fn increment_settlement_attempt(&mut self) {
        if let Some(settlement) = &mut self.settlement {
            settlement.settlement_attempts += 1;
            settlement.last_settlement_attempt = Some(Utc::now());
            settlement.status = SettlementStatus::Processing;
            self.last_updated = Utc::now();
        }
    }

    /// Mark as awaiting external facilitator response
    pub fn mark_awaiting_external(&mut self) {
        if let Some(settlement) = &mut self.settlement {
            settlement.status = SettlementStatus::AwaitingExternal;
            self.last_updated = Utc::now();
        }
    }

    /// Mark as pending sync (notification sent to facilitator)
    #[allow(dead_code)]
    pub fn mark_pending_sync(&mut self) {
        if let Some(settlement) = &mut self.settlement {
            settlement.sync_status = SyncStatus::PendingSync;
            self.last_updated = Utc::now();
        }
    }

    /// Mark as synced (ACK received from facilitator)
    #[allow(dead_code)]
    pub fn mark_synced(&mut self) {
        if let Some(settlement) = &mut self.settlement {
            settlement.sync_status = SyncStatus::Synced;
            settlement.synced_at = Some(Utc::now());
            self.last_updated = Utc::now();
        }
    }
}

/// x402 transactions are keyed on their correlation id for filesystem storage.
impl StorableEntity for X402Transaction {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Filesystem-backed transaction store
/// Provides atomic operations for x402 transaction lifecycle
#[derive(Clone)]
pub struct TransactionStore {
    /// In-memory cache for fast lookups and read-modify-write serialization
    cache: Arc<RwLock<HashMap<String, X402Transaction>>>,

    /// Generic storage backend handling durable CRUD (encryption at rest, atomic writes)
    storage: Arc<dyn StorageBackend<X402Transaction>>,
}

impl TransactionStore {
    /// Create new transaction store
    pub async fn new(base_path: PathBuf) -> Result<Self, std::io::Error> {
        let storage: Arc<dyn StorageBackend<X402Transaction>> = Arc::from(
            uncached_storage(base_path.clone(), "x402_transaction")
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?,
        );

        let cache = Arc::new(RwLock::new(HashMap::new()));

        let store = Self { cache, storage };

        // Load existing transactions into cache
        store.load_from_disk().await?;

        info!("[transaction-store] Initialized at {:?}", base_path);

        Ok(store)
    }

    /// Load all transactions from the storage backend into cache
    async fn load_from_disk(&self) -> Result<(), std::io::Error> {
        let all = self
            .storage
            .list_all()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let count = all.len();

        let mut cache = self.cache.write().await;
        for transaction in all {
            cache.insert(transaction.id.clone(), transaction);
        }

        info!("[transaction-store] Loaded {} transactions from disk", count);
        Ok(())
    }

    /// Save transaction through the storage backend (atomic write handled by the backend)
    async fn save_to_disk(
        &self,
        transaction: &X402Transaction,
    ) -> Result<(), std::io::Error> {
        self.storage
            .save_atomic(transaction)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Persist a new transaction; returns `AlreadyExists` if a record is already on disk.
    async fn create_on_disk(
        &self,
        transaction: &X402Transaction,
    ) -> Result<(), std::io::Error> {
        if self
            .storage
            .exists(&transaction.id)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?
        {
            return Err(std::io::Error::new(ErrorKind::AlreadyExists, "transaction already exists"));
        }

        self.storage
            .save_atomic(transaction)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Delete transaction through the storage backend
    async fn delete_from_disk(
        &self,
        correlation_id: &str,
    ) -> Result<(), std::io::Error> {
        self.storage
            .delete(correlation_id)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Create new transaction (verification stage)
    pub async fn create_transaction(
        &self,
        correlation_id: String,
        channel_id: String,
        channel_name: String,
        resource_path: String,
        payment_payload: PaymentPayload,
        verification_mode: String,
        facilitator_gateway_id: Option<String>,
    ) -> Result<String, String> {
        let mut cache = self.cache.write().await;

        if cache.contains_key(&correlation_id) {
            return Err(format!("Transaction already exists: {}", correlation_id));
        }

        let transaction = X402Transaction::new(
            correlation_id.clone(),
            channel_id,
            channel_name,
            resource_path,
            payment_payload,
            verification_mode,
            facilitator_gateway_id,
        );

        if let Err(e) = self
            .create_on_disk(&transaction)
            .await
        {
            error!("Failed to save transaction to disk: {}", e);
            if e.kind() == ErrorKind::AlreadyExists {
                return Err(format!("Transaction already exists: {}", correlation_id));
            }
            return Err(format!("Failed to persist transaction: {}", e));
        }

        emit_payment_audit(&transaction, PaymentStage::VerifyAttempt, None, None);
        cache.insert(correlation_id.clone(), transaction);

        info!("[transaction-store] Created transaction: {}", correlation_id);

        Ok(correlation_id)
    }

    /// Get transaction by correlation_id
    #[allow(dead_code)]
    pub async fn get(
        &self,
        correlation_id: &str,
    ) -> Option<X402Transaction> {
        let cache = self.cache.read().await;
        cache
            .get(correlation_id)
            .cloned()
    }

    /// Complete verification successfully
    pub async fn complete_verification(
        &self,
        correlation_id: &str,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.complete_verification();

            let receipt = crate::payment_credentials::issue_payment_receipt(receipt_input_from_transaction(
                transaction,
                false,
                None,
            ))
            .await;
            if let Some(ref c) = receipt {
                transaction.receipt_vc_jwt = Some(c.jwt.clone());
                transaction.receipt_vc_fingerprint = Some(c.fingerprint.clone());
            }

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            emit_payment_audit(
                transaction,
                PaymentStage::Verified,
                None,
                receipt
                    .as_ref()
                    .map(|c| c.jwt.as_str()),
            );
            info!("[transaction-store] Verification completed: {}", correlation_id);
            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Fail verification
    pub async fn fail_verification(
        &self,
        correlation_id: &str,
        error: String,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            let error_for_audit = error.clone();
            transaction.fail_verification(error);

            let rejection = crate::payment_credentials::issue_payment_rejection(rejection_input_from_transaction(
                transaction,
                error_for_audit.clone(),
            ))
            .await;
            if let Some(ref c) = rejection {
                transaction.rejection_vc_jwt = Some(c.jwt.clone());
                transaction.rejection_vc_fingerprint = Some(c.fingerprint.clone());
            }

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            emit_payment_audit(
                transaction,
                PaymentStage::Failed,
                Some(error_for_audit),
                rejection
                    .as_ref()
                    .map(|c| c.jwt.as_str()),
            );
            info!("[transaction-store] Verification failed: {}", correlation_id);
            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Initialize settlement stage
    pub async fn init_settlement(
        &self,
        correlation_id: &str,
        settlement_mode: String,
        settlement_method: String,
        tx_hash: Option<String>,
        confirmations: Option<u64>,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.init_settlement(settlement_mode, settlement_method, tx_hash, confirmations);

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            info!("[transaction-store] Settlement initialized: {}", correlation_id);
            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Complete settlement
    pub async fn complete_settlement(
        &self,
        correlation_id: &str,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.complete_settlement();

            let settlement_evidence = transaction
                .settlement
                .as_ref()
                .map(|s| crate::payment_credentials::SettlementEvidence {
                    tx_hash: (!s.tx_hash.is_empty()).then(|| s.tx_hash.clone()),
                    network: (!s.network.is_empty()).then(|| s.network.clone()),
                    confirmations: s.confirmations,
                });
            let receipt = crate::payment_credentials::issue_payment_receipt(receipt_input_from_transaction(
                transaction,
                true,
                settlement_evidence,
            ))
            .await;
            if let Some(ref c) = receipt {
                transaction.receipt_vc_jwt = Some(c.jwt.clone());
                transaction.receipt_vc_fingerprint = Some(c.fingerprint.clone());
            }

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            emit_payment_audit(
                transaction,
                PaymentStage::Settled,
                None,
                receipt
                    .as_ref()
                    .map(|c| c.jwt.as_str()),
            );
            info!("[transaction-store] Settlement completed: {}", correlation_id);
            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Fail settlement
    pub async fn fail_settlement(
        &self,
        correlation_id: &str,
        error: String,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            let error_for_audit = error.clone();
            transaction.fail_settlement(error);

            let rejection = crate::payment_credentials::issue_payment_rejection(rejection_input_from_transaction(
                transaction,
                error_for_audit.clone(),
            ))
            .await;
            if let Some(ref c) = rejection {
                transaction.rejection_vc_jwt = Some(c.jwt.clone());
                transaction.rejection_vc_fingerprint = Some(c.fingerprint.clone());
            }

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            emit_payment_audit(
                transaction,
                PaymentStage::SettlementFailed,
                Some(error_for_audit),
                rejection
                    .as_ref()
                    .map(|c| c.jwt.as_str()),
            );
            info!("[transaction-store] Settlement failed: {}", correlation_id);
            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Increment settlement attempt counter
    pub async fn increment_settlement_attempt(
        &self,
        correlation_id: &str,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.increment_settlement_attempt();

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Mark as awaiting external facilitator
    pub async fn mark_awaiting_external(
        &self,
        correlation_id: &str,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.mark_awaiting_external();

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Mark as pending sync (DIDComm notification sent to facilitator)
    pub async fn mark_pending_sync(
        &self,
        correlation_id: &str,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.mark_pending_sync();

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Set facilitator_gateway_id (used when remote gateway requests verification)
    /// This allows the facilitator to send settlement-complete notification back to requester
    pub async fn set_facilitator_gateway_id(
        &self,
        correlation_id: &str,
        gateway_id: String,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction
                .verification
                .facilitator_gateway_id = Some(gateway_id.clone());
            transaction.last_updated = Utc::now();

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            info!("[transaction-store] Set facilitator_gateway_id={} for: {}", gateway_id, correlation_id);
            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Mark as synced (ACK received from facilitator)
    #[allow(dead_code)]
    pub async fn mark_synced(
        &self,
        correlation_id: &str,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.mark_synced();

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// Update settlement tx_hash (from remote gateway response)
    pub async fn set_settlement_tx_hash(
        &self,
        correlation_id: &str,
        tx_hash: String,
    ) -> Result<(), String> {
        let mut cache = self.cache.write().await;

        if let Some(transaction) = cache.get_mut(correlation_id) {
            transaction.set_settlement_tx_hash(tx_hash);

            // Save to disk
            if let Err(e) = self
                .save_to_disk(transaction)
                .await
            {
                error!("Failed to save transaction to disk: {}", e);
                return Err(format!("Failed to persist transaction: {}", e));
            }

            Ok(())
        } else {
            Err(format!("Transaction not found: {}", correlation_id))
        }
    }

    /// List all transactions
    pub async fn list_all(&self) -> Vec<X402Transaction> {
        let cache = self.cache.read().await;
        cache
            .values()
            .cloned()
            .collect()
    }

    /// List transactions by settlement status
    pub async fn list_by_settlement_status(
        &self,
        status: SettlementStatus,
    ) -> Vec<X402Transaction> {
        let cache = self.cache.read().await;
        cache
            .values()
            .filter(|t| {
                t.settlement
                    .as_ref()
                    .map(|s| s.status == status)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// List verified transactions that have pending/incomplete settlements
    /// Filtered by settlement_method to determine gateway responsibility:
    /// - "local" = originating gateway (GW1) is responsible
    /// - "fabric_gateway" = facilitator gateway (GW2) is responsible
    /// - "external_facilitator" = external service is responsible
    pub async fn list_unsettled_verified(
        &self,
        settlement_method_filter: Option<&str>,
    ) -> Vec<X402Transaction> {
        let cache = self.cache.read().await;
        cache
            .values()
            .filter(|t| {
                // Must be verified
                if t.verification.status != VerificationStatus::Verified {
                    return false;
                }

                // Must have settlement stage
                let Some(settlement) = &t.settlement else {
                    return false;
                };

                // Must not be completed/failed
                if matches!(
                    settlement.status,
                    SettlementStatus::Completed | SettlementStatus::Failed | SettlementStatus::Refunded
                ) {
                    return false;
                }

                // Filter by settlement method if specified
                if let Some(filter) = settlement_method_filter {
                    settlement.settlement_method == filter
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    /// List transactions with pending sync status
    /// These transactions need settlement completion notifications sent to their originating gateway
    pub async fn list_pending_sync(&self) -> Vec<X402Transaction> {
        let cache = self.cache.read().await;
        cache
            .values()
            .filter(|t| {
                if let Some(settlement) = &t.settlement {
                    settlement.sync_status == SyncStatus::PendingSync
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }

    /// Delete old transactions based on retention policy
    pub async fn cleanup_old_transactions(
        &self,
        retention_days: i64,
    ) -> Result<usize, String> {
        let cutoff = Utc::now() - Duration::days(retention_days);
        let mut cache = self.cache.write().await;
        let mut deleted = 0;

        let to_delete: Vec<String> = cache
            .iter()
            .filter(|(_, t)| {
                // Delete if:
                // 1. Older than retention AND verification failed, OR
                // 2. Older than retention AND settlement synced/local
                t.last_updated < cutoff
                    && (t.verification.status == VerificationStatus::Failed
                        || t.settlement
                            .as_ref()
                            .map(|s| s.sync_status == SyncStatus::Synced || s.sync_status == SyncStatus::Local)
                            .unwrap_or(false))
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_delete {
            if let Err(e) = self
                .delete_from_disk(&id)
                .await
            {
                error!("Failed to delete transaction {} from disk: {}", id, e);
            } else {
                cache.remove(&id);
                deleted += 1;
            }
        }

        info!("[transaction-store] Cleaned up {} old transactions (retention: {} days)", deleted, retention_days);

        Ok(deleted)
    }

    /// Delete a transaction by correlation ID
    pub async fn delete(
        &self,
        correlation_id: &str,
    ) -> Result<(), String> {
        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(correlation_id);

        // Delete from disk
        self.delete_from_disk(correlation_id)
            .await
            .map_err(|e| format!("Failed to delete file: {}", e))?;

        info!("[transaction-store] Deleted transaction: {}", correlation_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::fs;
    use uuid::Uuid;

    fn mock_payment_payload() -> PaymentPayload {
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

        serde_json::from_str(payload_json).unwrap()
    }

    #[tokio::test]
    async fn test_transaction_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("x402-test-{}", Uuid::new_v4()));
        let store = TransactionStore::new(temp_dir.clone())
            .await
            .unwrap();

        let payload = mock_payment_payload();

        let correlation_id = Uuid::new_v4().to_string();

        // Create transaction
        store
            .create_transaction(
                correlation_id.clone(),
                "channel-1".to_string(),
                "Test Channel".to_string(),
                "/test".to_string(),
                payload.clone(),
                "Local".to_string(),
                None,
            )
            .await
            .unwrap();

        // Verify it exists
        let txn = store
            .get(&correlation_id)
            .await
            .unwrap();
        assert_eq!(txn.verification.status, VerificationStatus::Pending);
        assert!(txn.settlement.is_none());

        // Complete verification
        store
            .complete_verification(&correlation_id)
            .await
            .unwrap();
        let txn = store
            .get(&correlation_id)
            .await
            .unwrap();
        assert_eq!(txn.verification.status, VerificationStatus::Verified);

        // Initialize settlement
        store
            .init_settlement(
                &correlation_id,
                "immediate".to_string(),
                "local".to_string(),
                Some("0xtxhash".to_string()),
                Some(12),
            )
            .await
            .unwrap();

        let txn = store
            .get(&correlation_id)
            .await
            .unwrap();
        assert!(txn.settlement.is_some());
        let settlement = txn.settlement.unwrap();
        assert_eq!(settlement.status, SettlementStatus::Pending);
        assert_eq!(settlement.tx_hash, "0xtxhash");

        // Complete settlement
        store
            .complete_settlement(&correlation_id)
            .await
            .unwrap();
        let txn = store
            .get(&correlation_id)
            .await
            .unwrap();
        assert_eq!(txn.settlement.unwrap().status, SettlementStatus::Completed);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn create_transaction_rejects_duplicate_correlation_id() {
        let temp_dir = std::env::temp_dir().join(format!("x402-test-{}", Uuid::new_v4()));
        let store = TransactionStore::new(temp_dir.clone())
            .await
            .unwrap();
        let payload = mock_payment_payload();
        let correlation_id = Uuid::new_v4().to_string();

        let first_result = store
            .create_transaction(
                correlation_id.clone(),
                "channel-1".to_string(),
                "Test Channel".to_string(),
                "/test".to_string(),
                payload.clone(),
                "Local".to_string(),
                None,
            )
            .await;
        let second_result = store
            .create_transaction(
                correlation_id.clone(),
                "channel-2".to_string(),
                "Other Channel".to_string(),
                "/other".to_string(),
                payload,
                "Local".to_string(),
                None,
            )
            .await;

        assert_eq!(first_result.unwrap(), correlation_id);
        assert!(
            second_result
                .unwrap_err()
                .contains("already exists")
        );

        let transactions = store.list_all().await;
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].surface_id, "channel-1");
        assert_eq!(transactions[0].resource_path, "/test");

        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn create_transaction_rejects_existing_transaction_file() {
        let temp_dir = std::env::temp_dir().join(format!("x402-test-{}", Uuid::new_v4()));
        let store = TransactionStore::new(temp_dir.clone())
            .await
            .unwrap();
        let payload = mock_payment_payload();
        let correlation_id = Uuid::new_v4().to_string();

        store
            .create_transaction(
                correlation_id.clone(),
                "channel-1".to_string(),
                "Test Channel".to_string(),
                "/test".to_string(),
                payload.clone(),
                "Local".to_string(),
                None,
            )
            .await
            .unwrap();

        store
            .cache
            .write()
            .await
            .clear();

        let second_result = store
            .create_transaction(
                correlation_id.clone(),
                "channel-2".to_string(),
                "Other Channel".to_string(),
                "/other".to_string(),
                payload,
                "Local".to_string(),
                None,
            )
            .await;

        assert!(
            second_result
                .unwrap_err()
                .contains("already exists")
        );

        let reloaded_store = TransactionStore::new(temp_dir.clone())
            .await
            .unwrap();
        let transaction = reloaded_store
            .get(&correlation_id)
            .await
            .unwrap();
        assert_eq!(transaction.surface_id, "channel-1");
        assert_eq!(transaction.resource_path, "/test");

        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn concurrent_create_transaction_allows_only_one_record() {
        let temp_dir = std::env::temp_dir().join(format!("x402-test-{}", Uuid::new_v4()));
        let store = Arc::new(
            TransactionStore::new(temp_dir.clone())
                .await
                .unwrap(),
        );
        let payload = mock_payment_payload();
        let correlation_id = Uuid::new_v4().to_string();

        let first_store = Arc::clone(&store);
        let first_payload = payload.clone();
        let first_correlation_id = correlation_id.clone();
        let first = tokio::spawn(async move {
            first_store
                .create_transaction(
                    first_correlation_id,
                    "channel-1".to_string(),
                    "Test Channel".to_string(),
                    "/test".to_string(),
                    first_payload,
                    "Local".to_string(),
                    None,
                )
                .await
        });

        let second_store = Arc::clone(&store);
        let second_correlation_id = correlation_id.clone();
        let second = tokio::spawn(async move {
            second_store
                .create_transaction(
                    second_correlation_id,
                    "channel-2".to_string(),
                    "Other Channel".to_string(),
                    "/other".to_string(),
                    payload,
                    "Local".to_string(),
                    None,
                )
                .await
        });

        let first_result = first.await.unwrap();
        let second_result = second.await.unwrap();
        let success_count = [&first_result, &second_result]
            .iter()
            .filter(|result| result.is_ok())
            .count();
        let duplicate_count = [&first_result, &second_result]
            .iter()
            .filter(|result| {
                result
                    .as_ref()
                    .is_err_and(|error| error.contains("already exists"))
            })
            .count();

        assert_eq!(success_count, 1);
        assert_eq!(duplicate_count, 1);
        assert_eq!(store.list_all().await.len(), 1);

        let _ = fs::remove_dir_all(&temp_dir).await;
    }
}
