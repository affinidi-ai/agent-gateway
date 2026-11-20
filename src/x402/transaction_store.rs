//! x402 transaction store.
//!
//! Holds the recorded x402 transactions, each stored as a single JSON file named by its
//! correlation id. Records are kept as they are and served to the admin API; only a
//! settlement-complete from a transaction's own facilitator gateway changes one, and
//! retention deletes only final records.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
            delegation: None,
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

impl SettlementStatus {
    /// Whether settlement has not reached a final outcome yet.
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::Pending | Self::Processing | Self::AwaitingRemote | Self::AwaitingExternal)
    }
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

/// Recorded x402 transaction
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

    /// Payment payload from the client. Once verification resolved it to one of the surface's
    /// payment requirements, `accepted` is that requirement.
    pub payment_payload: PaymentPayload,

    /// Whether `accepted` was bound to the surface's payment requirement when the record was
    /// written. Older records read as `false` and carry the caller's own `accepted`.
    #[serde(default)]
    pub payment_requirement_bound: bool,

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
    #[cfg(test)]
    pub(crate) fn new(
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
            payment_requirement_bound: true,
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

    /// Attach a settlement stage with `status`, taken from the payment payload.
    #[cfg(test)]
    pub(crate) fn with_settlement(
        mut self,
        status: SettlementStatus,
        settlement_method: &str,
    ) -> Self {
        let payload = &self.payment_payload;
        self.settlement = Some(SettlementStage {
            status,
            settlement_mode: "deferred".to_string(),
            settlement_method: settlement_method.to_string(),
            tx_hash: String::new(),
            network: payload.network().to_string(),
            amount: payload.amount().to_string(),
            scheme: payload.scheme().to_string(),
            pay_to: payload
                .accepted
                .pay_to
                .clone(),
            asset: Some(payload.accepted.asset.clone()),
            from_address: payload.from(),
            confirmations: None,
            settlement_attempts: 0,
            last_settlement_attempt: None,
            settlement_completed_at: None,
            error: None,
            sync_status: SyncStatus::Local,
            synced_at: None,
        });
        self
    }

    /// Whether the transaction has reached a final outcome: its settlement is completed,
    /// failed or refunded, or, with no settlement, its verification failed.
    pub fn is_final(&self) -> bool {
        match &self.settlement {
            Some(settlement) => !settlement
                .status
                .is_in_progress(),
            None => self.verification.status == VerificationStatus::Failed,
        }
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
}

/// x402 transactions are keyed on their correlation id for filesystem storage.
impl StorableEntity for X402Transaction {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Filesystem-backed x402 transaction store
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

    /// Get transaction by correlation_id
    pub async fn get(
        &self,
        correlation_id: &str,
    ) -> Option<X402Transaction> {
        let cache = self.cache.read().await;
        cache
            .get(correlation_id)
            .cloned()
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

    /// Delete final transactions last updated before the retention window.
    pub async fn cleanup_old_transactions(
        &self,
        retention_days: i64,
    ) -> Result<usize, String> {
        let cutoff = Utc::now() - Duration::days(retention_days);
        let mut cache = self.cache.write().await;
        let mut deleted = 0;

        let to_delete: Vec<String> = cache
            .iter()
            .filter(|(_, t)| t.last_updated < cutoff && t.is_final())
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
impl TransactionStore {
    pub(crate) async fn insert(
        &self,
        transaction: X402Transaction,
    ) {
        self.save_to_disk(&transaction)
            .await
            .unwrap();
        self.cache
            .write()
            .await
            .insert(transaction.id.clone(), transaction);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn transaction(
        verification: VerificationStatus,
        settlement: Option<SettlementStatus>,
        last_updated: DateTime<Utc>,
    ) -> X402Transaction {
        let mut transaction = X402Transaction::new(
            Uuid::new_v4().to_string(),
            "channel-1".to_string(),
            "Test Channel".to_string(),
            "/test".to_string(),
            mock_payment_payload(),
            "Local".to_string(),
            None,
        );
        if let Some(status) = settlement {
            transaction = transaction.with_settlement(status, "local");
        }
        transaction
            .verification
            .status = verification;
        transaction.last_updated = last_updated;
        transaction
    }

    async fn store() -> (TransactionStore, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let store = TransactionStore::new(root.path().join("x402"))
            .await
            .unwrap();
        (store, root)
    }

    #[tokio::test]
    async fn completing_a_settlement_marks_it_completed() {
        let (store, _root) = store().await;
        let pending = transaction(VerificationStatus::Verified, Some(SettlementStatus::Pending), Utc::now());
        let id = pending.id.clone();
        store.insert(pending).await;

        store
            .complete_settlement(&id)
            .await
            .unwrap();

        let settlement = store
            .get(&id)
            .await
            .unwrap()
            .settlement
            .unwrap();
        assert_eq!(settlement.status, SettlementStatus::Completed);
        assert!(
            settlement
                .settlement_completed_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn completing_an_unknown_transaction_fails() {
        let (store, _root) = store().await;

        let error = store
            .complete_settlement("missing")
            .await
            .unwrap_err();

        assert_eq!(error, "Transaction not found: missing");
    }

    #[tokio::test]
    async fn cleanup_keeps_old_transactions_whose_settlement_is_in_progress() {
        let (store, _root) = store().await;
        let old = Utc::now() - Duration::days(30);
        let in_progress: Vec<X402Transaction> = [
            SettlementStatus::Pending,
            SettlementStatus::Processing,
            SettlementStatus::AwaitingRemote,
            SettlementStatus::AwaitingExternal,
        ]
        .into_iter()
        .map(|status| transaction(VerificationStatus::Failed, Some(status), old))
        .collect();
        for txn in &in_progress {
            store
                .insert(txn.clone())
                .await;
        }

        let deleted = store
            .cleanup_old_transactions(7)
            .await
            .unwrap();

        assert_eq!(deleted, 0);
        for txn in &in_progress {
            let kept = store
                .get(&txn.id)
                .await
                .expect("in-progress transaction was deleted");
            assert_eq!(
                kept.settlement
                    .unwrap()
                    .status,
                txn.settlement
                    .as_ref()
                    .unwrap()
                    .status
            );
        }
    }

    #[tokio::test]
    async fn cleanup_deletes_old_final_transactions_only() {
        let (store, _root) = store().await;
        let old = Utc::now() - Duration::days(30);
        let old_completed = transaction(VerificationStatus::Verified, Some(SettlementStatus::Completed), old);
        let old_failed = transaction(VerificationStatus::Verified, Some(SettlementStatus::Failed), old);
        let old_refunded = transaction(VerificationStatus::Verified, Some(SettlementStatus::Refunded), old);
        let old_unverified = transaction(VerificationStatus::Failed, None, old);
        let old_verified_unsettled = transaction(VerificationStatus::Verified, None, old);
        let recent_completed = transaction(VerificationStatus::Verified, Some(SettlementStatus::Completed), Utc::now());
        for txn in
            [&old_completed, &old_failed, &old_refunded, &old_unverified, &old_verified_unsettled, &recent_completed]
        {
            store
                .insert(txn.clone())
                .await;
        }

        let deleted = store
            .cleanup_old_transactions(7)
            .await
            .unwrap();

        assert_eq!(deleted, 4);
        for gone in [&old_completed, &old_failed, &old_refunded, &old_unverified] {
            assert!(
                store
                    .get(&gone.id)
                    .await
                    .is_none(),
                "{} was kept",
                gone.id
            );
        }
        assert_eq!(
            store
                .get(&recent_completed.id)
                .await
                .unwrap()
                .settlement
                .unwrap()
                .status,
            SettlementStatus::Completed
        );
        assert_eq!(
            store
                .get(&old_verified_unsettled.id)
                .await
                .unwrap()
                .verification
                .status,
            VerificationStatus::Verified
        );
        assert_eq!(store.list_all().await.len(), 2);
    }

    #[tokio::test]
    async fn cleanup_removes_deleted_transactions_from_disk() {
        let (store, root) = store().await;
        let old_completed = transaction(
            VerificationStatus::Verified,
            Some(SettlementStatus::Completed),
            Utc::now() - Duration::days(30),
        );
        store
            .insert(old_completed)
            .await;

        assert_eq!(
            store
                .cleanup_old_transactions(7)
                .await
                .unwrap(),
            1
        );

        let reloaded = TransactionStore::new(root.path().join("x402"))
            .await
            .unwrap();
        assert!(
            reloaded
                .list_all()
                .await
                .is_empty()
        );
    }
}
