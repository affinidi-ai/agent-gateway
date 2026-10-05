//! MPP Transaction Store
//!
//! Filesystem-backed store for recording MPP payment transactions.
//! Provides audit trail and observability for all MPP payment flows.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{error, info};

use crate::delegation_vault::audit::PaymentStage;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};

/// MPP transaction status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MppTransactionStatus {
    /// Payment verified successfully
    Verified,
    /// Payment verification failed
    Failed,
    /// 402 challenge issued (no credential provided)
    ChallengeIssued,
}

/// A single MPP transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppTransaction {
    /// Unique transaction ID (UUID)
    pub id: String,

    /// Channel ID
    pub surface_id: String,

    /// Channel name
    pub channel_name: String,

    /// Resource URL being protected
    pub resource_url: String,

    /// Payment method (e.g. "tempo", "card", "lightning")
    pub payment_method: String,

    /// Transaction status
    pub status: MppTransactionStatus,

    /// Payment reference (tx_hash, Stripe PaymentIntent ID, etc.)
    /// Empty for challenge-issued or failed transactions.
    #[serde(default)]
    pub reference: String,

    /// Error message if verification failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Payer identifier (DID, address, etc.) from credential.source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,

    /// Amount from the payment method config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,

    /// Currency from the payment method config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// When the transaction was recorded
    pub created_at: DateTime<Utc>,

    /// Best-effort request trace id captured (before any `tokio::spawn`) at the
    /// point the payment was processed, so the payment audit event correlates
    /// with the originating request's other audit entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Signed `PaymentReceiptCredential` JWT (see `payment_credentials`),
    /// minted on `verified`. Absent when the `payment_receipt_vc` feature
    /// flag is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_vc_jwt: Option<String>,
    /// `sha256:<hex>` fingerprint of `receipt_vc_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_vc_fingerprint: Option<String>,
    /// Signed `PaymentRejectionCredential` JWT, minted on `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_vc_jwt: Option<String>,
    /// `sha256:<hex>` fingerprint of `rejection_vc_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_vc_fingerprint: Option<String>,
}

/// MPP transactions are keyed on their UUID for filesystem storage.
impl StorableEntity for MppTransaction {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Emit a protocol-independent payment audit event for an MPP transaction.
/// `vc_jwt`, when present, is a dispute-evidence credential minted for this
/// stage and is stamped onto the same event.
fn emit_mpp_payment_audit(
    txn: &MppTransaction,
    stage: PaymentStage,
    vc_jwt: Option<&str>,
) {
    use crate::delegation_vault::audit::{PaymentEventDetails, PaymentRail, record_payment_event};
    record_payment_event(
        PaymentEventDetails {
            rail: PaymentRail::Mpp,
            stage,
            transaction_id: txn.id.clone(),
            amount: txn.amount.clone(),
            currency: txn.currency.clone(),
            method: (!txn.payment_method.is_empty()).then(|| txn.payment_method.clone()),
            payer: txn.payer.clone(),
            error: txn.error.clone(),
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

/// Filesystem-backed MPP transaction store
pub struct MppTransactionStore {
    storage: Box<dyn StorageBackend<MppTransaction>>,
}

impl MppTransactionStore {
    /// Create a new MPP transaction store at the given directory path
    pub async fn new(base_path: PathBuf) -> Result<Self, std::io::Error> {
        let storage = cached_storage(base_path.clone(), "mpp_transaction")
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        info!("[mpp-txn-store] Initialized at {:?}", base_path);

        Ok(Self { storage })
    }

    /// Record a verified payment
    #[allow(clippy::too_many_arguments)]
    pub async fn record_verified(
        &self,
        channel_id: &str,
        channel_name: &str,
        resource_url: &str,
        payment_method: &str,
        reference: &str,
        payer: Option<&str>,
        amount: Option<&str>,
        currency: Option<&str>,
        trace_id: Option<String>,
    ) -> Result<String, String> {
        let id = uuid::Uuid::new_v4().to_string();

        let txn = MppTransaction {
            id: id.clone(),
            surface_id: channel_id.to_string(),
            channel_name: channel_name.to_string(),
            resource_url: resource_url.to_string(),
            payment_method: payment_method.to_string(),
            status: MppTransactionStatus::Verified,
            reference: reference.to_string(),
            error: None,
            payer: payer.map(|s| s.to_string()),
            amount: amount.map(|s| s.to_string()),
            currency: currency.map(|s| s.to_string()),
            created_at: Utc::now(),
            trace_id,
            receipt_vc_jwt: None,
            receipt_vc_fingerprint: None,
            rejection_vc_jwt: None,
            rejection_vc_fingerprint: None,
        };

        let receipt =
            crate::payment_credentials::issue_payment_receipt(crate::payment_credentials::PaymentReceiptInput {
                rail: "mpp",
                payment_id: txn.id.clone(),
                trace_id: txn.trace_id.clone(),
                amount: txn.amount.clone(),
                currency: txn.currency.clone(),
                method: (!txn.payment_method.is_empty()).then(|| txn.payment_method.clone()),
                payer: txn.payer.clone(),
                resource: Some(txn.resource_url.clone()),
                settled: true,
                settlement: None,
                payer_signature: None,
            })
            .await;
        let mut txn = txn;
        if let Some(ref c) = receipt {
            txn.receipt_vc_jwt = Some(c.jwt.clone());
            txn.receipt_vc_fingerprint = Some(c.fingerprint.clone());
        }

        emit_mpp_payment_audit(
            &txn,
            PaymentStage::Verified,
            receipt
                .as_ref()
                .map(|c| c.jwt.as_str()),
        );
        self.save_and_cache(txn)
            .await?;

        info!("[mpp-txn-store] Recorded verified payment: {}", id);
        Ok(id)
    }

    /// Record a failed payment verification
    pub async fn record_failed(
        &self,
        channel_id: &str,
        channel_name: &str,
        resource_url: &str,
        payment_method: &str,
        error_message: &str,
        payer: Option<&str>,
        trace_id: Option<String>,
    ) -> Result<String, String> {
        let id = uuid::Uuid::new_v4().to_string();

        let txn = MppTransaction {
            id: id.clone(),
            surface_id: channel_id.to_string(),
            channel_name: channel_name.to_string(),
            resource_url: resource_url.to_string(),
            payment_method: payment_method.to_string(),
            status: MppTransactionStatus::Failed,
            reference: String::new(),
            error: Some(error_message.to_string()),
            payer: payer.map(|s| s.to_string()),
            amount: None,
            currency: None,
            created_at: Utc::now(),
            trace_id,
            receipt_vc_jwt: None,
            receipt_vc_fingerprint: None,
            rejection_vc_jwt: None,
            rejection_vc_fingerprint: None,
        };

        let rejection =
            crate::payment_credentials::issue_payment_rejection(crate::payment_credentials::PaymentRejectionInput {
                rail: "mpp",
                payment_id: txn.id.clone(),
                trace_id: txn.trace_id.clone(),
                method: (!txn.payment_method.is_empty()).then(|| txn.payment_method.clone()),
                payer: txn.payer.clone(),
                reason: error_message.to_string(),
            })
            .await;
        let mut txn = txn;
        if let Some(ref c) = rejection {
            txn.rejection_vc_jwt = Some(c.jwt.clone());
            txn.rejection_vc_fingerprint = Some(c.fingerprint.clone());
        }

        emit_mpp_payment_audit(
            &txn,
            PaymentStage::Failed,
            rejection
                .as_ref()
                .map(|c| c.jwt.as_str()),
        );
        self.save_and_cache(txn)
            .await?;

        info!("[mpp-txn-store] Recorded failed payment: {}", id);
        Ok(id)
    }

    /// Record a 402 challenge issuance (no credential was provided)
    pub async fn record_challenge_issued(
        &self,
        channel_id: &str,
        channel_name: &str,
        resource_url: &str,
        trace_id: Option<String>,
    ) -> Result<String, String> {
        let id = uuid::Uuid::new_v4().to_string();

        let txn = MppTransaction {
            id: id.clone(),
            surface_id: channel_id.to_string(),
            channel_name: channel_name.to_string(),
            resource_url: resource_url.to_string(),
            payment_method: String::new(),
            status: MppTransactionStatus::ChallengeIssued,
            reference: String::new(),
            error: None,
            payer: None,
            amount: None,
            currency: None,
            created_at: Utc::now(),
            trace_id,
            receipt_vc_jwt: None,
            receipt_vc_fingerprint: None,
            rejection_vc_jwt: None,
            rejection_vc_fingerprint: None,
        };

        emit_mpp_payment_audit(&txn, PaymentStage::ChallengeIssued, None);
        self.save_and_cache(txn)
            .await?;

        info!("[mpp-txn-store] Recorded challenge issued: {}", id);
        Ok(id)
    }

    async fn save_and_cache(
        &self,
        txn: MppTransaction,
    ) -> Result<(), String> {
        self.storage
            .save_atomic(&txn)
            .await
            .map_err(|e| {
                error!("[mpp-txn-store] Failed to save to disk: {}", e);
                format!("Failed to persist transaction: {}", e)
            })
    }

    /// Get a transaction by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<MppTransaction> {
        match self.storage.get(id).await {
            Ok(txn) => txn,
            Err(e) => {
                error!("[mpp-txn-store] Failed to load {}: {}", id, e);
                None
            }
        }
    }

    /// List all transactions
    pub async fn list_all(&self) -> Vec<MppTransaction> {
        let mut txns = match self.storage.list_all().await {
            Ok(txns) => txns,
            Err(e) => {
                error!("[mpp-txn-store] Failed to list transactions: {}", e);
                Vec::new()
            }
        };
        txns.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });
        txns
    }

    /// List transactions for a specific channel
    pub async fn list_by_channel(
        &self,
        channel_id: &str,
    ) -> Vec<MppTransaction> {
        self.list_all()
            .await
            .into_iter()
            .filter(|t| t.surface_id == channel_id)
            .collect()
    }

    /// Clean up transactions older than the given number of days
    pub async fn cleanup_old_transactions(
        &self,
        retention_days: i64,
    ) -> Result<usize, String> {
        let cutoff = Utc::now() - Duration::days(retention_days);
        let to_delete: Vec<String> = self
            .list_all()
            .await
            .into_iter()
            .filter(|txn| txn.created_at < cutoff)
            .map(|txn| txn.id)
            .collect();

        let mut count = 0;
        for id in &to_delete {
            if let Err(e) = self.storage.delete(id).await {
                error!("[mpp-txn-store] Failed to delete {}: {}", id, e);
            } else {
                count += 1;
            }
        }

        info!("[mpp-txn-store] Cleaned up {} transactions older than {} days", count, retention_days);

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;

    #[tokio::test]
    async fn test_record_verified_payment() {
        let temp_dir = std::env::temp_dir().join(format!("mpp-txn-test-{}", uuid::Uuid::new_v4()));
        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();

        let id = store
            .record_verified(
                "ch-1",
                "test-channel",
                "/api/resource",
                "tempo",
                "0xdeadbeef",
                Some("did:key:z6Mk..."),
                Some("0.01"),
                Some("USDC"),
                None,
            )
            .await
            .unwrap();

        let txn = store.get(&id).await.unwrap();
        assert_eq!(txn.surface_id, "ch-1");
        assert_eq!(txn.payment_method, "tempo");
        assert_eq!(txn.status, MppTransactionStatus::Verified);
        assert_eq!(txn.reference, "0xdeadbeef");
        assert_eq!(txn.payer.as_deref(), Some("did:key:z6Mk..."));
        assert_eq!(txn.amount.as_deref(), Some("0.01"));
        assert!(txn.error.is_none());

        // Verify file on disk
        let path = temp_dir.join(format!("{}.json", id));
        assert!(path.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_record_failed_payment() {
        let temp_dir = std::env::temp_dir().join(format!("mpp-txn-test-{}", uuid::Uuid::new_v4()));
        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();

        let id = store
            .record_failed(
                "ch-1",
                "test-channel",
                "/api/resource",
                "card",
                "Stripe verification failed: amount mismatch",
                None,
                None,
            )
            .await
            .unwrap();

        let txn = store.get(&id).await.unwrap();
        assert_eq!(txn.status, MppTransactionStatus::Failed);
        assert_eq!(txn.error.as_deref(), Some("Stripe verification failed: amount mismatch"));
        assert!(txn.reference.is_empty());
        assert!(txn.payer.is_none());

        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_record_challenge_issued() {
        let temp_dir = std::env::temp_dir().join(format!("mpp-txn-test-{}", uuid::Uuid::new_v4()));
        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();

        let id = store
            .record_challenge_issued("ch-1", "test-channel", "/api/resource", None)
            .await
            .unwrap();

        let txn = store.get(&id).await.unwrap();
        assert_eq!(txn.status, MppTransactionStatus::ChallengeIssued);
        assert!(txn.payment_method.is_empty());

        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_list_by_channel() {
        let temp_dir = std::env::temp_dir().join(format!("mpp-txn-test-{}", uuid::Uuid::new_v4()));
        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();

        store
            .record_verified("ch-1", "channel-a", "/a", "tempo", "ref1", None, None, None, None)
            .await
            .unwrap();
        store
            .record_verified("ch-2", "channel-b", "/b", "card", "ref2", None, None, None, None)
            .await
            .unwrap();
        store
            .record_failed("ch-1", "channel-a", "/c", "tempo", "bad proof", None, None)
            .await
            .unwrap();

        let ch1_txns = store
            .list_by_channel("ch-1")
            .await;
        assert_eq!(ch1_txns.len(), 2);
        assert!(
            ch1_txns
                .iter()
                .all(|t| t.surface_id == "ch-1")
        );

        let ch2_txns = store
            .list_by_channel("ch-2")
            .await;
        assert_eq!(ch2_txns.len(), 1);

        let all = store.list_all().await;
        assert_eq!(all.len(), 3);

        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_cleanup_old_transactions() {
        let temp_dir = std::env::temp_dir().join(format!("mpp-txn-test-{}", uuid::Uuid::new_v4()));
        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();

        // Record a transaction
        let id = store
            .record_verified("ch-1", "test", "/res", "tempo", "ref", None, None, None, None)
            .await
            .unwrap();

        // Cleanup with 0-day retention should delete it
        let deleted = store
            .cleanup_old_transactions(0)
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        assert!(store.get(&id).await.is_none());
        assert!(
            store
                .list_all()
                .await
                .is_empty()
        );

        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_persistence_across_reload() {
        let temp_dir = std::env::temp_dir().join(format!("mpp-txn-test-{}", uuid::Uuid::new_v4()));

        // Create store and record a transaction
        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();
        let id = store
            .record_verified("ch-1", "test", "/res", "tempo", "0xabc", None, None, None, None)
            .await
            .unwrap();
        drop(store);

        // Create a new store at the same path — should reload from disk
        let store2 = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();
        let txn = store2.get(&id).await.unwrap();
        assert_eq!(txn.reference, "0xabc");
        assert_eq!(txn.status, MppTransactionStatus::Verified);

        let _ = fs::remove_dir_all(&temp_dir).await;
    }
}
