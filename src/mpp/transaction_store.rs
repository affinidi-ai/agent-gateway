//! MPP Transaction Store
//!
//! Filesystem-backed store of the MPP payment transactions this gateway
//! recorded when it verified MPP payments itself. Nothing records new ones; the
//! admin API lists, reads and prunes the existing records.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{error, info};

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
impl MppTransaction {
    pub(crate) fn for_test(
        surface_id: &str,
        status: MppTransactionStatus,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            surface_id: surface_id.to_string(),
            channel_name: "test-channel".to_string(),
            resource_url: "/api/resource".to_string(),
            payment_method: "tempo".to_string(),
            status,
            reference: String::new(),
            error: None,
            payer: None,
            amount: None,
            currency: None,
            created_at: Utc::now(),
            trace_id: None,
            receipt_vc_jwt: None,
            receipt_vc_fingerprint: None,
            rejection_vc_jwt: None,
            rejection_vc_fingerprint: None,
        }
    }
}

#[cfg(test)]
impl MppTransactionStore {
    pub(crate) async fn insert(
        &self,
        txn: MppTransaction,
    ) {
        self.storage
            .save_atomic(&txn)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;

    async fn record(
        store: &MppTransactionStore,
        surface_id: &str,
        status: MppTransactionStatus,
        reference: &str,
    ) -> String {
        let mut txn = MppTransaction::for_test(surface_id, status);
        txn.reference = reference.to_string();
        let id = txn.id.clone();
        store.insert(txn).await;
        id
    }

    #[tokio::test]
    async fn test_list_by_channel() {
        let temp_dir = std::env::temp_dir().join(format!("mpp-txn-test-{}", uuid::Uuid::new_v4()));
        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();

        record(&store, "ch-1", MppTransactionStatus::Verified, "ref1").await;
        record(&store, "ch-2", MppTransactionStatus::Verified, "ref2").await;
        record(&store, "ch-1", MppTransactionStatus::Failed, "").await;

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
        assert_eq!(ch2_txns[0].reference, "ref2");

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

        let id = record(&store, "ch-1", MppTransactionStatus::Verified, "ref").await;

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

        let store = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();
        let id = record(&store, "ch-1", MppTransactionStatus::Verified, "0xabc").await;
        drop(store);

        let store2 = MppTransactionStore::new(temp_dir.clone())
            .await
            .unwrap();
        let txn = store2.get(&id).await.unwrap();
        assert_eq!(txn.reference, "0xabc");
        assert_eq!(txn.status, MppTransactionStatus::Verified);
        assert!(
            store2
                .get("missing")
                .await
                .is_none()
        );

        let _ = fs::remove_dir_all(&temp_dir).await;
    }
}
