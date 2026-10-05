//! Admin API endpoints for MPP transaction observability
//!
//! Mirrors `crate::x402::admin_api` so the dashboard's unified Transactions
//! page can read MPP payment records alongside x402 ones.

use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::transaction_store::MppTransaction;

/// Admin API state containing the MPP transaction store
#[derive(Clone)]
pub struct MppAdminApiState {
    pub transaction_store: Option<Arc<super::MppTransactionStore>>,
}

/// Error response for admin API. Carries an explicit status so an unknown
/// transaction id reports 404 rather than the same 500 used for a genuine
/// backend misconfiguration (missing transaction store).
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    #[serde(skip)]
    pub status: StatusCode,
    pub error: String,
}

impl ErrorResponse {
    fn not_found(error: String) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error,
        }
    }

    fn internal(error: String) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error,
        }
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = self.status;
        (status, Json(self)).into_response()
    }
}

/// Query parameters for listing MPP transactions
#[derive(Deserialize)]
pub struct ListMppTransactionsQuery {
    /// Filter by surface (channel) ID
    pub surface_id: Option<String>,

    /// Maximum number of results
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

/// Summary row for the unified Transactions page
#[derive(Serialize)]
pub struct MppTransactionSummary {
    pub id: String,
    pub surface_id: String,
    pub channel_name: String,
    pub resource_url: String,
    pub payment_method: String,
    pub status: String,
    pub reference: String,
    pub error: Option<String>,
    pub payer: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub created_at: i64,
}

impl From<&MppTransaction> for MppTransactionSummary {
    fn from(txn: &MppTransaction) -> Self {
        Self {
            id: txn.id.clone(),
            surface_id: txn.surface_id.clone(),
            channel_name: txn.channel_name.clone(),
            resource_url: txn.resource_url.clone(),
            payment_method: txn.payment_method.clone(),
            status: format!("{:?}", txn.status).to_lowercase(),
            reference: txn.reference.clone(),
            error: txn.error.clone(),
            payer: txn.payer.clone(),
            amount: txn.amount.clone(),
            currency: txn.currency.clone(),
            created_at: txn.created_at.timestamp(),
        }
    }
}

#[derive(Serialize)]
pub struct ListMppTransactionsResponse {
    pub transactions: Vec<MppTransactionSummary>,
    pub total: usize,
}

/// List MPP transactions, optionally filtered by surface (channel) ID
async fn list_mpp_transactions(
    State(state): State<MppAdminApiState>,
    Query(query): Query<ListMppTransactionsQuery>,
) -> Result<Json<ListMppTransactionsResponse>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse::internal("MPP transaction store not configured".to_string()))?;

    let all = match query.surface_id {
        Some(ref surface_id) => {
            transaction_store
                .list_by_channel(surface_id)
                .await
        }
        None => {
            transaction_store
                .list_all()
                .await
        }
    };

    let total = all.len();
    let transactions = all
        .iter()
        .take(query.limit)
        .map(MppTransactionSummary::from)
        .collect();

    Ok(Json(ListMppTransactionsResponse { transactions, total }))
}

/// Get a specific MPP transaction by ID (returns the full stored record)
async fn get_mpp_transaction(
    State(state): State<MppAdminApiState>,
    Path(transaction_id): Path<String>,
) -> Result<Json<MppTransaction>, ErrorResponse> {
    let transaction_store = state
        .transaction_store
        .ok_or_else(|| ErrorResponse::internal("MPP transaction store not configured".to_string()))?;

    transaction_store
        .get(&transaction_id)
        .await
        .map(Json)
        .ok_or_else(|| ErrorResponse::not_found(format!("Transaction not found: {}", transaction_id)))
}

/// Create the MPP admin API router
pub fn create_mpp_admin_router() -> Router<MppAdminApiState> {
    Router::new()
        .route("/mpp/transactions", get(list_mpp_transactions))
        .route("/mpp/transactions/{transaction_id}", get(get_mpp_transaction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::MppTransactionStore;
    use axum::extract::{Path, Query, State};

    async fn temp_store() -> MppTransactionStore {
        let dir = std::env::temp_dir().join(format!("mpp-admin-api-test-{}", uuid::Uuid::new_v4()));
        MppTransactionStore::new(dir)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn list_returns_recorded_transactions() {
        let store = temp_store().await;
        store
            .record_verified(
                "ch-1",
                "test-channel",
                "/api/resource",
                "stripe",
                "pi_123",
                Some("did:key:z6Mk..."),
                Some("5000"),
                Some("usd"),
                None,
            )
            .await
            .unwrap();

        let state = MppAdminApiState {
            transaction_store: Some(Arc::new(store)),
        };
        let response =
            list_mpp_transactions(State(state), Query(ListMppTransactionsQuery { surface_id: None, limit: 100 }))
                .await
                .unwrap();

        assert_eq!(response.0.total, 1);
        assert_eq!(response.0.transactions[0].status, "verified");
        assert_eq!(
            response.0.transactions[0]
                .currency
                .as_deref(),
            Some("usd")
        );
    }

    #[tokio::test]
    async fn list_without_store_configured_errors() {
        let state = MppAdminApiState { transaction_store: None };
        let result =
            list_mpp_transactions(State(state), Query(ListMppTransactionsQuery { surface_id: None, limit: 100 })).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_returns_full_record() {
        let store = temp_store().await;
        let id = store
            .record_failed("ch-1", "test-channel", "/api/resource", "stripe", "card_declined", None, None)
            .await
            .unwrap();

        let state = MppAdminApiState {
            transaction_store: Some(Arc::new(store)),
        };
        let response = get_mpp_transaction(State(state), Path(id.clone()))
            .await
            .unwrap();

        assert_eq!(response.0.id, id);
        assert_eq!(response.0.error.as_deref(), Some("card_declined"));
    }

    #[tokio::test]
    async fn get_unknown_id_errors() {
        let store = temp_store().await;
        let state = MppAdminApiState {
            transaction_store: Some(Arc::new(store)),
        };
        let result = get_mpp_transaction(State(state), Path("does-not-exist".to_string())).await;

        assert!(result.is_err());
    }
}
