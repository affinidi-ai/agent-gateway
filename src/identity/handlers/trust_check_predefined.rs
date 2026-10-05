//! `GET /v1/trust-check/predefined-queries` — read-only catalogue of
//! predefined Trust Check TRQP queries. Consumed by the
//! surface builder's Query Template dropdown.

use axum::Json;

use crate::trust_registry_verification::predefined_queries::{PredefinedTrustCheckQuery, builtin_catalogue};

pub async fn list_predefined_trust_check_queries() -> Json<Vec<PredefinedTrustCheckQuery>> {
    Json(builtin_catalogue().to_vec())
}
