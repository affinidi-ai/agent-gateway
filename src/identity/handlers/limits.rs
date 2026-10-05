//! Dashboard API for appliance resource limits.
//!
//! Returns every configured limit (from `limits.json`) with its operator-facing
//! name/description, the cap, and the current live count — used by the Settings
//! "Limits" view and the create-button guards.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

/// One configured resource limit with its current live usage.
#[derive(Debug, Serialize)]
pub struct LimitItem {
    /// Dot-notation dimension id (e.g. `secrets.secret`).
    pub id: String,
    /// Operator-facing display name.
    pub name: String,
    /// Operator-facing description.
    pub description: String,
    /// Configured maximum.
    pub limit: u64,
    /// Current number of entities counted for the dimension.
    pub current: u64,
}

/// `GET /v1/limits` — every configured limit with its current usage, sorted by id.
pub async fn list_limits() -> impl IntoResponse {
    let cfg = crate::config::global_limits();
    let mut items: Vec<LimitItem> = Vec::with_capacity(cfg.limits.len());
    for (id, def) in &cfg.limits {
        let current = crate::config::current_count(id).await as u64;
        items.push(LimitItem {
            id: id.clone(),
            name: def.name.clone(),
            description: def.description.clone(),
            limit: def.limit,
            current,
        });
    }
    items.sort_by(|a, b| a.id.cmp(&b.id));
    (StatusCode::OK, Json(items))
}
