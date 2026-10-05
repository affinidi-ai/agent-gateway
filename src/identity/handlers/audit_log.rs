use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::identity::state::IdentityApiState;

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_page")]
    pub page: usize,
    pub filter: Option<String>,
    pub category: Option<String>,
    /// Policy-decision refinements — restrict to matching policy decisions.
    pub flow: Option<String>,
    pub scope: Option<String>,
    pub decision: Option<String>,
}

fn default_limit() -> usize {
    100
}
fn default_page() -> usize {
    1
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub events: Vec<crate::delegation_vault::audit::DelegationAuditEvent>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    /// Per-category event counts across the text-filtered set (before the
    /// category filter), so the UI can show each category's count.
    pub category_counts: std::collections::BTreeMap<String, usize>,
}

pub async fn get_audit_log(
    State(_state): State<IdentityApiState>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, String)> {
    let limit = query.limit.clamp(1, 500);
    let page = query.page.max(1);

    let filter_str = query.filter.clone();
    let category = query.category.clone();
    let flow = query.flow.clone();
    let scope = query.scope.clone();
    let decision = query.decision.clone();

    let result = crate::delegation_vault::audit::read_audit_log(
        page,
        limit,
        crate::delegation_vault::audit::AuditLogFilter {
            text: filter_str.as_deref(),
            category: category.as_deref(),
            flow: flow.as_deref(),
            scope: scope.as_deref(),
            decision: decision.as_deref(),
            exclude_vp_audit: false,
        },
    )
    .await;

    let log_page = match result {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Failed to read audit log: {}", e);
            return Ok(Json(AuditLogResponse {
                events: Vec::new(),
                total: 0,
                page,
                page_size: limit,
                total_pages: 0,
                category_counts: std::collections::BTreeMap::new(),
            }));
        }
    };

    Ok(Json(AuditLogResponse {
        events: log_page.events,
        total: log_page.total,
        page: log_page.page,
        page_size: log_page.page_size,
        total_pages: log_page.total_pages,
        category_counts: log_page.category_counts,
    }))
}
