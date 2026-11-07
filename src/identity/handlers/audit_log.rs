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
    /// Whether the read stopped before the end of the audit history: the
    /// counts then describe the records it reached, not the whole history.
    pub truncated: bool,
    /// Records the history holds that the read could not return. The counts
    /// are lower bounds by this many.
    pub dropped_records: usize,
    /// Bytes the audit history takes on disk, live log and rotated files.
    pub history_bytes: u64,
    /// The advisory size an operator asked to be told about, `0` for none.
    pub soft_cap_bytes: u64,
}

impl From<crate::delegation_vault::audit::AuditLogPage> for AuditLogResponse {
    fn from(page: crate::delegation_vault::audit::AuditLogPage) -> Self {
        Self {
            events: page.events,
            total: page.total,
            page: page.page,
            page_size: page.page_size,
            total_pages: page.total_pages,
            category_counts: page.category_counts,
            truncated: page.truncated,
            dropped_records: page.dropped_records,
            history_bytes: page.history_bytes,
            soft_cap_bytes: page.soft_cap_bytes,
        }
    }
}

pub async fn get_audit_log(
    State(_state): State<IdentityApiState>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, Json<serde_json::Value>)> {
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

    respond(result)
}

/// Answers with the page, or with `500` when the read failed. An empty page
/// would assert that this is the whole of the administrator's evidence. The
/// failure is a JSON `{"error": …}` body, the shape `/v1/delegation-audit`
/// answers a failed read of the same history with; the io detail stays in the
/// log.
fn respond(
    result: anyhow::Result<crate::delegation_vault::audit::AuditLogPage>
) -> Result<Json<AuditLogResponse>, (StatusCode, Json<serde_json::Value>)> {
    match result {
        Ok(page) => Ok(Json(AuditLogResponse::from(page))),
        Err(e) => {
            tracing::warn!(target: "credential_delegation", error = %e, "Failed to read the VP Audit Log");
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to read the audit log"}))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::audit::AuditLogPage;

    #[test]
    fn a_read_that_failed_is_answered_with_an_error_not_an_empty_page() {
        let (status, Json(body)) = respond(Err(anyhow::anyhow!("Audit logger not initialized")))
            .expect_err("a failed read must not answer with a page");

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body,
            serde_json::json!({"error": "Failed to read the audit log"}),
            "the same JSON shape as /v1/delegation-audit, and the io detail stays in the log"
        );
    }

    #[test]
    fn a_page_read_from_part_of_the_history_says_so_in_the_response() {
        let page = AuditLogPage {
            events: Vec::new(),
            total: 3,
            page: 1,
            page_size: 25,
            total_pages: 1,
            category_counts: std::collections::BTreeMap::from([("token_injected".to_string(), 3)]),
            truncated: true,
            dropped_records: 2,
            history_bytes: 4096,
            soft_cap_bytes: 1024,
        };

        let Json(response) = respond(Ok(page)).expect("a page is answered with 200");
        let body = serde_json::to_value(response).unwrap();

        assert_eq!(body["truncated"], serde_json::json!(true));
        assert_eq!(body["total"], serde_json::json!(3));
        assert_eq!(body["category_counts"]["token_injected"], serde_json::json!(3));
        assert_eq!(body["history_bytes"], serde_json::json!(4096), "the size of the history is answered with it");
        assert_eq!(body["soft_cap_bytes"], serde_json::json!(1024));
        assert_eq!(
            body["dropped_records"],
            serde_json::json!(2),
            "the records the read could not return are counted apart from stopping early"
        );
    }

    #[test]
    fn a_page_read_to_the_end_of_the_history_is_not_marked_truncated() {
        let page = AuditLogPage {
            events: Vec::new(),
            total: 0,
            page: 1,
            page_size: 25,
            total_pages: 1,
            category_counts: std::collections::BTreeMap::new(),
            truncated: false,
            dropped_records: 0,
            history_bytes: 0,
            soft_cap_bytes: 0,
        };

        let Json(response) = respond(Ok(page)).expect("a page is answered with 200");
        let body = serde_json::to_value(response).unwrap();

        assert_eq!(body["truncated"], serde_json::json!(false));
        assert_eq!(body["total_pages"], serde_json::json!(1));
    }
}
