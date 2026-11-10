use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::credential_providers::storage::CredentialProviderStorage;
use crate::delegation_vault::read_scope::{VaultReadScope, VaultReader};
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
    State(state): State<IdentityApiState>,
    reader: VaultReader,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, Json<serde_json::Value>)> {
    audit_log_page(
        state
            .credential_provider_store
            .as_deref(),
        &reader,
        query,
    )
    .await
}

/// The page of the VP Audit Log `reader` may read: a tenant's access token
/// reads only the records of its own tenant's credential providers. While the
/// credential providers cannot be read, such a caller gets an empty page,
/// marked `truncated` because nothing was read; a failed read of the log
/// itself is answered with `500`.
async fn audit_log_page(
    providers: Option<&dyn CredentialProviderStorage>,
    reader: &VaultReader,
    query: AuditLogQuery,
) -> Result<Json<AuditLogResponse>, (StatusCode, Json<serde_json::Value>)> {
    let limit = query.limit.clamp(1, 500);
    let page = query.page.max(1);
    let empty = || AuditLogResponse {
        events: Vec::new(),
        total: 0,
        page,
        page_size: limit,
        total_pages: 0,
        category_counts: std::collections::BTreeMap::new(),
        truncated: true,
        dropped_records: 0,
        history_bytes: 0,
        soft_cap_bytes: 0,
    };

    let scope = match VaultReadScope::of(providers, reader).await {
        Ok(scope) => scope,
        Err(e) => {
            tracing::warn!(error = %e, "Audit log read refused: the credential providers could not be read");
            return Ok(Json(empty()));
        }
    };

    let result = crate::delegation_vault::audit::read_audit_log(
        page,
        limit,
        crate::delegation_vault::audit::AuditLogFilter {
            text: query.filter.as_deref(),
            category: query.category.as_deref(),
            flow: query.flow.as_deref(),
            scope: query.scope.as_deref(),
            decision: query.decision.as_deref(),
            exclude_vp_audit: false,
        },
        scope,
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
    use crate::auth_manager::pat::PatDelegationContext;
    use crate::delegation_vault::audit::{AuditLogPage, reading_audit_log_from};
    use crate::delegation_vault::test_support::{
        InMemoryProviders, audit_log_of_two_tenants, delegation, reader, tenant,
    };
    use crate::tenancy::PatTenantContext;

    async fn read(
        providers: &InMemoryProviders,
        tenant: Option<&PatTenantContext>,
        delegation: Option<&PatDelegationContext>,
    ) -> AuditLogResponse {
        let directory = tempfile::tempdir().unwrap();
        let log = audit_log_of_two_tenants(directory.path()).await;
        let query = serde_json::from_value(serde_json::json!({})).unwrap();
        let caller = reader(tenant.cloned(), None, delegation.cloned());
        reading_audit_log_from(log, audit_log_page(Some(providers), &caller, query))
            .await
            .map(|Json(page)| page)
            .expect("a page is answered with 200")
    }

    fn provider_ids(response: &AuditLogResponse) -> Vec<Option<&str>> {
        response
            .events
            .iter()
            .map(|event| event.provider_id.as_deref())
            .collect()
    }

    /// The VP Audit Log's records without a provider, such as policy
    /// decisions, are hidden from a tenant's token too.
    #[tokio::test]
    async fn a_tenant_token_reads_only_its_tenants_records_in_the_vp_audit_log() {
        let providers = InMemoryProviders::of_two_tenants();
        let response = read(&providers, Some(&tenant("tenant-a")), Some(&delegation(true))).await;
        assert_eq!(provider_ids(&response), [Some("cp-a")]);
        assert_eq!((response.total, response.total_pages), (1, 1));
        assert_eq!(response.category_counts, std::collections::BTreeMap::from([("consent_granted".to_string(), 1)]));
    }

    #[tokio::test]
    async fn an_appliance_wide_caller_reads_the_whole_vp_audit_log() {
        let response = read(&InMemoryProviders::unreadable(), None, None).await;
        assert_eq!(response.total, 7);
        assert_eq!(
            provider_ids(&response),
            [None, Some("github"), None, Some("cp-deleted"), Some("cp-global"), Some("cp-b"), Some("cp-a")]
        );
        assert_eq!(response.category_counts["policy_decision"], 1);
    }

    #[tokio::test]
    async fn a_token_scoped_by_required_headers_alone_reads_no_vp_audit_record() {
        let response = read(&InMemoryProviders::of_two_tenants(), None, Some(&delegation(true))).await;
        assert!(response.events.is_empty());
        assert_eq!(response.total, 0);
        assert!(
            response
                .category_counts
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_tenant_token_reads_an_empty_vp_audit_log_while_the_provider_store_fails() {
        let response = read(&InMemoryProviders::unreadable(), Some(&tenant("tenant-a")), Some(&delegation(true))).await;
        assert!(response.events.is_empty());
        assert_eq!((response.total, response.total_pages), (0, 0));
        assert!(
            response
                .category_counts
                .is_empty()
        );
        assert!(response.truncated, "nothing was read, so the page does not claim to be the whole history");
        assert_eq!((response.history_bytes, response.dropped_records), (0, 0), "and it says nothing of the log");
    }

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
