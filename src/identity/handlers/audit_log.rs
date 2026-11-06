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
}

pub async fn get_audit_log(
    State(state): State<IdentityApiState>,
    reader: VaultReader,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, String)> {
    Ok(Json(
        audit_log_page(
            state
                .credential_provider_store
                .as_deref(),
            &reader,
            query,
        )
        .await,
    ))
}

/// The page of the VP Audit Log `reader` may read: a tenant's access token
/// reads only the records of its own tenant's credential providers. While the
/// credential providers cannot be read, such a caller gets an empty page.
async fn audit_log_page(
    providers: Option<&dyn CredentialProviderStorage>,
    reader: &VaultReader,
    query: AuditLogQuery,
) -> AuditLogResponse {
    let limit = query.limit.clamp(1, 500);
    let page = query.page.max(1);
    let empty = || AuditLogResponse {
        events: Vec::new(),
        total: 0,
        page,
        page_size: limit,
        total_pages: 0,
        category_counts: std::collections::BTreeMap::new(),
    };

    let scope = match VaultReadScope::of(providers, reader).await {
        Ok(scope) => scope,
        Err(e) => {
            tracing::warn!(error = %e, "Audit log read refused: the credential providers could not be read");
            return empty();
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
        &scope,
    )
    .await;

    match result {
        Ok(log_page) => AuditLogResponse {
            events: log_page.events,
            total: log_page.total,
            page: log_page.page,
            page_size: log_page.page_size,
            total_pages: log_page.total_pages,
            category_counts: log_page.category_counts,
        },
        Err(e) => {
            tracing::warn!("Failed to read audit log: {}", e);
            empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_manager::pat::PatDelegationContext;
    use crate::delegation_vault::audit::reading_audit_log_from;
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
        reading_audit_log_from(log, audit_log_page(Some(providers), &caller, query)).await
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
    }
}
