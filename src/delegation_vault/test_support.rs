//! Credential providers of two tenants, their VP Audit Log, the callers that
//! read them, and a surface store that cannot be read, shared by the
//! delegation vault's tests.

use std::sync::Arc;

use axum::http::Extensions;

use super::read_scope::VaultReader;
use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
use crate::credential_providers::CredentialProvider;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::tenancy::PatTenantContext;

pub(crate) fn provider(
    id: &str,
    tenant_id: Option<&str>,
) -> CredentialProvider {
    serde_json::from_value(serde_json::json!({
        "id": id, "tenant_id": tenant_id, "name": "GitHub", "provider_id": "github",
        "provider_type": "oauth2_client_credentials", "token_endpoint": "https://github.example/token",
        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
    }))
    .unwrap()
}

/// A VP Audit Log in `directory` holding, oldest first, a `consent_granted`
/// of `cp-a`, a `token_injected` of each of `cp-b`, `cp-global` and the
/// deleted `cp-deleted`, a `token_revoked` naming no provider, a
/// `consent_granted` naming the slug `github`, and a `policy_decision`.
pub(crate) async fn audit_log_of_two_tenants(directory: &std::path::Path) -> std::path::PathBuf {
    use super::audit::{DelegationAuditAction, audit_event, audit_policy_decision};
    let event = |action, provider_id| {
        audit_event(action, Some("did:web:agent.example"), Some("sha256:user-1"), provider_id, Some("surface-1"))
    };
    let mut events = vec![
        event(DelegationAuditAction::ConsentGranted, Some("cp-a")),
        event(DelegationAuditAction::TokenInjected, Some("cp-b")),
        event(DelegationAuditAction::TokenInjected, Some("cp-global")),
        event(DelegationAuditAction::TokenInjected, Some("cp-deleted")),
        event(DelegationAuditAction::TokenRevoked, None),
        event(DelegationAuditAction::ConsentGranted, Some("github")),
    ];
    let ((), decisions) = crate::audit::producer::capture(async {
        audit_policy_decision(
            "gateway",
            "allow",
            "policy-1",
            None,
            None,
            None,
            Some("surface-1"),
            None,
            Some("did:web:caller.example"),
            Some("POST"),
            Some("/"),
            None,
            "access_point",
            None,
            None,
            None,
            None,
        )
    })
    .await;
    assert_eq!(decisions.len(), 1);
    events.extend(decisions);
    let path = directory.join("delegation-audit.jsonl");
    let lines: String = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap() + "\n")
        .collect();
    std::fs::write(&path, lines).unwrap();
    path
}

/// When [`OLD_ROW`] occurred.
pub(crate) const OLD_ROW_TIME: &str = "2026-11-07T10:00:00Z";

/// A record as releases before `occurred_at` stored it: its time under
/// `timestamp`, and no event id.
pub(crate) const OLD_ROW: &str =
    r#"{"timestamp":"2026-11-07T10:00:00Z","event":"consent_granted","provider_id":"cp-global","via_fabric":false}"#;

/// When the consent of [`EXPIRY_ROW`] ended.
pub(crate) const EXPIRY_ROW_END: &str = "2026-11-24T08:00:00Z";

/// A `consent_expired` record as the gateway writes it: the consent was
/// removed at `occurred_at`, two hours after it ended at `expired_at`.
pub(crate) const EXPIRY_ROW: &str = r#"{"occurred_at":"2026-11-24T10:00:00+00:00","event":"consent_expired","provider_id":"cp-global","via_fabric":false,"detail":"consent_granted_at:2026-11-24T07:00:00Z,consent_expired_at:2026-11-24T08:00:00Z,source:sweep","expired_at":"2026-11-24T08:00:00Z"}"#;

/// A `consent_expired` record as releases before `expired_at` stored it.
pub(crate) const OLD_EXPIRY_ROW: &str =
    r#"{"timestamp":"2026-11-07T10:00:00Z","event":"consent_expired","provider_id":"cp-global","via_fabric":false}"#;

/// A line naming its time under both names, which no release writes.
pub(crate) const ROW_WITH_BOTH_TIMES: &str = r#"{"timestamp":"2026-11-07T10:00:00Z","occurred_at":"2026-11-07T11:00:00Z","event":"token_revoked","via_fabric":false}"#;

/// A VP Audit Log in `directory` holding the `stored` lines, oldest first,
/// then `written` as the gateway writes it.
pub(crate) fn audit_log_holding(
    directory: &std::path::Path,
    stored: &[&str],
    written: &super::audit::DelegationAuditEvent,
) -> std::path::PathBuf {
    let path = directory.join("delegation-audit.jsonl");
    let lines: String = stored
        .iter()
        .map(|line| format!("{line}\n"))
        .chain([serde_json::to_string(written).unwrap() + "\n"])
        .collect();
    std::fs::write(&path, lines).unwrap();
    path
}

/// The `occurred_at` and `timestamp` of each record of an audit page, as
/// answered.
pub(crate) fn times_of(page: &serde_json::Value) -> Vec<(Option<&serde_json::Value>, Option<&serde_json::Value>)> {
    page["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| (event.get("occurred_at"), event.get("timestamp")))
        .collect()
}

/// Credential providers held in memory: `cp-a` of `tenant-a`, `cp-b` of
/// `tenant-b` and the appliance-wide `cp-global`, all with the slug `github`;
/// or a store that cannot be read.
pub(crate) struct InMemoryProviders {
    providers: Option<Vec<CredentialProvider>>,
}

impl InMemoryProviders {
    pub(crate) fn of_two_tenants() -> Self {
        Self {
            providers: Some(vec![
                provider("cp-a", Some("tenant-a")),
                provider("cp-b", Some("tenant-b")),
                provider("cp-global", None),
            ]),
        }
    }

    pub(crate) fn unreadable() -> Self {
        Self { providers: None }
    }

    pub(crate) fn of(providers: Vec<CredentialProvider>) -> Self {
        Self { providers: Some(providers) }
    }

    fn providers(&self) -> anyhow::Result<&[CredentialProvider]> {
        self.providers
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("credential providers unreadable"))
    }
}

#[async_trait::async_trait]
impl CredentialProviderStorage for InMemoryProviders {
    async fn create(
        &self,
        _provider: CredentialProvider,
    ) -> anyhow::Result<CredentialProvider> {
        unimplemented!("the management routes never write a provider")
    }

    async fn get(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<CredentialProvider>> {
        Ok(self
            .providers()?
            .iter()
            .find(|provider| provider.id == id)
            .cloned())
    }

    async fn get_checked(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<CredentialProvider>> {
        self.get(id).await
    }

    async fn list(&self) -> anyhow::Result<Vec<CredentialProvider>> {
        Ok(self.providers()?.to_vec())
    }

    async fn update(
        &self,
        _provider: CredentialProvider,
    ) -> anyhow::Result<CredentialProvider> {
        unimplemented!("the management routes never write a provider")
    }

    async fn delete(
        &self,
        _id: &str,
    ) -> anyhow::Result<bool> {
        unimplemented!("the management routes never write a provider")
    }

    async fn find_by_provider_id(
        &self,
        _tenant_id: Option<&str>,
        _provider_id: &str,
    ) -> anyhow::Result<Option<CredentialProvider>> {
        unimplemented!("the management routes look providers up by id")
    }
}

pub(crate) fn tenant(tenant_id: &str) -> PatTenantContext {
    PatTenantContext {
        token_id: "pat-t".to_string(),
        tenant_id: tenant_id.to_string(),
    }
}

pub(crate) fn pattern(tenant_id: &str) -> PatResourceScope {
    PatResourceScope(Arc::new(regex::Regex::new(&format!("^TENANT:{tenant_id}:credential-providers:.*$")).unwrap()))
}

pub(crate) fn delegation(resource_scoped: bool) -> PatDelegationContext {
    PatDelegationContext {
        token_id: "pat-t".to_string(),
        delegation_depth: 0,
        resource_scoped,
    }
}

/// Request extensions holding these contexts, as the session and
/// access-token middleware set them.
pub(crate) fn extensions(
    tenant: Option<PatTenantContext>,
    resource_scope: Option<PatResourceScope>,
    delegation: Option<PatDelegationContext>,
) -> Extensions {
    let mut extensions = Extensions::new();
    if let Some(tenant) = tenant {
        extensions.insert(tenant);
    }
    if let Some(resource_scope) = resource_scope {
        extensions.insert(resource_scope);
    }
    if let Some(delegation) = delegation {
        extensions.insert(delegation);
    }
    extensions
}

/// The caller a request with these extensions describes.
pub(crate) fn reader(
    tenant: Option<PatTenantContext>,
    resource_scope: Option<PatResourceScope>,
    delegation: Option<PatDelegationContext>,
) -> VaultReader {
    VaultReader::from_extensions(&extensions(tenant, resource_scope, delegation))
}

/// A surface store every read and write of which fails.
pub(crate) struct UnreadableSurfaces;

#[async_trait::async_trait]
impl crate::surfaces::AgentSurfaceStore for UnreadableSurfaces {
    async fn get_checked(
        &self,
        surface_id: &str,
    ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
        self.get(surface_id).await
    }

    async fn save(
        &self,
        _surface: &crate::config::agent_surface::AgentSurface,
    ) -> anyhow::Result<()> {
        anyhow::bail!("disk unavailable")
    }

    async fn get(
        &self,
        _surface_id: &str,
    ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
        anyhow::bail!("disk unavailable")
    }

    async fn list_all(&self) -> anyhow::Result<Vec<crate::config::agent_surface::AgentSurface>> {
        anyhow::bail!("disk unavailable")
    }

    async fn delete(
        &self,
        _surface_id: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("disk unavailable")
    }
}
