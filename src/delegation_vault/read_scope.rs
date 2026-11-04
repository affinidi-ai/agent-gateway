//! Which agent-keyed vault tokens and delegation audit records a management
//! caller may read. A record belongs to the tenant of its credential provider.

use std::collections::HashSet;

use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::tenancy::PatTenantContext;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultReadScope {
    /// A session or an access token with neither a tenant nor a resource
    /// scope reads every record.
    Appliance,
    /// A tenant's access token reads the records of these credential
    /// providers, the ones its tenant owns.
    Tenant(HashSet<String>),
    /// An access token scoped by required headers alone, or by a resource
    /// pattern without a tenant, reads none.
    Nothing,
}

impl VaultReadScope {
    /// The scope of the caller the request extensions describe. Only a
    /// tenant's token reads `providers`, once; a failed read is an error,
    /// never a wider scope.
    pub async fn of(
        providers: Option<&dyn CredentialProviderStorage>,
        tenant: Option<&PatTenantContext>,
        resource_scope: Option<&PatResourceScope>,
        delegation: Option<&PatDelegationContext>,
    ) -> anyhow::Result<Self> {
        if let Some(tenant) = tenant {
            let Some(providers) = providers else {
                return Ok(Self::Tenant(HashSet::new()));
            };
            let owned = providers
                .list()
                .await?
                .into_iter()
                .filter(|provider| provider.tenant_id.as_deref() == Some(tenant.tenant_id.as_str()))
                .map(|provider| provider.id)
                .collect();
            return Ok(Self::Tenant(owned));
        }
        if resource_scope.is_some() || delegation.is_some_and(|delegation| delegation.resource_scoped) {
            return Ok(Self::Nothing);
        }
        Ok(Self::Appliance)
    }

    /// Whether the caller may read a record of the credential provider
    /// `credential_provider_id`. A tenant reads only its own providers'
    /// records: never one of an appliance-wide, missing or deleted provider,
    /// nor one that names no provider.
    pub fn reads(
        &self,
        credential_provider_id: Option<&str>,
    ) -> bool {
        match self {
            Self::Appliance => true,
            Self::Tenant(providers) => credential_provider_id.is_some_and(|id| providers.contains(id)),
            Self::Nothing => false,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::credential_providers::CredentialProvider;
    use std::sync::Arc;

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

    /// A VP Audit Log in `directory` holding, oldest first, a
    /// `consent_granted` of `cp-a`, a `token_injected` of each of `cp-b`,
    /// `cp-global` and the deleted `cp-deleted`, a `token_revoked` naming no
    /// provider, a `consent_granted` naming the slug `github`, and a
    /// `policy_decision`.
    pub(crate) async fn audit_log_of_two_tenants(directory: &std::path::Path) -> std::path::PathBuf {
        use crate::delegation_vault::audit::{DelegationAuditAction, audit_event, audit_policy_decision};
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

    /// Credential providers held in memory: `cp-a` of `tenant-a`, `cp-b` of
    /// `tenant-b` and the appliance-wide `cp-global`, all with the slug
    /// `github`; or a store that cannot be read.
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

    async fn tenant_scope(
        providers: &InMemoryProviders,
        tenant_id: &str,
    ) -> anyhow::Result<VaultReadScope> {
        VaultReadScope::of(
            Some(providers),
            Some(&tenant(tenant_id)),
            Some(&pattern(tenant_id)),
            Some(&delegation(true)),
        )
        .await
    }

    #[tokio::test]
    async fn a_tenant_token_reads_only_records_of_its_own_tenants_providers() {
        let providers = InMemoryProviders::of_two_tenants();
        let tenant_a = tenant_scope(&providers, "tenant-a")
            .await
            .unwrap();
        assert_eq!(tenant_a, VaultReadScope::Tenant(HashSet::from(["cp-a".to_string()])));
        assert!(tenant_a.reads(Some("cp-a")));
        assert!(!tenant_a.reads(Some("cp-b")));
        let tenant_b = tenant_scope(&providers, "tenant-b")
            .await
            .unwrap();
        assert!(tenant_b.reads(Some("cp-b")));
        assert!(!tenant_b.reads(Some("cp-a")));
    }

    /// Slugs are unique only per tenant and every provider here is `github`,
    /// so a slug never names a tenant's provider.
    #[tokio::test]
    async fn a_tenant_token_never_reads_records_of_untenanted_missing_or_deleted_providers() {
        let tenant_a = tenant_scope(&InMemoryProviders::of_two_tenants(), "tenant-a")
            .await
            .unwrap();
        for credential_provider_id in [Some("cp-global"), Some("cp-deleted"), Some("github"), Some(""), None] {
            assert!(!tenant_a.reads(credential_provider_id), "{credential_provider_id:?}");
        }
    }

    #[tokio::test]
    async fn a_tenant_token_reads_no_record_without_a_provider_store() {
        let scope =
            VaultReadScope::of(None, Some(&tenant("tenant-a")), Some(&pattern("tenant-a")), Some(&delegation(true)))
                .await
                .unwrap();
        assert_eq!(scope, VaultReadScope::Tenant(HashSet::new()));
        assert!(!scope.reads(Some("cp-a")));
    }

    #[tokio::test]
    async fn an_appliance_wide_caller_reads_every_record_without_reading_the_provider_store() {
        let unreadable = InMemoryProviders::unreadable();
        for delegation in [None, Some(delegation(false))] {
            let scope = VaultReadScope::of(Some(&unreadable), None, None, delegation.as_ref())
                .await
                .unwrap();
            assert_eq!(scope, VaultReadScope::Appliance);
            for credential_provider_id in [Some("cp-a"), Some("cp-b"), Some("cp-global"), Some("cp-deleted"), None] {
                assert!(scope.reads(credential_provider_id), "{credential_provider_id:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_token_scoped_by_required_headers_alone_reads_no_record() {
        let scope = VaultReadScope::of(Some(&InMemoryProviders::unreadable()), None, None, Some(&delegation(true)))
            .await
            .unwrap();
        assert_eq!(scope, VaultReadScope::Nothing);
        for credential_provider_id in [Some("cp-a"), Some("cp-global"), None] {
            assert!(!scope.reads(credential_provider_id), "{credential_provider_id:?}");
        }
    }

    #[tokio::test]
    async fn a_resource_scope_without_a_tenant_reads_no_record() {
        let unreadable = InMemoryProviders::unreadable();
        for delegation in [None, Some(delegation(true))] {
            let scope = VaultReadScope::of(Some(&unreadable), None, Some(&pattern("tenant-a")), delegation.as_ref())
                .await
                .unwrap();
            assert_eq!(scope, VaultReadScope::Nothing);
            assert!(!scope.reads(Some("cp-a")));
        }
    }

    #[tokio::test]
    async fn a_tenant_token_is_refused_when_the_provider_store_fails() {
        let error = tenant_scope(&InMemoryProviders::unreadable(), "tenant-a")
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "credential providers unreadable");
    }
}
