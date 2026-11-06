//! Which agent-keyed vault tokens and delegation audit records a management
//! caller may read. A record belongs to the tenant of its credential provider.

use std::collections::HashSet;

use axum::extract::FromRequestParts;
use axum::http::Extensions;
use axum::http::request::Parts;

use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::tenancy::PatTenantContext;

/// The management caller of a read, as the session and access-token
/// middleware describe it in the request extensions. A handler takes it
/// whole, so none can decide a [`VaultReadScope`] from part of the caller.
pub struct VaultReader {
    tenant: Option<PatTenantContext>,
    resource_scope: Option<PatResourceScope>,
    delegation: Option<PatDelegationContext>,
}

impl VaultReader {
    /// The caller `extensions` describe, taken whole.
    pub(crate) fn from_extensions(extensions: &Extensions) -> Self {
        Self {
            tenant: extensions.get().cloned(),
            resource_scope: extensions.get().cloned(),
            delegation: extensions.get().cloned(),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for VaultReader {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self::from_extensions(&parts.extensions))
    }
}

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
    /// The scope of `reader`. Only a tenant's token reads `providers`, once; a
    /// failed read is an error, never a wider scope.
    pub async fn of(
        providers: Option<&dyn CredentialProviderStorage>,
        reader: &VaultReader,
    ) -> anyhow::Result<Self> {
        let VaultReader {
            tenant,
            resource_scope,
            delegation,
        } = reader;
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
        if resource_scope.is_some()
            || delegation
                .as_ref()
                .is_some_and(|delegation| delegation.resource_scoped)
        {
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
mod tests {
    use super::*;
    use crate::delegation_vault::test_support::{InMemoryProviders, delegation, extensions, pattern, reader, tenant};

    async fn tenant_scope(
        providers: &InMemoryProviders,
        tenant_id: &str,
    ) -> anyhow::Result<VaultReadScope> {
        VaultReadScope::of(
            Some(providers),
            &reader(Some(tenant(tenant_id)), Some(pattern(tenant_id)), Some(delegation(true))),
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
        let scope = VaultReadScope::of(
            None,
            &reader(Some(tenant("tenant-a")), Some(pattern("tenant-a")), Some(delegation(true))),
        )
        .await
        .unwrap();
        assert_eq!(scope, VaultReadScope::Tenant(HashSet::new()));
        assert!(!scope.reads(Some("cp-a")));
    }

    #[tokio::test]
    async fn an_appliance_wide_caller_reads_every_record_without_reading_the_provider_store() {
        let unreadable = InMemoryProviders::unreadable();
        for delegation in [None, Some(delegation(false))] {
            let scope = VaultReadScope::of(Some(&unreadable), &reader(None, None, delegation))
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
        let scope =
            VaultReadScope::of(Some(&InMemoryProviders::unreadable()), &reader(None, None, Some(delegation(true))))
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
            let scope = VaultReadScope::of(Some(&unreadable), &reader(None, Some(pattern("tenant-a")), delegation))
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

    /// The extensions the session and access-token middleware set for each
    /// kind of caller decide its scope through the extractor.
    #[tokio::test]
    async fn the_vault_reader_takes_the_whole_caller_from_the_request() {
        let providers = InMemoryProviders::of_two_tenants();
        let callers = [
            ("a session", extensions(None, None, None), VaultReadScope::Appliance),
            ("an appliance-wide token", extensions(None, None, Some(delegation(false))), VaultReadScope::Appliance),
            (
                "a tenant token",
                extensions(Some(tenant("tenant-a")), Some(pattern("tenant-a")), Some(delegation(true))),
                VaultReadScope::Tenant(HashSet::from(["cp-a".to_string()])),
            ),
            (
                "a token scoped by required headers alone",
                extensions(None, None, Some(delegation(true))),
                VaultReadScope::Nothing,
            ),
        ];
        for (caller, extensions, expected) in callers {
            let mut request = axum::http::Request::new(());
            *request.extensions_mut() = extensions;
            let (mut parts, ()) = request.into_parts();
            let reader = VaultReader::from_request_parts(&mut parts, &())
                .await
                .unwrap();
            let scope = VaultReadScope::of(Some(&providers), &reader)
                .await
                .unwrap();
            assert_eq!(scope, expected, "{caller}");
        }
    }
}
