//! A grant by binding lives only as long as its binding.
//!
//! A surface change that removes a `consent_mode: external` binding (a surface
//! deleted, a Transit Point removed, its binding removed, its `subject` or
//! provider changed, the surface moved to another tenant) revokes and deletes
//! that binding's grants before the change is saved. A change that adds a
//! binding deletes any grant already stored under it, left from an earlier
//! binding of the same surface, Transit Point id and provider, so re-adding a
//! binding never re-arms an old grant: it needs a new consent. When the grants
//! cannot be removed, the change is refused, so no grant outlives its binding.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tracing::warn;

use super::surfaces::SurfaceApiError;
use crate::config::agent_surface::{AgentSurface, GrantSubject};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::delegation_vault::audit::AuditCallerContext;
use crate::delegation_vault::grants::{DelegatedGrant, EncryptionRequired, OWNER_PRINCIPAL};
use crate::delegation_vault::storage::DelegationVaultStorage;
use crate::secrets::SecretsStore;

/// What removing a binding's grants needs, and who asked for the change.
pub(crate) struct GrantRemoval<'a> {
    pub vault: Option<&'a Arc<dyn DelegationVaultStorage>>,
    pub providers: Option<&'a Arc<dyn CredentialProviderStorage>>,
    pub secrets: Option<&'a Arc<dyn SecretsStore>>,
    /// The test allow-list of revocation fixtures; `None` in production.
    pub exact_allowlist: Option<&'a str>,
    pub actor: Option<&'a AuditCallerContext>,
}

impl<'a> GrantRemoval<'a> {
    pub(crate) fn of(
        state: &'a crate::identity::IdentityApiState,
        exact_allowlist: Option<&'a str>,
        actor: Option<&'a AuditCallerContext>,
    ) -> Self {
        Self {
            vault: state
                .delegation_vault_store
                .as_ref(),
            providers: state
                .credential_provider_store
                .as_ref(),
            secrets: state.secrets_store.as_ref(),
            exact_allowlist,
            actor,
        }
    }
}

/// One `consent_mode: external` binding, as its grants are keyed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ExternalBinding {
    tenant_id: Option<String>,
    surface_id: String,
    hop: String,
    credential_provider_id: String,
    /// `None` for a stored binding without a subject, which holds every grant
    /// of its Transit Point and provider.
    subject: Option<bool>,
}

impl ExternalBinding {
    fn holds(
        &self,
        grant: &DelegatedGrant,
    ) -> bool {
        grant.tenant_id == self.tenant_id
            && grant.surface_id == self.surface_id
            && grant.hop == self.hop
            && grant.credential_provider_id == self.credential_provider_id
            && self
                .subject
                .is_none_or(|owner| (grant.principal == OWNER_PRINCIPAL) == owner)
    }
}

/// The external consent bindings of `surface`, its base and every variant.
fn external_bindings(surface: &AgentSurface) -> HashSet<ExternalBinding> {
    super::surface_tenancy::transit_point_lists(surface)
        .into_iter()
        .flat_map(|(_, points)| points.iter())
        .filter_map(|point| {
            let binding = point
                .transit_credentials
                .as_ref()
                .filter(|binding| binding.is_external())?;
            Some(ExternalBinding {
                tenant_id: surface.tenant_id.clone(),
                surface_id: surface.surface_id.clone(),
                hop: point.id.clone(),
                credential_provider_id: binding
                    .credential_provider_id
                    .clone(),
                subject: binding
                    .subject
                    .map(|subject| subject == GrantSubject::Owner),
            })
        })
        .collect()
}

fn unavailable() -> SurfaceApiError {
    SurfaceApiError::Unavailable(
        "The delegation vault is unavailable, so the grants of the bindings this change removes cannot be revoked \
         and deleted"
            .to_string(),
    )
}

/// Revoke and delete the grants of every external consent binding that only
/// one of `before` and `after` has, before the change from one to the other is
/// saved: `before` is `None` for a surface being created, `after` for one being
/// deleted. Fails, so the change is refused, when the grants cannot be read or
/// deleted.
pub(crate) async fn remove_changed_binding_grants(
    removal: &GrantRemoval<'_>,
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) -> Result<(), SurfaceApiError> {
    let before = before
        .map(external_bindings)
        .unwrap_or_default();
    let after = after
        .map(external_bindings)
        .unwrap_or_default();
    let changed: Vec<&ExternalBinding> = before
        .symmetric_difference(&after)
        .collect();
    if changed.is_empty() {
        return Ok(());
    }
    let vault = removal
        .vault
        .ok_or_else(unavailable)?;
    let grants = match vault.all_grants().await {
        Ok(grants) => grants,
        Err(error) if error.is::<EncryptionRequired>() => {
            return match vault
                .has_stored_grants()
                .await
            {
                Ok(false) => Ok(()),
                Ok(true) => Err(SurfaceApiError::Unavailable(
                    "Delegated grants are stored but cannot be read while at-rest encryption is off, so the grants \
                     of the bindings this change removes cannot be revoked or deleted; enable [encryption] with the \
                     key they were written under"
                        .to_string(),
                )),
                Err(_) => Err(unavailable()),
            };
        }
        Err(error) => {
            warn!(target: "credential_delegation", error = %error, "Failed to list grants for a surface change");
            return Err(unavailable());
        }
    };
    let affected: Vec<DelegatedGrant> = grants
        .into_iter()
        .filter(|grant| {
            changed
                .iter()
                .any(|binding| binding.holds(grant))
        })
        .collect();
    if affected.is_empty() {
        return Ok(());
    }
    let (Some(store), Some(secrets)) = (removal.providers, removal.secrets) else {
        return Err(unavailable());
    };
    let mut providers = HashMap::new();
    for id in affected
        .iter()
        .map(|grant| {
            grant
                .credential_provider_id
                .as_str()
        })
        .collect::<HashSet<_>>()
    {
        if let Some(provider) = store
            .get(id)
            .await
            .map_err(|_| unavailable())?
        {
            providers.insert(id.to_string(), provider);
        }
    }
    crate::delegation_vault::revocation::remove_grants(
        vault,
        affected,
        &providers,
        secrets,
        removal.exact_allowlist,
        removal.actor,
    )
    .await
    .map_err(|error| {
        warn!(target: "credential_delegation", error = %error, "Failed to delete a grant for a surface change");
        unavailable()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::grants::GrantKey;
    use crate::delegation_vault::revocation::tests::RecordingServer;
    use serde_json::json;

    const CALLER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    struct Fixture {
        _directory: tempfile::TempDir,
        server: RecordingServer,
        vault: Arc<dyn DelegationVaultStorage>,
        providers: Arc<dyn CredentialProviderStorage>,
        secrets: Arc<dyn SecretsStore>,
    }

    impl Fixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            unsafe {
                std::env::set_var("SURFACE_GRANTS_TEST_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
            }
            crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
                enabled: true,
                key_env_var: "SURFACE_GRANTS_TEST_MASTER_KEY".to_string(),
                ..Default::default()
            })
            .unwrap();
            crate::identity::credential_identity::configure_pepper_for_tests(true);
            let server = RecordingServer::start(200).await;
            let providers = crate::credential_providers::storage::FileSystemCredentialProviderStore::new(
                directory
                    .path()
                    .join("providers"),
            )
            .await
            .unwrap();
            for id in ["vendor", "vendor-2"] {
                let mut provider =
                    crate::delegation_vault::revocation::tests::provider(Some(&server.url), "none", None);
                provider.id = id.to_string();
                provider.provider_id = id.to_string();
                providers
                    .create(provider)
                    .await
                    .unwrap();
            }
            let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
                crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                    .await
                    .unwrap(),
            );
            let secrets: Arc<dyn SecretsStore> = Arc::new(
                crate::secrets::FilesystemSecretsStore::new(
                    directory
                        .path()
                        .join("secrets")
                        .to_str()
                        .unwrap(),
                )
                .unwrap(),
            );
            Self {
                _directory: directory,
                server,
                vault,
                providers: Arc::new(providers),
                secrets,
            }
        }

        fn removal(&self) -> GrantRemoval<'_> {
            GrantRemoval {
                vault: Some(&self.vault),
                providers: Some(&self.providers),
                secrets: Some(&self.secrets),
                exact_allowlist: None,
                actor: None,
            }
        }

        async fn change(
            &self,
            before: Option<&AgentSurface>,
            after: Option<&AgentSurface>,
        ) -> Result<(), SurfaceApiError> {
            let origin = self.server.origin();
            let removal = GrantRemoval {
                exact_allowlist: Some(&origin),
                ..self.removal()
            };
            remove_changed_binding_grants(&removal, before, after).await
        }

        async fn store(
            &self,
            key: &GrantKey,
            token: &str,
        ) {
            self.vault
                .store_grant(crate::delegation_vault::grants::tests::grant(key, token))
                .await
                .unwrap();
        }

        async fn kept(
            &self,
            key: &GrantKey,
        ) -> bool {
            self.vault
                .grant(key)
                .await
                .unwrap()
                .is_some()
        }
    }

    fn owner_key(hop: &str) -> GrantKey {
        GrantKey::owner(Some("tenant-a"), "surface", hop, "vendor")
    }

    fn caller_key(hop: &str) -> GrantKey {
        GrantKey::caller(Some("tenant-a"), "surface", hop, "vendor", CALLER).unwrap()
    }

    fn point(
        id: &str,
        binding: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut point = json!({"id": id, "alias": format!("alias-{id}"), "target_endpoint": "https://203.0.113.30/mcp",
            "require_transit_token": true});
        if let Some(binding) = binding {
            point["transit_credentials"] = binding;
        }
        point
    }

    fn external(
        provider: &str,
        subject: &str,
    ) -> Option<serde_json::Value> {
        Some(json!({"credential_provider_id": provider, "consent_mode": "external", "subject": subject}))
    }

    fn surface(points: serde_json::Value) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "surface", "name": "surface", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://managed.example/agent"},
            "transit": {"points": points}
        }))
        .unwrap()
    }

    /// Transit Point `owner-hop` binds `vendor` for its owner and
    /// `caller-hop` binds it per caller.
    fn bound() -> AgentSurface {
        surface(json!([
            point("owner-hop", external("vendor", "owner")),
            point("caller-hop", external("vendor", "caller"))
        ]))
    }

    async fn with_grants() -> Fixture {
        let fixture = Fixture::new().await;
        fixture
            .store(&owner_key("owner-hop"), "owner-access")
            .await;
        fixture
            .store(&caller_key("caller-hop"), "caller-access")
            .await;
        fixture
            .store(&GrantKey::owner(Some("tenant-a"), "other-surface", "owner-hop", "vendor"), "other-access")
            .await;
        fixture
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deleting_a_surface_revokes_and_deletes_its_grants_only() {
        let fixture = with_grants().await;
        fixture
            .change(Some(&bound()), None)
            .await
            .unwrap();
        assert!(
            !fixture
                .kept(&owner_key("owner-hop"))
                .await
        );
        assert!(
            !fixture
                .kept(&caller_key("caller-hop"))
                .await
        );
        assert!(
            fixture
                .kept(&GrantKey::owner(Some("tenant-a"), "other-surface", "owner-hop", "vendor"))
                .await,
            "another surface's grant is kept"
        );
        assert_eq!(
            fixture
                .server
                .revoked_tokens(),
            ["caller-access", "caller-access-refresh", "owner-access", "owner-access-refresh"]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removing_or_changing_a_binding_revokes_and_deletes_its_grants() {
        let caller_only = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        let mut moved = bound();
        moved.tenant_id = Some("tenant-b".into());
        for (case, after, owner_kept, caller_kept) in [
            ("the Transit Point removed", caller_only, false, true),
            (
                "its binding removed",
                surface(json!([point("owner-hop", None), point("caller-hop", external("vendor", "caller"))])),
                false,
                true,
            ),
            (
                "its subject changed",
                surface(json!([
                    point("owner-hop", external("vendor", "caller")),
                    point("caller-hop", external("vendor", "caller"))
                ])),
                false,
                true,
            ),
            (
                "its provider changed",
                surface(json!([
                    point("owner-hop", external("vendor-2", "owner")),
                    point("caller-hop", external("vendor", "caller"))
                ])),
                false,
                true,
            ),
            (
                "another consent mode",
                surface(json!([
                    point("owner-hop", Some(json!({"credential_provider_id": "vendor"}))),
                    point("caller-hop", external("vendor", "caller"))
                ])),
                false,
                true,
            ),
            ("the surface moved to another tenant", moved, false, false),
            ("nothing changed", bound(), true, true),
        ] {
            let fixture = with_grants().await;
            fixture
                .change(Some(&bound()), Some(&after))
                .await
                .unwrap_or_else(|error| panic!("{case}: {error:?}"));
            assert_eq!(
                fixture
                    .kept(&owner_key("owner-hop"))
                    .await,
                owner_kept,
                "{case}: the owner grant"
            );
            assert_eq!(
                fixture
                    .kept(&caller_key("caller-hop"))
                    .await,
                caller_kept,
                "{case}: the caller grant"
            );
            let revoked = fixture
                .server
                .revoked_tokens();
            assert_eq!(revoked.contains(&"owner-access-refresh".to_string()), !owner_kept, "{case}: {revoked:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn re_adding_a_binding_never_re_arms_an_old_grant() {
        let fixture = with_grants().await;
        let unbound = surface(json!([point("owner-hop", None), point("caller-hop", external("vendor", "caller"))]));
        fixture
            .change(Some(&bound()), Some(&unbound))
            .await
            .unwrap();
        fixture
            .change(Some(&unbound), Some(&bound()))
            .await
            .unwrap();
        assert!(
            !fixture
                .kept(&owner_key("owner-hop"))
                .await,
            "the re-added binding needs a new consent"
        );

        let fixture = with_grants().await;
        fixture
            .change(None, Some(&bound()))
            .await
            .unwrap();
        assert!(
            !fixture
                .kept(&owner_key("owner-hop"))
                .await,
            "a surface created again under the same id never finds a grant left by an earlier one"
        );
        assert!(
            !fixture
                .kept(&caller_key("caller-hop"))
                .await
        );

        let fixture = with_grants().await;
        let without_owner_hop = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        fixture
            .change(Some(&without_owner_hop), Some(&bound()))
            .await
            .unwrap();
        assert!(
            !fixture
                .kept(&owner_key("owner-hop"))
                .await,
            "a Transit Point added again under its old id"
        );
        assert!(
            fixture
                .kept(&caller_key("caller-hop"))
                .await,
            "an unchanged binding keeps its grants"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_kept_by_a_variant_keeps_its_grants() {
        let fixture = with_grants().await;
        let mut variant_only = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        variant_only.variants = vec![
            serde_json::from_value(json!({"id": "v-1", "alias": "candidate", "name": "candidate", "enabled": true,
                "overrides": {"transit": {"points": [point("owner-hop", external("vendor", "owner"))]}}}))
            .unwrap(),
        ];
        fixture
            .change(Some(&bound()), Some(&variant_only))
            .await
            .unwrap();
        assert!(
            fixture
                .kept(&owner_key("owner-hop"))
                .await
        );
        assert!(
            fixture
                .server
                .requests()
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_change_that_cannot_remove_its_grants_is_refused() {
        let fixture = with_grants().await;
        let no_vault = GrantRemoval {
            vault: None,
            ..fixture.removal()
        };
        assert!(matches!(
            remove_changed_binding_grants(&no_vault, Some(&bound()), None).await,
            Err(SurfaceApiError::Unavailable(_))
        ));
        assert!(
            remove_changed_binding_grants(&no_vault, Some(&bound()), Some(&bound()))
                .await
                .is_ok(),
            "a change that removes no binding needs no vault"
        );

        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig::default()).unwrap();
        let unencrypted: Arc<dyn DelegationVaultStorage> = Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(
                fixture
                    ._directory
                    .path()
                    .join("vault"),
            )
            .await
            .unwrap(),
        );
        let unreadable = GrantRemoval {
            vault: Some(&unencrypted),
            ..fixture.removal()
        };
        assert!(matches!(
            remove_changed_binding_grants(&unreadable, Some(&bound()), None).await,
            Err(SurfaceApiError::Unavailable(message)) if message.contains("at-rest encryption is off")
        ));
        assert!(
            fixture
                ._directory
                .path()
                .join("vault/delegated_grants")
                .join(format!("{}.json.enc", owner_key("owner-hop").record_id()))
                .exists()
        );
    }
}
