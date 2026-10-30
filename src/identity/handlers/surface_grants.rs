//! A grant by binding lives only as long as its binding.
//!
//! A surface change that removes a `consent_mode: external` binding (a surface
//! deleted, a Transit Point removed, its binding removed, its `subject` or
//! provider changed, the surface moved to another tenant, or the only variant
//! that holds it disabled) deletes that binding's grants before the change is
//! saved, then revokes at the vendor what it deleted. Both run on one task of
//! their own, so a write dropped part way, as when its client disconnects,
//! still deletes, revokes and audits every one of them. A change that
//! adds a binding deletes any grant already stored under it, left from an
//! earlier binding of the same surface, Transit Point id and provider, so
//! re-adding a binding never re-arms an old grant: it needs a new consent.
//! When the grants cannot be removed, the change is refused, so no grant
//! outlives its binding.
//!
//! The grants of a binding are found by their record ids, so a change reads
//! and decrypts only the grants of the bindings it changes: a grant that cannot
//! be read refuses only the changes that remove its own binding, and names
//! itself, so an operator can purge it.
//!
//! Every surface write takes the surface's lock, reads the stored surface
//! under it, and removes the grants of what the write changes from that
//! stored surface, so a write built from a stale read still removes the
//! grants of a binding it drops. A grant is stored only under the same lock,
//! after checking that its binding is saved, so no grant is stored for a
//! binding a concurrent write is removing.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Weak};

use tracing::warn;

use super::surfaces::SurfaceApiError;
use crate::config::agent_surface::{AgentSurface, GrantSubject, TransitPoint};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::delegation_vault::audit::AuditCallerContext;
use crate::delegation_vault::grants::{
    DelegatedGrant, GrantBinding, OWNER_PRINCIPAL, PepperMismatch, Principals, StoredGrant, UnreadableGrant,
};
use crate::delegation_vault::storage::DelegationVaultStorage;
use crate::secrets::SecretsStore;
use crate::surfaces::AgentSurfaceStore;

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

    fn grant_binding(&self) -> GrantBinding {
        GrantBinding::new(self.tenant_id.as_deref(), &self.surface_id, &self.hop, &self.credential_provider_id)
    }

    fn principals(&self) -> Principals {
        match self.subject {
            Some(true) => Principals::Owner,
            Some(false) => Principals::Callers,
            None => Principals::All,
        }
    }
}

/// The lists of Transit Points a surface serves: its own, and each enabled
/// variant's replacement list, unless the variant turns transit off. A
/// disabled variant's points are not served, so they keep no grants.
fn live_transit_point_lists(surface: &AgentSurface) -> Vec<&[TransitPoint]> {
    let mut lists = vec![surface.transit_points()];
    for variant in surface
        .variants
        .iter()
        .filter(|variant| variant.enabled)
    {
        let Some(transit) = variant
            .overrides
            .transit
            .as_ref()
        else {
            continue;
        };
        if transit.disabled == Some(true) {
            continue;
        }
        if let Some(points) = transit.points.as_deref() {
            lists.push(points);
        }
    }
    lists
}

/// The external consent bindings `surface` serves, in its base and every
/// enabled variant.
fn external_bindings(surface: &AgentSurface) -> HashSet<ExternalBinding> {
    live_transit_point_lists(surface)
        .into_iter()
        .flatten()
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
        "The delegation vault is unavailable, so the grants of the bindings this change removes cannot be removed"
            .to_string(),
    )
}

/// Why the grants of `binding` cannot be removed, for the refusal of the
/// change that removes it.
fn refusal(
    binding: &ExternalBinding,
    error: &anyhow::Error,
) -> SurfaceApiError {
    if let Some(unreadable) = error.downcast_ref::<UnreadableGrant>() {
        return SurfaceApiError::Unavailable(format!(
            "The delegated grant {} of Transit Point '{}' cannot be read ({}), so this change, which removes or adds \
             its binding, is refused: the grant could be neither revoked nor deleted. Make it readable again (for \
             at-rest encryption, enable [encryption] with the key it was written under), or have an operator purge \
             it with DELETE /api/v1/delegation-vault/grants/{}, which leaves it unrevoked at the vendor",
            unreadable.grant_id, binding.hop, unreadable.reason, unreadable.grant_id
        ));
    }
    if error.is::<PepperMismatch>() {
        return SurfaceApiError::Unavailable(
            "The delegated grants stored were written under another identity hash pepper, so the grants of the \
             bindings this change removes cannot be found; restore the AG_IDENTITY_HASH_PEPPER they were written \
             under, or have an operator purge them"
                .to_string(),
        );
    }
    warn!(target: "credential_delegation", error = %error, "Failed to read a binding's grants for a surface change");
    unavailable()
}

/// A surface's lock, shared by a write and the task that deletes the grants
/// the write removes, and released when both have let go of it.
pub(crate) type SharedSurfaceLock = Arc<tokio::sync::OwnedMutexGuard<()>>;

/// Remove the grants of every external consent binding that only one of
/// `before` and `after` has, before the change from one to the other is saved:
/// `before` is `None` for a surface being created, `after` for one being
/// deleted. Only those bindings' grants are read. The grants are deleted, and
/// then revoked at their authorization servers, on one task of their own: this
/// returns once every deletion has ended, and the task returned, which the
/// caller need not wait for, ends with the revocations. Dropping the caller
/// part way stops neither. `surface_lock` is held until every deletion has
/// ended, even when the caller is dropped first. Fails, so the change is
/// refused, when a grant of those bindings cannot be read or deleted.
pub(crate) async fn remove_changed_binding_grants(
    removal: &GrantRemoval<'_>,
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
    surface_lock: Option<SharedSurfaceLock>,
) -> Result<Option<tokio::task::JoinHandle<()>>, SurfaceApiError> {
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
        return Ok(None);
    }
    let vault = removal
        .vault
        .ok_or_else(unavailable)?;
    let mut affected: HashMap<String, DelegatedGrant> = HashMap::new();
    for binding in changed {
        let grants = vault
            .binding_grants(&binding.grant_binding(), binding.principals())
            .await
            .map_err(|error| refusal(binding, &error))?;
        for grant in grants {
            affected.insert(grant.id.clone(), grant);
        }
    }
    if affected.is_empty() {
        return Ok(None);
    }
    let mut providers = HashMap::new();
    if let Some(store) = removal.providers {
        for id in affected
            .values()
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
    }
    let revoker = crate::delegation_vault::revocation::Revoker {
        providers,
        secrets: removal.secrets.cloned(),
        exact_allowlist: removal
            .exact_allowlist
            .map(str::to_string),
        actor: removal.actor.cloned(),
    };
    crate::delegation_vault::revocation::delete_then_revoke(
        vault,
        affected.into_keys().collect(),
        revoker,
        surface_lock,
    )
    .await
    .map(Some)
    .map_err(|error| {
        warn!(target: "credential_delegation", error = %error, "Failed to delete a grant for a surface change");
        unavailable()
    })
}

/// One async mutex per surface id, held only while some task holds or awaits
/// it.
static SURFACE_LOCKS: LazyLock<std::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Default::default);

/// Hold the lock of surface `surface_id`, which serialises the surface's
/// writes and the storing of its grants.
pub(crate) async fn lock_surface(surface_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let mut locks = SURFACE_LOCKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        match locks
            .get(surface_id)
            .and_then(Weak::upgrade)
        {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(surface_id.to_string(), Arc::downgrade(&lock));
                lock
            }
        }
    };
    lock.lock_owned().await
}

/// What a surface write expects of the surface stored under its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    /// A create: no surface may be stored under the id.
    Absent,
    /// An update, a delete or a reassignment.
    Any,
}

/// Run `write`, which saves `after` under `surface_id`, or deletes the surface
/// when `after` is `None`, under the surface's lock, after removing the grants
/// of every external consent binding that differs between the surface stored
/// now, read under the lock, and `after`. A write built from an earlier read
/// therefore still removes the grants of a binding that a concurrent write
/// added and this one drops. A write dropped while it deletes grants releases
/// the lock only once they are all deleted.
pub(crate) async fn write_surface<T, Write, Pending>(
    removal: &GrantRemoval<'_>,
    surfaces: &dyn AgentSurfaceStore,
    surface_id: &str,
    stored: Stored,
    after: Option<&AgentSurface>,
    write: Write,
) -> Result<T, SurfaceApiError>
where
    Write: FnOnce() -> Pending,
    Pending: std::future::Future<Output = Result<T, SurfaceApiError>>,
{
    let lock = Arc::new(lock_surface(surface_id).await);
    let current = surfaces
        .get(surface_id)
        .await
        .map_err(|error| SurfaceApiError::InternalError(format!("Failed to get surface: {error}")))?;
    if stored == Stored::Absent && current.is_some() {
        return Err(SurfaceApiError::BadRequest(format!("Surface with ID '{surface_id}' already exists")));
    }
    remove_changed_binding_grants(removal, current.as_ref(), after, Some(Arc::clone(&lock))).await?;
    let written = write().await;
    drop(lock);
    written
}

/// Store `grant` only while its binding is saved: under the surface's lock,
/// the stored surface must serve the binding, with the grant's tenant,
/// Transit Point, provider and subject. Otherwise it is refused with
/// [`SurfaceApiError::NotFound`] and nothing is stored, so no grant outlives a
/// binding a concurrent write removed.
#[allow(dead_code)] // the consent completion of external consent stores grants through it
pub(crate) async fn store_grant_while_bound(
    vault: &Arc<dyn DelegationVaultStorage>,
    surfaces: &dyn AgentSurfaceStore,
    grant: DelegatedGrant,
) -> Result<StoredGrant, SurfaceApiError> {
    let _lock = lock_surface(&grant.surface_id).await;
    let surface = surfaces
        .get(&grant.surface_id)
        .await
        .map_err(|error| SurfaceApiError::InternalError(format!("Failed to get surface: {error}")))?;
    let bound = surface.is_some_and(|surface| {
        external_bindings(&surface)
            .iter()
            .any(|binding| binding.holds(&grant))
    });
    if !bound {
        return Err(SurfaceApiError::NotFound(
            "The binding this grant was given for is no longer saved, so the grant is not stored".to_string(),
        ));
    }
    vault
        .store_grant(grant)
        .await
        .map_err(|error| {
            warn!(target: "credential_delegation", error = %error, "Failed to store a delegated grant");
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
            Self::with_server(RecordingServer::start(200).await).await
        }

        async fn with_server(server: RecordingServer) -> Self {
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
            if let Some(revocations) = remove_changed_binding_grants(&removal, before, after, None).await? {
                revocations.await.unwrap();
            }
            Ok(())
        }

        fn grant_file(
            &self,
            key: &GrantKey,
        ) -> std::path::PathBuf {
            self._directory
                .path()
                .join("vault/delegated_grants")
                .join(format!("{}.json.enc", key.record_id()))
        }

        async fn surfaces(&self) -> crate::surfaces::FileSystemAgentSurfaceStore {
            crate::surfaces::FileSystemAgentSurfaceStore::new(
                self._directory
                    .path()
                    .join("surfaces"),
            )
            .await
            .unwrap()
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
            remove_changed_binding_grants(&no_vault, Some(&bound()), None, None).await,
            Err(SurfaceApiError::Unavailable(_))
        ));
        assert!(
            remove_changed_binding_grants(&no_vault, Some(&bound()), Some(&bound()), None)
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
            remove_changed_binding_grants(&unreadable, Some(&bound()), None, None).await,
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

    /// A grant that cannot be read refuses only the changes that remove its
    /// own binding, and the refusal names it so an operator can purge it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreadable_grant_refuses_only_the_changes_that_remove_its_own_binding() {
        let fixture = with_grants().await;
        std::fs::write(fixture.grant_file(&owner_key("owner-hop")), "not a grant").unwrap();
        let owner_only = surface(json!([point("owner-hop", external("vendor", "owner"))]));
        fixture
            .change(Some(&bound()), Some(&owner_only))
            .await
            .expect("a change that leaves the unreadable grant's binding alone goes ahead");
        assert!(
            !fixture
                .kept(&caller_key("caller-hop"))
                .await
        );
        let refused = fixture
            .change(Some(&owner_only), Some(&surface(json!([]))))
            .await
            .unwrap_err();
        let SurfaceApiError::Unavailable(message) = refused else {
            panic!("expected a 503, got {refused:?}");
        };
        let id = owner_key("owner-hop").record_id();
        assert!(message.contains(&id), "{message}");
        assert!(message.contains("owner-hop"), "{message}");
        assert!(message.contains(&format!("DELETE /api/v1/delegation-vault/grants/{id}")), "{message}");
        assert!(
            fixture
                .grant_file(&owner_key("owner-hop"))
                .exists()
        );
    }

    /// While at-rest encryption is off, only a change that removes a binding
    /// with grants stored is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn with_encryption_off_a_binding_without_stored_grants_is_still_removed() {
        let fixture = with_grants().await;
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
        let removal = GrantRemoval {
            vault: Some(&unencrypted),
            ..fixture.removal()
        };
        let with_unused = surface(json!([
            point("owner-hop", external("vendor", "owner")),
            point("caller-hop", external("vendor", "caller")),
            point("unused-hop", external("vendor", "owner"))
        ]));
        assert!(
            remove_changed_binding_grants(&removal, Some(&with_unused), Some(&bound()), None)
                .await
                .is_ok(),
            "no grant of the removed binding is stored"
        );
        let caller_only = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        assert!(matches!(
            remove_changed_binding_grants(&removal, Some(&bound()), Some(&caller_only), None).await,
            Err(SurfaceApiError::Unavailable(message)) if message.contains("at-rest encryption is off")
        ));
    }

    /// A binding that only a disabled variant holds is not served, so it keeps
    /// no grant: disabling the variant, or its transit, removes them, and
    /// enabling it again needs a new consent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_that_only_a_disabled_variant_holds_loses_its_grants() {
        let mut in_variant = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        in_variant.variants = vec![
            serde_json::from_value(json!({"id": "v-1", "alias": "candidate", "name": "candidate", "enabled": true,
                "overrides": {"transit": {"points": [point("owner-hop", external("vendor", "owner"))]}}}))
            .unwrap(),
        ];
        let mut disabled = in_variant.clone();
        disabled.variants[0].enabled = false;
        let mut transit_off = in_variant.clone();
        transit_off.variants[0]
            .overrides
            .transit
            .as_mut()
            .unwrap()
            .disabled = Some(true);
        for (case, after) in [("the variant disabled", disabled), ("the variant's transit turned off", transit_off)] {
            let fixture = with_grants().await;
            fixture
                .change(Some(&in_variant), Some(&after))
                .await
                .unwrap();
            assert!(
                !fixture
                    .kept(&owner_key("owner-hop"))
                    .await,
                "{case}"
            );
            assert!(
                fixture
                    .kept(&caller_key("caller-hop"))
                    .await,
                "{case}"
            );
            fixture
                .store(&owner_key("owner-hop"), "while-disabled")
                .await;
            fixture
                .change(Some(&after), Some(&in_variant))
                .await
                .unwrap();
            assert!(
                !fixture
                    .kept(&owner_key("owner-hop"))
                    .await,
                "{case}: enabling it again needs a new consent"
            );
        }
    }

    /// A change deletes the grants it removes before it returns, and revokes
    /// them on a task of their own, so it never waits on a vendor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_change_deletes_grants_at_once_and_revokes_them_in_the_background() {
        let delay = std::time::Duration::from_secs(2);
        let fixture = Fixture::with_server(RecordingServer::start_with_delay(200, delay).await).await;
        fixture
            .store(&owner_key("owner-hop"), "owner-access")
            .await;
        fixture
            .store(&caller_key("caller-hop"), "caller-access")
            .await;
        let origin = fixture.server.origin();
        let removal = GrantRemoval {
            exact_allowlist: Some(&origin),
            ..fixture.removal()
        };
        let started = std::time::Instant::now();
        let revocations = remove_changed_binding_grants(&removal, Some(&bound()), None, None)
            .await
            .unwrap()
            .expect("grants were removed");
        assert!(started.elapsed() < delay / 2, "the change waited on the vendor: {:?}", started.elapsed());
        for key in [owner_key("owner-hop"), caller_key("caller-hop")] {
            assert!(!fixture.kept(&key).await, "{key:?} is released no more");
        }
        tokio::time::timeout(delay * 4, revocations)
            .await
            .expect("the revocations end")
            .unwrap();
        assert_eq!(
            fixture
                .server
                .revoked_tokens(),
            ["caller-access", "caller-access-refresh", "owner-access", "owner-access-refresh"]
        );
    }

    /// Without a secrets store a change still removes its grants; a client
    /// that needs a secret is then not revoked, which its audit says.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_a_secrets_store_a_change_still_removes_its_grants() {
        let fixture = with_grants().await;
        let removal = GrantRemoval {
            secrets: None,
            ..fixture.removal()
        };
        assert!(
            remove_changed_binding_grants(&removal, Some(&bound()), None, None)
                .await
                .is_ok()
        );
        for key in [owner_key("owner-hop"), caller_key("caller-hop")] {
            assert!(!fixture.kept(&key).await, "{key:?}");
        }
    }

    /// A write takes the surface's lock and removes the grants of what it
    /// changes from the surface stored now, so a write built from an earlier
    /// read still removes the grants of a binding it drops.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_built_from_a_stale_read_still_removes_the_grants_of_a_binding_it_drops() {
        let fixture = with_grants().await;
        let surfaces = fixture.surfaces().await;
        surfaces
            .save(&bound())
            .await
            .unwrap();
        let origin = fixture.server.origin();
        let removal = GrantRemoval {
            exact_allowlist: Some(&origin),
            ..fixture.removal()
        };
        // Built from a read taken before `owner-hop` was added.
        let stale = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        write_surface(&removal, &surfaces, "surface", Stored::Any, Some(&stale), || async {
            surfaces
                .save(&stale)
                .await
                .map_err(|error| SurfaceApiError::InternalError(error.to_string()))
        })
        .await
        .unwrap();
        assert!(
            !fixture
                .kept(&owner_key("owner-hop"))
                .await,
            "the grant of the binding the write dropped is removed"
        );
        assert!(
            fixture
                .kept(&caller_key("caller-hop"))
                .await,
            "the binding the write kept keeps its grant"
        );

        let refused = write_surface(&removal, &surfaces, "surface", Stored::Absent, Some(&bound()), || async {
            Ok::<(), SurfaceApiError>(())
        })
        .await;
        assert!(matches!(refused, Err(SurfaceApiError::BadRequest(message)) if message.contains("already exists")));
        assert!(
            fixture
                .kept(&caller_key("caller-hop"))
                .await,
            "a refused create touches no grant"
        );
    }

    /// A grant is stored only under the surface's lock and only while its
    /// binding is saved, so a write that is removing the binding cannot leave
    /// a grant behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_is_stored_only_while_its_binding_is_saved() {
        use crate::delegation_vault::grants::tests::grant;
        let fixture = Fixture::new().await;
        let surfaces = Arc::new(fixture.surfaces().await);
        surfaces
            .save(&bound())
            .await
            .unwrap();
        store_grant_while_bound(&fixture.vault, &*surfaces, grant(&owner_key("owner-hop"), "owner-access"))
            .await
            .expect("the binding is saved");
        assert!(
            fixture
                .kept(&owner_key("owner-hop"))
                .await
        );
        for (case, key) in [
            ("another Transit Point", owner_key("other-hop")),
            ("the binding's other subject", caller_key("owner-hop")),
        ] {
            let refused = store_grant_while_bound(&fixture.vault, &*surfaces, grant(&key, "access")).await;
            assert!(matches!(refused, Err(SurfaceApiError::NotFound(_))), "{case}");
            assert!(!fixture.kept(&key).await, "{case}");
        }

        let unbound = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        let held = lock_surface("surface").await;
        let late = tokio::spawn({
            let vault = fixture.vault.clone();
            let surfaces = surfaces.clone();
            async move { store_grant_while_bound(&vault, &*surfaces, grant(&owner_key("owner-hop"), "late-access")).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!late.is_finished(), "a grant waits for the write that holds the surface's lock");
        fixture
            .change(Some(&bound()), Some(&unbound))
            .await
            .unwrap();
        surfaces
            .save(&unbound)
            .await
            .unwrap();
        drop(held);
        assert!(matches!(late.await.unwrap(), Err(SurfaceApiError::NotFound(_))));
        assert!(
            !fixture
                .kept(&owner_key("owner-hop"))
                .await,
            "no grant outlives the binding the write removed"
        );
    }

    /// A vault that pauses after its first grant deletion until `resume` has a
    /// permit, so a test can drop a write part way through deleting.
    struct PausingVault {
        inner: Arc<dyn DelegationVaultStorage>,
        deletions: std::sync::atomic::AtomicUsize,
        first_deleted: tokio::sync::Notify,
        resume: tokio::sync::Semaphore,
    }

    impl PausingVault {
        async fn deleted(&self) {
            if self
                .deletions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                self.first_deleted
                    .notify_one();
                self.resume
                    .acquire()
                    .await
                    .unwrap()
                    .forget();
            }
        }
    }

    #[async_trait::async_trait]
    impl DelegationVaultStorage for PausingVault {
        async fn store(
            &self,
            _token: crate::delegation_vault::DelegationToken,
        ) -> anyhow::Result<crate::delegation_vault::DelegationToken> {
            unreachable!("no agent-keyed token is stored")
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<crate::delegation_vault::DelegationToken>> {
            unreachable!("no agent-keyed token is read")
        }

        async fn lookup(
            &self,
            _agent_did: &str,
            _user_identity_hash: &str,
            _provider_id: &str,
        ) -> anyhow::Result<crate::delegation_vault::VaultLookupResult> {
            unreachable!("no agent-keyed token is read")
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::delegation_vault::DelegationToken>> {
            unreachable!("no agent-keyed token is read")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<bool> {
            unreachable!("no agent-keyed token is deleted")
        }

        async fn delete_by_user(
            &self,
            _user_identity_hash: &str,
        ) -> anyhow::Result<usize> {
            unreachable!("no agent-keyed token is deleted")
        }

        async fn update(
            &self,
            _token: crate::delegation_vault::DelegationToken,
        ) -> anyhow::Result<crate::delegation_vault::DelegationToken> {
            unreachable!("no agent-keyed token is stored")
        }

        async fn mark_used(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unreachable!("no agent-keyed token is used")
        }

        async fn binding_grants(
            &self,
            binding: &GrantBinding,
            principals: Principals,
        ) -> anyhow::Result<Vec<DelegatedGrant>> {
            self.inner
                .binding_grants(binding, principals)
                .await
        }

        async fn delete_grant(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<DelegatedGrant>> {
            let deleted = self
                .inner
                .delete_grant(id)
                .await;
            self.deleted().await;
            deleted
        }

        async fn purge_grant(
            &self,
            id: &str,
            tenant_id: Option<&str>,
        ) -> anyhow::Result<bool> {
            let purged = self
                .inner
                .purge_grant(id, tenant_id)
                .await;
            self.deleted().await;
            purged
        }
    }

    /// A write dropped part way through deleting a binding's grants, as when
    /// its client disconnects, still deletes and revokes every one of them,
    /// and holds the surface's lock until they are deleted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_write_dropped_while_deleting_grants_still_deletes_and_revokes_them_all() {
        const SURFACE: &str = "dropped-write";
        let fixture = Fixture::new().await;
        let keys: Vec<GrantKey> = (0..4)
            .map(|index| {
                GrantKey::caller(Some("tenant-a"), SURFACE, "caller-hop", "vendor", &format!("{index:064x}")).unwrap()
            })
            .collect();
        for (index, key) in keys.iter().enumerate() {
            fixture
                .store(key, &format!("caller-{index}"))
                .await;
        }
        let mut before = bound();
        before.surface_id = SURFACE.to_string();
        let mut after = surface(json!([point("owner-hop", external("vendor", "owner"))]));
        after.surface_id = SURFACE.to_string();
        let surfaces = fixture.surfaces().await;
        surfaces
            .save(&before)
            .await
            .unwrap();
        let pausing = Arc::new(PausingVault {
            inner: fixture.vault.clone(),
            deletions: Default::default(),
            first_deleted: Default::default(),
            resume: tokio::sync::Semaphore::new(0),
        });
        let vault: Arc<dyn DelegationVaultStorage> = pausing.clone();
        let origin = fixture.server.origin();
        let removal = GrantRemoval {
            vault: Some(&vault),
            exact_allowlist: Some(&origin),
            ..fixture.removal()
        };

        let mut write = Box::pin(write_surface(&removal, &surfaces, SURFACE, Stored::Any, Some(&after), || async {
            surfaces
                .save(&after)
                .await
                .map_err(|error| SurfaceApiError::InternalError(error.to_string()))
        }));
        tokio::select! {
            _ = &mut write => panic!("the write ended while a deletion was paused"),
            () = pausing.first_deleted.notified() => {}
        }
        drop(write);
        let held_while_deleting = tokio::time::timeout(std::time::Duration::from_millis(200), lock_surface(SURFACE))
            .await
            .is_err();
        pausing.resume.add_permits(1);

        let mut expected: Vec<String> = (0..4)
            .flat_map(|index| [format!("caller-{index}"), format!("caller-{index}-refresh")])
            .collect();
        expected.sort();
        let revoked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while fixture
                .server
                .revoked_tokens()
                != expected
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            revoked.is_ok(),
            "every grant the dropped write deleted is revoked: {:?}",
            fixture
                .server
                .revoked_tokens()
        );
        for key in &keys {
            assert!(!fixture.kept(key).await, "{key:?} is deleted");
        }
        assert!(held_while_deleting, "the surface's lock is held until every grant is deleted");
        let stored = surfaces
            .get(SURFACE)
            .await
            .unwrap()
            .expect("the surface is still stored");
        assert_eq!(stored.transit_points().len(), 2, "the dropped write saved nothing");
    }
}
