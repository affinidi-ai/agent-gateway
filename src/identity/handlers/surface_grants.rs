//! A grant by binding lives only as long as its binding.
//!
//! A surface change that removes a `consent_mode: external` binding (a surface
//! deleted, a Transit Point removed, its binding removed, its `subject` or
//! provider changed, the surface moved to another tenant, or the only variant
//! that holds it disabled) deletes that binding's grants while the change is
//! saved, then, once it is saved, revokes at the vendor what it deleted; a
//! change that is not saved puts them back. Both run on one task of their
//! own, so a write dropped part way, as when its client disconnects, still
//! settles, and audits, every one of them. A change that
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
//! grants of a binding it drops. The grants are revoked only once the write
//! is saved: a write that fails puts them back, and one dropped before it
//! reported is decided by the surface stored, read again under the lock.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Weak};

use tracing::warn;

use super::surfaces::SurfaceApiError;
use crate::config::agent_surface::{AgentSurface, GrantSubject, TransitPoint};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::delegation_vault::audit::AuditCallerContext;
use crate::delegation_vault::grants::{DelegatedGrant, GrantBinding, PepperMismatch, Principals, UnreadableGrant};
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
/// deleted. Only those bindings' grants are read. The grants are deleted on
/// one task of their own, which this returns once every deletion has ended;
/// the task then waits for `outcome`, that of the save, and revokes them at
/// their authorization servers once the save succeeded, or puts them back,
/// unrevoked, when it failed. When the caller was dropped first, the task
/// decides by whether the change is stored. With no `outcome` they are
/// revoked at once. The task returned, which the caller need not wait for,
/// ends with the revocations. Dropping the caller part way stops none of
/// this. `surface_lock` is held until the grants are deleted and, with
/// `outcome`, until it is known and they are put back, even when the caller
/// is dropped first. Fails, so the change is refused, when a grant of those
/// bindings cannot be read or deleted.
pub(crate) async fn remove_changed_binding_grants(
    removal: &GrantRemoval<'_>,
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
    surface_lock: Option<SharedSurfaceLock>,
    outcome: Option<crate::delegation_vault::revocation::ChangeOutcome>,
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
        outcome,
    )
    .await
    .map(Some)
    .map_err(|error| {
        warn!(target: "credential_delegation", error = %error, "Failed to delete a grant for a surface change");
        unavailable()
    })
}

/// Serialises the writes that bind credential providers with the deletes and
/// tenant moves of providers: a surface write holds it shared, a provider
/// delete or move exclusively, for the whole of its check and change, so no
/// write binds a provider that a delete has checked is unbound.
static PROVIDER_BINDINGS: LazyLock<tokio::sync::RwLock<()>> = LazyLock::new(Default::default);

/// Hold [`PROVIDER_BINDINGS`] shared, as a surface write does.
pub(crate) async fn hold_provider_bindings() -> tokio::sync::RwLockReadGuard<'static, ()> {
    PROVIDER_BINDINGS.read().await
}

/// Hold [`PROVIDER_BINDINGS`] exclusively, as a provider delete or tenant
/// move does.
pub(crate) async fn hold_provider_bindings_exclusively() -> tokio::sync::RwLockWriteGuard<'static, ()> {
    PROVIDER_BINDINGS
        .write()
        .await
}

/// Refuse `after` when it binds a credential provider that no longer exists,
/// one the surface stored now, `current`, does not bind already: its
/// references were checked before the write took the provider lock, so a
/// provider deleted in between is caught here.
async fn refuse_deleted_providers(
    removal: &GrantRemoval<'_>,
    current: Option<&AgentSurface>,
    after: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    let Some(store) = removal.providers else {
        return Ok(());
    };
    let kept = current
        .map(super::surface_tenancy::bound_credential_provider_ids)
        .unwrap_or_default();
    for id in super::surface_tenancy::bound_credential_provider_ids(after) {
        if kept.contains(id) {
            continue;
        }
        if store
            .get(id)
            .await
            .map_err(|_| unavailable())?
            .is_none()
        {
            return Err(SurfaceApiError::BadRequest(format!("Credential provider '{id}' does not exist")));
        }
    }
    Ok(())
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
/// when `after` is `None`, under the provider lock held shared and the
/// surface's lock, removing the grants of every external consent binding that
/// differs between the surface stored now, read under the lock, and `after`.
/// A write built from an earlier read therefore still removes the grants of a
/// binding that a concurrent write added and this one drops. The grants are
/// revoked only once `write` succeeds; when it fails they are put back before
/// the lock is released. When the write is dropped, the surface stored is
/// read again under the lock ([`written`]): the grants are revoked when the
/// write was saved all the same, and put back otherwise. A write that binds a
/// provider deleted since its references were checked is refused.
pub(crate) async fn write_surface<T, Write, Pending>(
    removal: &GrantRemoval<'_>,
    surfaces: Arc<dyn AgentSurfaceStore>,
    surface_id: &str,
    stored: Stored,
    after: Option<&AgentSurface>,
    write: Write,
) -> Result<T, SurfaceApiError>
where
    Write: FnOnce() -> Pending,
    Pending: std::future::Future<Output = Result<T, SurfaceApiError>>,
{
    let _bindings = hold_provider_bindings().await;
    let lock = Arc::new(lock_surface(surface_id).await);
    let current = surfaces
        .get(surface_id)
        .await
        .map_err(|error| SurfaceApiError::InternalError(format!("Failed to get surface: {error}")))?;
    if stored == Stored::Absent && current.is_some() {
        return Err(SurfaceApiError::BadRequest(format!("Surface with ID '{surface_id}' already exists")));
    }
    if let Some(after) = after {
        refuse_deleted_providers(removal, current.as_ref(), after).await?;
    }
    let (saved, outcome) = tokio::sync::oneshot::channel();
    let outcome = crate::delegation_vault::revocation::ChangeOutcome {
        saved: outcome,
        stored: Box::pin(written(surfaces, surface_id.to_string(), after.map(external_bindings))),
    };
    remove_changed_binding_grants(removal, current.as_ref(), after, Some(Arc::clone(&lock)), Some(outcome)).await?;
    let written = write().await;
    let _ = saved.send(written.is_ok());
    drop(lock);
    written
}

/// Whether a dropped write was saved: the surface stored under `surface_id`
/// serves exactly `expected`, the external consent bindings of the surface
/// the write saves, or is absent when the write deleted it (`None`). The
/// write removed grants only when its bindings differ from those stored
/// before it, so this tells the two apart. A read that fails counts as saved,
/// so the grants are revoked rather than kept under a binding that may be
/// gone.
async fn written(
    surfaces: Arc<dyn AgentSurfaceStore>,
    surface_id: String,
    expected: Option<HashSet<ExternalBinding>>,
) -> bool {
    match surfaces
        .get(&surface_id)
        .await
    {
        Ok(stored) => {
            stored
                .as_ref()
                .map(external_bindings)
                == expected
        }
        Err(error) => {
            warn!(
                target: "credential_delegation",
                surface_id = ?surface_id,
                error = %error,
                "Cannot read whether a dropped surface write was saved; the grants it removed are revoked"
            );
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::grants::{GrantKey, StoredGrant};
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
            if let Some(revocations) = remove_changed_binding_grants(&removal, before, after, None, None).await? {
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

        async fn surfaces(&self) -> Arc<dyn AgentSurfaceStore> {
            Arc::new(
                crate::surfaces::FileSystemAgentSurfaceStore::new(
                    self._directory
                        .path()
                        .join("surfaces"),
                )
                .await
                .unwrap(),
            )
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
            remove_changed_binding_grants(&no_vault, Some(&bound()), None, None, None).await,
            Err(SurfaceApiError::Unavailable(_))
        ));
        assert!(
            remove_changed_binding_grants(&no_vault, Some(&bound()), Some(&bound()), None, None)
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
            remove_changed_binding_grants(&unreadable, Some(&bound()), None, None, None).await,
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
            remove_changed_binding_grants(&removal, Some(&with_unused), Some(&bound()), None, None)
                .await
                .is_ok(),
            "no grant of the removed binding is stored"
        );
        let caller_only = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        assert!(matches!(
            remove_changed_binding_grants(&removal, Some(&bound()), Some(&caller_only), None, None).await,
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
        let revocations = remove_changed_binding_grants(&removal, Some(&bound()), None, None, None)
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
            remove_changed_binding_grants(&removal, Some(&bound()), None, None, None)
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
        write_surface(&removal, surfaces.clone(), "surface", Stored::Any, Some(&stale), || async {
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

        let refused = write_surface(&removal, surfaces.clone(), "surface", Stored::Absent, Some(&bound()), || async {
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

    /// A save that fails leaves the grants of the bindings it would have
    /// removed, unrevoked: they are deleted only while the save runs, and put
    /// back when it fails, before the surface's lock is released.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_save_that_fails_keeps_the_grants_of_the_bindings_it_would_remove() {
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
        let unbound = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        let failed = write_surface(&removal, surfaces.clone(), "surface", Stored::Any, Some(&unbound), || async {
            Err::<(), _>(SurfaceApiError::InternalError("the disk is full".into()))
        })
        .await;
        assert!(matches!(failed, Err(SurfaceApiError::InternalError(_))), "{failed:?}");
        drop(lock_surface("surface").await);
        assert!(
            fixture
                .kept(&owner_key("owner-hop"))
                .await,
            "the grant of the binding the failed save would have removed is kept"
        );
        assert!(
            fixture
                .server
                .revoked_tokens()
                .is_empty(),
            "and never revoked"
        );
    }

    /// A grant deleted for a save that fails is put back; one that cannot be
    /// put back is revoked, never left live at the vendor with no copy kept.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_that_cannot_be_put_back_is_revoked() {
        let fixture = with_grants().await;
        let surfaces = fixture.surfaces().await;
        surfaces
            .save(&bound())
            .await
            .unwrap();
        let refusing: Arc<dyn DelegationVaultStorage> = Arc::new(PausingVault {
            inner: fixture.vault.clone(),
            deletions: std::sync::atomic::AtomicUsize::new(1),
            first_deleted: Default::default(),
            resume: tokio::sync::Semaphore::new(0),
            refuse_stores: true,
        });
        let origin = fixture.server.origin();
        let removal = GrantRemoval {
            vault: Some(&refusing),
            exact_allowlist: Some(&origin),
            ..fixture.removal()
        };
        let unbound = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        let failed = write_surface(&removal, surfaces.clone(), "surface", Stored::Any, Some(&unbound), || async {
            Err::<(), _>(SurfaceApiError::InternalError("the disk is full".into()))
        })
        .await;
        assert!(matches!(failed, Err(SurfaceApiError::InternalError(_))), "{failed:?}");
        assert!(
            !fixture
                .kept(&owner_key("owner-hop"))
                .await,
            "the grant could not be put back"
        );
        let revoked = async {
            while fixture
                .server
                .revoked_tokens()
                .len()
                < 2
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), revoked)
            .await
            .expect("so it is revoked");
        assert_eq!(
            fixture
                .server
                .revoked_tokens(),
            ["owner-access", "owner-access-refresh"]
        );
    }

    /// A write binds a provider only while it exists: one deleted since the
    /// write's references were checked is refused under the provider lock,
    /// which a provider delete holds for its whole check and delete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_binding_a_provider_deleted_since_it_was_checked_is_refused() {
        let fixture = Fixture::new().await;
        let surfaces = fixture.surfaces().await;
        let removal = fixture.removal();
        let saved = std::sync::atomic::AtomicBool::new(false);
        let gone = surface(json!([point("owner-hop", external("deleted-vendor", "owner"))]));
        let refused = write_surface(&removal, surfaces.clone(), "surface", Stored::Absent, Some(&gone), || async {
            saved.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok::<(), SurfaceApiError>(())
        })
        .await;
        assert!(
            matches!(refused, Err(SurfaceApiError::BadRequest(ref message)) if message.contains("deleted-vendor")),
            "{refused:?}"
        );
        assert!(!saved.load(std::sync::atomic::Ordering::SeqCst), "nothing is saved");

        write_surface(&removal, surfaces.clone(), "surface", Stored::Absent, Some(&bound()), || async {
            Ok::<(), SurfaceApiError>(())
        })
        .await
        .expect("a provider that exists is bound");

        let exclusive = hold_provider_bindings_exclusively().await;
        let write = tokio::spawn({
            let surfaces = fixture.surfaces().await;
            let vault = fixture.vault.clone();
            let providers = fixture.providers.clone();
            async move {
                let removal = GrantRemoval {
                    vault: Some(&vault),
                    providers: Some(&providers),
                    secrets: None,
                    exact_allowlist: None,
                    actor: None,
                };
                write_surface(&removal, surfaces.clone(), "surface", Stored::Any, Some(&bound()), || async {
                    Ok::<(), SurfaceApiError>(())
                })
                .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!write.is_finished(), "a surface write waits for a provider delete in progress");
        drop(exclusive);
        write
            .await
            .unwrap()
            .expect("and goes on once it ends");
    }

    /// A vault that pauses after its first grant deletion until `resume` has a
    /// permit, so a test can drop a write part way through deleting, and
    /// refuses to store a grant while `refuse_stores` is set.
    struct PausingVault {
        inner: Arc<dyn DelegationVaultStorage>,
        deletions: std::sync::atomic::AtomicUsize,
        first_deleted: tokio::sync::Notify,
        resume: tokio::sync::Semaphore,
        refuse_stores: bool,
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

        async fn store_grant(
            &self,
            grant: DelegatedGrant,
        ) -> anyhow::Result<StoredGrant> {
            if self.refuse_stores {
                anyhow::bail!("the vault refuses to store a grant");
            }
            self.inner
                .store_grant(grant)
                .await
        }
    }

    /// A write dropped part way through deleting a binding's grants, as when
    /// its client disconnects, saves nothing, so every grant it deleted is put
    /// back, unrevoked, and the surface's lock is held until they all are.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_write_dropped_while_deleting_grants_puts_every_one_back() {
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
            refuse_stores: false,
        });
        let vault: Arc<dyn DelegationVaultStorage> = pausing.clone();
        let origin = fixture.server.origin();
        let removal = GrantRemoval {
            vault: Some(&vault),
            exact_allowlist: Some(&origin),
            ..fixture.removal()
        };

        let mut write =
            Box::pin(write_surface(&removal, surfaces.clone(), SURFACE, Stored::Any, Some(&after), || async {
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

        drop(
            tokio::time::timeout(std::time::Duration::from_secs(10), lock_surface(SURFACE))
                .await
                .expect("the lock is released once every grant is back"),
        );
        for key in &keys {
            assert!(fixture.kept(key).await, "{key:?} is put back");
        }
        assert!(
            fixture
                .server
                .revoked_tokens()
                .is_empty(),
            "no grant of a binding still saved is revoked"
        );
        assert!(held_while_deleting, "the surface's lock is held until every grant is back");
        let stored = surfaces
            .get(SURFACE)
            .await
            .unwrap()
            .expect("the surface is still stored");
        assert_eq!(stored.transit_points().len(), 2, "the dropped write saved nothing");
    }

    /// A write dropped after its save made the change durable, as when its
    /// client disconnects while the save finishes, has removed the binding all
    /// the same: the task reads the stored surface again, under the surface's
    /// lock, and revokes the binding's grants instead of putting them back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_write_dropped_after_its_save_revokes_the_grants_of_the_binding_it_removed() {
        const SURFACE: &str = "dropped-after-save";
        let fixture = Fixture::new().await;
        let removed = GrantKey::owner(Some("tenant-a"), SURFACE, "owner-hop", "vendor");
        let kept = GrantKey::caller(Some("tenant-a"), SURFACE, "caller-hop", "vendor", CALLER).unwrap();
        fixture
            .store(&removed, "owner-access")
            .await;
        fixture
            .store(&kept, "caller-access")
            .await;
        let mut before = bound();
        before.surface_id = SURFACE.to_string();
        let mut after = surface(json!([point("caller-hop", external("vendor", "caller"))]));
        after.surface_id = SURFACE.to_string();
        let surfaces = fixture.surfaces().await;
        surfaces
            .save(&before)
            .await
            .unwrap();
        let origin = fixture.server.origin();
        let removal = GrantRemoval {
            exact_allowlist: Some(&origin),
            ..fixture.removal()
        };
        let durable = tokio::sync::Notify::new();

        let mut write =
            Box::pin(write_surface(&removal, surfaces.clone(), SURFACE, Stored::Any, Some(&after), || async {
                surfaces
                    .save(&after)
                    .await
                    .map_err(|error| SurfaceApiError::InternalError(error.to_string()))?;
                durable.notify_one();
                std::future::pending::<Result<(), SurfaceApiError>>().await
            }));
        tokio::select! {
            _ = &mut write => panic!("the write ended before its save finished"),
            () = durable.notified() => {}
        }
        drop(write);

        drop(
            tokio::time::timeout(std::time::Duration::from_secs(10), lock_surface(SURFACE))
                .await
                .expect("the surface's lock is released once the outcome is settled"),
        );
        assert!(!fixture.kept(&removed).await, "the grant of the binding the saved change removed is not put back");
        assert!(fixture.kept(&kept).await, "the binding the change kept keeps its grant");
        let revoked = async {
            while fixture
                .server
                .revoked_tokens()
                .len()
                < 2
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), revoked)
            .await
            .expect("the removed grant is revoked");
        assert_eq!(
            fixture
                .server
                .revoked_tokens(),
            ["owner-access", "owner-access-refresh"]
        );
    }
}
