//! Readiness of a surface that derives a DID from an API Key Provider key id. The request path
//! derives such a DID with no key lookup, so a stored surface naming a key it may not use is
//! held back here: under `tenant_credential_isolation: warn` it is only logged, under `enforce`
//! it is not ready, and while the API key store cannot be read a surface naming a key id that has
//! not been checked is not ready. While only some key folders cannot be loaded, a surface naming
//! a key id no loaded folder holds is not ready, and one naming key ids found elsewhere is judged
//! as usual. A surface naming a revoked key is not ready in every mode.
//! Verdicts are taken when a surface goes live and on the first request that finds none for the
//! key ids the served surface names, one request at a time per surface, and kept per surface id. Such a judgment lists the whole API
//! key store and reads from disk the key folders of the surface and of the owners of the keys it
//! names, so a key another node created or revoked is seen. A key id found then is judged again
//! once its recheck is due, by one request at a time, from those folders alone, read from disk;
//! a key id found missing, or judged while the store could not be read, is judged again from a
//! whole listing. The verdicts that read a surface as a key's owner are dropped when that surface
//! changes, and those that judged a key when this node changes its status.
//! Admitting the surfaces of a boot or reload reads the API key store once, and the credential
//! policy report of that boot or reload judges from the same listing.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tracing::{info, warn};

use crate::config::agent_surface::AgentSurface;
use crate::identity::handlers::surface_tenancy::{
    KeyListing, KeyStatus, ProviderKeyIds, ProviderKeyIssue, ProviderKeyIssueKind, judge_provider_keys,
    provider_key_ids, provider_key_listing_in, served_provider_key_ids,
};
use crate::source_auth::errors::NotReadyReason;

/// The rule a provider-key refusal and its log lines name.
pub const PROVIDER_KEY_TENANT_RULE: &str = "provider_key_tenant";

/// The reason a surface naming a key id is not ready while the API key store cannot be read.
pub const API_KEY_STORE_UNAVAILABLE: &str = "api_key_store_unavailable";

/// The reason a surface naming a revoked key is not ready.
pub const API_KEY_REVOKED: &str = "api_key_revoked";

/// The reason a surface naming a key id no key has is not ready.
pub const API_KEY_MISSING: &str = "api_key_missing";

/// The surfaces owning each API key, by key id, the revoked key ids and the key folders that
/// could not be loaded, from one listing of the API key store, or why the store could not be read.
pub type KeyOwnersListing = Result<KeyListing, &'static str>;

/// Lists the owners and status of every key of `api_keys`; an error when there is no store or it
/// cannot be listed at all.
pub(crate) async fn list_key_owners(api_keys: Option<&dyn crate::api_keys::store::ApiKeyStore>) -> KeyOwnersListing {
    provider_key_listing_in(api_keys.ok_or("the API key store is not configured")?)
        .await
        .map_err(|_| "listing API keys failed")
}

/// How long a key id is kept as judged without `cache_refresh_interval_secs`. A key another
/// node creates or revokes is read at the next judgment, so the id is judged again after this
/// long, but no sooner: a surface naming a key id reads the key folders of the keys it names
/// from disk, and lists the API key store for a key found missing, at most this often.
const MISSING_KEY_RECHECK: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a key id is kept as judged: `cache_refresh_interval_secs` when set, the interval at
/// which this node's stores pick up other nodes' writes, else [`MISSING_KEY_RECHECK`].
pub(crate) fn missing_key_recheck() -> std::time::Duration {
    match crate::storage::filesystem::cache_refresh_interval_secs() {
        0 => MISSING_KEY_RECHECK,
        secs => std::time::Duration::from_secs(secs),
    }
}

#[derive(Clone, Default)]
struct Sources {
    api_keys: Option<Arc<dyn crate::api_keys::store::ApiKeyStore>>,
    surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
}

/// The surfaces owning each key, by key id, the revoked key ids, the stores the keys and their
/// surfaces' tenants are read from, and whether the keys come from a listing of the whole store.
struct Owners {
    keys: KeyListing,
    api_keys: Arc<dyn crate::api_keys::store::ApiKeyStore>,
    surfaces: Arc<dyn crate::surfaces::AgentSurfaceStore>,
    whole: bool,
}

/// The key ids judged for a surface of `tenant_id`, those found in a key folder, those of them it
/// may not use, those revoked, those no key has, those judged while the stores could not be read,
/// the surfaces read as their owners, and when each id is judged again.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    tenant_id: Option<String>,
    judged: HashSet<String>,
    found: HashSet<String>,
    refused: HashSet<String>,
    revoked: HashSet<String>,
    missing: HashSet<String>,
    unavailable: HashSet<String>,
    owners: HashSet<String>,
    recheck: HashMap<String, Instant>,
}

impl Entry {
    /// Whether the entry judged every id of `ids` for `tenant_id`, none of them due for a
    /// recheck at `now`, and if so why the surface is refused, if it is.
    fn decides(
        &self,
        tenant_id: Option<&str>,
        ids: &ProviderKeyIds,
        now: Instant,
    ) -> Option<Option<NotReadyReason>> {
        ids.all()
            .all(|id| {
                self.recheck
                    .get(id)
                    .is_none_or(|at| now < *at)
            })
            .then(|| self.verdict(tenant_id, ids))
            .flatten()
    }

    /// Whether the entry judged every id of `ids` for `tenant_id`, due for a recheck or not, and
    /// if so why the surface is refused, if it is.
    fn verdict(
        &self,
        tenant_id: Option<&str>,
        ids: &ProviderKeyIds,
    ) -> Option<Option<NotReadyReason>> {
        (self.tenant_id.as_deref() == tenant_id
            && ids
                .all()
                .all(|id| self.judged.contains(id)))
        .then(|| {
            let any = |set: &HashSet<String>| {
                ids.all()
                    .any(|id| set.contains(id))
            };
            refusal(any(&self.unavailable), any(&self.revoked), any(&self.missing), any(&self.refused))
        })
    }

    /// When the entry judged every id of `ids` for `tenant_id` and each one due for a recheck at
    /// `now` was found in a key folder: those ids, to be judged again from the key folders of the
    /// surfaces read as their owners, which are returned too.
    fn found_due(
        &self,
        tenant_id: Option<&str>,
        ids: &ProviderKeyIds,
        now: Instant,
    ) -> Option<(ProviderKeyIds, HashSet<String>)> {
        let due = |id: &String| {
            self.recheck
                .get(id)
                .is_some_and(|at| now >= *at)
        };
        let eligible = self.tenant_id.as_deref() == tenant_id
            && ids
                .all()
                .all(|id| self.judged.contains(id) && (!due(id) || self.found.contains(id)))
            && ids.all().any(due);
        eligible.then(|| {
            let pick = |list: &[String]| {
                list.iter()
                    .filter(|id| due(id))
                    .cloned()
                    .collect()
            };
            (
                ProviderKeyIds {
                    keys: pick(&ids.keys),
                    legacy_secrets: pick(&ids.legacy_secrets),
                },
                self.owners.clone(),
            )
        })
    }

    /// The verdict `issues` gives for `ids`, judging again at `recheck_at` every id found in a key
    /// folder, found missing, or judged while the stores could not be read.
    fn of(
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
        verdict: &Verdict,
        recheck_at: Instant,
    ) -> Self {
        let ids_where = |keep: &dyn Fn(ProviderKeyIssueKind) -> bool| {
            verdict
                .issues
                .iter()
                .filter(|issue| keep(issue.kind))
                .map(|issue| issue.key_id.clone())
                .collect()
        };
        Self {
            tenant_id: surface.tenant_id.clone(),
            judged: ids.all().cloned().collect(),
            found: verdict.found.clone(),
            unavailable: ids_where(&|kind| kind == ProviderKeyIssueKind::StoreUnavailable),
            revoked: ids_where(&|kind| kind == ProviderKeyIssueKind::RevokedKey),
            missing: ids_where(&|kind| kind == ProviderKeyIssueKind::MissingKey),
            refused: ids_where(&|kind| {
                kind.is_breach()
                    && !matches!(
                        kind,
                        ProviderKeyIssueKind::StoreUnavailable
                            | ProviderKeyIssueKind::RevokedKey
                            | ProviderKeyIssueKind::MissingKey
                    )
            }),
            owners: verdict.owners.clone(),
            recheck: ids
                .all()
                .filter(|id| {
                    verdict.found.contains(*id)
                        || verdict
                            .issues
                            .iter()
                            .any(|issue| {
                                issue.key_id == **id
                                    && matches!(
                                        issue.kind,
                                        ProviderKeyIssueKind::MissingKey | ProviderKeyIssueKind::StoreUnavailable
                                    )
                            })
                })
                .map(|id| (id.clone(), recheck_at))
                .collect(),
        }
    }

    /// Takes in a later judgment of the same surface: for the same tenant its verdict replaces
    /// the kept one for every id it judged, for another tenant it replaces the entry.
    fn merge(
        &mut self,
        later: Self,
    ) {
        if self.tenant_id != later.tenant_id {
            *self = later;
            return;
        }
        for id in &later.judged {
            self.found.remove(id);
            self.refused.remove(id);
            self.revoked.remove(id);
            self.missing.remove(id);
            self.unavailable.remove(id);
            self.recheck.remove(id);
        }
        self.judged
            .extend(later.judged);
        self.found.extend(later.found);
        self.refused
            .extend(later.refused);
        self.revoked
            .extend(later.revoked);
        self.missing
            .extend(later.missing);
        self.unavailable
            .extend(later.unavailable);
        self.owners
            .extend(later.owners);
        self.recheck
            .extend(later.recheck);
    }
}

struct Verdict {
    issues: Vec<ProviderKeyIssue>,
    found: HashSet<String>,
    owners: HashSet<String>,
}

impl Verdict {
    fn reason(&self) -> Option<NotReadyReason> {
        let any = |kind: &dyn Fn(ProviderKeyIssueKind) -> bool| {
            self.issues
                .iter()
                .any(|issue| kind(issue.kind))
        };
        refusal(
            any(&|kind| kind == ProviderKeyIssueKind::StoreUnavailable),
            any(&|kind| kind == ProviderKeyIssueKind::RevokedKey),
            any(&|kind| kind == ProviderKeyIssueKind::MissingKey),
            any(&|kind| kind.is_breach()),
        )
    }
}

/// Why a surface is refused: while the stores cannot be read, then for a revoked key, then for a
/// key id no key has, then for a key it may not use.
fn refusal(
    unavailable: bool,
    revoked: bool,
    missing: bool,
    refused: bool,
) -> Option<NotReadyReason> {
    if unavailable {
        Some(NotReadyReason::ApiKeyStoreUnavailable)
    } else if revoked {
        Some(NotReadyReason::ApiKeyRevoked)
    } else if missing {
        Some(NotReadyReason::ApiKeyMissing)
    } else {
        refused.then_some(NotReadyReason::ProviderKeyTenant)
    }
}

/// Whether this node's kept verdict lets a surface naming key ids serve, without saying why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingStatus {
    Serving,
    NotServing,
    /// No verdict covers the surface's tenant and key ids yet.
    NotJudged,
}

#[derive(Default)]
pub struct ProviderKeyGate {
    sources: std::sync::RwLock<Sources>,
    entries: DashMap<String, Entry>,
    rechecks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    changes: AtomicU64,
    store_outage_logged: AtomicBool,
    #[cfg(test)]
    missing_key_recheck: std::sync::Mutex<Option<std::time::Duration>>,
}

static GATE: std::sync::LazyLock<ProviderKeyGate> = std::sync::LazyLock::new(ProviderKeyGate::default);

#[cfg(test)]
thread_local! {
    static TEST_THREAD_GATE: std::cell::Cell<Option<&'static ProviderKeyGate>> = const { std::cell::Cell::new(None) };
}

/// Makes the current thread use `gate` from [`gate`], so an in-process gateway's runtime keeps
/// its verdicts apart from every other one in the test process.
#[cfg(test)]
pub(crate) fn use_thread_gate(gate: &'static ProviderKeyGate) {
    TEST_THREAD_GATE.with(|slot| slot.set(Some(gate)));
}

/// The process-wide gate.
pub fn gate() -> &'static ProviderKeyGate {
    #[cfg(test)]
    if let Some(gate) = TEST_THREAD_GATE.with(std::cell::Cell::get) {
        return gate;
    }
    &GATE
}

fn ids_of(surface: &AgentSurface) -> ProviderKeyIds {
    provider_key_ids(surface).unwrap_or_else(|_| served_provider_key_ids(&base_view(surface)).unwrap_or_default())
}

fn base_view(surface: &AgentSurface) -> AgentSurface {
    AgentSurface {
        variants: Vec::new(),
        default_variant_id: None,
        ..surface.clone()
    }
}

impl ProviderKeyGate {
    /// The stores verdicts read key owners and their surfaces' tenants from. Without an API key
    /// store, every surface that names a key id is not ready.
    pub fn set_sources(
        &self,
        api_keys: Option<Arc<dyn crate::api_keys::store::ApiKeyStore>>,
        surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    ) {
        *self
            .sources
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Sources { api_keys, surfaces };
    }

    /// The API key store verdicts read keys from, when one is set.
    pub fn api_key_store(&self) -> Option<Arc<dyn crate::api_keys::store::ApiKeyStore>> {
        self.sources
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .api_keys
            .clone()
    }

    /// Judges `surface` as it goes live, in its base and every variant, replacing any verdict
    /// kept for it, and logs what it may not use.
    pub async fn admit(
        &self,
        surface: &AgentSurface,
    ) {
        self.admit_all(std::iter::once(surface))
            .await;
    }

    /// [`Self::admit`] for every surface of `surfaces`, all judged from one listing of the API
    /// key store, which is read only when one of them names a key id. Returns that listing's key
    /// owners, `None` when the store was not read.
    pub async fn admit_all<'a>(
        &self,
        surfaces: impl IntoIterator<Item = &'a AgentSurface>,
    ) -> Option<KeyOwnersListing> {
        let mut naming = Vec::new();
        for surface in surfaces {
            let ids = ids_of(surface);
            if ids.is_empty() {
                self.entries
                    .remove(&surface.surface_id);
            } else {
                naming.push((surface, ids));
            }
        }
        if naming.is_empty() {
            return None;
        }
        let changes = self.changes();
        let listing = self
            .list_owners_from_disk(
                naming
                    .iter()
                    .map(|(surface, ids)| (surface.surface_id.as_str(), ids)),
            )
            .await;
        for (surface, ids) in naming {
            let verdict = self
                .judge_from(surface, &ids, &listing)
                .await;
            let judged = Entry::of(surface, &ids, &verdict, self.recheck_at());
            match self
                .entries
                .entry(surface.surface_id.clone())
            {
                dashmap::Entry::Occupied(kept) if self.changes() != changes => {
                    kept.remove();
                }
                dashmap::Entry::Occupied(mut kept) => *kept.get_mut() = judged,
                dashmap::Entry::Vacant(vacant) if self.changes() == changes => {
                    vacant.insert(judged);
                }
                dashmap::Entry::Vacant(_) => {}
            }
        }
        Some(listing.map(|owners| owners.keys))
    }

    /// Drops the verdict of a surface that no longer serves. A judgment already reading the
    /// stores when this runs is not kept.
    pub fn forget(
        &self,
        surface_id: &str,
    ) {
        self.changes
            .fetch_add(1, Ordering::SeqCst);
        self.entries
            .remove(surface_id);
        self.rechecks
            .remove(surface_id);
    }

    /// Drops every verdict that read `surface_id` as the owner of a key, so a surface naming its
    /// keys is judged again on its next request after the owner's tenant changes or it is gone. A
    /// judgment already reading the stores when this runs is not kept.
    pub fn owner_changed(
        &self,
        surface_id: &str,
    ) {
        self.changes
            .fetch_add(1, Ordering::SeqCst);
        self.entries
            .retain(|_, entry| {
                !entry
                    .owners
                    .contains(surface_id)
            });
    }

    /// Drops every verdict that judged `key_id`, so a surface naming the key is judged again on
    /// its next request after this node revokes or deletes it. Called once the key's change is
    /// stored; a judgment already reading the stores when this runs is not kept.
    pub fn key_changed(
        &self,
        key_id: &str,
    ) {
        self.changes
            .fetch_add(1, Ordering::SeqCst);
        self.entries
            .retain(|_, entry| !entry.judged.contains(key_id));
    }

    /// Why a request to `surface`, as served, is refused because it derives a DID from a key id,
    /// if it is. A served surface naming an id no verdict covers is judged now, one request at a
    /// time per surface: a request that waited takes a verdict kept meanwhile only when it covers
    /// its own tenant and key ids, and judges again otherwise.
    pub async fn refuses(
        &self,
        surface: &AgentSurface,
    ) -> Option<NotReadyReason> {
        let ids = served_provider_key_ids(surface).unwrap_or_else(|_| ids_of(surface));
        if ids.is_empty() {
            return None;
        }
        if let Some(reason) = self.kept(surface, &ids) {
            return reason;
        }
        let flight = self
            .rechecks
            .entry(surface.surface_id.clone())
            .or_default()
            .clone();
        let _flight = flight.lock().await;
        if let Some(reason) = self.kept(surface, &ids) {
            return reason;
        }
        if let Some(reason) = self
            .recheck_found(surface, &ids)
            .await
        {
            return reason;
        }
        let changes = self.changes();
        let verdict = self
            .judge(surface, &ids)
            .await;
        let judged = Entry::of(surface, &ids, &verdict, self.recheck_at());
        match self
            .entries
            .entry(surface.surface_id.clone())
        {
            _ if self.changes() != changes => {}
            dashmap::Entry::Occupied(mut kept) => kept.get_mut().merge(judged),
            dashmap::Entry::Vacant(vacant) => {
                vacant.insert(judged);
            }
        }
        verdict.reason()
    }

    /// The kept verdict on `surface` when it covers its tenant and every id of `ids`, none of them
    /// due for a recheck.
    fn kept(
        &self,
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
    ) -> Option<Option<NotReadyReason>> {
        self.entries
            .get(&surface.surface_id)?
            .decides(surface.tenant_id.as_deref(), ids, Instant::now())
    }

    /// Judges again the due key ids of a kept verdict that were found in a key folder, from the
    /// key folders of the surface and of the surfaces read as their owners, read from disk,
    /// without listing the whole store: owners stay valid, as key ids are never reused, and a key
    /// folder this verdict does not read cannot refuse it. `None` when no such verdict applies, or
    /// it no longer covers `ids` once merged, so the surface is judged from a whole listing.
    /// Called holding the surface's flight lock.
    async fn recheck_found(
        &self,
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
    ) -> Option<Option<NotReadyReason>> {
        let tenant_id = surface.tenant_id.as_deref();
        let (due, mut folders) = self
            .entries
            .get(&surface.surface_id)?
            .found_due(tenant_id, ids, Instant::now())?;
        folders.insert(surface.surface_id.clone());
        let changes = self.changes();
        let listing = self
            .list_folders(folders, &due)
            .await;
        let verdict = self
            .judge_from(surface, &due, &listing)
            .await;
        let judged = Entry::of(surface, &due, &verdict, self.recheck_at());
        let mut kept = self
            .entries
            .get_mut(&surface.surface_id)?;
        if self.changes() != changes {
            return None;
        }
        kept.merge(judged);
        kept.decides(tenant_id, ids, Instant::now())
    }

    /// How many key owners and keys have changed, read before a judgment and again, under the
    /// entry's lock, before its verdict is kept.
    fn changes(&self) -> u64 {
        self.changes
            .load(Ordering::SeqCst)
    }

    /// Whether the verdict this node keeps lets `surface`, as served (a resolved view, or a
    /// surface with variants in every view), serve. Reads only the kept verdict, never the stores,
    /// and a verdict due for a recheck still counts.
    pub fn serving_status(
        &self,
        surface: &AgentSurface,
    ) -> ServingStatus {
        let ids = served_provider_key_ids(surface).unwrap_or_else(|_| ids_of(surface));
        match self
            .entries
            .get(&surface.surface_id)
            .and_then(|entry| entry.verdict(surface.tenant_id.as_deref(), &ids))
        {
            Some(None) => ServingStatus::Serving,
            Some(Some(_)) => ServingStatus::NotServing,
            None => ServingStatus::NotJudged,
        }
    }

    /// The reason a kept verdict refuses `surface` as served (a resolved view, or a surface with
    /// variants in every view) under; `None` when no verdict refuses it or none covers its key
    /// ids yet.
    #[cfg(test)]
    pub(crate) fn recorded_refusal(
        &self,
        surface: &AgentSurface,
    ) -> Option<&'static str> {
        let ids = served_provider_key_ids(surface).unwrap_or_else(|_| ids_of(surface));
        if ids.is_empty() {
            return None;
        }
        match self
            .entries
            .get(&surface.surface_id)?
            .decides(surface.tenant_id.as_deref(), &ids, Instant::now())?
        {
            Some(NotReadyReason::ApiKeyStoreUnavailable) => Some(API_KEY_STORE_UNAVAILABLE),
            Some(NotReadyReason::ApiKeyRevoked) => Some(API_KEY_REVOKED),
            Some(NotReadyReason::ApiKeyMissing) => Some(API_KEY_MISSING),
            Some(NotReadyReason::ProviderKeyTenant) => Some(PROVIDER_KEY_TENANT_RULE),
            Some(NotReadyReason::NoSourceAuthentication) | None => None,
        }
    }

    /// Whether a verdict is kept for `surface_id`.
    #[cfg(test)]
    pub(crate) fn has_verdict(
        &self,
        surface_id: &str,
    ) -> bool {
        self.entries
            .contains_key(surface_id)
    }

    /// When a key id judged now is judged again.
    fn recheck_at(&self) -> Instant {
        #[cfg(test)]
        if let Some(recheck) = *self
            .missing_key_recheck
            .lock()
            .unwrap()
        {
            return Instant::now() + recheck;
        }
        Instant::now() + missing_key_recheck()
    }

    /// The owners and status of every key, read from the API key store, or why they cannot be.
    async fn list_owners(&self) -> Result<Owners, &'static str> {
        let sources = self
            .sources
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (Some(api_keys), Some(surfaces)) = (sources.api_keys, sources.surfaces) else {
            return Err("the API key store is not configured");
        };
        let keys = list_key_owners(Some(api_keys.as_ref())).await?;
        Ok(Owners {
            keys,
            api_keys,
            surfaces,
            whole: true,
        })
    }

    /// The keys of `ids` held in the key folders `folders`, read from disk, and nothing else.
    async fn list_folders(
        &self,
        folders: HashSet<String>,
        ids: &ProviderKeyIds,
    ) -> Result<Owners, &'static str> {
        let sources = self
            .sources
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (Some(api_keys), Some(surfaces)) = (sources.api_keys, sources.surfaces) else {
            return Err("the API key store is not configured");
        };
        let mut owners = Owners {
            keys: KeyListing::default(),
            api_keys,
            surfaces,
            whole: false,
        };
        let named = ids
            .all()
            .map(String::as_str)
            .collect();
        take_in_from_disk(&mut owners, folders, &named).await;
        Ok(owners)
    }

    /// [`Self::list_owners`], with the keys each surface of `naming` names, by surface id, read
    /// from disk, so a key another node created or revoked is judged as it is stored.
    async fn list_owners_from_disk<'a>(
        &self,
        naming: impl IntoIterator<Item = (&'a str, &'a ProviderKeyIds)>,
    ) -> Result<Owners, &'static str> {
        let mut owners = self.list_owners().await?;
        read_named_keys_from_disk(&mut owners, naming).await;
        Ok(owners)
    }

    async fn judge(
        &self,
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
    ) -> Verdict {
        let listing = self
            .list_owners_from_disk([(surface.surface_id.as_str(), ids)])
            .await;
        self.judge_from(surface, ids, &listing)
            .await
    }

    async fn judge_from(
        &self,
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
        listing: &Result<Owners, &'static str>,
    ) -> Verdict {
        let isolation = crate::config::credential_policy::credential_policy().tenant_credential_isolation;
        let tenant_id = surface.tenant_id.as_deref();
        let Owners {
            keys: owners, surfaces, whole, ..
        } = match listing {
            Ok(owners) => owners,
            Err(cause) => return self.store_outage(surface, ids, isolation, cause),
        };
        let mut owner_ids: Vec<String> = Vec::new();
        for id in ids.all() {
            for owner_id in owners.owners_of(id) {
                if !owner_ids.contains(owner_id) {
                    owner_ids.push(owner_id.clone());
                }
            }
        }
        let mut owner_tenants: Vec<(String, Option<String>)> = Vec::new();
        for owner_id in &owner_ids {
            match surfaces.get(owner_id).await {
                Ok(Some(owner)) => owner_tenants.push((owner_id.clone(), owner.tenant_id)),
                Ok(None) => {}
                Err(_) => return self.store_outage(surface, ids, isolation, "reading a key's surface failed"),
            }
        }
        if *whole {
            self.log_listing(owners);
        }
        let owner_tenants: HashMap<&str, Option<&str>> = owner_tenants
            .iter()
            .map(|(id, tenant)| (id.as_str(), tenant.as_deref()))
            .collect();
        let issues = judge_provider_keys(&surface.surface_id, tenant_id, ids, Some(owners), &owner_tenants, isolation);
        log(surface, &issues);
        Verdict {
            issues,
            found: ids
                .all()
                .filter(|id| matches!(owners.status_of(id), KeyStatus::Found(_)))
                .cloned()
                .collect(),
            owners: owner_ids
                .into_iter()
                .collect(),
        }
    }

    /// Logs once that a listing of the whole store left key folders out, naming them, and once
    /// that the store can be read again when a later one leaves none out.
    fn log_listing(
        &self,
        keys: &KeyListing,
    ) {
        if keys.is_complete() {
            if self
                .store_outage_logged
                .swap(false, Ordering::Relaxed)
            {
                info!("The API key store can be read again: surfaces naming an API key id are judged as they serve");
            }
        } else if !self
            .store_outage_logged
            .swap(true, Ordering::Relaxed)
        {
            warn!(
                rule = PROVIDER_KEY_TENANT_RULE,
                reason = API_KEY_STORE_UNAVAILABLE,
                skipped = ?keys.skipped(),
                "API key folders could not be loaded: surfaces naming an API key id that no loaded folder holds are not ready until they can"
            );
        }
    }

    /// The verdict while the stores cannot be read: every id unjudged and the surface not
    /// ready. The outage is logged once, until the stores can be read again.
    fn store_outage(
        &self,
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
        isolation: crate::config::credential_policy::RuleMode,
        cause: &'static str,
    ) -> Verdict {
        if !self
            .store_outage_logged
            .swap(true, Ordering::Relaxed)
        {
            warn!(
                rule = PROVIDER_KEY_TENANT_RULE,
                reason = API_KEY_STORE_UNAVAILABLE,
                cause,
                "The API key store cannot be read: surfaces naming an API key id are not ready until it can"
            );
        }
        Verdict {
            issues: judge_provider_keys(
                &surface.surface_id,
                surface.tenant_id.as_deref(),
                ids,
                None,
                &HashMap::new(),
                isolation,
            ),
            found: HashSet::new(),
            owners: HashSet::new(),
        }
    }
}

/// Reads from disk the key folder of each surface of `naming` and of every surface `owners`
/// lists as owning a key id one of them names, each folder once, and takes in the named keys they
/// hold, so a key another node created or revoked since this node loaded the folder is listed as
/// stored. Only those folders are read; their cached keys are refreshed.
async fn read_named_keys_from_disk<'a>(
    owners: &mut Owners,
    naming: impl IntoIterator<Item = (&'a str, &'a ProviderKeyIds)>,
) {
    let mut folders: HashSet<String> = HashSet::new();
    let mut named: HashSet<&str> = HashSet::new();
    for (surface_id, ids) in naming {
        folders.insert(surface_id.to_string());
        for id in ids.all() {
            named.insert(id.as_str());
            folders.extend(
                owners
                    .keys
                    .owners_of(id)
                    .iter()
                    .cloned(),
            );
        }
    }
    take_in_from_disk(owners, folders, &named).await
}

/// Reads each key folder of `folders` from disk and takes the keys of `named` it holds into
/// `owners`, dropping the folder as an owner of every named key it no longer holds, so a key
/// another node deleted is not found from this node's cache. A folder that cannot be read is
/// skipped and owns none of them, so a named key no other folder holds is judged store
/// unavailable.
async fn take_in_from_disk(
    owners: &mut Owners,
    folders: HashSet<String>,
    named: &HashSet<&str>,
) {
    for folder in folders {
        match owners
            .api_keys
            .list_from_disk(&folder)
            .await
        {
            Ok(keys) => owners
                .keys
                .take_in_folder(&folder, keys, named),
            Err(error) => {
                warn!(folder = %folder, %error, "Could not read an API key folder from disk");
                owners
                    .keys
                    .skip_folder(&folder, named);
            }
        }
    }
}

/// One line per verdict that finds anything: the surface, its tenant, the rule, and each key id
/// with its issue. Never a secret.
fn log(
    surface: &AgentSurface,
    issues: &[ProviderKeyIssue],
) {
    if issues.is_empty() {
        return;
    }
    let found = issues
        .iter()
        .map(|issue| format!("{}:{}", issue.key_id, issue.kind.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    warn!(
        surface = %surface.surface_id,
        tenant = surface.tenant_id.as_deref().unwrap_or("appliance"),
        rule = PROVIDER_KEY_TENANT_RULE,
        api_key_ids = %found,
        not_ready = issues.iter().any(|issue| issue.kind.is_breach()),
        "Surface derives a DID from an API key it may not use, or that is revoked, or whose key or surface is gone"
    );
}

/// A gate for the current thread whose stores hold `owners` (surface id, tenant) and `keys`
/// (owner surface id, key id), under `tenant_credential_isolation: enforce`.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use super::ProviderKeyGate;

    pub(crate) struct EnforcedGate {
        pub gate: &'static ProviderKeyGate,
        pub api_keys: Arc<crate::api_keys::FileSystemApiKeyStore>,
        pub surfaces: Arc<crate::surfaces::FileSystemAgentSurfaceStore>,
        pub dir: tempfile::TempDir,
    }

    pub(crate) async fn enforced_gate(
        owners: &[(&str, Option<&str>)],
        keys: &[(&str, &str)],
    ) -> EnforcedGate {
        use crate::api_keys::store::ApiKeyStore as _;
        use crate::surfaces::AgentSurfaceStore as _;

        crate::config::credential_policy::use_thread_credential_policy(
            crate::config::credential_policy::CredentialPolicyConfig {
                tenant_credential_isolation: crate::config::credential_policy::RuleMode::Enforce,
                ..Default::default()
            },
        );
        let dir = tempfile::tempdir().unwrap();
        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(dir.path().join("surfaces"))
                .await
                .unwrap(),
        );
        for (id, tenant) in owners {
            surfaces
                .save(
                    &serde_json::from_value(serde_json::json!({
                        "surface_id": id, "name": id, "tenant_id": tenant,
                        "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": "a2a"},
                        "target": {"endpoint": "http://127.0.0.1:9"}
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let api_keys = Arc::new(
            crate::api_keys::FileSystemApiKeyStore::new(
                &dir.path()
                    .join("api_keys")
                    .to_string_lossy(),
            )
            .await
            .unwrap(),
        );
        for (owner, key_id) in keys {
            api_keys
                .create_with_material(owner, key_id.to_string(), format!("atgs_{key_id}"), "client", None, "test")
                .await
                .unwrap();
        }
        let gate: &'static ProviderKeyGate = Box::leak(Box::default());
        gate.set_sources(Some(api_keys.clone()), Some(surfaces.clone()));
        super::use_thread_gate(gate);
        EnforcedGate { gate, api_keys, surfaces, dir }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::test_support::enforced_gate;
    use super::*;

    const KEY_A: &str = "atgk_gate_a";
    const KEY_B: &str = "atgk_gate_b";

    fn naming(
        id: &str,
        tenant: &str,
        extra: serde_json::Value,
    ) -> AgentSurface {
        let mut surface = serde_json::json!({
            "surface_id": id, "name": id, "tenant_id": tenant,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": "a2a"},
            "target": {"endpoint": "http://127.0.0.1:9"}
        });
        for (key, value) in extra.as_object().unwrap() {
            surface[key] = value.clone();
        }
        serde_json::from_value(surface).unwrap()
    }

    fn external(key_id: &str) -> serde_json::Value {
        serde_json::json!({"identity_slots": {"external": {"type": "from_api_key", "api_key_id": key_id}}})
    }

    async fn gate() -> super::test_support::EnforcedGate {
        enforced_gate(
            &[("owner-a", Some("tenant-a")), ("owner-b", Some("tenant-b"))],
            &[("owner-a", KEY_A), ("owner-b", KEY_B)],
        )
        .await
    }

    fn ids(keys: &[&str]) -> ProviderKeyIds {
        ProviderKeyIds {
            keys: keys
                .iter()
                .map(|key| key.to_string())
                .collect(),
            legacy_secrets: Vec::new(),
        }
    }

    #[test]
    fn an_entry_decides_only_for_its_tenant_and_the_ids_it_judged() {
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(30);
        let entry = Entry {
            tenant_id: Some("tenant-a".into()),
            judged: [
                KEY_A.to_string(),
                KEY_B.to_string(),
                "atgk_missing".to_string(),
                "atgk_unread".to_string(),
                "atgk_revoked".to_string(),
            ]
            .into(),
            refused: [KEY_B.to_string()].into(),
            found: HashSet::new(),
            revoked: ["atgk_revoked".to_string()].into(),
            missing: ["atgk_missing".to_string()].into(),
            unavailable: ["atgk_unread".to_string()].into(),
            owners: HashSet::new(),
            recheck: [("atgk_missing".to_string(), later), ("atgk_unread".to_string(), later)].into(),
        };
        let tenant = NotReadyReason::ProviderKeyTenant;
        let outage = NotReadyReason::ApiKeyStoreUnavailable;
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&[KEY_A]), now), Some(None));
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&[KEY_A, KEY_B]), now), Some(Some(tenant)));
        assert_eq!(entry.decides(Some("tenant-b"), &ids(&[KEY_A]), now), None, "another tenant is judged again");
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&[KEY_A, "atgk_new"]), now), None, "a new id is judged");
        assert_eq!(entry.decides(None, &ids(&[KEY_A]), now), None);
        let missing = NotReadyReason::ApiKeyMissing;
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&["atgk_missing"]), now), Some(Some(missing)));
        assert_eq!(
            entry.decides(Some("tenant-a"), &ids(&[KEY_B, "atgk_missing"]), now),
            Some(Some(missing)),
            "a missing key is named before a key the surface may not use"
        );
        assert_eq!(
            entry.decides(Some("tenant-a"), &ids(&["atgk_missing"]), later),
            None,
            "a missing key is judged again once its recheck is due"
        );
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&[KEY_A, "atgk_unread"]), now), Some(Some(outage)));
        let revoked = NotReadyReason::ApiKeyRevoked;
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&["atgk_revoked"]), now), Some(Some(revoked)));
        assert_eq!(
            entry.decides(Some("tenant-a"), &ids(&[KEY_B, "atgk_revoked"]), now),
            Some(Some(revoked)),
            "a revoked key is named before a key the surface may not use"
        );
        assert_eq!(
            entry.decides(Some("tenant-a"), &ids(&["atgk_missing", "atgk_revoked"]), now),
            Some(Some(revoked)),
            "a revoked key is named before a missing one"
        );
        assert_eq!(
            entry.decides(Some("tenant-a"), &ids(&["atgk_revoked", "atgk_unread"]), now),
            Some(Some(outage)),
            "an outage is named first"
        );
        assert_eq!(
            entry.decides(Some("tenant-a"), &ids(&["atgk_unread"]), later),
            None,
            "a key judged during an outage is judged again once its recheck is due"
        );
    }

    #[tokio::test]
    async fn a_change_to_a_keys_owner_drops_the_verdicts_that_read_it() {
        use crate::surfaces::AgentSurfaceStore as _;

        let enforced = gate().await;
        let names_a = naming("owner-a", "tenant-a", external(KEY_A));
        let names_b = naming("owner-b", "tenant-b", external(KEY_B));
        enforced
            .gate
            .admit(&names_a)
            .await;
        enforced
            .gate
            .admit(&names_b)
            .await;
        assert_eq!(
            enforced
                .gate
                .refuses(&names_a)
                .await,
            None
        );

        let mut moved = enforced
            .surfaces
            .get("owner-a")
            .await
            .unwrap()
            .unwrap();
        moved.tenant_id = Some("tenant-b".to_string());
        enforced
            .surfaces
            .save(&moved)
            .await
            .unwrap();
        assert_eq!(
            enforced
                .gate
                .refuses(&names_a)
                .await,
            None,
            "the kept verdict stands until the owner's change is applied"
        );

        enforced
            .gate
            .owner_changed("owner-a");
        assert!(
            !enforced
                .gate
                .has_verdict("owner-a")
        );
        assert!(
            enforced
                .gate
                .has_verdict("owner-b"),
            "a verdict that read another owner is kept"
        );
        assert_eq!(
            enforced
                .gate
                .refuses(&names_a)
                .await,
            None,
            "judged again: a surface's own key is its own in any tenant"
        );
        assert!(
            enforced
                .gate
                .has_verdict("owner-a")
        );
    }

    #[tokio::test]
    async fn a_judgment_an_owner_change_overtakes_is_not_kept() {
        let enforced = gate().await;
        enforced.gate.set_sources(
            Some(Arc::new(FlakyKeys {
                owner_changed_while_listing: Some((enforced.gate, "owner-a")),
                ..FlakyKeys::failing(&enforced, 0)
            })),
            Some(enforced.surfaces.clone()),
        );
        let names_a = naming("owner-a", "tenant-a", external(KEY_A));

        assert_eq!(
            enforced
                .gate
                .refuses(&names_a)
                .await,
            None,
            "the request is answered with the verdict it took"
        );
        assert!(
            !enforced
                .gate
                .has_verdict("owner-a"),
            "a request's verdict that an owner change overtook is not kept"
        );

        enforced
            .gate
            .admit(&names_a)
            .await;
        assert!(
            !enforced
                .gate
                .has_verdict("owner-a"),
            "nor is an admission's"
        );

        enforced
            .gate
            .set_sources(Some(enforced.api_keys.clone()), Some(enforced.surfaces.clone()));
        enforced
            .gate
            .admit(&names_a)
            .await;
        assert!(
            enforced
                .gate
                .has_verdict("owner-a")
        );
    }

    #[tokio::test]
    async fn a_request_adds_what_it_judges_to_the_surfaces_verdict() {
        let enforced = gate().await;
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        let cross = naming("owner-a", "tenant-a", external(KEY_B));

        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None
        );
        assert_eq!(
            enforced
                .gate
                .refuses(&cross)
                .await,
            Some(NotReadyReason::ProviderKeyTenant)
        );
        let entry = enforced
            .gate
            .entries
            .get("owner-a")
            .unwrap();
        assert_eq!(entry.judged, [KEY_A.to_string(), KEY_B.to_string()].into());
        assert_eq!(entry.refused, [KEY_B.to_string()].into());
        drop(entry);
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None,
            "its own key stays served"
        );

        let moved = naming("owner-a", "tenant-b", external(KEY_A));
        assert_eq!(
            enforced
                .gate
                .refuses(&moved)
                .await,
            None,
            "a tenant change is judged afresh, and its own key is its own in any tenant"
        );
        assert_eq!(
            enforced
                .gate
                .entries
                .get("owner-a")
                .unwrap()
                .tenant_id
                .as_deref(),
            Some("tenant-b")
        );
    }

    #[tokio::test]
    async fn a_variant_naming_a_key_the_base_does_not_is_refused_only_where_it_serves() {
        let enforced = gate().await;
        let mut surface = naming("owner-a", "tenant-a", external(KEY_A));
        surface.variants = serde_json::from_value(serde_json::json!([{
            "id": "cross-id", "alias": "cross", "name": "Cross", "enabled": true,
            "overrides": {"identity_slots": {"external": {"type": "from_api_key", "api_key_id": KEY_B}}}
        }]))
        .unwrap();

        enforced
            .gate
            .admit(&surface)
            .await;

        let variant = surface
            .resolve_variant(Some("cross"))
            .unwrap();
        let base = base_view(&surface);
        assert_eq!(
            enforced
                .gate
                .refuses(&variant)
                .await,
            Some(NotReadyReason::ProviderKeyTenant)
        );
        assert_eq!(
            enforced
                .gate
                .refuses(&base)
                .await,
            None
        );
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&surface),
            Some(PROVIDER_KEY_TENANT_RULE)
        );
        enforced
            .gate
            .forget("owner-a");
        assert!(
            !enforced
                .gate
                .has_verdict("owner-a")
        );
    }

    struct FlakyKeys {
        inner: Arc<crate::api_keys::FileSystemApiKeyStore>,
        failures: AtomicUsize,
        listings: Arc<AtomicUsize>,
        owner_changed_while_listing: Option<(&'static ProviderKeyGate, &'static str)>,
        key_changed_while_listing: Option<(&'static ProviderKeyGate, &'static str)>,
        forgotten_while_listing: Option<(&'static ProviderKeyGate, &'static str)>,
        revoked_after_disk_read: std::sync::Mutex<Option<(&'static ProviderKeyGate, &'static str, &'static str)>>,
        disk_reads: Arc<AtomicUsize>,
    }

    impl FlakyKeys {
        /// Keys of `enforced` whose first `failures` listings fail.
        fn failing(
            enforced: &super::test_support::EnforcedGate,
            failures: usize,
        ) -> Self {
            Self {
                inner: enforced.api_keys.clone(),
                failures: AtomicUsize::new(failures),
                listings: Arc::default(),
                owner_changed_while_listing: None,
                key_changed_while_listing: None,
                forgotten_while_listing: None,
                revoked_after_disk_read: std::sync::Mutex::default(),
                disk_reads: Arc::default(),
            }
        }
    }

    /// Makes every recheck kept for `surface_id` due now, and every later one due at once.
    fn expire_rechecks(
        gate: &ProviderKeyGate,
        surface_id: &str,
    ) {
        *gate
            .missing_key_recheck
            .lock()
            .unwrap() = Some(std::time::Duration::ZERO);
        gate.entries
            .get_mut(surface_id)
            .unwrap()
            .recheck
            .values_mut()
            .for_each(|at| *at = Instant::now());
    }

    #[async_trait::async_trait]
    impl crate::api_keys::store::ApiKeyStore for FlakyKeys {
        async fn create_with_material(
            &self,
            agent_id: &str,
            key_id: String,
            secret: String,
            client_id: &str,
            labels: Option<HashMap<String, String>>,
            actor: &str,
        ) -> crate::api_keys::ApiKeyResult<crate::api_keys::ApiKeyCreated> {
            self.inner
                .create_with_material(agent_id, key_id, secret, client_id, labels, actor)
                .await
        }

        async fn list(
            &self,
            agent_id: &str,
        ) -> crate::api_keys::ApiKeyResult<Vec<crate::api_keys::ApiKeyMeta>> {
            self.inner
                .list(agent_id)
                .await
        }

        async fn list_from_disk(
            &self,
            agent_id: &str,
        ) -> crate::api_keys::ApiKeyResult<Vec<crate::api_keys::ApiKeyMeta>> {
            self.disk_reads
                .fetch_add(1, Ordering::SeqCst);
            let keys = self
                .inner
                .list_from_disk(agent_id)
                .await;
            let revoke = self
                .revoked_after_disk_read
                .lock()
                .unwrap()
                .take();
            if let Some((gate, owner, key_id)) = revoke {
                self.inner
                    .revoke(owner, key_id, "test")
                    .await
                    .unwrap();
                gate.key_changed(key_id);
            }
            keys
        }

        async fn list_all(&self) -> crate::api_keys::ApiKeyResult<Vec<crate::api_keys::ApiKeyMeta>> {
            self.listings
                .fetch_add(1, Ordering::SeqCst);
            if self
                .failures
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                .is_ok()
            {
                return Err(std::io::Error::other("store offline").into());
            }
            if let Some((gate, owner)) = self.owner_changed_while_listing {
                gate.owner_changed(owner);
            }
            if let Some((gate, key_id)) = self.key_changed_while_listing {
                gate.key_changed(key_id);
            }
            if let Some((gate, surface_id)) = self.forgotten_while_listing {
                gate.forget(surface_id);
            }
            self.inner.list_all().await
        }

        async fn get_record(
            &self,
            agent_id: &str,
            key_id: &str,
        ) -> crate::api_keys::ApiKeyResult<Option<crate::api_keys::ApiKeyRecord>> {
            self.inner
                .get_record(agent_id, key_id)
                .await
        }

        async fn revoke(
            &self,
            agent_id: &str,
            key_id: &str,
            actor: &str,
        ) -> crate::api_keys::ApiKeyResult<()> {
            self.inner
                .revoke(agent_id, key_id, actor)
                .await
        }

        async fn rotate(
            &self,
            agent_id: &str,
            key_id: &str,
            actor: &str,
        ) -> crate::api_keys::ApiKeyResult<crate::api_keys::ApiKeyCreated> {
            self.inner
                .rotate(agent_id, key_id, actor)
                .await
        }

        async fn delete(
            &self,
            agent_id: &str,
            key_id: &str,
            actor: &str,
        ) -> crate::api_keys::ApiKeyResult<()> {
            self.inner
                .delete(agent_id, key_id, actor)
                .await
        }

        async fn touch_usage(
            &self,
            agent_id: &str,
            key_id: &str,
        ) -> crate::api_keys::ApiKeyResult<()> {
            self.inner
                .touch_usage(agent_id, key_id)
                .await
        }
    }

    #[tokio::test]
    async fn an_outage_is_reported_only_for_a_view_it_left_unchecked() {
        let enforced = gate().await;
        let mut surface = naming("owner-a", "tenant-a", external(KEY_A));
        surface.variants = serde_json::from_value(serde_json::json!([{
            "id": "late-id", "alias": "late", "name": "Late", "enabled": true,
            "overrides": {"identity_slots": {"external": {"type": "from_api_key", "api_key_id": "atgk_gate_late"}}}
        }]))
        .unwrap();
        let base = base_view(&surface);
        assert_eq!(
            enforced
                .gate
                .refuses(&base)
                .await,
            None
        );

        enforced
            .gate
            .set_sources(None, Some(enforced.surfaces.clone()));
        let late = surface
            .resolve_variant(Some("late"))
            .unwrap();
        assert_eq!(
            enforced
                .gate
                .refuses(&late)
                .await,
            Some(NotReadyReason::ApiKeyStoreUnavailable)
        );

        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&base),
            None,
            "the base was checked before the outage"
        );
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&late),
            Some(API_KEY_STORE_UNAVAILABLE)
        );
    }

    #[tokio::test]
    async fn a_missing_key_is_judged_again_only_after_its_recheck_interval() {
        use crate::api_keys::store::ApiKeyStore as _;
        let enforced = gate().await;
        let later = "atgk_gate_later";
        let naming_later = naming("later", "tenant-a", external(later));

        assert_eq!(
            enforced
                .gate
                .refuses(&naming_later)
                .await,
            Some(NotReadyReason::ApiKeyMissing),
            "a missing key is a breach"
        );
        enforced
            .api_keys
            .create_with_material("owner-b", later.to_string(), "atgs_later".to_string(), "client", None, "test")
            .await
            .unwrap();
        assert_eq!(
            enforced
                .gate
                .refuses(&naming_later)
                .await,
            Some(NotReadyReason::ApiKeyMissing),
            "within the interval the missing verdict is kept"
        );

        expire_rechecks(enforced.gate, "later");
        assert_eq!(
            enforced
                .gate
                .refuses(&naming_later)
                .await,
            Some(NotReadyReason::ProviderKeyTenant),
            "once due, the key is judged again and is another tenant's"
        );
        let entry = enforced
            .gate
            .entries
            .get("later")
            .unwrap();
        assert!(
            entry.refused.contains(later)
                && entry
                    .recheck
                    .contains_key(later),
            "{entry:?}"
        );
    }

    fn use_isolation(mode: crate::config::credential_policy::RuleMode) {
        crate::config::credential_policy::use_thread_credential_policy(
            crate::config::credential_policy::CredentialPolicyConfig {
                tenant_credential_isolation: mode,
                ..Default::default()
            },
        );
    }

    #[tokio::test]
    async fn a_key_revoked_on_this_node_refuses_the_surfaces_naming_it_at_once_in_both_modes() {
        use crate::api_keys::store::ApiKeyStore as _;
        use crate::config::credential_policy::RuleMode;
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            let enforced = gate().await;
            use_isolation(mode);
            let own = naming("owner-a", "tenant-a", external(KEY_A));
            let active = naming("owner-b", "tenant-b", external(KEY_B));
            enforced
                .gate
                .admit_all([&own, &active])
                .await;
            assert_eq!(
                enforced
                    .gate
                    .refuses(&own)
                    .await,
                None,
                "{mode:?}"
            );

            enforced
                .api_keys
                .revoke("owner-a", KEY_A, "test")
                .await
                .unwrap();
            enforced
                .gate
                .key_changed(KEY_A);

            assert!(
                enforced
                    .gate
                    .has_verdict("owner-b"),
                "a verdict that judged another key is kept"
            );
            assert_eq!(
                enforced
                    .gate
                    .refuses(&own)
                    .await,
                Some(NotReadyReason::ApiKeyRevoked),
                "{mode:?}: the first request after the revoke"
            );
            assert_eq!(
                enforced
                    .gate
                    .refuses(&own)
                    .await,
                Some(NotReadyReason::ApiKeyRevoked),
                "{mode:?}: the kept verdict"
            );
            assert_eq!(
                enforced
                    .gate
                    .recorded_refusal(&own),
                Some(API_KEY_REVOKED)
            );
            assert_eq!(
                enforced
                    .gate
                    .refuses(&active)
                    .await,
                None,
                "{mode:?}: an active own key still serves"
            );
        }
    }

    #[tokio::test]
    async fn a_key_revoked_on_another_node_is_refused_once_the_recheck_is_due_and_not_before() {
        a_key_revoked_on_another_node_is_refused_once_due(crate::config::credential_policy::RuleMode::Warn).await;
    }

    #[tokio::test]
    async fn a_key_revoked_on_another_node_is_refused_once_the_recheck_is_due_under_enforce() {
        a_key_revoked_on_another_node_is_refused_once_due(crate::config::credential_policy::RuleMode::Enforce).await;
    }

    async fn a_key_revoked_on_another_node_is_refused_once_due(mode: crate::config::credential_policy::RuleMode) {
        use crate::api_keys::store::ApiKeyStore as _;
        let enforced = gate().await;
        use_isolation(mode);
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None,
            "{mode:?}"
        );
        other_node(&enforced)
            .await
            .revoke("owner-a", KEY_A, "test")
            .await
            .unwrap();
        let cached_status = |enforced: &super::test_support::EnforcedGate| {
            let api_keys = enforced.api_keys.clone();
            async move {
                api_keys
                    .list("owner-a")
                    .await
                    .unwrap()[0]
                    .status
            }
        };
        assert_eq!(cached_status(&enforced).await, crate::api_keys::ApiKeyStatus::Active, "this node's cache is stale");

        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None,
            "{mode:?}: within the recheck interval the kept verdict stands"
        );

        expire_rechecks(enforced.gate, "owner-a");
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            Some(NotReadyReason::ApiKeyRevoked),
            "{mode:?}: once due, the key's folder is read from disk"
        );
        assert_eq!(cached_status(&enforced).await, crate::api_keys::ApiKeyStatus::Revoked);
    }

    async fn other_node(enforced: &super::test_support::EnforcedGate) -> crate::api_keys::FileSystemApiKeyStore {
        crate::api_keys::FileSystemApiKeyStore::new(
            &enforced
                .dir
                .path()
                .join("api_keys")
                .to_string_lossy(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_key_another_node_added_to_a_loaded_folder_and_revoked_is_refused_once_the_recheck_is_due() {
        use crate::api_keys::store::ApiKeyStore as _;
        let enforced = gate().await;
        use_isolation(crate::config::credential_policy::RuleMode::Warn);
        let later = "atgk_gate_added";
        let other_node = other_node(&enforced).await;
        other_node
            .create_with_material("owner-a", later.to_string(), "atgs_added".to_string(), "client", None, "test")
            .await
            .unwrap();
        other_node
            .revoke("owner-a", later, "test")
            .await
            .unwrap();
        let names_later = naming("owner-a", "tenant-a", external(later));

        assert_eq!(
            enforced
                .gate
                .refuses(&names_later)
                .await,
            Some(NotReadyReason::ApiKeyRevoked),
            "the surface's own folder is read from disk, though this node loaded it before the key was added"
        );
    }

    #[tokio::test]
    async fn admitting_a_surface_whose_own_key_another_node_deleted_judges_it_missing_in_both_modes() {
        use crate::api_keys::store::ApiKeyStore as _;
        use crate::config::credential_policy::RuleMode;
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            let enforced = gate().await;
            use_isolation(mode);
            let own = naming("owner-a", "tenant-a", external(KEY_A));
            other_node(&enforced)
                .await
                .delete("owner-a", KEY_A, "test")
                .await
                .unwrap();

            enforced
                .gate
                .admit_all([&own])
                .await;

            assert_eq!(
                enforced
                    .gate
                    .recorded_refusal(&own),
                Some(API_KEY_MISSING),
                "{mode:?}: this node's cached copy of the key is not trusted"
            );
        }
    }

    #[tokio::test]
    async fn admitting_a_surface_reads_the_status_of_the_keys_it_names_from_disk() {
        use crate::api_keys::store::ApiKeyStore as _;
        let enforced = gate().await;
        use_isolation(crate::config::credential_policy::RuleMode::Warn);
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        let cross = naming("cross", "tenant-a", external(KEY_B));
        other_node(&enforced)
            .await
            .revoke("owner-b", KEY_B, "test")
            .await
            .unwrap();
        other_node(&enforced)
            .await
            .revoke("owner-a", KEY_A, "test")
            .await
            .unwrap();

        enforced
            .gate
            .admit_all([&own, &cross])
            .await;

        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&own),
            Some(API_KEY_REVOKED)
        );
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&cross),
            Some(API_KEY_REVOKED),
            "another surface's key is read from its owner's folder"
        );
    }

    /// Makes every recheck kept for `surface_id` due now, leaving later ones at the usual interval.
    fn due_now(
        gate: &ProviderKeyGate,
        surface_id: &str,
    ) {
        gate.entries
            .get_mut(surface_id)
            .unwrap()
            .recheck
            .values_mut()
            .for_each(|at| *at = Instant::now());
    }

    /// Makes `folder` of the API key store of `enforced` unreadable; `false` when running as root,
    /// where every read succeeds.
    fn lock_folder(
        enforced: &super::test_support::EnforcedGate,
        folder: &str,
    ) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        let path = enforced
            .dir
            .path()
            .join("api_keys")
            .join(folder);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::read_dir(&path).is_err()
    }

    fn unlock_folder(
        enforced: &super::test_support::EnforcedGate,
        folder: &str,
    ) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            enforced
                .dir
                .path()
                .join("api_keys")
                .join(folder),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn a_due_recheck_reads_only_its_own_folders_so_an_unrelated_unreadable_folder_does_not_refuse_it() {
        let enforced = gate().await;
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None
        );
        let locked = lock_folder(&enforced, "owner-b");
        let fresh = Arc::new(other_node(&enforced).await);
        enforced
            .gate
            .set_sources(Some(fresh), Some(enforced.surfaces.clone()));
        due_now(enforced.gate, "owner-a");

        let rechecked = enforced
            .gate
            .refuses(&own)
            .await;
        let first = enforced
            .gate
            .refuses(&naming("first", "tenant-a", external(KEY_A)))
            .await;
        unlock_folder(&enforced, "owner-b");
        if !locked {
            return;
        }

        assert_eq!(rechecked, None, "its own folder reads fine");
        assert_eq!(
            first,
            Some(NotReadyReason::ProviderKeyTenant),
            "a first judgment judges a key in a readable folder as usual"
        );
    }

    #[tokio::test]
    async fn a_due_recheck_whose_own_folder_is_unreadable_refuses_as_unavailable() {
        let enforced = gate().await;
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None
        );
        let locked = lock_folder(&enforced, "owner-a");
        due_now(enforced.gate, "owner-a");

        let rechecked = enforced
            .gate
            .refuses(&own)
            .await;
        unlock_folder(&enforced, "owner-a");
        if !locked {
            return;
        }

        assert_eq!(rechecked, Some(NotReadyReason::ApiKeyStoreUnavailable));
    }

    #[tokio::test]
    async fn requests_that_find_the_same_recheck_due_read_the_folders_once() {
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        let disk_reads = flaky.disk_reads.clone();
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None
        );
        assert_eq!(listings.load(Ordering::SeqCst), 1);
        let before = disk_reads.load(Ordering::SeqCst);
        due_now(enforced.gate, "owner-a");

        let answers = futures::future::join_all((0..5).map(|_| enforced.gate.refuses(&own))).await;

        assert_eq!(answers, vec![None; 5]);
        assert_eq!(disk_reads.load(Ordering::SeqCst) - before, 1, "one read of the one folder");
        assert_eq!(listings.load(Ordering::SeqCst), 1, "a recheck lists no whole store");
    }

    #[tokio::test]
    async fn concurrent_requests_with_no_kept_verdict_list_the_store_once() {
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));

        let answers = futures::future::join_all((0..5).map(|_| enforced.gate.refuses(&own))).await;

        assert_eq!(answers, vec![None; 5]);
        assert_eq!(listings.load(Ordering::SeqCst), 1, "the requests that waited take the kept verdict");
    }

    #[tokio::test]
    async fn concurrent_requests_to_a_variant_and_its_base_are_each_judged_for_their_own_keys() {
        let enforced = gate().await;
        let mut surface = naming("owner-a", "tenant-a", external(KEY_A));
        surface.variants = serde_json::from_value(serde_json::json!([{
            "id": "cross-id", "alias": "cross", "name": "Cross", "enabled": true,
            "overrides": {"identity_slots": {"external": {"type": "from_api_key", "api_key_id": KEY_B}}}
        }]))
        .unwrap();
        let base = base_view(&surface);
        let variant = surface
            .resolve_variant(Some("cross"))
            .unwrap();

        let answers = futures::future::join_all([
            enforced.gate.refuses(&base),
            enforced
                .gate
                .refuses(&variant),
            enforced.gate.refuses(&base),
        ])
        .await;

        assert_eq!(answers, vec![None, Some(NotReadyReason::ProviderKeyTenant), None]);
    }

    #[tokio::test]
    async fn a_request_waiting_on_a_judgment_a_revoke_overtook_is_judged_again() {
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        *flaky
            .revoked_after_disk_read
            .lock()
            .unwrap() = Some((enforced.gate, "owner-a", KEY_A));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));

        let answers = futures::future::join_all((0..2).map(|_| enforced.gate.refuses(&own))).await;

        assert_eq!(
            answers,
            vec![None, Some(NotReadyReason::ApiKeyRevoked)],
            "the first read the key before the revoke; the second never takes that verdict"
        );
        assert_eq!(listings.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_judgment_the_surface_was_forgotten_during_is_not_kept() {
        let enforced = gate().await;
        let keys = FlakyKeys::failing(&enforced, 0);
        enforced.gate.set_sources(
            Some(Arc::new(FlakyKeys {
                forgotten_while_listing: Some((enforced.gate, "owner-a")),
                ..keys
            })),
            Some(enforced.surfaces.clone()),
        );
        let own = naming("owner-a", "tenant-a", external(KEY_A));

        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None
        );
        assert!(
            !enforced
                .gate
                .has_verdict("owner-a"),
            "a verdict read before the surface was forgotten is not kept"
        );
    }

    #[tokio::test]
    async fn the_serving_status_reads_only_the_kept_verdict() {
        use crate::api_keys::store::ApiKeyStore as _;
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        let listings = flaky.listings.clone();
        let disk_reads = flaky.disk_reads.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));

        assert_eq!(
            enforced
                .gate
                .serving_status(&own),
            ServingStatus::NotJudged
        );
        assert_eq!((listings.load(Ordering::SeqCst), disk_reads.load(Ordering::SeqCst)), (0, 0));
        assert!(
            !enforced
                .gate
                .has_verdict("owner-a"),
            "reading the status judges nothing"
        );

        enforced
            .gate
            .admit(&own)
            .await;
        assert_eq!(
            enforced
                .gate
                .serving_status(&own),
            ServingStatus::Serving
        );
        assert_eq!(
            enforced
                .gate
                .serving_status(&naming("owner-a", "tenant-b", external(KEY_A))),
            ServingStatus::NotJudged,
            "a verdict for another tenant does not count"
        );
        due_now(enforced.gate, "owner-a");
        assert_eq!(
            enforced
                .gate
                .serving_status(&own),
            ServingStatus::Serving,
            "a verdict due for a recheck still counts"
        );

        enforced
            .api_keys
            .revoke("owner-a", KEY_A, "test")
            .await
            .unwrap();
        enforced
            .gate
            .key_changed(KEY_A);
        enforced
            .gate
            .refuses(&own)
            .await;
        let reads = (listings.load(Ordering::SeqCst), disk_reads.load(Ordering::SeqCst));
        assert_eq!(
            enforced
                .gate
                .serving_status(&own),
            ServingStatus::NotServing
        );
        assert_eq!((listings.load(Ordering::SeqCst), disk_reads.load(Ordering::SeqCst)), reads);
        assert_eq!(
            serde_json::to_value([ServingStatus::Serving, ServingStatus::NotServing, ServingStatus::NotJudged])
                .unwrap(),
            serde_json::json!(["serving", "not_serving", "not_judged"])
        );
    }

    #[tokio::test]
    async fn rotating_a_key_keeps_its_surface_serving_and_a_revoked_key_stays_revoked() {
        use crate::api_keys::store::ApiKeyStore as _;
        let enforced = gate().await;
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        enforced
            .gate
            .admit(&own)
            .await;

        enforced
            .api_keys
            .rotate("owner-a", KEY_A, "test")
            .await
            .unwrap();
        expire_rechecks(enforced.gate, "owner-a");
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None,
            "a rotated key stays active"
        );

        enforced
            .api_keys
            .revoke("owner-a", KEY_A, "test")
            .await
            .unwrap();
        enforced
            .gate
            .key_changed(KEY_A);
        let rotated = enforced
            .api_keys
            .rotate("owner-a", KEY_A, "test")
            .await;
        assert!(
            rotated
                .as_ref()
                .is_err_and(|error| error.to_string() == format!("API key already revoked: {KEY_A}")),
            "{:?}",
            rotated.map(|created| created.key_id)
        );
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            Some(NotReadyReason::ApiKeyRevoked)
        );
    }

    #[tokio::test]
    async fn a_judgment_a_key_change_overtakes_is_not_kept() {
        let enforced = gate().await;
        let keys = FlakyKeys::failing(&enforced, 0);
        enforced.gate.set_sources(
            Some(Arc::new(FlakyKeys {
                key_changed_while_listing: Some((enforced.gate, KEY_A)),
                ..keys
            })),
            Some(enforced.surfaces.clone()),
        );
        let own = naming("owner-a", "tenant-a", external(KEY_A));

        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None
        );
        assert!(
            !enforced
                .gate
                .has_verdict("owner-a"),
            "a verdict a key change overtook is not kept"
        );
    }

    #[test]
    fn a_revoked_key_is_a_breach_in_both_modes_reported_once_whoever_owns_it() {
        use crate::config::credential_policy::RuleMode;
        let listing = KeyListing::from(HashMap::from([
            (KEY_A.to_string(), vec!["owner-a".to_string()]),
            (KEY_B.to_string(), vec!["owner-b".to_string()]),
        ]))
        .with(&[KEY_A, KEY_B], &[]);
        let tenants: HashMap<&str, Option<&str>> =
            [("owner-a", Some("tenant-a")), ("owner-b", Some("tenant-b"))].into();
        let legacy = |id: &str| ProviderKeyIds {
            keys: Vec::new(),
            legacy_secrets: vec![id.to_string()],
        };
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            let judge = |surface_id: &str, ids: &ProviderKeyIds| {
                judge_provider_keys(surface_id, Some("tenant-a"), ids, Some(&listing), &tenants, mode)
                    .into_iter()
                    .map(|issue| (issue.key_id, issue.kind))
                    .collect::<Vec<_>>()
            };
            let revoked = |id: &str| vec![(id.to_string(), ProviderKeyIssueKind::RevokedKey)];
            assert_eq!(judge("owner-a", &ids(&[KEY_A])), revoked(KEY_A), "{mode:?}: its own key");
            assert_eq!(judge("borrower", &ids(&[KEY_B])), revoked(KEY_B), "{mode:?}: another tenant's key");
            assert_eq!(judge("owner-a", &legacy(KEY_A)), revoked(KEY_A), "{mode:?}: a legacy secret");
            assert_eq!(judge("owner-a", &legacy("atgk_gone")), vec![], "{mode:?}: a legacy secret no key has");
        }
        assert!(ProviderKeyIssueKind::RevokedKey.is_breach());
        assert_eq!(ProviderKeyIssueKind::RevokedKey.as_str(), "revoked_key");
    }

    #[test]
    fn a_key_id_is_listed_revoked_when_any_of_its_records_is() {
        let meta = |agent: &str, status| crate::api_keys::ApiKeyMeta {
            key_id: KEY_A.to_string(),
            agent_id: agent.to_string(),
            status,
            ..serde_json::from_value(serde_json::json!({
                "key_id": KEY_A, "agent_id": agent, "client_id": "client", "status": "active",
                "created_at": "2026-01-01T00:00:00Z", "issuer": {"actor": "test", "method": "test"},
                "needs_rotation": false
            }))
            .unwrap()
        };
        let mut listing = KeyListing::default();
        listing.add(meta("owner-a", crate::api_keys::ApiKeyStatus::Active));
        assert!(!listing.is_revoked(KEY_A));
        listing.add(meta("owner-a", crate::api_keys::ApiKeyStatus::Revoked));
        listing.add(meta("owner-a", crate::api_keys::ApiKeyStatus::Active));
        assert!(listing.is_revoked(KEY_A));
        assert_eq!(listing.owners_of(KEY_A), ["owner-a".to_string()], "an owner is listed once");
    }

    #[test]
    fn the_missing_key_recheck_follows_the_cache_refresh_interval() {
        assert_eq!(missing_key_recheck(), MISSING_KEY_RECHECK);
    }

    #[tokio::test]
    async fn a_key_store_outage_refuses_only_while_it_lasts() {
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 1));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));

        enforced
            .gate
            .admit(&own)
            .await;
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&own),
            Some(API_KEY_STORE_UNAVAILABLE)
        );
        for _ in 0..3 {
            assert_eq!(
                enforced
                    .gate
                    .refuses(&own)
                    .await,
                Some(NotReadyReason::ApiKeyStoreUnavailable)
            );
        }
        assert_eq!(
            listings.load(Ordering::SeqCst),
            1,
            "requests within the recheck answer from the outage verdict without reading the store"
        );

        expire_rechecks(enforced.gate, "owner-a");
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None,
            "served once the recheck is due and the store can be read"
        );
        assert_eq!(listings.load(Ordering::SeqCst), 2);
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&own),
            None
        );
        assert_eq!(
            enforced
                .gate
                .refuses(&own)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn admitting_many_surfaces_reads_the_api_key_store_once() {
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        let cross = naming("cross", "tenant-a", external(KEY_B));
        let missing = naming("missing", "tenant-a", external("atgk_gate_missing"));
        let plain = naming("plain", "tenant-a", serde_json::json!({}));

        enforced
            .gate
            .admit_all([&own, &cross, &missing, &plain])
            .await;

        assert_eq!(listings.load(Ordering::SeqCst), 1);
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&own),
            None
        );
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&cross),
            Some(PROVIDER_KEY_TENANT_RULE)
        );
        assert!(
            enforced
                .gate
                .has_verdict("missing")
        );
        assert!(
            !enforced
                .gate
                .has_verdict("plain"),
            "a surface naming no key id keeps no verdict"
        );
    }

    /// The provider key rows the credential policy report gives `surfaces` from `owners`.
    fn report_rows(
        surfaces: &[AgentSurface],
        owners: Option<&KeyListing>,
    ) -> Vec<(String, &'static str, bool)> {
        crate::identity::handlers::credential_policy_report::find_breaches(
            &[],
            surfaces,
            &HashMap::new(),
            owners,
            &crate::delegation_vault::oauth::TokenEgress::from_environment(),
            &crate::config::target_auth_rules::HttpsMcpProxies::default(),
        )
        .provider_keys
        .into_iter()
        .map(|finding| (finding.surface_id, finding.issue.kind.as_str(), finding.issue.kind.is_breach()))
        .collect()
    }

    const REPORT_OUTAGE: &str = "Credential policy report: the API key store cannot be read";

    #[tokio::test]
    async fn the_credential_policy_report_judges_from_the_listing_the_admission_read() {
        use crate::identity::handlers::credential_policy_report::report_key_owners;
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky.clone()), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        let cross = naming("cross", "tenant-a", external(KEY_B));
        let stored = [own.clone(), cross.clone(), naming("owner-b", "tenant-b", serde_json::json!({}))];

        let listed = enforced
            .gate
            .admit_all([&own, &cross])
            .await;
        let owners = report_key_owners(listed, Some(flaky.as_ref()), &stored).await;

        assert_eq!(listings.load(Ordering::SeqCst), 1, "one listing for the admission and the report");
        assert_eq!(report_rows(&stored, owners.as_ref()), vec![("cross".to_string(), "other_tenant", true)]);
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&cross),
            Some(PROVIDER_KEY_TENANT_RULE),
            "the gate refuses the surface the report lists"
        );
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&own),
            None
        );
    }

    #[tokio::test]
    async fn the_credential_policy_report_reads_the_store_once_only_when_the_admission_did_not() {
        use crate::identity::handlers::credential_policy_report::report_key_owners;
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky.clone()), Some(enforced.surfaces.clone()));
        let plain = naming("plain", "tenant-a", serde_json::json!({}));
        let mut inactive = naming("inactive", "tenant-a", external(KEY_B));
        inactive.status = crate::config::agent_surface::SurfaceStatus::Disabled;

        let listed = enforced
            .gate
            .admit_all([&plain])
            .await;
        assert!(listed.is_none());
        let owners = report_key_owners(listed, Some(flaky.as_ref()), &[plain.clone(), inactive.clone()]).await;
        assert_eq!(listings.load(Ordering::SeqCst), 1, "the report reads for a stored surface naming a key id");
        assert_eq!(
            owners
                .unwrap()
                .owners_of(KEY_B),
            ["owner-b".to_string()]
        );

        assert_eq!(report_key_owners(None, Some(flaky.as_ref()), &[plain]).await, None);
        assert_eq!(listings.load(Ordering::SeqCst), 1, "no surface names a key id: no listing");
    }

    #[tokio::test]
    async fn the_credential_policy_report_lists_an_outage_as_store_unavailable_and_logs_it_once() {
        use crate::identity::handlers::credential_policy_report::report_key_owners;
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 1));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky.clone()), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        let cross = naming("cross", "tenant-a", external(KEY_B));
        let stored = [own.clone(), cross.clone(), naming("owner-b", "tenant-b", serde_json::json!({}))];

        let listed = enforced
            .gate
            .admit_all([&own, &cross])
            .await;
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let owners = report_key_owners(listed, Some(flaky.as_ref()), &stored).await;
        let text = logs.text();

        assert_eq!(owners, None);
        assert_eq!(listings.load(Ordering::SeqCst), 1, "the report does not read the store again");
        assert_eq!(
            text.matches(REPORT_OUTAGE)
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("listing API keys failed") && !text.contains("atgs_"), "{text}");
        assert_eq!(
            report_rows(&stored, owners.as_ref()),
            vec![("owner-a".to_string(), "store_unavailable", true), ("cross".to_string(), "store_unavailable", true),]
        );
    }

    #[tokio::test]
    async fn a_key_whose_owning_surface_is_gone_is_refused_when_enforced() {
        let enforced = enforced_gate(
            &[("owner-a", Some("tenant-a"))],
            &[("owner-a", KEY_A), ("deleted-owner", "atgk_gate_orphan")],
        )
        .await;
        let orphan = naming("orphan", "tenant-a", external("atgk_gate_orphan"));

        assert_eq!(
            enforced
                .gate
                .refuses(&orphan)
                .await,
            Some(NotReadyReason::ProviderKeyTenant)
        );
        assert_eq!(
            enforced
                .gate
                .refuses(&naming("owner-a", "tenant-a", external(KEY_A)))
                .await,
            None
        );

        crate::config::credential_policy::use_thread_credential_policy(
            crate::config::credential_policy::CredentialPolicyConfig {
                tenant_credential_isolation: crate::config::credential_policy::RuleMode::Warn,
                ..Default::default()
            },
        );
        enforced.gate.forget("orphan");
        assert_eq!(
            enforced
                .gate
                .refuses(&orphan)
                .await,
            None,
            "under warn it is only logged"
        );
    }

    #[tokio::test]
    async fn a_key_of_another_surface_of_the_same_tenant_is_refused_only_when_enforced() {
        let enforced = gate().await;
        let borrower = naming("borrower", "tenant-a", external(KEY_A));

        assert_eq!(
            enforced
                .gate
                .refuses(&borrower)
                .await,
            Some(NotReadyReason::ProviderKeyTenant)
        );
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&borrower),
            Some(PROVIDER_KEY_TENANT_RULE)
        );

        crate::config::credential_policy::use_thread_credential_policy(
            crate::config::credential_policy::CredentialPolicyConfig {
                tenant_credential_isolation: crate::config::credential_policy::RuleMode::Warn,
                ..Default::default()
            },
        );
        enforced
            .gate
            .forget("borrower");
        assert_eq!(
            enforced
                .gate
                .refuses(&borrower)
                .await,
            None,
            "under warn it is only logged"
        );
    }

    #[test]
    fn another_surfaces_key_is_judged_other_surface_and_another_tenants_only_other_tenant() {
        let owners: KeyListing = HashMap::from([
            (KEY_A.to_string(), vec!["owner-a".to_string()]),
            (KEY_B.to_string(), vec!["owner-b".to_string()]),
        ])
        .into();
        let tenants: HashMap<&str, Option<&str>> =
            [("owner-a", Some("tenant-a")), ("owner-b", Some("tenant-b"))].into();
        let judge = |surface_id: &str, ids: &ProviderKeyIds, isolation| {
            judge_provider_keys(surface_id, Some("tenant-a"), ids, Some(&owners), &tenants, isolation)
                .into_iter()
                .map(|issue| (issue.key_id, issue.kind))
                .collect::<Vec<_>>()
        };
        let enforce = crate::config::credential_policy::RuleMode::Enforce;
        let warn = crate::config::credential_policy::RuleMode::Warn;

        assert_eq!(judge("owner-a", &ids(&[KEY_A]), enforce), vec![]);
        assert_eq!(
            judge("borrower", &ids(&[KEY_A, KEY_B]), enforce),
            vec![
                (KEY_A.to_string(), ProviderKeyIssueKind::OtherSurface { enforced: true }),
                (KEY_B.to_string(), ProviderKeyIssueKind::OtherTenant { enforced: true }),
            ]
        );
        assert_eq!(
            judge("borrower", &ids(&[KEY_A]), warn),
            vec![(KEY_A.to_string(), ProviderKeyIssueKind::OtherSurface { enforced: false })]
        );
        let legacy = ProviderKeyIds {
            keys: Vec::new(),
            legacy_secrets: vec![KEY_A.to_string()],
        };
        assert_eq!(
            judge("borrower", &legacy, enforce),
            vec![(KEY_A.to_string(), ProviderKeyIssueKind::OtherSurface { enforced: true })]
        );
        assert_eq!(judge("owner-a", &legacy, enforce), vec![]);
        let mistenanted: HashMap<&str, Option<&str>> = [("owner-a", Some("tenant-b"))].into();
        for surface_tenants in [&mistenanted, &HashMap::new()] {
            assert_eq!(
                judge_provider_keys(
                    "owner-a",
                    Some("tenant-a"),
                    &ids(&[KEY_A]),
                    Some(&owners),
                    surface_tenants,
                    enforce
                ),
                vec![],
                "its own key, whatever tenant the stores read for it or none"
            );
        }
        assert!(ProviderKeyIssueKind::OtherSurface { enforced: true }.is_breach());
        assert!(!ProviderKeyIssueKind::OtherSurface { enforced: false }.is_breach());
        assert_eq!(ProviderKeyIssueKind::OtherSurface { enforced: true }.as_str(), "other_surface");
    }

    fn legacy_secret(key_id: &str) -> serde_json::Value {
        serde_json::json!({
            "identity_slots": {"inbound": {"type": "from_api_key"}},
            "access_point": {
                "listen_address": "https://gateway.example", "route": "/legacy", "protocol": "a2a",
                "caller_authentication": {"methods": [{
                    "type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": key_id
                }]}
            }
        })
    }

    #[tokio::test]
    async fn an_unreadable_key_folder_refuses_only_the_surfaces_naming_an_id_no_loaded_folder_holds() {
        use crate::identity::handlers::credential_policy_report::report_key_owners;
        let enforced = gate().await;
        let locked = lock_folder(&enforced, "owner-b");
        let fresh = Arc::new(other_node(&enforced).await);
        enforced
            .gate
            .set_sources(Some(fresh.clone()), Some(enforced.surfaces.clone()));
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        let cross = naming("cross", "tenant-a", external(KEY_B));
        let legacy = naming("legacy", "tenant-a", legacy_secret(KEY_B));
        let borrower = naming("borrower", "tenant-a", external(KEY_A));

        let answers = [
            enforced
                .gate
                .refuses(&own)
                .await,
            enforced
                .gate
                .refuses(&cross)
                .await,
            enforced
                .gate
                .refuses(&legacy)
                .await,
            enforced
                .gate
                .refuses(&borrower)
                .await,
        ];
        let cross_found = enforced
            .gate
            .entries
            .get("cross")
            .map(|entry| entry.found.clone());
        let stored = [own.clone(), cross.clone(), legacy.clone()];
        let reported = report_key_owners(None, Some(fresh.as_ref()), &stored).await;
        unlock_folder(&enforced, "owner-b");
        if !locked {
            return;
        }

        let unavailable = Some(NotReadyReason::ApiKeyStoreUnavailable);
        assert_eq!(
            answers,
            [None, unavailable, unavailable, Some(NotReadyReason::ProviderKeyTenant)],
            "a found id is judged as usual; an id only the unreadable folder may hold is refused"
        );
        assert_eq!(cross_found, Some(HashSet::new()), "an id no loaded folder holds is not found");
        assert_eq!(
            enforced
                .gate
                .recorded_refusal(&cross),
            Some(API_KEY_STORE_UNAVAILABLE),
            "the kept verdict gives the reason the request was answered with"
        );
        assert_eq!(
            report_rows(&stored, reported.as_ref()),
            vec![("cross".to_string(), "store_unavailable", true), ("legacy".to_string(), "store_unavailable", true)]
        );
    }

    #[tokio::test]
    async fn admitting_surfaces_while_one_naming_its_own_key_has_an_unreadable_folder_refuses_only_that_one() {
        let enforced = enforced_gate(
            &[("owner-a", Some("tenant-a")), ("owner-x", Some("tenant-a"))],
            &[("owner-a", KEY_A), ("owner-x", "atgk_gate_x")],
        )
        .await;
        let own = naming("owner-a", "tenant-a", external(KEY_A));
        let locked_own = naming("owner-x", "tenant-a", external("atgk_gate_x"));
        let locked = lock_folder(&enforced, "owner-x");

        enforced
            .gate
            .admit_all([&locked_own, &own])
            .await;
        let refusals = [
            enforced
                .gate
                .recorded_refusal(&own),
            enforced
                .gate
                .recorded_refusal(&locked_own),
        ];
        unlock_folder(&enforced, "owner-x");
        if !locked {
            return;
        }

        assert_eq!(refusals, [None, Some(API_KEY_STORE_UNAVAILABLE)]);
    }

    #[tokio::test]
    async fn a_partial_outage_is_logged_once_naming_its_folders_and_its_end_once_none_is_skipped() {
        let enforced = gate().await;
        let locked = lock_folder(&enforced, "owner-b");
        enforced
            .gate
            .set_sources(Some(Arc::new(other_node(&enforced).await)), Some(enforced.surfaces.clone()));
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

        for surface in [naming("owner-a", "tenant-a", external(KEY_A)), naming("cross", "tenant-a", external(KEY_B))] {
            enforced
                .gate
                .refuses(&surface)
                .await;
        }
        let during = logs.text();
        unlock_folder(&enforced, "owner-b");
        enforced
            .gate
            .refuses(&naming("later", "tenant-a", external(KEY_A)))
            .await;
        let after = logs.text();
        if !locked {
            return;
        }

        const PARTIAL: &str = "API key folders could not be loaded";
        const READABLE: &str = "The API key store can be read again";
        assert_eq!(
            during
                .matches(PARTIAL)
                .count(),
            1,
            "{during}"
        );
        assert!(during.contains("owner-b"), "{during}");
        assert!(!during.contains(READABLE), "{during}");
        assert_eq!(
            after
                .matches(READABLE)
                .count(),
            1,
            "{after}"
        );
    }

    #[tokio::test]
    async fn admitting_surfaces_naming_no_key_id_reads_no_store() {
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 0));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));

        enforced
            .gate
            .admit_all([&naming("plain", "tenant-a", serde_json::json!({}))])
            .await;

        assert_eq!(listings.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_outage_during_admission_refuses_every_surface_naming_a_key_id() {
        let enforced = gate().await;
        let flaky = Arc::new(FlakyKeys::failing(&enforced, 1));
        let listings = flaky.listings.clone();
        enforced
            .gate
            .set_sources(Some(flaky), Some(enforced.surfaces.clone()));
        let own = naming("own", "tenant-a", external(KEY_A));
        let other = naming("other", "tenant-b", external(KEY_B));

        enforced
            .gate
            .admit_all([&own, &other])
            .await;

        assert_eq!(listings.load(Ordering::SeqCst), 1);
        for surface in [&own, &other] {
            assert_eq!(
                enforced
                    .gate
                    .refuses(surface)
                    .await,
                Some(NotReadyReason::ApiKeyStoreUnavailable)
            );
        }
        assert_eq!(listings.load(Ordering::SeqCst), 1);
    }
}
