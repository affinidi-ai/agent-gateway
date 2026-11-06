//! Readiness of a surface that derives a DID from an API Key Provider key id. The request path
//! derives such a DID with no key lookup, so a stored surface naming a key it may not use is
//! held back here: under `tenant_credential_isolation: warn` it is only logged, under `enforce`
//! it is not ready, and while the API key store cannot be read a surface naming a key id that has
//! not been checked is not ready. Verdicts are taken when a surface goes live and on the first
//! request that finds none for the key ids the served surface names, and kept per surface id; a
//! key id judged while the store could not be read, like one found missing, is judged again once
//! its recheck is due, and the verdicts that read a surface as a key's owner are dropped when that
//! surface changes. Admitting the surfaces of a boot or reload reads the API key store once.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tracing::{info, warn};

use crate::config::agent_surface::AgentSurface;
use crate::identity::handlers::surface_tenancy::{
    ProviderKeyIds, ProviderKeyIssue, ProviderKeyIssueKind, judge_provider_keys, provider_key_ids,
    provider_key_owners_in, served_provider_key_ids,
};
use crate::source_auth::errors::NotReadyReason;

/// The rule a provider-key refusal and its log lines name.
pub const PROVIDER_KEY_TENANT_RULE: &str = "provider_key_tenant";

/// The reason a surface naming a key id is not ready while the API key store cannot be read.
pub const API_KEY_STORE_UNAVAILABLE: &str = "api_key_store_unavailable";

/// How long a key id found missing, whose owning surface was missing, or judged while the API
/// key store could not be read, is kept as judged without `cache_refresh_interval_secs`. A key
/// another node creates shows up in this node's API key store at the next listing, so the id is
/// judged again after this long, but no sooner: a surface naming a key that does not exist, or
/// served while the store cannot be read, lists the API key store at most this often.
const MISSING_KEY_RECHECK: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a missing key id is kept as judged: `cache_refresh_interval_secs` when set, the
/// interval at which this node's stores pick up other nodes' writes, else
/// [`MISSING_KEY_RECHECK`].
fn missing_key_recheck() -> std::time::Duration {
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

/// The surfaces owning each key, by key id, and the store their tenants are read from.
struct Owners {
    keys: HashMap<String, Vec<String>>,
    surfaces: Arc<dyn crate::surfaces::AgentSurfaceStore>,
}

/// The key ids judged for a surface of `tenant_id`, those of them it may not use, those judged
/// while the stores could not be read, the surfaces read as their owners, and when each id found
/// missing or judged during an outage is judged again.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    tenant_id: Option<String>,
    judged: HashSet<String>,
    refused: HashSet<String>,
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
        (self.tenant_id.as_deref() == tenant_id
            && ids.all().all(|id| {
                self.judged.contains(id)
                    && self
                        .recheck
                        .get(id)
                        .is_none_or(|at| now < *at)
            }))
        .then(|| {
            if ids
                .all()
                .any(|id| self.unavailable.contains(id))
            {
                return Some(NotReadyReason::ApiKeyStoreUnavailable);
            }
            ids.all()
                .any(|id| self.refused.contains(id))
                .then_some(NotReadyReason::ProviderKeyTenant)
        })
    }

    /// The verdict `issues` gives for `ids`, judging an id found missing, or one the stores
    /// could not judge, again at `recheck_at`.
    fn of(
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
        verdict: &Verdict,
        recheck_at: Instant,
    ) -> Self {
        Self {
            tenant_id: surface.tenant_id.clone(),
            judged: ids.all().cloned().collect(),
            unavailable: verdict
                .issues
                .iter()
                .filter(|issue| issue.kind == ProviderKeyIssueKind::StoreUnavailable)
                .map(|issue| issue.key_id.clone())
                .collect(),
            refused: verdict
                .issues
                .iter()
                .filter(|issue| issue.kind.is_breach() && issue.kind != ProviderKeyIssueKind::StoreUnavailable)
                .map(|issue| issue.key_id.clone())
                .collect(),
            owners: verdict.owners.clone(),
            recheck: verdict
                .issues
                .iter()
                .filter(|issue| {
                    matches!(
                        issue.kind,
                        ProviderKeyIssueKind::MissingKey
                            | ProviderKeyIssueKind::MissingOwner { .. }
                            | ProviderKeyIssueKind::StoreUnavailable
                    )
                })
                .map(|issue| (issue.key_id.clone(), recheck_at))
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
            self.refused.remove(id);
            self.unavailable.remove(id);
            self.recheck.remove(id);
        }
        self.judged
            .extend(later.judged);
        self.refused
            .extend(later.refused);
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
    owners: HashSet<String>,
    store_unavailable: bool,
}

impl Verdict {
    fn reason(&self) -> Option<NotReadyReason> {
        if self.store_unavailable {
            return Some(NotReadyReason::ApiKeyStoreUnavailable);
        }
        self.issues
            .iter()
            .any(|issue| issue.kind.is_breach())
            .then_some(NotReadyReason::ProviderKeyTenant)
    }
}

#[derive(Default)]
pub struct ProviderKeyGate {
    sources: std::sync::RwLock<Sources>,
    entries: DashMap<String, Entry>,
    owner_changes: AtomicU64,
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
    /// key store, which is read only when one of them names a key id.
    pub async fn admit_all<'a>(
        &self,
        surfaces: impl IntoIterator<Item = &'a AgentSurface>,
    ) {
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
            return;
        }
        let owner_changes = self.owner_changes();
        let listing = self.list_owners().await;
        for (surface, ids) in naming {
            let verdict = self
                .judge_from(surface, &ids, &listing)
                .await;
            let judged = Entry::of(surface, &ids, &verdict, self.recheck_at());
            match self
                .entries
                .entry(surface.surface_id.clone())
            {
                dashmap::Entry::Occupied(kept) if self.owner_changes() != owner_changes => {
                    kept.remove();
                }
                dashmap::Entry::Occupied(mut kept) => *kept.get_mut() = judged,
                dashmap::Entry::Vacant(vacant) if self.owner_changes() == owner_changes => {
                    vacant.insert(judged);
                }
                dashmap::Entry::Vacant(_) => {}
            }
        }
    }

    /// Drops the verdict of a surface that no longer serves.
    pub fn forget(
        &self,
        surface_id: &str,
    ) {
        self.entries
            .remove(surface_id);
    }

    /// Drops every verdict that read `surface_id` as the owner of a key, so a surface naming its
    /// keys is judged again on its next request after the owner's tenant changes or it is gone. A
    /// judgment already reading the stores when this runs is not kept.
    pub fn owner_changed(
        &self,
        surface_id: &str,
    ) {
        self.owner_changes
            .fetch_add(1, Ordering::SeqCst);
        self.entries
            .retain(|_, entry| {
                !entry
                    .owners
                    .contains(surface_id)
            });
    }

    /// Why a request to `surface`, as served, is refused because it derives a DID from a key id,
    /// if it is. A served surface naming an id no verdict covers is judged now.
    pub async fn refuses(
        &self,
        surface: &AgentSurface,
    ) -> Option<NotReadyReason> {
        let ids = served_provider_key_ids(surface).unwrap_or_else(|_| ids_of(surface));
        if ids.is_empty() {
            return None;
        }
        if let Some(reason) = self
            .entries
            .get(&surface.surface_id)
            .and_then(|entry| entry.decides(surface.tenant_id.as_deref(), &ids, Instant::now()))
        {
            return reason;
        }
        let owner_changes = self.owner_changes();
        let verdict = self
            .judge(surface, &ids)
            .await;
        let judged = Entry::of(surface, &ids, &verdict, self.recheck_at());
        match self
            .entries
            .entry(surface.surface_id.clone())
        {
            _ if self.owner_changes() != owner_changes => {}
            dashmap::Entry::Occupied(mut kept) => kept.get_mut().merge(judged),
            dashmap::Entry::Vacant(vacant) => {
                vacant.insert(judged);
            }
        }
        verdict.reason()
    }

    /// How many key owners have changed, read before a judgment and again, under the entry's
    /// lock, before its verdict is kept.
    fn owner_changes(&self) -> u64 {
        self.owner_changes
            .load(Ordering::SeqCst)
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
            Some(_) => Some(PROVIDER_KEY_TENANT_RULE),
            None => None,
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

    /// When a key id found missing now is judged again.
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

    /// The owners of every key, read from the API key store, or why they cannot be.
    async fn list_owners(&self) -> Result<Owners, &'static str> {
        let sources = self
            .sources
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (Some(api_keys), Some(surfaces)) = (sources.api_keys, sources.surfaces) else {
            return Err("the API key store is not configured");
        };
        let keys = provider_key_owners_in(api_keys.as_ref())
            .await
            .map_err(|_| "listing API keys failed")?;
        Ok(Owners { keys, surfaces })
    }

    async fn judge(
        &self,
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
    ) -> Verdict {
        let listing = self.list_owners().await;
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
        let Owners { keys: owners, surfaces } = match listing {
            Ok(owners) => owners,
            Err(cause) => return self.store_outage(tenant_id, ids, isolation, cause),
        };
        let mut owner_ids: Vec<String> = Vec::new();
        for id in ids.all() {
            for owner_id in owners
                .get(id)
                .into_iter()
                .flatten()
            {
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
                Err(_) => return self.store_outage(tenant_id, ids, isolation, "reading a key's surface failed"),
            }
        }
        if self
            .store_outage_logged
            .swap(false, Ordering::Relaxed)
        {
            info!("The API key store can be read again: surfaces naming an API key id are judged as they serve");
        }
        let owner_tenants: HashMap<&str, Option<&str>> = owner_tenants
            .iter()
            .map(|(id, tenant)| (id.as_str(), tenant.as_deref()))
            .collect();
        let issues = judge_provider_keys(tenant_id, ids, Some(owners), &owner_tenants, isolation);
        log(surface, &issues);
        Verdict {
            issues,
            owners: owner_ids
                .into_iter()
                .collect(),
            store_unavailable: false,
        }
    }

    /// The verdict while the stores cannot be read: every id unjudged and the surface not
    /// ready. The outage is logged once, until the stores can be read again.
    fn store_outage(
        &self,
        tenant_id: Option<&str>,
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
            issues: judge_provider_keys(tenant_id, ids, None, &HashMap::new(), isolation),
            owners: HashSet::new(),
            store_unavailable: true,
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
        "Surface derives a DID from an API key it may not use, or whose key or surface is gone"
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
        _dir: tempfile::TempDir,
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
        EnforcedGate {
            gate,
            api_keys,
            surfaces,
            _dir: dir,
        }
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
            judged: [KEY_A.to_string(), KEY_B.to_string(), "atgk_missing".to_string(), "atgk_unread".to_string()]
                .into(),
            refused: [KEY_B.to_string()].into(),
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
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&["atgk_missing"]), now), Some(None));
        assert_eq!(
            entry.decides(Some("tenant-a"), &ids(&["atgk_missing"]), later),
            None,
            "a missing key is judged again once its recheck is due"
        );
        assert_eq!(entry.decides(Some("tenant-a"), &ids(&[KEY_A, "atgk_unread"]), now), Some(Some(outage)));
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
        let names_a = naming("names-a", "tenant-a", external(KEY_A));
        let names_b = naming("names-b", "tenant-b", external(KEY_B));
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
                .has_verdict("names-a")
        );
        assert!(
            enforced
                .gate
                .has_verdict("names-b"),
            "a verdict that read another owner is kept"
        );
        assert_eq!(
            enforced
                .gate
                .refuses(&names_a)
                .await,
            Some(NotReadyReason::ProviderKeyTenant)
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
        let names_a = naming("names-a", "tenant-a", external(KEY_A));

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
                .has_verdict("names-a"),
            "a request's verdict that an owner change overtook is not kept"
        );

        enforced
            .gate
            .admit(&names_a)
            .await;
        assert!(
            !enforced
                .gate
                .has_verdict("names-a"),
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
                .has_verdict("names-a")
        );
    }

    #[tokio::test]
    async fn a_request_adds_what_it_judges_to_the_surfaces_verdict() {
        let enforced = gate().await;
        let own = naming("names", "tenant-a", external(KEY_A));
        let cross = naming("names", "tenant-a", external(KEY_B));

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
            .get("names")
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

        let moved = naming("names", "tenant-b", external(KEY_B));
        assert_eq!(
            enforced
                .gate
                .refuses(&moved)
                .await,
            None,
            "a tenant change is judged afresh"
        );
        assert_eq!(
            enforced
                .gate
                .entries
                .get("names")
                .unwrap()
                .tenant_id
                .as_deref(),
            Some("tenant-b")
        );
    }

    #[tokio::test]
    async fn a_variant_naming_a_key_the_base_does_not_is_refused_only_where_it_serves() {
        let enforced = gate().await;
        let mut surface = naming("variants", "tenant-a", external(KEY_A));
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
            .forget("variants");
        assert!(
            !enforced
                .gate
                .has_verdict("variants")
        );
    }

    struct FlakyKeys {
        inner: Arc<crate::api_keys::FileSystemApiKeyStore>,
        failures: AtomicUsize,
        listings: Arc<AtomicUsize>,
        owner_changed_while_listing: Option<(&'static ProviderKeyGate, &'static str)>,
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
        let mut surface = naming("partly", "tenant-a", external(KEY_A));
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
            None,
            "a missing key is no breach"
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
            None,
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
        assert!(entry.recheck.is_empty() && entry.refused.contains(later), "{entry:?}");
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
        let own = naming("outage", "tenant-a", external(KEY_A));

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

        expire_rechecks(enforced.gate, "outage");
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
        let own = naming("own", "tenant-a", external(KEY_A));
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
                .refuses(&naming("own", "tenant-a", external(KEY_A)))
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
