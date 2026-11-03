//! Readiness of a surface that derives a DID from an API Key Provider key id. The request path
//! derives such a DID with no key lookup, so a stored surface naming a key it may not use is
//! held back here: under `tenant_credential_isolation: warn` an appliance-wide key is only
//! logged, and any other breach, or an API key store that cannot be read, makes the surface not
//! ready. Verdicts are taken when a surface goes live and on the first request that finds none
//! for the key ids the served surface names, and kept per surface id.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::warn;

use crate::config::agent_surface::AgentSurface;
use crate::identity::handlers::surface_tenancy::{
    ProviderKeyIds, ProviderKeyIssue, judge_provider_keys, provider_key_ids, provider_key_owners_in,
    served_provider_key_ids,
};

/// The rule a provider-key refusal and its log lines name.
pub const PROVIDER_KEY_TENANT_RULE: &str = "provider_key_tenant";

#[derive(Clone, Default)]
struct Sources {
    api_keys: Option<Arc<dyn crate::api_keys::store::ApiKeyStore>>,
    surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
}

/// The key ids judged for a surface of `tenant_id`, and those of them it may not use.
struct Entry {
    tenant_id: Option<String>,
    judged: HashSet<String>,
    refused: HashSet<String>,
}

impl Entry {
    /// Whether the entry judged every id of `ids` for `tenant_id`, and if so whether one is refused.
    fn decides(
        &self,
        tenant_id: Option<&str>,
        ids: &ProviderKeyIds,
    ) -> Option<bool> {
        (self.tenant_id.as_deref() == tenant_id
            && ids
                .all()
                .all(|id| self.judged.contains(id)))
        .then(|| {
            ids.all()
                .any(|id| self.refused.contains(id))
        })
    }
}

#[derive(Default)]
pub struct ProviderKeyGate {
    sources: std::sync::RwLock<Sources>,
    entries: DashMap<String, Entry>,
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
        let ids = ids_of(surface);
        if ids.is_empty() {
            self.entries
                .remove(&surface.surface_id);
            return;
        }
        let issues = self
            .judge(surface, &ids)
            .await;
        self.entries
            .insert(surface.surface_id.clone(), entry(surface, &ids, &issues));
    }

    /// Drops the verdict of a surface that no longer serves.
    pub fn forget(
        &self,
        surface_id: &str,
    ) {
        self.entries
            .remove(surface_id);
    }

    /// Whether a request to `surface`, as served, is refused because it derives a DID from a key
    /// id it may not use. A served surface naming an id no verdict covers is judged now.
    pub async fn refuses(
        &self,
        surface: &AgentSurface,
    ) -> bool {
        let ids = served_provider_key_ids(surface).unwrap_or_else(|_| ids_of(surface));
        if ids.is_empty() {
            return false;
        }
        if let Some(refused) = self
            .entries
            .get(&surface.surface_id)
            .and_then(|entry| entry.decides(surface.tenant_id.as_deref(), &ids))
        {
            return refused;
        }
        let issues = self
            .judge(surface, &ids)
            .await;
        let judged = entry(surface, &ids, &issues);
        let refused = !judged.refused.is_empty();
        let mut kept = self
            .entries
            .entry(surface.surface_id.clone())
            .or_insert_with(|| Entry {
                tenant_id: surface.tenant_id.clone(),
                judged: HashSet::new(),
                refused: HashSet::new(),
            });
        if kept.tenant_id != judged.tenant_id {
            *kept = judged;
        } else {
            kept.judged
                .extend(judged.judged);
            kept.refused
                .extend(judged.refused);
        }
        refused
    }

    /// The rule a kept verdict refuses `surface` under, for the admin API; `None` when no verdict
    /// refuses it or none covers its key ids yet.
    pub fn recorded_refusal(
        &self,
        surface: &AgentSurface,
    ) -> Option<&'static str> {
        let ids = ids_of(surface);
        if ids.is_empty() {
            return None;
        }
        self.entries
            .get(&surface.surface_id)?
            .decides(surface.tenant_id.as_deref(), &ids)?
            .then_some(PROVIDER_KEY_TENANT_RULE)
    }

    async fn judge(
        &self,
        surface: &AgentSurface,
        ids: &ProviderKeyIds,
    ) -> Vec<ProviderKeyIssue> {
        let isolation = crate::config::credential_policy::credential_policy().tenant_credential_isolation;
        let tenant_id = surface.tenant_id.as_deref();
        let sources = self
            .sources
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (Some(api_keys), Some(surfaces)) = (sources.api_keys, sources.surfaces) else {
            return log(surface, judge_provider_keys(tenant_id, ids, None, &HashMap::new(), isolation));
        };
        let Ok(owners) = provider_key_owners_in(api_keys.as_ref()).await else {
            return log(surface, judge_provider_keys(tenant_id, ids, None, &HashMap::new(), isolation));
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
        for owner_id in owner_ids {
            match surfaces.get(&owner_id).await {
                Ok(Some(owner)) => owner_tenants.push((owner_id, owner.tenant_id)),
                Ok(None) => {}
                Err(_) => {
                    return log(surface, judge_provider_keys(tenant_id, ids, None, &HashMap::new(), isolation));
                }
            }
        }
        let owner_tenants: HashMap<&str, Option<&str>> = owner_tenants
            .iter()
            .map(|(id, tenant)| (id.as_str(), tenant.as_deref()))
            .collect();
        log(surface, judge_provider_keys(tenant_id, ids, Some(&owners), &owner_tenants, isolation))
    }
}

fn entry(
    surface: &AgentSurface,
    ids: &ProviderKeyIds,
    issues: &[ProviderKeyIssue],
) -> Entry {
    Entry {
        tenant_id: surface.tenant_id.clone(),
        judged: ids.all().cloned().collect(),
        refused: issues
            .iter()
            .filter(|issue| issue.kind.is_breach())
            .map(|issue| issue.key_id.clone())
            .collect(),
    }
}

/// One line per verdict that finds anything: the surface, its tenant, the rule, and each key id
/// with its issue. Never a secret.
fn log(
    surface: &AgentSurface,
    issues: Vec<ProviderKeyIssue>,
) -> Vec<ProviderKeyIssue> {
    if !issues.is_empty() {
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
    issues
}
