//! Appliance-wide (global) policy assignments: reusable policies enforced on
//! **every** object of a plane (every gateway, or every agent surface),
//! independent of each object's own OPA configuration. Evaluated deny-overrides
//! alongside the per-object policies at the enforcement point.

use crate::policies::policy_definitions::{FileSystemPolicyDefinitionStore, PolicyType, content_hash};
use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{error, warn};

/// The fixed document id — there is exactly one global-assignments document.
const GLOBAL_DOC_ID: &str = "global";

/// The two policy planes that can be enforced appliance-wide.
pub const PLANE_GATEWAY: &str = "gateway";
pub const PLANE_AGENT_SURFACE: &str = "agent_surface";

/// One globally-enforced policy assignment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobalAssignment {
    /// Stored policy-definition id enforced globally for the plane.
    pub policy_id: String,
    /// When true the policy is evaluated and recorded but **not** enforced (a
    /// would-be deny is logged and the request proceeds) — for safe rollout.
    #[serde(default)]
    pub monitor_only: bool,
}

/// Appliance-wide policy assignments, keyed by plane (`gateway`,
/// `agent_surface`). Persisted as a single document.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct GlobalPolicyAssignments {
    /// Ordered assignments per plane. A missing/empty key means no global policy
    /// is enforced for that plane.
    #[serde(default)]
    pub assignments: HashMap<String, Vec<GlobalAssignment>>,
}

impl GlobalPolicyAssignments {
    /// Whether any assignment (across all planes) references `policy_id` — used
    /// to recompile the global set when a referenced policy definition changes.
    pub fn references_policy(
        &self,
        policy_id: &str,
    ) -> bool {
        self.assignments
            .values()
            .flatten()
            .any(|a| a.policy_id == policy_id)
    }

    /// Drop every assignment of `policy_id` across all planes, removing planes
    /// left empty. Returns whether anything was removed.
    pub fn remove_policy(
        &mut self,
        policy_id: &str,
    ) -> bool {
        let before = self
            .assignments
            .values()
            .map(Vec::len)
            .sum::<usize>();
        for list in self.assignments.values_mut() {
            list.retain(|a| a.policy_id != policy_id);
        }
        self.assignments
            .retain(|_, list| !list.is_empty());
        let after = self
            .assignments
            .values()
            .map(Vec::len)
            .sum::<usize>();
        after != before
    }

    /// The planes that enforce `policy_id` appliance-wide — used to report a
    /// policy's blast radius.
    pub fn planes_enforcing(
        &self,
        policy_id: &str,
    ) -> Vec<String> {
        self.assignments
            .iter()
            .filter(|(_, list)| {
                list.iter()
                    .any(|a| a.policy_id == policy_id)
            })
            .map(|(plane, _)| plane.clone())
            .collect()
    }
}

/// The Rego query path for a plane, or `None` for an unknown plane.
fn plane_query(plane: &str) -> Option<String> {
    let pkg = match plane {
        PLANE_GATEWAY => super::GATEWAY_POLICY_PACKAGE,
        PLANE_AGENT_SURFACE => super::SURFACE_POLICY_PACKAGE,
        _ => return None,
    };
    Some(format!("data.{}.allow", pkg))
}

/// The policy type a plane's definitions must declare.
pub fn plane_policy_type(plane: &str) -> Option<PolicyType> {
    match plane {
        PLANE_GATEWAY => Some(PolicyType::Gateway),
        PLANE_AGENT_SURFACE => Some(PolicyType::AgentSurface),
        _ => None,
    }
}

/// Row wrapper so the single global-assignments document can be stored via the
/// id-keyed [`StorableEntity`] filesystem backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GlobalPolicyDocument {
    #[serde(default = "global_doc_id")]
    id: String,
    #[serde(flatten)]
    assignments: GlobalPolicyAssignments,
}

fn global_doc_id() -> String {
    GLOBAL_DOC_ID.to_string()
}

impl StorableEntity for GlobalPolicyDocument {
    fn id(&self) -> &str {
        &self.id
    }
}

/// File-based store for the single global policy-assignments document.
pub struct FileSystemGlobalPolicyStore {
    storage: Box<dyn StorageBackend<GlobalPolicyDocument>>,
}

impl FileSystemGlobalPolicyStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage = rwlock_storage(PathBuf::from(storage_dir), "global_policy").await?;
        Ok(Self { storage })
    }

    /// Reconcile the in-memory cache with the shared-storage directory, so a
    /// node promoted from standby enforces the active writer's latest
    /// appliance-wide assignments rather than a stale boot snapshot.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }

    /// Load the current assignments (empty when none have been saved yet).
    pub async fn get(&self) -> GlobalPolicyAssignments {
        self.storage
            .get(GLOBAL_DOC_ID)
            .await
            .ok()
            .flatten()
            .map(|d| d.assignments)
            .unwrap_or_default()
    }

    /// Replace the assignments document.
    pub async fn save(
        &self,
        assignments: GlobalPolicyAssignments,
    ) -> Result<()> {
        self.storage
            .save(&GlobalPolicyDocument {
                id: GLOBAL_DOC_ID.to_string(),
                assignments,
            })
            .await
    }
}

/// One compiled globally-enforced policy plus its attestation evidence.
struct GlobalCompiledPolicy {
    engine: regorus::Engine,
    monitor_only: bool,
    policy_id: String,
    policy_name: String,
    version: Option<u32>,
    content_hash: String,
}

/// The compiled global set for one plane. `broken` is set when an **enforced**
/// (non-monitor) member could not be resolved/compiled, so the whole plane
/// fails closed at evaluation.
struct GlobalSet {
    policies: Vec<GlobalCompiledPolicy>,
    broken: bool,
}

/// The outcome of evaluating the appliance-wide set for a plane, carrying the
/// deciding policy's attestation evidence when it denied.
#[derive(Debug, Clone)]
pub struct GlobalDecision {
    pub allow: bool,
    pub reason: Option<String>,
    pub policy_id: Option<String>,
    pub policy_name: Option<String>,
    pub version: Option<u32>,
    pub content_hash: Option<String>,
}

impl GlobalDecision {
    fn allow() -> Self {
        Self {
            allow: true,
            reason: None,
            policy_id: None,
            policy_name: None,
            version: None,
            content_hash: None,
        }
    }

    fn allow_with(
        policy_id: Option<String>,
        policy_name: Option<String>,
        version: Option<u32>,
        content_hash: Option<String>,
    ) -> Self {
        Self {
            allow: true,
            reason: None,
            policy_id,
            policy_name,
            version,
            content_hash,
        }
    }

    fn deny(
        reason: &str,
        policy_id: Option<String>,
        policy_name: Option<String>,
        version: Option<u32>,
        content_hash: Option<String>,
    ) -> Self {
        Self {
            allow: false,
            reason: Some(reason.to_string()),
            policy_id,
            policy_name,
            version,
            content_hash,
        }
    }
}

/// Manager for appliance-wide policy sets. Holds a compiled set per plane and
/// evaluates them deny-overrides ahead of each object's own policy.
pub struct GlobalPolicyManager {
    engines: RwLock<HashMap<String, GlobalSet>>,
    policy_definition_store: RwLock<Option<Arc<FileSystemPolicyDefinitionStore>>>,
}

impl GlobalPolicyManager {
    pub fn new() -> Self {
        Self {
            engines: RwLock::new(HashMap::new()),
            policy_definition_store: RwLock::new(None),
        }
    }

    /// Set (or replace) the definition store used to resolve each assignment's
    /// Rego at refresh time.
    pub fn set_policy_definition_store(
        &self,
        store: Arc<FileSystemPolicyDefinitionStore>,
    ) {
        *self
            .policy_definition_store
            .write()
            .expect("policy_definition_store lock poisoned") = Some(store);
    }

    /// Recompile every plane's global set from the current assignments. An
    /// enforced member that is missing/disabled/empty or fails to compile marks
    /// its plane `broken` (fail-closed); a monitor-only member with the same
    /// failure is skipped without breaking the plane.
    pub async fn refresh(
        &self,
        assignments: &GlobalPolicyAssignments,
    ) {
        let _access_change = crate::mcp::subscriptions::AccessChange::begin();
        let store = self
            .policy_definition_store
            .read()
            .expect("policy_definition_store lock poisoned")
            .clone();

        let mut new_engines: HashMap<String, GlobalSet> = HashMap::new();
        for (plane, list) in &assignments.assignments {
            if plane_query(plane).is_none() {
                continue;
            }
            let expected_type = plane_policy_type(plane);
            let mut set = GlobalSet {
                policies: Vec::new(),
                broken: false,
            };
            for a in list {
                let def = match &store {
                    Some(s) => s.get(&a.policy_id).await,
                    None => None,
                };
                let usable = def.filter(|d| {
                    d.enabled
                        && !d.policy.trim().is_empty()
                        && expected_type
                            .as_ref()
                            .is_none_or(|t| &d.policy_type == t)
                });
                let Some(def) = usable else {
                    if !a.monitor_only {
                        set.broken = true;
                        error!(
                            plane = %plane,
                            policy_id = %a.policy_id,
                            "Global policy assignment unresolved/disabled/wrong-type — plane fails closed (appliance-wide deny) until corrected"
                        );
                    }
                    continue;
                };
                let mut engine = regorus::Engine::new();
                match engine.add_policy(format!("global_{}_{}", plane, a.policy_id), def.policy.clone()) {
                    Ok(_) => {
                        let hash = def
                            .content_hash
                            .clone()
                            .unwrap_or_else(|| content_hash(&def.policy_type, &def.policy));
                        set.policies
                            .push(GlobalCompiledPolicy {
                                engine,
                                monitor_only: a.monitor_only,
                                policy_id: a.policy_id.clone(),
                                policy_name: def.name,
                                version: def.version,
                                content_hash: hash,
                            });
                    }
                    Err(_) if a.monitor_only => {}
                    Err(_) => {
                        set.broken = true;
                        error!(
                            plane = %plane,
                            policy_id = %a.policy_id,
                            "Global policy assignment failed to compile — plane fails closed (appliance-wide deny) until corrected"
                        );
                    }
                }
            }
            if !set.policies.is_empty() || set.broken {
                new_engines.insert(plane.clone(), set);
            }
        }
        *self
            .engines
            .write()
            .expect("engines lock poisoned") = new_engines;
    }

    /// Whether any appliance-wide policy is enforced (or broken) for a plane.
    pub fn has_global(
        &self,
        plane: &str,
    ) -> bool {
        self.engines
            .read()
            .expect("engines lock poisoned")
            .get(plane)
            .map(|s| !s.policies.is_empty() || s.broken)
            .unwrap_or(false)
    }

    /// Evaluate the appliance-wide set for a plane, deny-overrides. A monitor-only
    /// member that would deny is logged but does not block. A broken plane, or an
    /// enforced member that denies or errors, denies (fail-closed).
    pub fn evaluate_global(
        &self,
        plane: &str,
        input: &serde_json::Value,
    ) -> GlobalDecision {
        let engines = self
            .engines
            .read()
            .expect("engines lock poisoned");
        let Some(set) = engines.get(plane) else {
            return GlobalDecision::allow();
        };
        if set.broken {
            return GlobalDecision::deny("Appliance-wide policy failed to compile", None, None, None, None);
        }
        let Some(query) = plane_query(plane) else {
            return GlobalDecision::allow();
        };
        let input_json = match serde_json::to_string(input) {
            Ok(j) => j,
            Err(_) => return GlobalDecision::deny("Failed to serialize policy input", None, None, None, None),
        };
        let first_policy = set.policies.first();
        for p in &set.policies {
            let mut engine = p.engine.clone();
            if engine
                .set_input_json(&input_json)
                .is_err()
            {
                if p.monitor_only {
                    continue;
                }
                return GlobalDecision::deny(
                    "Appliance-wide policy input error",
                    Some(p.policy_id.clone()),
                    Some(p.policy_name.clone()),
                    p.version,
                    Some(p.content_hash.clone()),
                );
            }
            let allow = match engine.eval_bool_query(query.clone(), false) {
                Ok(a) => a,
                // Wrong package / missing `allow` → treat as deny (fail-closed).
                Err(e)
                    if e.to_string()
                        .contains(super::REGORUS_QUERY_NO_VALUE_MARKER) =>
                {
                    false
                }
                Err(_) if p.monitor_only => continue,
                Err(_) => {
                    return GlobalDecision::deny(
                        "Appliance-wide policy evaluation error",
                        Some(p.policy_id.clone()),
                        Some(p.policy_name.clone()),
                        p.version,
                        Some(p.content_hash.clone()),
                    );
                }
            };
            if !allow {
                if p.monitor_only {
                    warn!(policy_id = %p.policy_id, plane = %plane, "monitor-only appliance-wide policy would deny");
                    continue;
                }
                return GlobalDecision::deny(
                    "Blocked by appliance-wide policy",
                    Some(p.policy_id.clone()),
                    Some(p.policy_name.clone()),
                    p.version,
                    Some(p.content_hash.clone()),
                );
            }
        }
        GlobalDecision::allow_with(
            first_policy.map(|p| p.policy_id.clone()),
            first_policy.map(|p| p.policy_name.clone()),
            first_policy.and_then(|p| p.version),
            first_policy.map(|p| p.content_hash.clone()),
        )
    }
}

impl Default for GlobalPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::policies::policy_definitions::PolicyDefinition;

    #[test]
    fn for_plane_references_and_planes_enforcing() {
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![
                GlobalAssignment {
                    policy_id: "p1".to_string(),
                    monitor_only: false,
                },
                GlobalAssignment {
                    policy_id: "p2".to_string(),
                    monitor_only: true,
                },
            ],
        );
        assert!(a.references_policy("p2"));
        assert!(!a.references_policy("nope"));
        assert_eq!(a.planes_enforcing("p1"), vec![PLANE_GATEWAY.to_string()]);
        assert!(
            a.planes_enforcing("nope")
                .is_empty()
        );
    }

    #[test]
    fn remove_policy_prunes_assignments_and_empty_planes() {
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![
                GlobalAssignment {
                    policy_id: "p1".to_string(),
                    monitor_only: false,
                },
                GlobalAssignment {
                    policy_id: "p2".to_string(),
                    monitor_only: true,
                },
            ],
        );
        a.assignments.insert(
            PLANE_AGENT_SURFACE.to_string(),
            vec![GlobalAssignment {
                policy_id: "p1".to_string(),
                monitor_only: false,
            }],
        );

        assert!(a.remove_policy("p1"));
        assert!(!a.references_policy("p1"));
        assert!(
            !a.assignments
                .contains_key(PLANE_AGENT_SURFACE)
        );
        assert_eq!(
            a.assignments[PLANE_GATEWAY]
                .iter()
                .map(|x| x.policy_id.as_str())
                .collect::<Vec<_>>(),
            vec!["p2"]
        );
    }

    #[test]
    fn remove_policy_unreferenced_is_noop() {
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![GlobalAssignment {
                policy_id: "p1".to_string(),
                monitor_only: false,
            }],
        );
        let snapshot = a.clone();
        assert!(!a.remove_policy("nope"));
        assert_eq!(a, snapshot);
    }

    #[tokio::test]
    async fn store_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemGlobalPolicyStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        assert!(
            store
                .get()
                .await
                .assignments
                .is_empty()
        );
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![GlobalAssignment {
                policy_id: "p1".to_string(),
                monitor_only: false,
            }],
        );
        store
            .save(a.clone())
            .await
            .expect("save");
        assert_eq!(store.get().await, a);
    }

    pub(crate) async fn store_with(defs: Vec<PolicyDefinition>) -> Arc<FileSystemPolicyDefinitionStore> {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            FileSystemPolicyDefinitionStore::new(
                dir.path()
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .expect("store"),
        );
        for d in defs {
            store
                .save(d)
                .await
                .expect("save def");
        }
        // Leak the tempdir so the backing files survive for the test's lifetime.
        std::mem::forget(dir);
        store
    }

    pub(crate) fn gw_def(
        id: &str,
        rego: &str,
    ) -> PolicyDefinition {
        PolicyDefinition {
            id: id.to_string(),
            tenant_id: None,
            name: id.to_string(),
            description: String::new(),
            policy_type: PolicyType::Gateway,
            policy: rego.to_string(),
            enabled: true,
            created_at: "t".to_string(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        }
    }

    #[tokio::test]
    async fn evaluate_global_deny_overrides_monitor_only_and_fail_closed() {
        let allow = gw_def("allow", "package gateway.policy\ndefault allow = true");
        let deny = gw_def("deny", "package gateway.policy\ndefault allow = false");
        let store = store_with(vec![allow, deny]).await;

        let manager = GlobalPolicyManager::new();
        manager.set_policy_definition_store(store);

        // Enforced deny in the set → deny with the deciding policy's evidence.
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![
                GlobalAssignment {
                    policy_id: "allow".to_string(),
                    monitor_only: false,
                },
                GlobalAssignment {
                    policy_id: "deny".to_string(),
                    monitor_only: false,
                },
            ],
        );
        manager.refresh(&a).await;
        assert!(manager.has_global(PLANE_GATEWAY));
        let d = manager.evaluate_global(PLANE_GATEWAY, &serde_json::json!({}));
        assert!(!d.allow);
        assert_eq!(d.policy_id.as_deref(), Some("deny"));
        assert_eq!(d.version, Some(1));

        // The same deny as monitor-only → allowed (would-be deny only logged).
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![GlobalAssignment {
                policy_id: "deny".to_string(),
                monitor_only: true,
            }],
        );
        manager.refresh(&a).await;
        assert!(
            manager
                .evaluate_global(PLANE_GATEWAY, &serde_json::json!({}))
                .allow
        );

        // A missing enforced policy → broken plane → fail-closed deny.
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![GlobalAssignment {
                policy_id: "gone".to_string(),
                monitor_only: false,
            }],
        );
        manager.refresh(&a).await;
        assert!(manager.has_global(PLANE_GATEWAY));
        assert!(
            !manager
                .evaluate_global(PLANE_GATEWAY, &serde_json::json!({}))
                .allow
        );

        // Clearing assignments → no global for the plane → allow.
        manager
            .refresh(&GlobalPolicyAssignments::default())
            .await;
        assert!(!manager.has_global(PLANE_GATEWAY));
        assert!(
            manager
                .evaluate_global(PLANE_GATEWAY, &serde_json::json!({}))
                .allow
        );
    }

    #[tokio::test]
    async fn deleted_and_pruned_policy_stops_enforcing_without_failing_closed() {
        let allow = gw_def("allow", "package gateway.policy\ndefault allow = true");
        let deny = gw_def("deny", "package gateway.policy\ndefault allow = false");
        let store = store_with(vec![allow, deny]).await;
        let manager = GlobalPolicyManager::new();
        manager.set_policy_definition_store(store.clone());

        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            PLANE_GATEWAY.to_string(),
            vec![
                GlobalAssignment {
                    policy_id: "allow".to_string(),
                    monitor_only: false,
                },
                GlobalAssignment {
                    policy_id: "deny".to_string(),
                    monitor_only: false,
                },
            ],
        );
        manager.refresh(&a).await;
        assert!(
            !manager
                .evaluate_global(PLANE_GATEWAY, &serde_json::json!({}))
                .allow
        );

        store
            .delete("deny")
            .await
            .expect("delete deny");
        assert!(a.remove_policy("deny"));
        manager.refresh(&a).await;

        assert!(manager.has_global(PLANE_GATEWAY));
        let d = manager.evaluate_global(PLANE_GATEWAY, &serde_json::json!({}));
        assert!(d.allow);
    }
}
