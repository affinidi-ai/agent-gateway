//! Lazy, idempotent VTA **context provisioning** for surfaces and variants.
//!
//! Every Agent Surface — and optionally every Surface Variant — can have its
//! own VTA context, so one surface's key cannot sign for another. Creating all
//! of them up front would be wasteful and would fail for surfaces that never
//! sign, so a context is created **on first use**, keyed by its derived name.
//!
//! ## Why the name is derived, not stored
//!
//! [`crate::config::agent_surface::derived_context_name`] keys on the stable
//! UUIDs, never on `alias`/`name`. A rename must not orphan a context: the
//! artifacts its key signed have to stay verifiable, and an orphan would also
//! mean the next sign silently provisions a *second* context for the same
//! surface.
//!
//! ## Why deletion does not reclaim
//!
//! Deleting a surface deliberately leaves its context and keys alone — the
//! credentials they signed are still in the wild. [`ContextProvisioner::orphaned`]
//! lists them for explicit operator cleanup instead.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};

use crate::vta::VtaError;
use crate::vta::key_directory::ContextId;

/// Creates a context on the VTA. A port, because the Trust Task that does it
/// requires super-admin over the target VTA and lands with the provisioning
/// control service (VTA-16); the lifecycle rules around it are what this module
/// owns and tests.
#[async_trait]
pub trait ContextCreator: Send + Sync {
    /// Create (or adopt, if it already exists) the context named `name`, and
    /// return its id. Must be **idempotent**: this is called once per name by
    /// construction, but a retry after a timeout must not create a duplicate.
    async fn create_context(
        &self,
        name: &str,
    ) -> Result<ContextId, VtaError>;
}

/// A creator that always refuses, for appliances that cannot auto-provision.
///
/// This is not a failure mode but a **tier**: auto-provisioning needs
/// super-admin over the target VTA, which a customer-owned (BYO) VTA does not
/// grant. On such a tier an unmapped surface is a configuration error the
/// operator fixes by naming a context explicitly — see
/// [`ContextProvisioner::ensure_context`].
pub struct UnavailableContextCreator;

#[async_trait]
impl ContextCreator for UnavailableContextCreator {
    async fn create_context(
        &self,
        name: &str,
    ) -> Result<ContextId, VtaError> {
        Err(VtaError::Config(format!(
            "this gateway cannot create VTA contexts (it does not hold super-admin on the target VTA); \
             set `signing.context_id` explicitly for the surface that needs `{name}`"
        )))
    }
}

/// Resolves a derived context name to a live context, creating it once.
pub struct ContextProvisioner {
    creator: Arc<dyn ContextCreator>,
    /// Upper bound on how many contexts this gateway may create. Bounds the
    /// blast radius of a loop or a misconfiguration that would otherwise mint
    /// a context per request.
    max_contexts: usize,
    known: RwLock<HashMap<String, ContextId>>,
    /// One lock per derived name, so two concurrent first-signs on the same
    /// surface create **exactly one** context instead of racing.
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl ContextProvisioner {
    pub fn new(
        creator: Arc<dyn ContextCreator>,
        max_contexts: usize,
    ) -> Self {
        Self {
            creator,
            max_contexts,
            known: RwLock::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Adopt contexts the operator already mapped, so they count toward the
    /// quota and are never re-created.
    pub async fn adopt(
        &self,
        name: impl Into<String>,
        context: ContextId,
    ) {
        self.known
            .write()
            .await
            .insert(name.into(), context);
    }

    /// The context for `name`, creating it on first use.
    pub async fn ensure_context(
        &self,
        name: &str,
    ) -> Result<ContextId, VtaError> {
        if let Some(hit) = self
            .known
            .read()
            .await
            .get(name)
            .cloned()
        {
            return Ok(hit);
        }

        let gate = {
            let mut locks = self.locks.lock().await;
            Arc::clone(
                locks
                    .entry(name.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = gate.lock().await;

        // Re-check under the per-name lock: the racing caller may have created
        // it while this one waited.
        if let Some(hit) = self
            .known
            .read()
            .await
            .get(name)
            .cloned()
        {
            return Ok(hit);
        }

        // Quota check happens *inside* the lock, so a burst of concurrent
        // first-signs cannot collectively overshoot it.
        let count = self.known.read().await.len();
        if count >= self.max_contexts {
            tracing::warn!(
                target: "vta_audit",
                context_name = %name,
                limit = self.max_contexts,
                "VTA context creation refused — the max_contexts limit is reached",
            );
            return Err(VtaError::Config(format!(
                "VTA context quota exhausted: {count} of {} contexts are in use, so `{name}` cannot be created; \
                 raise `[vta] max_contexts` or map the surface to an existing context",
                self.max_contexts
            )));
        }

        let context = self
            .creator
            .create_context(name)
            .await?;
        tracing::info!(
            target: "vta_audit",
            context_name = %name,
            context_id = %context.as_str(),
            in_use = count + 1,
            limit = self.max_contexts,
            "VTA context provisioned",
        );
        self.known
            .write()
            .await
            .insert(name.to_string(), context.clone());
        Ok(context)
    }

    /// Every context name this provisioner has created or adopted, for the Key
    /// Management inventory (VTA-20).
    pub async fn known_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .known
            .read()
            .await
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    }

    /// Context names this gateway created that no live surface or variant
    /// claims any more.
    ///
    /// Deleting a surface deliberately does **not** delete its keys — artifacts
    /// they signed must stay verifiable — so these are reported for explicit
    /// operator cleanup rather than reclaimed. Surfaced by the Key Management
    /// dashboard (VTA-20).
    #[allow(dead_code)]
    pub async fn orphaned(
        &self,
        live: &HashSet<String>,
    ) -> Vec<String> {
        let mut orphans: Vec<String> = self
            .known
            .read()
            .await
            .keys()
            .filter(|name| !live.contains(*name))
            .cloned()
            .collect();
        orphans.sort();
        orphans
    }

    /// How many contexts are currently accounted for. Rendered against
    /// `max_contexts` by the Key Management dashboard (VTA-20).
    #[allow(dead_code)]
    pub async fn in_use(&self) -> usize {
        self.known.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::config::agent_surface::derived_context_name;

    struct CountingCreator {
        calls: AtomicUsize,
        /// Simulate a slow VTA, so a concurrency test actually overlaps.
        delay: std::time::Duration,
    }

    impl CountingCreator {
        fn new(delay_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                delay: std::time::Duration::from_millis(delay_ms),
            })
        }

        fn calls(&self) -> usize {
            self.calls
                .load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ContextCreator for CountingCreator {
        async fn create_context(
            &self,
            name: &str,
        ) -> Result<ContextId, VtaError> {
            tokio::time::sleep(self.delay).await;
            let n = self
                .calls
                .fetch_add(1, Ordering::SeqCst);
            Ok(ContextId(format!("{name}#{n}")))
        }
    }

    fn detail(
        result: Result<(), VtaError>,
        expectation: &str,
    ) -> String {
        match result {
            Ok(()) => panic!("{expectation}"),
            Err(e) => e.log_detail().to_string(),
        }
    }

    // ---- derived naming ---------------------------------------------------

    #[test]
    fn a_context_name_is_derived_from_stable_ids_only() {
        let surface = derived_context_name(Some("tenant-a"), "11111111-2222-3333-4444-555555555555", None);
        assert_eq!(surface, "ctx:tenant-a/11111111-2222-3333-4444-555555555555");

        let variant = derived_context_name(Some("tenant-a"), "11111111-2222-3333-4444-555555555555", Some("v-dev"));
        assert_eq!(variant, "ctx:tenant-a/11111111-2222-3333-4444-555555555555/v-dev");
        assert_ne!(surface, variant, "a variant context must not collide with its surface");
    }

    #[test]
    fn an_appliance_global_surface_cannot_collide_with_a_tenant() {
        assert_eq!(derived_context_name(None, "s1", None), "ctx:_global/s1");
        assert_eq!(derived_context_name(Some("   "), "s1", None), "ctx:_global/s1");
        assert_ne!(derived_context_name(None, "s1", None), derived_context_name(Some("t"), "s1", None));
    }

    /// Renaming is exactly what the UUID keying exists to survive: the name is
    /// a pure function of ids, so a rename cannot produce a different one.
    #[tokio::test]
    async fn renaming_a_surface_does_not_orphan_its_context() {
        let creator = CountingCreator::new(0);
        let provisioner = ContextProvisioner::new(Arc::clone(&creator) as Arc<dyn ContextCreator>, 10);

        let before = derived_context_name(Some("t"), "surface-uuid", None);
        let first = provisioner
            .ensure_context(&before)
            .await
            .unwrap();

        // The operator renames the surface from "sales" to "revenue"; the ids
        // are untouched, so the derived name — and the context — are the same.
        let after = derived_context_name(Some("t"), "surface-uuid", None);
        let second = provisioner
            .ensure_context(&after)
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(creator.calls(), 1, "a rename must not provision a second context");
        assert!(
            provisioner
                .orphaned(&HashSet::from([after]))
                .await
                .is_empty()
        );
    }

    // ---- lazy + idempotent ------------------------------------------------

    #[tokio::test]
    async fn nothing_is_provisioned_until_a_context_is_needed() {
        let creator = CountingCreator::new(0);
        let provisioner = ContextProvisioner::new(Arc::clone(&creator) as Arc<dyn ContextCreator>, 10);
        assert_eq!(creator.calls(), 0);
        assert_eq!(provisioner.in_use().await, 0);

        provisioner
            .ensure_context("ctx:_global/s1")
            .await
            .unwrap();
        assert_eq!(creator.calls(), 1);
        assert_eq!(provisioner.in_use().await, 1);
    }

    #[tokio::test]
    async fn concurrent_first_signs_create_exactly_one_context() {
        let creator = CountingCreator::new(25);
        let provisioner = Arc::new(ContextProvisioner::new(Arc::clone(&creator) as Arc<dyn ContextCreator>, 10));

        let name = "ctx:_global/busy-surface";
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let provisioner = Arc::clone(&provisioner);
            tasks.push(tokio::spawn(async move {
                provisioner
                    .ensure_context(name)
                    .await
                    .unwrap()
            }));
        }
        let mut resolved = Vec::new();
        for task in tasks {
            resolved.push(task.await.unwrap());
        }

        assert_eq!(creator.calls(), 1, "eight concurrent first-signs must create one context");
        assert!(
            resolved
                .windows(2)
                .all(|w| w[0] == w[1]),
            "every caller must get the same context: {resolved:?}"
        );
        assert_eq!(provisioner.in_use().await, 1);
    }

    #[tokio::test]
    async fn an_adopted_context_is_never_recreated_and_counts_toward_the_quota() {
        let creator = CountingCreator::new(0);
        let provisioner = ContextProvisioner::new(Arc::clone(&creator) as Arc<dyn ContextCreator>, 2);

        provisioner
            .adopt("ctx:_global/s1", ContextId("operator-mapped".to_string()))
            .await;
        let resolved = provisioner
            .ensure_context("ctx:_global/s1")
            .await
            .unwrap();

        assert_eq!(resolved, ContextId("operator-mapped".to_string()));
        assert_eq!(creator.calls(), 0);
        assert_eq!(provisioner.in_use().await, 1);
    }

    // ---- quota ------------------------------------------------------------

    #[tokio::test]
    async fn exceeding_the_quota_fails_closed_and_names_the_limit() {
        let creator = CountingCreator::new(0);
        let provisioner = ContextProvisioner::new(Arc::clone(&creator) as Arc<dyn ContextCreator>, 2);

        provisioner
            .ensure_context("ctx:_global/s1")
            .await
            .unwrap();
        provisioner
            .ensure_context("ctx:_global/s2")
            .await
            .unwrap();

        let msg = detail(
            provisioner
                .ensure_context("ctx:_global/s3")
                .await
                .map(|_| ()),
            "the third context is over the limit",
        );
        assert!(msg.contains('2'), "the error must name the limit: {msg}");
        assert!(msg.contains("max_contexts"), "the error must say how to fix it: {msg}");
        assert!(msg.contains("ctx:_global/s3"), "the error must name the context: {msg}");
        assert_eq!(creator.calls(), 2, "nothing is created once the quota is reached");

        // An already-provisioned context still resolves — the quota bounds
        // creation, not use.
        provisioner
            .ensure_context("ctx:_global/s1")
            .await
            .expect("an existing context is unaffected by the quota");
    }

    // ---- tier ------------------------------------------------------------

    #[tokio::test]
    async fn a_tier_that_cannot_auto_provision_says_how_to_fix_it() {
        let provisioner = ContextProvisioner::new(Arc::new(UnavailableContextCreator), 10);
        let msg = detail(
            provisioner
                .ensure_context("ctx:_global/s1")
                .await
                .map(|_| ()),
            "auto-provisioning is unavailable",
        );
        assert!(msg.contains("signing.context_id"), "the message must be actionable: {msg}");
        assert!(msg.contains("ctx:_global/s1"), "the message must name the context: {msg}");

        // Mapping it explicitly is the documented escape hatch, and works.
        provisioner
            .adopt("ctx:_global/s1", ContextId("ctx-operator".to_string()))
            .await;
        assert_eq!(
            provisioner
                .ensure_context("ctx:_global/s1")
                .await
                .unwrap(),
            ContextId("ctx-operator".to_string())
        );
    }

    // ---- orphans ----------------------------------------------------------

    #[tokio::test]
    async fn deleting_a_surface_reports_an_orphan_rather_than_reclaiming_it() {
        let creator = CountingCreator::new(0);
        let provisioner = ContextProvisioner::new(Arc::clone(&creator) as Arc<dyn ContextCreator>, 10);
        provisioner
            .ensure_context("ctx:_global/kept")
            .await
            .unwrap();
        provisioner
            .ensure_context("ctx:_global/deleted")
            .await
            .unwrap();

        let live = HashSet::from(["ctx:_global/kept".to_string()]);
        assert_eq!(
            provisioner
                .orphaned(&live)
                .await,
            vec!["ctx:_global/deleted".to_string()]
        );
        // Reported, not reclaimed: still resolvable, so anything it signed
        // stays verifiable.
        assert_eq!(provisioner.in_use().await, 2);
    }
}
