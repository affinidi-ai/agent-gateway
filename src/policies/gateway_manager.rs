use crate::gateways::types::Gateway;
use crate::policies::policy_definitions::{FileSystemPolicyDefinitionStore, PolicyType, content_hash};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

/// Gateway policy manager that handles OPA policies at the gateway level.
///
/// - For the **self** gateway: policy is enforced on all inbound traffic.
/// - For **remote** gateways: policy is enforced on outbound traffic to that gateway.
///
/// Gateway policy is evaluated **before** surface-level policy.
/// A gateway deny cannot be overridden by a surface allow (no privilege escalation).
///
/// ## Performance
///
/// Policies are pre-compiled via `regorus::Engine::add_policy()` and stored as
/// template engines. On each evaluation, the template is **cloned** (cheap —
/// regorus uses `Arc` internally with the `arc` feature) and evaluated on the
/// clone. This avoids write-lock serialization: concurrent requests evaluate in
/// parallel on independent engine clones with no contention.
///
/// The self-gateway ID uses `std::sync::RwLock` (not tokio) for lock-free reads
/// on the hot path — no async context switch for a simple string lookup.
pub struct GatewayPolicyManager {
    /// Pre-compiled policy set per gateway (keyed by gateway id): an ordered
    /// deny-overrides set, each member carrying the attestation evidence
    /// (version + content hash) of the revision it compiled.
    engines: Arc<RwLock<HashMap<String, Vec<CompiledGatewayPolicy>>>>,
    /// Gateway ids whose policy is config-enabled. Tracked independently of the
    /// compiled engines so an enabled-but-broken policy still enforces
    /// (fail-closed) instead of silently skipping when no engine compiled.
    enforced: RwLock<HashSet<String>>,
    /// Cached self-gateway ID. Uses std::sync::RwLock for non-async, non-yielding reads.
    self_gateway_id: RwLock<Option<String>>,
    /// Definition store for resolving a gateway's Rego from its
    /// `policy_definition_id` at compile time (reference-only).
    policy_definition_store: RwLock<Option<Arc<FileSystemPolicyDefinitionStore>>>,
}

/// A compiled gateway policy plus the attestation evidence for the revision it
/// was compiled from. `version` is `None` for a legacy inline policy with no
/// definition; `content_hash` binds the exact Rego bytes enforced.
struct CompiledGatewayPolicy {
    engine: regorus::Engine,
    policy_definition_id: Option<String>,
    version: Option<u32>,
    content_hash: String,
}

pub type GatewayPolicyEvidence = (Option<String>, Option<u32>, String);
pub type GatewayPolicyDecisionWithEvidence = (crate::policies::PolicyDecision, Option<GatewayPolicyEvidence>);

impl GatewayPolicyManager {
    pub fn new() -> Self {
        Self {
            engines: Arc::new(RwLock::new(HashMap::new())),
            enforced: RwLock::new(HashSet::new()),
            self_gateway_id: RwLock::new(None),
            policy_definition_store: RwLock::new(None),
        }
    }

    /// Set (or replace) the policy definition store used to resolve a gateway's
    /// Rego from its `policy_definition_id` at compile time.
    pub fn set_policy_definition_store(
        &self,
        store: Arc<FileSystemPolicyDefinitionStore>,
    ) {
        *self
            .policy_definition_store
            .write()
            .expect("policy_definition_store lock poisoned") = Some(store);
    }

    /// Set the self-gateway ID (called once at startup or on config reload)
    pub fn set_self_gateway_id(
        &self,
        id: String,
    ) {
        *self
            .self_gateway_id
            .write()
            .expect("self_gateway_id lock poisoned") = Some(id);
    }

    /// Get the self-gateway ID (lock-free read, no async overhead)
    pub fn get_self_gateway_id(&self) -> Option<String> {
        self.self_gateway_id
            .read()
            .expect("self_gateway_id lock poisoned")
            .clone()
    }

    /// Load or update the OPA policy for a gateway.
    ///
    /// Reference-only: when the config carries a `policy_definition_id`, the Rego
    /// and its version/content-hash are resolved from the definition store at
    /// compile time; the inline `policy` is only a legacy fallback. The gateway
    /// is marked enforced before compiling so an enabled-but-broken policy still
    /// denies (fail-closed).
    pub async fn update_gateway_policy(
        &self,
        gateway: &Gateway,
    ) -> Result<(), String> {
        let _access_change = crate::mcp::subscriptions::AccessChange::begin();
        let gateway_id = &gateway.id;

        // Keep the tracked self-gateway id in step with policy updates. The self
        // gateway can be created after startup (e.g. during federation), so the
        // id captured at boot may be `None`; registering it here ensures the
        // fabric-receive enforcement path sees policies applied to a
        // late-created self gateway.
        if gateway.gateway_type == crate::gateways::types::GatewayType::SelfGateway {
            self.set_self_gateway_id(gateway.id.clone());
        }

        let enabled = gateway
            .opa_policy_config
            .as_ref()
            .is_some_and(|c| c.enabled);

        // Not configured, or configured but disabled — drop any engine and stop enforcing.
        if !enabled {
            self.enforced
                .write()
                .expect("enforced lock poisoned")
                .remove(gateway_id);
            let mut engines = self
                .engines
                .write()
                .expect("engines lock poisoned");
            if engines
                .remove(gateway_id)
                .is_some()
            {
                info!(gateway_id = %gateway_id, "Removed OPA policy for gateway");
            }
            return Ok(());
        }

        // Mark enforced BEFORE resolving/compiling so an enabled-but-broken
        // policy still denies (fail-closed) instead of silently skipping.
        self.enforced
            .write()
            .expect("enforced lock poisoned")
            .insert(gateway_id.clone());

        let policy_config = gateway
            .opa_policy_config
            .as_ref()
            .expect("enabled implies a policy config");

        // Reference-only, multi-policy deny-overrides set: resolve the ordered,
        // deduped definition ids (single `policy_definition_id` first, then
        // `policy_definition_ids`) and compile each. A legacy gateway with no
        // definition compiles its inline `policy` as a single-member set. Any
        // resolve/compile failure evicts the whole set so the enforced PEP
        // denies (fail-closed).
        match self
            .resolve_and_compile_gateway_set(gateway_id, policy_config)
            .await
        {
            Ok(compiled) => {
                self.engines
                    .write()
                    .expect("engines lock poisoned")
                    .insert(gateway_id.clone(), compiled);
                info!(gateway_id = %gateway_id, "Gateway OPA policy compiled and cached");
                Ok(())
            }
            Err(e) => {
                self.engines
                    .write()
                    .expect("engines lock poisoned")
                    .remove(gateway_id);
                Err(e)
            }
        }
    }

    /// Resolve + compile the ordered, deduped multi-policy deny-overrides set for
    /// a gateway. The single `policy_definition_id` is enforced first, then each
    /// id in `policy_definition_ids` (deduped). A gateway with no definition
    /// reference compiles its inline `policy` as a single-member set.
    async fn resolve_and_compile_gateway_set(
        &self,
        gateway_id: &str,
        policy_config: &crate::gateways::types::GatewayOpaPolicyConfig,
    ) -> Result<Vec<CompiledGatewayPolicy>, String> {
        let mut def_ids: Vec<String> = Vec::new();
        if let Some(id) = policy_config
            .policy_definition_id
            .as_deref()
            .filter(|d| !d.is_empty())
        {
            def_ids.push(id.to_string());
        }
        for id in &policy_config.policy_definition_ids {
            if !id.is_empty() && !def_ids.contains(id) {
                def_ids.push(id.clone());
            }
        }

        // Legacy inline single policy (no definition reference).
        if def_ids.is_empty() {
            let rego = policy_config.policy.clone();
            let hash = content_hash(&PolicyType::Gateway, &rego);
            let mut engine = regorus::Engine::new();
            engine
                .add_policy(format!("gateway_{}", gateway_id), rego)
                .map_err(|e| format!("Failed to compile gateway policy: {}", e))?;
            return Ok(vec![CompiledGatewayPolicy {
                engine,
                policy_definition_id: None,
                version: None,
                content_hash: hash,
            }]);
        }

        let store = self
            .policy_definition_store
            .read()
            .expect("policy_definition_store lock poisoned")
            .clone()
            .ok_or_else(|| "Policy definition store not configured".to_string())?;
        let mut compiled = Vec::with_capacity(def_ids.len());
        for def_id in &def_ids {
            let def = store
                .get(def_id)
                .await
                .ok_or_else(|| format!("Policy definition not found: {}", def_id))?;
            let hash = def
                .content_hash
                .clone()
                .unwrap_or_else(|| content_hash(&PolicyType::Gateway, &def.policy));
            let mut engine = regorus::Engine::new();
            engine
                .add_policy(format!("gateway_{}_{}", gateway_id, def_id), def.policy)
                .map_err(|e| format!("Failed to compile gateway policy {}: {}", def_id, e))?;
            compiled.push(CompiledGatewayPolicy {
                engine,
                policy_definition_id: Some(def_id.clone()),
                version: def.version,
                content_hash: hash,
            });
        }
        Ok(compiled)
    }

    /// Test-only boolean convenience over [`Self::evaluate_policy_decision`].
    /// Production code calls `evaluate_policy_decision` directly so it can also
    /// record the deny reason in the policy-decision audit event.
    #[cfg(test)]
    pub fn evaluate_policy(
        &self,
        gateway_id: &str,
        input: serde_json::Value,
    ) -> Result<bool, String> {
        Ok(self
            .evaluate_policy_decision(gateway_id, input)?
            .allow)
    }

    /// Evaluate the gateway-level policy set (deny-overrides), returning the
    /// decision plus the attestation evidence of the deciding revision — the
    /// member that denied, or the first member on allow. Evidence is `None` when
    /// no engine is compiled.
    ///
    /// If no policy is configured for this gateway, allows by default; an
    /// enforced gateway with no compiled engine denies (fail-closed).
    pub fn evaluate_with_evidence(
        &self,
        gateway_id: &str,
        input: serde_json::Value,
    ) -> Result<GatewayPolicyDecisionWithEvidence, String> {
        // Snapshot the compiled set under a brief read lock; evaluation is then
        // lock-free on the cheap engine clones.
        let members: Vec<(regorus::Engine, Option<String>, Option<u32>, String)> = {
            let engines = self
                .engines
                .read()
                .expect("engines lock poisoned");
            match engines.get(gateway_id) {
                Some(set) if !set.is_empty() => set
                    .iter()
                    .map(|c| (c.engine.clone(), c.policy_definition_id.clone(), c.version, c.content_hash.clone()))
                    .collect(),
                _ => {
                    // Fail-closed: an enforced gateway with no compiled engine
                    // (its policy failed to compile) denies; an unenforced
                    // gateway (no policy configured) allows by default.
                    if self.is_enforced(gateway_id) {
                        warn!(gateway_id = %gateway_id, "Gateway policy is enforced but no engine compiled — denying (fail-closed)");
                        return Ok((
                            crate::policies::PolicyDecision {
                                allow: false,
                                reason: Some("Gateway policy is enabled but failed to compile".to_string()),
                            },
                            None,
                        ));
                    }
                    debug!(gateway_id = %gateway_id, "No gateway policy configured, allowing request");
                    return Ok((crate::policies::PolicyDecision { allow: true, reason: None }, None));
                }
            }
        };

        debug!(gateway_id = %gateway_id, member_count = members.len(), "Evaluating gateway-level OPA policy set");

        let input_json =
            serde_json::to_string(&input).map_err(|e| format!("Failed to serialize gateway policy input: {}", e))?;
        let first_evidence = members
            .first()
            .map(|(_, id, v, h)| (id.clone(), *v, h.clone()));

        for (engine_tmpl, policy_definition_id, version, hash) in &members {
            let mut engine = engine_tmpl.clone();
            engine
                .set_input_json(&input_json)
                .map_err(|e| format!("Failed to set policy input: {}", e))?;

            let allow = match engine.eval_bool_query(format!("data.{}.allow", super::GATEWAY_POLICY_PACKAGE), false) {
                Ok(allow) => allow,
                // No value for `data.gateway.policy.allow`: the module declares the
                // wrong package for the gateway scope, or omits `allow`. Fail closed
                // with an actionable reason (see `crate::policies::REGORUS_QUERY_NO_VALUE_MARKER`).
                Err(e)
                    if e.to_string()
                        .contains(crate::policies::REGORUS_QUERY_NO_VALUE_MARKER) =>
                {
                    return Ok((
                        crate::policies::PolicyDecision {
                            allow: false,
                            reason: Some(format!(
                                "Gateway policy produced no `allow` decision; it must declare `package {}` and define `allow` (e.g. `default allow = false`)",
                                super::GATEWAY_POLICY_PACKAGE
                            )),
                        },
                        Some((policy_definition_id.clone(), *version, hash.clone())),
                    ));
                }
                Err(e) => return Err(format!("Failed to evaluate gateway policy: {}", e)),
            };

            if !allow {
                let reason = engine
                    .eval_rule(format!("data.{}.deny_reason", super::GATEWAY_POLICY_PACKAGE))
                    .ok()
                    .and_then(|v| {
                        v.as_string()
                            .ok()
                            .map(|s| s.to_string())
                    })
                    .or_else(|| Some("Request blocked by gateway policy".to_string()));
                return Ok((
                    crate::policies::PolicyDecision { allow: false, reason },
                    Some((policy_definition_id.clone(), *version, hash.clone())),
                ));
            }
        }

        // Every member allowed.
        Ok((crate::policies::PolicyDecision { allow: true, reason: None }, first_evidence))
    }

    /// Evaluate the gateway-level policy set, returning just the decision.
    /// Deny-overrides across the set; use [`Self::evaluate_with_evidence`] to
    /// also obtain the deciding revision's attestation evidence.
    ///
    /// If no policy is configured for this gateway, allows by default.
    pub fn evaluate_policy_decision(
        &self,
        gateway_id: &str,
        input: serde_json::Value,
    ) -> Result<crate::policies::PolicyDecision, String> {
        Ok(self
            .evaluate_with_evidence(gateway_id, input)?
            .0)
    }

    /// Returns true when the gateway's policy is config-enabled (enforced),
    /// regardless of whether it compiled. The PEP evaluates whenever this is
    /// true; a missing engine then denies (fail-closed).
    pub fn is_enforced(
        &self,
        gateway_id: &str,
    ) -> bool {
        self.enforced
            .read()
            .expect("enforced lock poisoned")
            .contains(gateway_id)
    }

    /// Attestation evidence (definition id + version + content hash) of the **first** member of
    /// a gateway's compiled deny-overrides set, for the audit record at the
    /// gateway PEP. `None` when no engine is compiled. For a multi-policy set a
    /// deny may be decided by a later member; [`Self::evaluate_with_evidence`]
    /// returns the exact deciding revision.
    pub fn policy_evidence(
        &self,
        gateway_id: &str,
    ) -> Option<GatewayPolicyEvidence> {
        self.engines
            .read()
            .expect("engines lock poisoned")
            .get(gateway_id)
            .and_then(|set| set.first())
            .map(|c| (c.policy_definition_id.clone(), c.version, c.content_hash.clone()))
    }

    /// Resolve the display name for an optional gateway policy-definition ID,
    /// falling back to the Rego package name (`gateway.policy`) when no
    /// definition is attached.
    pub async fn resolve_policy_name_or_default(
        &self,
        def_id: Option<&str>,
    ) -> String {
        let store = self
            .policy_definition_store
            .read()
            .expect("policy_definition_store lock poisoned")
            .clone();
        if let Some(id) = def_id
            && let Some(store) = store
            && let Some(def) = store.get(id).await
        {
            return def.name;
        }
        super::GATEWAY_POLICY_PACKAGE.to_string()
    }

    /// Remove policy for a gateway
    #[allow(dead_code)]
    pub fn remove_gateway(
        &self,
        gateway_id: &str,
    ) {
        let _access_change = crate::mcp::subscriptions::AccessChange::begin();
        self.enforced
            .write()
            .expect("enforced lock poisoned")
            .remove(gateway_id);
        let mut engines = self
            .engines
            .write()
            .expect("engines lock poisoned");
        if engines
            .remove(gateway_id)
            .is_some()
        {
            info!(gateway_id = %gateway_id, "Removed gateway policy");
        }
    }
}

impl Default for GatewayPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::types::{GatewayCreationType, GatewayOpaPolicyConfig, GatewayStatus, GatewayType};

    fn create_test_gateway(
        id: &str,
        gateway_type: GatewayType,
        policy: Option<GatewayOpaPolicyConfig>,
    ) -> Gateway {
        Gateway {
            id: id.to_string(),
            tenant_id: None,
            name: format!("test-gateway-{}", id),
            description: "Test gateway".to_string(),
            did: "did:example:test".to_string(),
            issuer_did: None,
            issuer_did_source: None,
            trusted_issuer_dids: Vec::new(),
            gateway_type,
            status: GatewayStatus::Active,
            creation_type: GatewayCreationType::User,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            exposed_channels: Vec::new(),
            opa_policy_config: policy,
        }
    }

    #[tokio::test]
    async fn test_no_policy_allows_by_default() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway("gw-1", GatewayType::SelfGateway, None);

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        let input = serde_json::json!({
            "gateway": {
                "direction": "inbound"
            }
        });

        let allowed = manager
            .evaluate_policy("gw-1", input)
            .unwrap();
        assert!(allowed, "No policy should allow by default");
    }

    #[tokio::test]
    async fn test_disabled_policy_allows_by_default() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-2",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: false,
                policy: "package gateway.policy\ndefault allow = false".to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        let input = serde_json::json!({});

        let allowed = manager
            .evaluate_policy("gw-2", input)
            .unwrap();
        assert!(allowed, "Disabled policy should allow by default");
    }

    #[tokio::test]
    async fn test_policy_deny_unauthenticated() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-3",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: r#"
package gateway.policy

default allow = false

allow if {
    input.source_auth.claims.sub
}
"#
                .to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // Request without source_auth — should be denied
        let input_no_jwt = serde_json::json!({
            "gateway": {
                "direction": "inbound"
            }
        });

        let allowed = manager
            .evaluate_policy("gw-3", input_no_jwt)
            .unwrap();
        assert!(!allowed, "Unauthenticated request should be denied");

        // Request with source_auth — should be allowed
        let input_with_jwt = serde_json::json!({
            "gateway": {
                "direction": "inbound"
            },
            "source_auth": {
                "method": "jwt_bearer",
                "subject": "user-123",
                "claims": { "sub": "user-123" }
            }
        });

        let allowed = manager
            .evaluate_policy("gw-3", input_with_jwt)
            .unwrap();
        assert!(allowed, "Authenticated request should be allowed");
    }

    #[tokio::test]
    async fn wrong_package_gateway_policy_fails_closed() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-mismatch",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                // Surface package on a gateway — `data.gateway.policy.allow` never resolves.
                policy: "package surface.policy\ndefault allow = true".to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        );
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        let decision = manager
            .evaluate_policy_decision("gw-mismatch", serde_json::json!({}))
            .unwrap();
        assert!(!decision.allow, "wrong-package gateway policy must fail closed");
        assert!(
            decision
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("no `allow` decision"),
            "reason must be actionable: {:?}",
            decision.reason
        );
    }

    #[tokio::test]
    async fn enforced_but_broken_policy_denies_fail_closed() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-broken",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: "this is not valid rego {{{".to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        );
        // Compilation fails, but the gateway is still marked enforced.
        assert!(
            manager
                .update_gateway_policy(&gateway)
                .await
                .is_err()
        );
        assert!(manager.is_enforced("gw-broken"));
        let decision = manager
            .evaluate_policy_decision("gw-broken", serde_json::json!({}))
            .unwrap();
        assert!(!decision.allow, "an enabled-but-broken gateway policy must fail closed");
    }

    #[tokio::test]
    async fn reference_only_resolves_rego_and_records_version_hash() {
        use crate::policies::policy_definitions::PolicyDefinition;
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileSystemPolicyDefinitionStore::new(
                tmp.path()
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        store
            .save(PolicyDefinition {
                id: "gw-def".into(),
                tenant_id: None,
                name: "n".into(),
                description: String::new(),
                policy_type: PolicyType::Gateway,
                policy: "package gateway.policy\ndefault allow = false".into(),
                enabled: true,
                created_at: "t".into(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
            })
            .await
            .unwrap();

        let manager = GatewayPolicyManager::new();
        manager.set_policy_definition_store(store);
        let gateway = create_test_gateway(
            "gw-ref",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                // Reference-only: no inline Rego; resolved from the definition.
                policy: String::new(),
                policy_definition_id: Some("gw-def".to_string()),
                ..Default::default()
            }),
        );
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // Resolved from the definition (default allow = false) → denies.
        let decision = manager
            .evaluate_policy_decision("gw-ref", serde_json::json!({}))
            .unwrap();
        assert!(!decision.allow, "reference-only gateway must enforce the resolved definition");

        // Evidence carries the resolved definition id, version + content hash.
        let (policy_definition_id, version, hash) = manager
            .policy_evidence("gw-ref")
            .expect("compiled evidence present");
        assert_eq!(policy_definition_id.as_deref(), Some("gw-def"));
        assert_eq!(version, Some(1));
        assert!(hash.starts_with("sha256:"));
        assert_eq!(
            manager
                .resolve_policy_name_or_default(policy_definition_id.as_deref())
                .await,
            "n"
        );
    }

    #[tokio::test]
    async fn multi_policy_set_denies_when_any_member_denies() {
        use crate::policies::policy_definitions::{PolicyDefinition, content_hash};
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileSystemPolicyDefinitionStore::new(
                tmp.path()
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let mk = |id: &str, allow: bool| PolicyDefinition {
            id: id.into(),
            tenant_id: None,
            name: id.into(),
            description: String::new(),
            policy_type: PolicyType::Gateway,
            policy: format!("package gateway.policy\ndefault allow = {}", allow),
            enabled: true,
            created_at: "t".into(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        };
        store
            .save(mk("gw-allow", true))
            .await
            .unwrap();
        store
            .save(mk("gw-deny", false))
            .await
            .unwrap();

        let manager = GatewayPolicyManager::new();
        manager.set_policy_definition_store(store);
        let gateway = create_test_gateway(
            "gw-multi",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: String::new(),
                policy_definition_id: Some("gw-allow".to_string()),
                policy_definition_ids: vec!["gw-deny".to_string()],
            }),
        );
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // Deny-overrides: the allow member passes but the deny member blocks,
        // and the returned evidence is the *denying* member (not the first).
        let (decision, evidence) = manager
            .evaluate_with_evidence("gw-multi", serde_json::json!({}))
            .unwrap();
        assert!(!decision.allow, "a deny-overrides set must deny if any member denies");
        let (policy_definition_id, _v, hash) = evidence.expect("deciding evidence present");
        assert_eq!(policy_definition_id.as_deref(), Some("gw-deny"));
        assert_eq!(hash, content_hash(&PolicyType::Gateway, "package gateway.policy\ndefault allow = false"));
    }

    #[tokio::test]
    async fn multi_policy_set_allows_when_all_members_allow() {
        use crate::policies::policy_definitions::PolicyDefinition;
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileSystemPolicyDefinitionStore::new(
                tmp.path()
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let mk = |id: &str| PolicyDefinition {
            id: id.into(),
            tenant_id: None,
            name: id.into(),
            description: String::new(),
            policy_type: PolicyType::Gateway,
            policy: "package gateway.policy\ndefault allow = true".into(),
            enabled: true,
            created_at: "t".into(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        };
        store
            .save(mk("gw-a"))
            .await
            .unwrap();
        store
            .save(mk("gw-b"))
            .await
            .unwrap();

        let manager = GatewayPolicyManager::new();
        manager.set_policy_definition_store(store);
        let gateway = create_test_gateway(
            "gw-multi-allow",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: String::new(),
                policy_definition_id: Some("gw-a".to_string()),
                policy_definition_ids: vec!["gw-b".to_string()],
            }),
        );
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();
        let decision = manager
            .evaluate_policy_decision("gw-multi-allow", serde_json::json!({}))
            .unwrap();
        assert!(decision.allow, "a set where all members allow must allow");
    }

    #[tokio::test]
    async fn test_remove_gateway_policy() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-4",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: "package gateway.policy\ndefault allow = true".to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // Verify policy is loaded by evaluating it
        let input = serde_json::json!({});
        let allowed = manager
            .evaluate_policy("gw-4", input.clone())
            .unwrap();
        assert!(allowed, "Policy with default allow=true should allow");

        manager.remove_gateway("gw-4");

        // After removal, evaluate_policy returns Ok(true) (no policy = allow)
        let allowed = manager
            .evaluate_policy("gw-4", input)
            .unwrap();
        assert!(allowed, "After removal, no policy should allow by default");
    }

    #[tokio::test]
    async fn test_policy_allow_by_source_id() {
        let manager = GatewayPolicyManager::new();
        let did = "did:peer:2.VzDnaeZs48dBXnuWsUCzgYfnaY9Ps5xrwTgWR85ZzeUcuRR4Vu.EzQ3shrjtWsQZhRkPRRnj7RoddKdTrKv9z1kx91nvsfx5Zci1e.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci5leGFtcGxlLmNvbSJ9";
        let policy = format!(
            r#"package gateway.policy

default allow = false

allow if {{
    input.gateway.direction == "inbound"
    input.gateway.source_id == "{did}"
}}
"#
        );

        let gateway = create_test_gateway(
            "gw-src",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: policy.clone(),
                policy_definition_id: None,
                ..Default::default()
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        let input = serde_json::json!({
            "http": {
                "method": "POST",
                "path": "/",
                "headers": {
                    "CONTENT-TYPE": "application/json"
                }
            },
            "gateway": {
                "direction": "inbound",
                "source_id": did
            },
            "channel": {
                "config_id": "05fa9e89-1f0e-48b0-b76f-585fd6ac2dff",
                "name": "mcp-channel-1779115681393"
            }
        });

        let allowed = manager
            .evaluate_policy("gw-src", input)
            .unwrap();
        assert!(allowed, "Request with matching direction + source_id should be allowed, policy:\n{}", policy);
    }

    #[tokio::test]
    async fn removed_opa_config_drops_stale_engine_on_recompile() {
        // F3: a gateway that had an enforced deny policy, then had its
        // opa_policy_config removed on disk (now None), must drop the stale
        // engine + enforced membership when re-derived on promotion. The
        // promotion loop calls update_gateway_policy unconditionally for every
        // gateway; the function self-handles the None case.
        let manager = GatewayPolicyManager::new();
        let enforcing = create_test_gateway(
            "gw-removed",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: "package gateway.policy\ndefault allow = false".to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        );
        manager
            .update_gateway_policy(&enforcing)
            .await
            .unwrap();
        assert!(manager.is_enforced("gw-removed"), "precondition: policy enforced");
        assert!(
            !manager
                .evaluate_policy_decision("gw-removed", serde_json::json!({}))
                .unwrap()
                .allow,
            "precondition: deny policy is in effect"
        );

        // Config removed on disk → None on the next re-derive.
        let removed = create_test_gateway("gw-removed", GatewayType::SelfGateway, None);
        manager
            .update_gateway_policy(&removed)
            .await
            .unwrap();

        assert!(!manager.is_enforced("gw-removed"), "removing opa_policy_config must stop enforcing");
        assert!(
            manager
                .evaluate_policy("gw-removed", serde_json::json!({}))
                .unwrap(),
            "with the stale engine dropped, evaluation allows by default"
        );
    }
}
